package com.ahlyxlabs.conveyance.approval

import com.ahlyxlabs.conveyance.session.EndReason
import com.ahlyxlabs.conveyance.session.AuthenticatedPlaintext
import com.ahlyxlabs.conveyance.session.PhoneSession
import com.ahlyxlabs.conveyance.session.SessionState
import com.ahlyxlabs.conveyance.crypto.RustUnlockedIdentity
import com.ahlyxlabs.conveyance.storage.credentials.CredentialStore
import com.ahlyxlabs.conveyance.storage.identity.IdentityVault
import com.ahlyxlabs.conveyance.storage.identity.Tier1AuthInput
import com.ahlyxlabs.conveyance.storage.keystore.BiometricAuthException
import com.ahlyxlabs.conveyance.storage.log.ApprovalLog
import java.io.Closeable
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import uniffi.conveyance_crypto_ffi.ApprovalDecision as RustApprovalDecision
import uniffi.conveyance_crypto_ffi.ApprovalHistoryDestination
import uniffi.conveyance_crypto_ffi.ApprovalInboundKind
import uniffi.conveyance_crypto_ffi.ApprovalProtocol
import uniffi.conveyance_crypto_ffi.ValidatedApprovalRequest

fun interface ApprovalUnixClock {
    fun nowSeconds(): Long
}

object SystemApprovalUnixClock : ApprovalUnixClock {
    override fun nowSeconds(): Long = System.currentTimeMillis() / 1_000
}

data class ApprovalAuthPrompt(
    val instanceId: String,
    val sessionId: String,
    val attemptId: String,
    val deadlineElapsedMs: Long,
)

/** Creates one isolated approval runtime for one already ACTIVE paired Noise session. */
@Singleton
class PhoneApprovalRuntimeFactory @Inject constructor(
    private val protocolFactory: ApprovalProtocolFactory,
    private val approvalLog: ApprovalLog,
    private val credentials: CredentialStore,
    private val identityVault: IdentityVault,
) {
    private val claimedSessions = ConcurrentHashMap.newKeySet<String>()

    fun create(
        session: PhoneSession,
        ownerScope: CoroutineScope,
        monotonicClock: ApprovalMonotonicClock = AndroidApprovalMonotonicClock,
        unixClock: ApprovalUnixClock = SystemApprovalUnixClock,
    ): PhoneApprovalRuntime {
        val sessionId = session.sessionInstanceId
        if (!session.isActive() || session.authenticatedPeer == null) {
            session.endNow(EndReason.ProtocolViolation)
            throw IllegalStateException("approval requires an active session from a stored pairing")
        }
        if (!claimedSessions.add(sessionId)) {
            session.endNow(EndReason.ProtocolViolation)
            throw IllegalStateException("an approval dispatcher already owns this session")
        }
        val protocol = try {
            protocolFactory.newForSession()
        } catch (error: Exception) {
            claimedSessions.remove(sessionId)
            session.endNow(EndReason.ProtocolViolation)
            throw error
        }
        return try {
            PhoneApprovalRuntime(
                session = session,
                protocol = protocol,
                approvalLog = approvalLog,
                credentials = credentials,
                identityVault = identityVault,
                ownerScope = ownerScope,
                monotonicClock = monotonicClock,
                unixClock = unixClock,
                onClosed = { claimedSessions.remove(sessionId) },
            )
        } catch (error: Exception) {
            protocol.close()
            claimedSessions.remove(sessionId)
            session.endNow(EndReason.ProtocolViolation)
            throw error
        }
    }
}

/**
 * Application-level dispatch and authorization coordinator for one live
 * authenticated session. It owns no Compose UI and accepts plaintext only
 * from [PhoneSession.inbound]. The FFI object, request handle, state machine,
 * paired name, and outbound sender all remain tied to that one session.
 */
class PhoneApprovalRuntime internal constructor(
    private val session: PhoneSession,
    private val protocol: ApprovalProtocol,
    private val approvalLog: ApprovalLog,
    private val credentials: CredentialStore,
    private val identityVault: IdentityVault,
    ownerScope: CoroutineScope,
    private val monotonicClock: ApprovalMonotonicClock,
    private val unixClock: ApprovalUnixClock,
    private val onClosed: () -> Unit,
) : Closeable {
    private val sessionId = session.sessionInstanceId
    val sessionInstanceId: String get() = sessionId
    private val stateMachine = ApprovalStateMachine(sessionId, session, monotonicClock)
    private val peer = requireNotNull(session.authenticatedPeer)
    private val runtimeJob = SupervisorJob(ownerScope.coroutineContext[Job])
    private val runtimeScope = CoroutineScope(ownerScope.coroutineContext + runtimeJob)

    private var started = false
    private var closed = false
    private var currentRequest: ValidatedApprovalRequest? = null
    private val submittedAuthAttempts = mutableSetOf<String>()
    private val authPromptChannel = Channel<ApprovalAuthPrompt>(Channel.BUFFERED)

    val state: StateFlow<ApprovalState> = stateMachine.state
    val authPrompts = authPromptChannel.receiveAsFlow()
    val tier1AuthMethod get() = session.unlockedSession.authMethod

    @Synchronized
    fun start(): Boolean {
        if (started || closed || !session.isActive()) return false
        started = true
        runtimeScope.launch {
            session.state.collect { current ->
                if (current == SessionState.Ended || current == SessionState.NoSession) {
                    stateMachine.sessionLost()
                    releaseAfterSessionEnd()
                }
            }
        }
        runtimeScope.launch {
            try {
                session.inbound.collect { plaintext -> dispatch(plaintext) }
            } finally {
                stateMachine.sessionLost()
                releaseAfterSessionEnd()
            }
        }
        return true
    }

    fun approve(instanceId: String) {
        handleAction(stateMachine.approve(instanceId, sessionId))
    }

    fun deny(instanceId: String) {
        handleAction(stateMachine.deny(instanceId, sessionId))
    }

    /**
     * Called by a lifecycle-aware UI effect after the user tapped Approve.
     * The UI supplies the configured auth input; the vault rechecks it using
     * HIGH_RISK_APPROVAL and never creates/replaces the active session.
     */
    suspend fun authenticateTier3(
        prompt: ApprovalAuthPrompt,
        input: Tier1AuthInput,
    ) {
        val awaiting = state.value as? ApprovalState.AwaitingAuthentication
        if (awaiting == null || awaiting.pending.instanceId != prompt.instanceId ||
            awaiting.pending.sessionId != prompt.sessionId || prompt.sessionId != sessionId ||
            awaiting.attemptId != prompt.attemptId ||
            !session.isActive()
        ) {
            input.close()
            return
        }
        synchronized(this) {
            if (!submittedAuthAttempts.add(prompt.attemptId)) {
                input.close()
                return
            }
        }

        val outcome = try {
            val result = identityVault.reauthenticate(session.unlockedSession, input)
            val authOutcome = if (result.isSuccess) {
                ApprovalAuthOutcome.SUCCEEDED
            } else if (result.exceptionOrNull() is BiometricAuthException) {
                // Cancellation, lockout, and unavailable strong biometric
                // all stay retryable until this request's original deadline.
                ApprovalAuthOutcome.CANCELLED
            } else {
                ApprovalAuthOutcome.FAILED
            }
            currentCoroutineContext().ensureActive()
            authOutcome
        } catch (cancelled: CancellationException) {
            handleAction(
                stateMachine.completeAuthentication(
                    prompt.instanceId,
                    prompt.sessionId,
                    prompt.attemptId,
                    ApprovalAuthOutcome.CANCELLED,
                ),
            )
            throw cancelled
        } finally {
            input.close()
            synchronized(this) { submittedAuthAttempts.remove(prompt.attemptId) }
        }

        handleAction(
            stateMachine.completeAuthentication(
                prompt.instanceId,
                prompt.sessionId,
                prompt.attemptId,
                outcome,
            ),
        )
    }

    /** Explicit user cancellation outside Android's biometric callback. */
    fun cancelTier3Authentication(prompt: ApprovalAuthPrompt) {
        handleAction(
            stateMachine.completeAuthentication(
                prompt.instanceId,
                prompt.sessionId,
                prompt.attemptId,
                ApprovalAuthOutcome.CANCELLED,
            ),
        )
    }

    private suspend fun dispatch(message: AuthenticatedPlaintext) {
        val plaintext = message.bytes
        val receivedAtElapsedMs = message.receivedAtElapsedMs
        val inbound = try {
            protocol.decodeInbound(plaintext)
        } catch (_: Exception) {
            failProtocol()
            return
        } finally {
            plaintext.fill(0)
        }

        try {
            when (inbound.kind()) {
                ApprovalInboundKind.APPROVAL_REQUEST -> {
                    val request = inbound.approvalRequest() ?: run {
                        failProtocol()
                        return
                    }
                    receiveApprovalRequest(request, receivedAtElapsedMs)
                }
                ApprovalInboundKind.SESSION_END -> {
                    stateMachine.sessionLost()
                    session.endNow(EndReason.RemoteEnded)
                }
                ApprovalInboundKind.PING -> {
                    val pong = protocol.encodePong(inbound)
                    try {
                        session.send(pong)
                    } finally {
                        pong.fill(0)
                    }
                }
                ApprovalInboundKind.LIST_SERVICES_REQUEST -> {
                    // The spec permits this active-session query without an
                    // approval; it returns names only and never opens a DEK.
                    val response = protocol.encodeListServicesResponse(
                        inbound,
                        credentials.listServices(),
                    )
                    session.send(response)
                    response.fill(0)
                }
                ApprovalInboundKind.UNEXPECTED -> failProtocol()
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            failProtocol()
        } finally {
            inbound.close()
        }
    }

    private suspend fun receiveApprovalRequest(
        request: ValidatedApprovalRequest,
        receivedAtElapsedMs: Long,
    ) {
        try {
            val summary = request.summary()
            val history = try {
                approvalLog.successfulDestinationsNewestFirst(
                    protocol.destinationHistoryLimit().toInt(),
                )
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                // Unknown history must make the destination novel and force
                // Tier 3; it can never reduce the required authentication.
                emptyList()
            }
            val tier = protocol.evaluateTier(
                request,
                history.map { ApprovalHistoryDestination(it.service, it.endpoint) },
            )
            val requestIdBytes = summary.reqId.hexToBytes()

            // The request row is durable before state becomes visible to UI.
            approvalLog.append(
                reqId = requestIdBytes,
                eventType = EVENT_APPROVAL_REQUEST,
                payloadJson = summary.canonicalRequestJson,
                timestamp = unixClock.nowSeconds(),
            )

            val requiredTier = when (tier.tier.toInt()) {
                2 -> ApprovalRequiredTier.TIER_2
                3 -> ApprovalRequiredTier.TIER_3
                else -> throw IllegalStateException("Rust returned an unsupported approval tier")
            }
            synchronized(this) { currentRequest = request }
            val action = stateMachine.receive(
                card = ApprovalRequestCard(
                    requestId = summary.reqId,
                    opType = summary.opType,
                    pairedPcName = peer.pcName,
                    service = summary.service,
                    method = summary.method,
                    endpoint = summary.endpoint,
                    paramsJson = summary.paramsJson,
                    requestedBy = summary.requestedBy,
                    timestampUnixSeconds = summary.timestamp,
                ),
                tier = requiredTier,
                tier3Reasons = tier.reasons,
                receivedAtElapsedMs = receivedAtElapsedMs,
            )
            when (action) {
                is ApprovalAction.Rejected -> {
                    synchronized(this) { if (currentRequest === request) currentRequest = null }
                    request.close()
                    failProtocol()
                    return
                }
                is ApprovalAction.Finalize -> {
                    handleAction(action)
                    return
                }
                is ApprovalAction.Authenticate -> {
                    handleAction(action)
                    return
                }
                ApprovalAction.Ignored -> Unit
            }
            if (state.value !is ApprovalState.AwaitingUserDecision) {
                synchronized(this) { if (currentRequest === request) currentRequest = null }
                request.close()
                failProtocol()
                return
            }
            val pending = state.value as? ApprovalState.AwaitingUserDecision
                ?: throw IllegalStateException("approval state did not enter review")
            runtimeScope.launch {
                val waitMs = (pending.deadlineElapsedMs - monotonicClock.elapsedRealtimeMs()).coerceAtLeast(0)
                delay(waitMs)
                handleAction(stateMachine.expire(pending.instanceId, sessionId))
            }
        } catch (cancelled: CancellationException) {
            request.close()
            throw cancelled
        } catch (_: Exception) {
            request.close()
            failProtocol()
        }
    }

    private fun handleAction(action: ApprovalAction) {
        when (action) {
            ApprovalAction.Ignored -> Unit
            is ApprovalAction.Authenticate -> authPromptChannel.trySend(
                ApprovalAuthPrompt(
                    instanceId = action.instanceId,
                    sessionId = action.sessionId,
                    attemptId = action.attemptId,
                    deadlineElapsedMs = action.deadlineElapsedMs,
                ),
            )
            is ApprovalAction.Rejected -> failProtocol()
            is ApprovalAction.Finalize -> runtimeScope.launch { finalize(action) }
        }
    }

    private suspend fun finalize(action: ApprovalAction.Finalize) {
        val before = stateMachine.beforeFinalize(
            action.instanceId,
            action.sessionId,
            action.decision,
        )
        when (before) {
            ApprovalAction.Ignored -> return
            is ApprovalAction.Finalize -> {
                if (before.decision != action.decision) {
                    finalize(before)
                    return
                }
            }
            is ApprovalAction.Authenticate, is ApprovalAction.Rejected -> return
        }

        val request = synchronized(this) { currentRequest }
        if (request == null || !session.isActive()) {
            stateMachine.sessionLost()
            return
        }
        val committing = state.value as? ApprovalState.Finalizing ?: return
        if (committing.pending.instanceId != action.instanceId) return

        val rustDecision = action.decision.toRustDecision()
        val reason = when (action.decision) {
            ApprovalDecision.APPROVED -> REASON_USER_TAP
            ApprovalDecision.DENIED -> REASON_USER_DENIED
            ApprovalDecision.EXPIRED -> REASON_APPROVAL_TIMEOUT
        }
        val eventType = when (action.decision) {
            ApprovalDecision.APPROVED -> EVENT_APPROVAL_GRANTED
            ApprovalDecision.DENIED -> EVENT_APPROVAL_DENIED
            ApprovalDecision.EXPIRED -> EVENT_APPROVAL_EXPIRED
        }

        var signedBytes: ByteArray? = null
        try {
            val payload = request.terminalLogPayload(
                decision = rustDecision,
                reason = reason,
                requiredTier = if (committing.pending.requiredTier == ApprovalRequiredTier.TIER_3) {
                    3u.toUByte()
                } else {
                    2u.toUByte()
                },
                tier3Reasons = committing.pending.tier3Reasons,
            )
            val reqId = committing.pending.request.requestId.hexToBytes()
            signedBytes = approvalLog.appendWithBeforeCommit(
                reqId = reqId,
                eventType = eventType,
                payloadJson = payload,
                timestamp = unixClock.nowSeconds(),
            ) {
                when (val authorized = stateMachine.beforeSign(
                    action.instanceId,
                    action.sessionId,
                    action.decision,
                )) {
                    is ApprovalAction.Finalize -> {
                        if (authorized.decision != action.decision) {
                            throw ApprovalExpiredBeforeSignature(authorized)
                        }
                    }
                    else -> throw ApprovalNoLongerAuthorized()
                }
                protocol.signedResponse(
                    request,
                    rustDecision,
                    reason,
                    (session.unlockedSession.identity as? RustUnlockedIdentity)?.ffi
                        ?: throw IllegalStateException("active identity is not backed by the Rust handle"),
                )
            }
            val bytes = checkNotNull(signedBytes)
            try {
                session.send(bytes)
            } finally {
                bytes.fill(0)
            }
            stateMachine.completeFinalization(
                action.instanceId,
                action.sessionId,
                action.decision,
                sent = true,
            )
            synchronized(this) {
                if (currentRequest === request) currentRequest = null
            }
            request.close()
        } catch (expired: ApprovalExpiredBeforeSignature) {
            signedBytes?.fill(0)
            finalize(expired.expiredAction)
        } catch (_: ApprovalNoLongerAuthorized) {
            signedBytes?.fill(0)
            synchronized(this) { if (currentRequest === request) currentRequest = null }
            request.close()
        } catch (cancelled: CancellationException) {
            signedBytes?.fill(0)
            stateMachine.sessionLost()
            throw cancelled
        } catch (_: Exception) {
            signedBytes?.fill(0)
            stateMachine.failFinalization(
                action.instanceId,
                action.sessionId,
                SAFE_APPROVAL_FAILURE,
            )
            request.close()
            synchronized(this) { if (currentRequest === request) currentRequest = null }
            session.endNow(EndReason.ProtocolViolation)
        }
    }

    private fun failProtocol() {
        stateMachine.sessionLost()
        session.endNow(EndReason.ProtocolViolation)
    }

    private fun releaseAfterSessionEnd() {
        val shouldRelease = synchronized(this) {
            if (closed) {
                false
            } else {
                closed = true
                currentRequest?.close()
                currentRequest = null
                authPromptChannel.close()
                protocol.close()
                true
            }
        }
        if (!shouldRelease) return
        onClosed()
        runtimeJob.cancel()
    }

    override fun close() {
        if (session.isActive()) session.endNow(EndReason.UserEnded)
        stateMachine.sessionLost()
        releaseAfterSessionEnd()
    }

    private fun String.hexToBytes(): ByteArray {
        require(length == 32 && all { it in '0'..'9' || it in 'a'..'f' })
        return ByteArray(16) { index -> substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }

    private fun ApprovalDecision.toRustDecision(): RustApprovalDecision = when (this) {
        ApprovalDecision.APPROVED -> RustApprovalDecision.APPROVED
        ApprovalDecision.DENIED -> RustApprovalDecision.DENIED
        ApprovalDecision.EXPIRED -> RustApprovalDecision.EXPIRED
    }

    private class ApprovalExpiredBeforeSignature(
        val expiredAction: ApprovalAction.Finalize,
    ) : Exception()

    private class ApprovalNoLongerAuthorized : Exception()

    private companion object {
        const val EVENT_APPROVAL_REQUEST = "approval_request"
        const val EVENT_APPROVAL_GRANTED = "approval_granted"
        const val EVENT_APPROVAL_DENIED = "approval_denied"
        const val EVENT_APPROVAL_EXPIRED = "approval_expired"
        const val REASON_USER_TAP = "user_tap"
        const val REASON_USER_DENIED = "user_denied"
        const val REASON_APPROVAL_TIMEOUT = "approval_timeout"
        const val SAFE_APPROVAL_FAILURE = "Could not complete this approval. The session was closed."
    }
}
