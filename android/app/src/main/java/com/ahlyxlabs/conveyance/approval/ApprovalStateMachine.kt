package com.ahlyxlabs.conveyance.approval

import android.os.SystemClock
import java.util.UUID
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

const val APPROVAL_DEADLINE_MS: Long = 60_000

fun interface ApprovalMonotonicClock {
    fun elapsedRealtimeMs(): Long
}

object AndroidApprovalMonotonicClock : ApprovalMonotonicClock {
    // Same monotonic timebase as PhoneSession's authenticated plaintext receipt marker.
    override fun elapsedRealtimeMs(): Long = SystemClock.elapsedRealtime()
}

fun interface ApprovalSessionGuard {
    fun isActive(): Boolean
}

enum class ApprovalRequiredTier { TIER_2, TIER_3 }

enum class ApprovalAuthStatus { NOT_REQUIRED, NOT_STARTED, IN_PROGRESS, CANCELLED, FAILED, SUCCEEDED }

enum class ApprovalAuthOutcome { SUCCEEDED, CANCELLED, FAILED }

enum class ApprovalDecision { APPROVED, DENIED, EXPIRED }

data class ApprovalRequestCard(
    val requestId: String,
    val opType: String,
    val pairedPcName: String,
    val service: String,
    val method: String,
    val endpoint: String,
    val paramsJson: String,
    val requestedBy: String?,
    val timestampUnixSeconds: Long,
)

sealed interface ApprovalState {
    data object Empty : ApprovalState

    data class AwaitingUserDecision(
        val instanceId: String,
        val sessionId: String,
        val request: ApprovalRequestCard,
        val requiredTier: ApprovalRequiredTier,
        val tier3Reasons: List<String>,
        val receivedAtElapsedMs: Long,
        val deadlineElapsedMs: Long,
        val authStatus: ApprovalAuthStatus,
    ) : ApprovalState

    data class AwaitingAuthentication(
        val pending: AwaitingUserDecision,
        val attemptId: String,
    ) : ApprovalState

    data class Committing(
        val pending: AwaitingUserDecision,
        val decision: ApprovalDecision,
    ) : ApprovalState

    /** Finalization was claimed after the last session/deadline check. */
    data class Finalizing(
        val pending: AwaitingUserDecision,
        val decision: ApprovalDecision,
    ) : ApprovalState

    data class Approved(val instanceId: String, val requestId: String) : ApprovalState
    data class Denied(val instanceId: String, val requestId: String) : ApprovalState
    data class Expired(val instanceId: String, val requestId: String) : ApprovalState
    data class SessionLost(val instanceId: String, val requestId: String) : ApprovalState
    data class Cancelled(val instanceId: String, val requestId: String) : ApprovalState
    data class Failed(val instanceId: String, val requestId: String, val safeMessage: String) : ApprovalState
}

sealed interface ApprovalAction {
    data object Ignored : ApprovalAction
    data class Authenticate(
        val instanceId: String,
        val sessionId: String,
        val attemptId: String,
        val deadlineElapsedMs: Long,
    ) : ApprovalAction
    data class Finalize(val instanceId: String, val sessionId: String, val decision: ApprovalDecision) : ApprovalAction
    data class Rejected(val reason: Rejection) : ApprovalAction
}

enum class Rejection { NO_ACTIVE_SESSION, REQUEST_ALREADY_PENDING, REPLAYED_REQUEST_ID, WRONG_INSTANCE }

/**
 * One live authenticated session's approval state machine. Construct a new
 * instance for every PhoneSession. All callbacks carry request, session,
 * and auth-attempt identities, so callbacks from a prior session/request
 * cannot act on the current state.
 */
class ApprovalStateMachine(
    private val sessionId: String,
    private val session: ApprovalSessionGuard,
    private val clock: ApprovalMonotonicClock,
) {
    private val seenRequestIds = mutableSetOf<String>()
    private val _state = MutableStateFlow<ApprovalState>(ApprovalState.Empty)
    val state: StateFlow<ApprovalState> = _state.asStateFlow()

    @Synchronized
    fun receive(
        card: ApprovalRequestCard,
        tier: ApprovalRequiredTier,
        tier3Reasons: List<String>,
        receivedAtElapsedMs: Long = clock.elapsedRealtimeMs(),
    ): ApprovalAction {
        if (!session.isActive()) return ApprovalAction.Rejected(Rejection.NO_ACTIVE_SESSION)
        if (hasNonTerminalRequest()) return ApprovalAction.Rejected(Rejection.REQUEST_ALREADY_PENDING)
        if (!seenRequestIds.add(card.requestId)) return ApprovalAction.Rejected(Rejection.REPLAYED_REQUEST_ID)

        val state = ApprovalState.AwaitingUserDecision(
            instanceId = UUID.randomUUID().toString(),
            sessionId = sessionId,
            request = card.copy(),
            requiredTier = tier,
            tier3Reasons = tier3Reasons.toList(),
            receivedAtElapsedMs = receivedAtElapsedMs,
            deadlineElapsedMs = saturatingAdd(receivedAtElapsedMs, APPROVAL_DEADLINE_MS),
            authStatus = if (tier == ApprovalRequiredTier.TIER_2) {
                ApprovalAuthStatus.NOT_REQUIRED
            } else {
                ApprovalAuthStatus.NOT_STARTED
            },
        )
        if (clock.elapsedRealtimeMs() >= state.deadlineElapsedMs) {
            _state.value = ApprovalState.Committing(state, ApprovalDecision.EXPIRED)
            return ApprovalAction.Finalize(state.instanceId, sessionId, ApprovalDecision.EXPIRED)
        }
        _state.value = state
        return ApprovalAction.Ignored
    }

    @Synchronized
    fun approve(instanceId: String, callbackSessionId: String): ApprovalAction {
        val pending = pendingForApprove(instanceId, callbackSessionId) ?: return ApprovalAction.Ignored
        expireOrLoseSession(pending)?.let { return it }
        return if (pending.requiredTier == ApprovalRequiredTier.TIER_3) {
            val attemptId = UUID.randomUUID().toString()
            _state.value = ApprovalState.AwaitingAuthentication(
                pending.copy(authStatus = ApprovalAuthStatus.IN_PROGRESS),
                attemptId,
            )
            ApprovalAction.Authenticate(instanceId, sessionId, attemptId, pending.deadlineElapsedMs)
        } else {
            _state.value = ApprovalState.Committing(pending, ApprovalDecision.APPROVED)
            ApprovalAction.Finalize(instanceId, sessionId, ApprovalDecision.APPROVED)
        }
    }

    @Synchronized
    fun deny(instanceId: String, callbackSessionId: String): ApprovalAction {
        val pending = pendingForAction(instanceId, callbackSessionId) ?: return ApprovalAction.Ignored
        expireOrLoseSession(pending)?.let { return it }
        _state.value = ApprovalState.Committing(pending, ApprovalDecision.DENIED)
        return ApprovalAction.Finalize(instanceId, sessionId, ApprovalDecision.DENIED)
    }

    @Synchronized
    fun completeAuthentication(
        instanceId: String,
        callbackSessionId: String,
        attemptId: String,
        outcome: ApprovalAuthOutcome,
    ): ApprovalAction {
        val awaiting = _state.value as? ApprovalState.AwaitingAuthentication
            ?: return ApprovalAction.Ignored
        val pending = awaiting.pending
        if (pending.instanceId != instanceId || pending.sessionId != callbackSessionId ||
            awaiting.attemptId != attemptId || sessionId != callbackSessionId
        ) return ApprovalAction.Ignored

        expireOrLoseSession(pending)?.let { return it }
        return when (outcome) {
            ApprovalAuthOutcome.SUCCEEDED -> {
                _state.value = ApprovalState.Committing(
                    pending.copy(authStatus = ApprovalAuthStatus.SUCCEEDED),
                    ApprovalDecision.APPROVED,
                )
                ApprovalAction.Finalize(instanceId, sessionId, ApprovalDecision.APPROVED)
            }
            ApprovalAuthOutcome.CANCELLED, ApprovalAuthOutcome.FAILED -> {
                _state.value = pending.copy(
                    authStatus = if (outcome == ApprovalAuthOutcome.CANCELLED) {
                        ApprovalAuthStatus.CANCELLED
                    } else {
                        ApprovalAuthStatus.FAILED
                    },
                )
                ApprovalAction.Ignored
            }
        }
    }

    /** Called by the original deadline timer; never restarts the 60-second window. */
    @Synchronized
    fun expire(instanceId: String, callbackSessionId: String): ApprovalAction {
        val pending = when (val current = _state.value) {
            is ApprovalState.AwaitingUserDecision -> current
            is ApprovalState.AwaitingAuthentication -> current.pending
            else -> return ApprovalAction.Ignored
        }
        if (pending.instanceId != instanceId || pending.sessionId != callbackSessionId ||
            callbackSessionId != sessionId
        ) return ApprovalAction.Ignored
        if (clock.elapsedRealtimeMs() < pending.deadlineElapsedMs) return ApprovalAction.Ignored
        if (!session.isActive()) {
            _state.value = ApprovalState.SessionLost(instanceId, pending.request.requestId)
            return ApprovalAction.Ignored
        }
        _state.value = ApprovalState.Committing(pending, ApprovalDecision.EXPIRED)
        return ApprovalAction.Finalize(instanceId, sessionId, ApprovalDecision.EXPIRED)
    }

    /** Recheck immediately before signing/sending a decision. */
    @Synchronized
    fun beforeFinalize(
        instanceId: String,
        callbackSessionId: String,
        expectedDecision: ApprovalDecision,
    ): ApprovalAction {
        val committing = _state.value as? ApprovalState.Committing ?: return ApprovalAction.Ignored
        val pending = committing.pending
        if (pending.instanceId != instanceId || pending.sessionId != callbackSessionId ||
            callbackSessionId != sessionId || committing.decision != expectedDecision
        ) return ApprovalAction.Ignored
        if (!session.isActive()) {
            _state.value = ApprovalState.SessionLost(instanceId, pending.request.requestId)
            return ApprovalAction.Ignored
        }
        if (expectedDecision == ApprovalDecision.APPROVED &&
            clock.elapsedRealtimeMs() >= pending.deadlineElapsedMs
        ) {
            _state.value = ApprovalState.Committing(pending, ApprovalDecision.EXPIRED)
            return ApprovalAction.Finalize(instanceId, sessionId, ApprovalDecision.EXPIRED)
        }
        _state.value = ApprovalState.Finalizing(pending, expectedDecision)
        return ApprovalAction.Finalize(instanceId, sessionId, expectedDecision)
    }

    /**
     * Last synchronous authorization check run inside the log transaction,
     * immediately before Rust signs the response. If approval crossed its
     * original deadline while the log row was being staged, the transaction
     * rolls back and this returns Expired instead.
     */
    @Synchronized
    fun beforeSign(
        instanceId: String,
        callbackSessionId: String,
        expectedDecision: ApprovalDecision,
    ): ApprovalAction {
        val finalizing = _state.value as? ApprovalState.Finalizing ?: return ApprovalAction.Ignored
        val pending = finalizing.pending
        if (pending.instanceId != instanceId || pending.sessionId != callbackSessionId ||
            callbackSessionId != sessionId || finalizing.decision != expectedDecision
        ) return ApprovalAction.Ignored
        if (!session.isActive()) {
            _state.value = ApprovalState.SessionLost(instanceId, pending.request.requestId)
            return ApprovalAction.Ignored
        }
        if (expectedDecision == ApprovalDecision.APPROVED &&
            clock.elapsedRealtimeMs() >= pending.deadlineElapsedMs
        ) {
            _state.value = ApprovalState.Committing(pending, ApprovalDecision.EXPIRED)
            return ApprovalAction.Finalize(instanceId, sessionId, ApprovalDecision.EXPIRED)
        }
        return ApprovalAction.Finalize(instanceId, sessionId, expectedDecision)
    }

    @Synchronized
    fun completeFinalization(
        instanceId: String,
        callbackSessionId: String,
        decision: ApprovalDecision,
        sent: Boolean,
    ): ApprovalAction {
        val finalizing = _state.value as? ApprovalState.Finalizing ?: return ApprovalAction.Ignored
        val pending = finalizing.pending
        if (pending.instanceId != instanceId || pending.sessionId != callbackSessionId ||
            callbackSessionId != sessionId || finalizing.decision != decision
        ) return ApprovalAction.Ignored
        if (!sent) {
            _state.value = ApprovalState.SessionLost(instanceId, pending.request.requestId)
            return ApprovalAction.Ignored
        }
        _state.value = when (decision) {
            ApprovalDecision.APPROVED -> ApprovalState.Approved(instanceId, pending.request.requestId)
            ApprovalDecision.DENIED -> ApprovalState.Denied(instanceId, pending.request.requestId)
            ApprovalDecision.EXPIRED -> ApprovalState.Expired(instanceId, pending.request.requestId)
        }
        return ApprovalAction.Ignored
    }

    @Synchronized
    fun failFinalization(instanceId: String, callbackSessionId: String, safeMessage: String) {
        val pending = pendingFrom(_state.value) ?: return
        if (pending.instanceId != instanceId || pending.sessionId != callbackSessionId ||
            callbackSessionId != sessionId
        ) return
        if (_state.value !is ApprovalState.Committing && _state.value !is ApprovalState.Finalizing) return
        _state.value = ApprovalState.Failed(instanceId, pending.request.requestId, safeMessage)
    }

    @Synchronized
    fun sessionLost() {
        val pending = pendingFrom(_state.value) ?: return
        _state.value = ApprovalState.SessionLost(pending.instanceId, pending.request.requestId)
    }

    @Synchronized
    fun cancel() {
        val pending = pendingFrom(_state.value) ?: return
        _state.value = ApprovalState.Cancelled(pending.instanceId, pending.request.requestId)
    }

    private fun pendingForAction(instanceId: String, callbackSessionId: String): ApprovalState.AwaitingUserDecision? {
        val pending = when (val current = _state.value) {
            is ApprovalState.AwaitingUserDecision -> current
            is ApprovalState.AwaitingAuthentication -> current.pending
            else -> return null
        }
        if (pending.instanceId != instanceId || pending.sessionId != callbackSessionId ||
            callbackSessionId != sessionId
        ) return null
        return pending
    }

    private fun pendingForApprove(instanceId: String, callbackSessionId: String): ApprovalState.AwaitingUserDecision? {
        val pending = _state.value as? ApprovalState.AwaitingUserDecision ?: return null
        if (pending.instanceId != instanceId || pending.sessionId != callbackSessionId ||
            callbackSessionId != sessionId
        ) return null
        return pending
    }

    private fun expireOrLoseSession(pending: ApprovalState.AwaitingUserDecision): ApprovalAction? {
        if (!session.isActive()) {
            _state.value = ApprovalState.SessionLost(pending.instanceId, pending.request.requestId)
            return ApprovalAction.Ignored
        }
        if (clock.elapsedRealtimeMs() >= pending.deadlineElapsedMs) {
            _state.value = ApprovalState.Committing(pending, ApprovalDecision.EXPIRED)
            return ApprovalAction.Finalize(pending.instanceId, sessionId, ApprovalDecision.EXPIRED)
        }
        return null
    }

    private fun hasNonTerminalRequest(): Boolean = when (_state.value) {
        ApprovalState.Empty,
        is ApprovalState.Approved,
        is ApprovalState.Denied,
        is ApprovalState.Expired,
        is ApprovalState.SessionLost,
        is ApprovalState.Cancelled,
        is ApprovalState.Failed -> false
        else -> true
    }

    private fun pendingFrom(state: ApprovalState): ApprovalState.AwaitingUserDecision? = when (state) {
        is ApprovalState.AwaitingUserDecision -> state
        is ApprovalState.AwaitingAuthentication -> state.pending
        is ApprovalState.Committing -> state.pending
        is ApprovalState.Finalizing -> state.pending
        else -> null
    }

    private fun saturatingAdd(value: Long, delta: Long): Long =
        if (value > Long.MAX_VALUE - delta) Long.MAX_VALUE else value + delta
}
