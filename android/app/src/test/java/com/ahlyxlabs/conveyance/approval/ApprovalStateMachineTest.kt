package com.ahlyxlabs.conveyance.approval

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ApprovalStateMachineTest {
    private class FakeClock(var now: Long = 10_000) : ApprovalMonotonicClock {
        override fun elapsedRealtimeMs(): Long = now
    }

    private class FakeSession(var active: Boolean = true) : ApprovalSessionGuard {
        override fun isActive(): Boolean = active
    }

    private data class Setup(
        val clock: FakeClock,
        val session: FakeSession,
        val machine: ApprovalStateMachine,
        val instanceId: String,
    )

    private fun setup(
        sessionId: String = "session-a",
        requestId: String = "req-a",
        tier: ApprovalRequiredTier = ApprovalRequiredTier.TIER_3,
    ): Setup {
        val clock = FakeClock()
        val session = FakeSession()
        val machine = ApprovalStateMachine(sessionId, session, clock)
        assertEquals(ApprovalAction.Ignored, machine.receive(card(requestId), tier, listOf("novel_destination")))
        val pending = machine.state.value as ApprovalState.AwaitingUserDecision
        return Setup(clock, session, machine, pending.instanceId)
    }

    private fun card(requestId: String) = ApprovalRequestCard(
        requestId = requestId,
        opType = "authenticated_request",
        pairedPcName = "workstation",
        service = "github",
        method = "POST",
        endpoint = "/deploy",
        paramsJson = "{\"env\":\"prod\"}",
        requestedBy = "cli",
        timestampUnixSeconds = 1_700_000_000,
    )

    private fun finish(setup: Setup, decision: ApprovalDecision) {
        assertEquals(
            ApprovalAction.Finalize(setup.instanceId, "session-a", decision),
            setup.machine.beforeFinalize(setup.instanceId, "session-a", decision),
        )
        assertEquals(
            ApprovalAction.Ignored,
            setup.machine.completeFinalization(setup.instanceId, "session-a", decision, sent = true),
        )
    }

    @Test
    fun tierTwoApprovalNeedsExplicitTapButNoAuthentication() {
        val setup = setup(tier = ApprovalRequiredTier.TIER_2)
        assertEquals(
            ApprovalAction.Finalize(setup.instanceId, "session-a", ApprovalDecision.APPROVED),
            setup.machine.approve(setup.instanceId, "session-a"),
        )
        assertTrue(setup.machine.state.value is ApprovalState.Committing)
        finish(setup, ApprovalDecision.APPROVED)
        assertTrue(setup.machine.state.value is ApprovalState.Approved)
    }

    @Test
    fun tierThreeCannotFinalizeUntilMatchingAuthenticationSucceeds() {
        val setup = setup()
        val auth = setup.machine.approve(setup.instanceId, "session-a") as ApprovalAction.Authenticate
        assertTrue(setup.machine.state.value is ApprovalState.AwaitingAuthentication)
        assertEquals(ApprovalAction.Ignored, setup.machine.beforeFinalize(
            setup.instanceId,
            "session-a",
            ApprovalDecision.APPROVED,
        ))
        assertEquals(
            ApprovalAction.Finalize(setup.instanceId, "session-a", ApprovalDecision.APPROVED),
            setup.machine.completeAuthentication(
                setup.instanceId,
                "session-a",
                auth.attemptId,
                ApprovalAuthOutcome.SUCCEEDED,
            ),
        )
        finish(setup, ApprovalDecision.APPROVED)
        assertTrue(setup.machine.state.value is ApprovalState.Approved)
    }

    @Test
    fun authenticationCancellationOrFailureIsRetryableWithoutExtendingDeadline() {
        val setup = setup()
        val deadline = (setup.machine.state.value as ApprovalState.AwaitingUserDecision).deadlineElapsedMs
        val first = setup.machine.approve(setup.instanceId, "session-a") as ApprovalAction.Authenticate
        assertEquals(
            ApprovalAction.Ignored,
            setup.machine.completeAuthentication(
                setup.instanceId,
                "session-a",
                first.attemptId,
                ApprovalAuthOutcome.CANCELLED,
            ),
        )
        val afterCancel = setup.machine.state.value as ApprovalState.AwaitingUserDecision
        assertEquals(ApprovalAuthStatus.CANCELLED, afterCancel.authStatus)
        assertEquals(deadline, afterCancel.deadlineElapsedMs)

        val retry = setup.machine.approve(setup.instanceId, "session-a") as ApprovalAction.Authenticate
        setup.machine.completeAuthentication(
            setup.instanceId,
            "session-a",
            retry.attemptId,
            ApprovalAuthOutcome.FAILED,
        )
        val afterFailure = setup.machine.state.value as ApprovalState.AwaitingUserDecision
        assertEquals(ApprovalAuthStatus.FAILED, afterFailure.authStatus)
        assertEquals(deadline, afterFailure.deadlineElapsedMs)
        val finalRetry = setup.machine.approve(setup.instanceId, "session-a") as ApprovalAction.Authenticate
        assertTrue(finalRetry.attemptId != retry.attemptId)
    }

    @Test
    fun authenticationCompletionAfterOriginalDeadlineBecomesExpired() {
        val setup = setup()
        val auth = setup.machine.approve(setup.instanceId, "session-a") as ApprovalAction.Authenticate
        setup.clock.now += APPROVAL_DEADLINE_MS
        assertEquals(
            ApprovalAction.Finalize(setup.instanceId, "session-a", ApprovalDecision.EXPIRED),
            setup.machine.completeAuthentication(
                setup.instanceId,
                "session-a",
                auth.attemptId,
                ApprovalAuthOutcome.SUCCEEDED,
            ),
        )
        finish(setup, ApprovalDecision.EXPIRED)
        assertTrue(setup.machine.state.value is ApprovalState.Expired)
    }

    @Test
    fun approvalThatExpiresWhileTerminalLogIsStagedBecomesExpiredBeforeSigning() {
        val setup = setup(tier = ApprovalRequiredTier.TIER_2)
        assertTrue(setup.machine.approve(setup.instanceId, "session-a") is ApprovalAction.Finalize)
        assertEquals(
            ApprovalAction.Finalize(setup.instanceId, "session-a", ApprovalDecision.APPROVED),
            setup.machine.beforeFinalize(setup.instanceId, "session-a", ApprovalDecision.APPROVED),
        )

        // The Room terminal row has been staged; the monotonic deadline passes
        // before the synchronous pre-sign hook executes.
        setup.clock.now += APPROVAL_DEADLINE_MS
        assertEquals(
            ApprovalAction.Finalize(setup.instanceId, "session-a", ApprovalDecision.EXPIRED),
            setup.machine.beforeSign(setup.instanceId, "session-a", ApprovalDecision.APPROVED),
        )
        assertTrue(setup.machine.state.value is ApprovalState.Committing)
        assertEquals(
            ApprovalDecision.EXPIRED,
            (setup.machine.state.value as ApprovalState.Committing).decision,
        )
    }

    @Test
    fun sessionLossDuringAuthenticationPreventsApproval() {
        val setup = setup()
        val auth = setup.machine.approve(setup.instanceId, "session-a") as ApprovalAction.Authenticate
        setup.session.active = false
        assertEquals(
            ApprovalAction.Ignored,
            setup.machine.completeAuthentication(
                setup.instanceId,
                "session-a",
                auth.attemptId,
                ApprovalAuthOutcome.SUCCEEDED,
            ),
        )
        assertTrue(setup.machine.state.value is ApprovalState.SessionLost)
    }

    @Test
    fun denialDuringAuthenticationWinsAndLateSuccessIsIgnored() {
        val setup = setup()
        val auth = setup.machine.approve(setup.instanceId, "session-a") as ApprovalAction.Authenticate
        assertEquals(
            ApprovalAction.Finalize(setup.instanceId, "session-a", ApprovalDecision.DENIED),
            setup.machine.deny(setup.instanceId, "session-a"),
        )
        assertEquals(
            ApprovalAction.Ignored,
            setup.machine.completeAuthentication(
                setup.instanceId,
                "session-a",
                auth.attemptId,
                ApprovalAuthOutcome.SUCCEEDED,
            ),
        )
        finish(setup, ApprovalDecision.DENIED)
        assertTrue(setup.machine.state.value is ApprovalState.Denied)
    }

    @Test
    fun doubleApproveAndDuplicateRequestIdCannotProduceSecondDecision() {
        val setup = setup(tier = ApprovalRequiredTier.TIER_2)
        assertTrue(setup.machine.approve(setup.instanceId, "session-a") is ApprovalAction.Finalize)
        assertEquals(ApprovalAction.Ignored, setup.machine.approve(setup.instanceId, "session-a"))
        finish(setup, ApprovalDecision.APPROVED)
        assertEquals(ApprovalAction.Rejected(Rejection.REPLAYED_REQUEST_ID),
            setup.machine.receive(card("req-a"), ApprovalRequiredTier.TIER_2, emptyList()))
    }

    @Test
    fun secondApproveTapCannotLaunchConcurrentTierThreeAuthentication() {
        val setup = setup()
        val first = setup.machine.approve(setup.instanceId, "session-a") as ApprovalAction.Authenticate
        assertEquals(ApprovalAction.Ignored, setup.machine.approve(setup.instanceId, "session-a"))
        assertEquals(first.attemptId,
            (setup.machine.state.value as ApprovalState.AwaitingAuthentication).attemptId)
    }

    @Test
    fun noActiveSessionOrWrongSessionCannotPresentOrApprove() {
        val clock = FakeClock()
        val session = FakeSession(active = false)
        val machine = ApprovalStateMachine("session-a", session, clock)
        assertEquals(ApprovalAction.Rejected(Rejection.NO_ACTIVE_SESSION),
            machine.receive(card("req-a"), ApprovalRequiredTier.TIER_2, emptyList()))

        session.active = true
        machine.receive(card("req-a"), ApprovalRequiredTier.TIER_2, emptyList())
        val pending = machine.state.value as ApprovalState.AwaitingUserDecision
        assertEquals(ApprovalAction.Ignored, machine.approve(pending.instanceId, "session-b"))
        assertFalse(machine.state.value is ApprovalState.Committing)
    }

    @Test
    fun secondPendingRequestIsRejectedAndCannotReplaceTheFirst() {
        val setup = setup()
        assertEquals(ApprovalAction.Rejected(Rejection.REQUEST_ALREADY_PENDING),
            setup.machine.receive(card("req-b"), ApprovalRequiredTier.TIER_2, emptyList()))
        assertEquals("req-a", (setup.machine.state.value as ApprovalState.AwaitingUserDecision).request.requestId)
    }

    @Test
    fun staleAuthenticationCallbackFromPriorSessionCannotAuthorizeNewRequest() {
        val old = setup(sessionId = "session-old", requestId = "req-a")
        val oldAttempt = old.machine.approve(old.instanceId, "session-old") as ApprovalAction.Authenticate

        val current = setup(sessionId = "session-new", requestId = "req-b")
        val currentAttempt = current.machine.approve(current.instanceId, "session-new") as ApprovalAction.Authenticate
        assertEquals(ApprovalAction.Ignored, current.machine.completeAuthentication(
            old.instanceId,
            "session-old",
            oldAttempt.attemptId,
            ApprovalAuthOutcome.SUCCEEDED,
        ))
        assertTrue(current.machine.state.value is ApprovalState.AwaitingAuthentication)
        assertEquals(currentAttempt.attemptId,
            (current.machine.state.value as ApprovalState.AwaitingAuthentication).attemptId)
    }

    @Test
    fun staleAuthenticationCallbackFromRequestACannotAuthorizeRequestBOnSameSession() {
        val setup = setup(sessionId = "session-a", requestId = "request-a")
        val attemptA = setup.machine.approve(setup.instanceId, "session-a") as ApprovalAction.Authenticate
        assertEquals(
            ApprovalAction.Finalize(setup.instanceId, "session-a", ApprovalDecision.DENIED),
            setup.machine.deny(setup.instanceId, "session-a"),
        )
        finish(setup, ApprovalDecision.DENIED)

        assertEquals(
            ApprovalAction.Ignored,
            setup.machine.receive(card("request-b"), ApprovalRequiredTier.TIER_3, emptyList()),
        )
        val pendingB = setup.machine.state.value as ApprovalState.AwaitingUserDecision
        val attemptB = setup.machine.approve(pendingB.instanceId, "session-a") as ApprovalAction.Authenticate
        assertEquals(
            ApprovalAction.Ignored,
            setup.machine.completeAuthentication(
                setup.instanceId,
                "session-a",
                attemptA.attemptId,
                ApprovalAuthOutcome.SUCCEEDED,
            ),
        )
        assertEquals(attemptB.attemptId,
            (setup.machine.state.value as ApprovalState.AwaitingAuthentication).attemptId)
    }

    @Test
    fun deadlineExpiryWhileVisibleBecomesDistinctTerminalExpiry() {
        val setup = setup(tier = ApprovalRequiredTier.TIER_2)
        setup.clock.now += APPROVAL_DEADLINE_MS
        assertEquals(
            ApprovalAction.Finalize(setup.instanceId, "session-a", ApprovalDecision.EXPIRED),
            setup.machine.expire(setup.instanceId, "session-a"),
        )
        finish(setup, ApprovalDecision.EXPIRED)
        assertTrue(setup.machine.state.value is ApprovalState.Expired)
    }

    @Test
    fun sixtySecondDeadlineStartsAtAuthenticatedReceiptBeforeValidationAndLogging() {
        val clock = FakeClock(now = 80_000)
        val machine = ApprovalStateMachine("session-a", FakeSession(), clock)
        val receiptElapsedMs = 1_000L

        val action = machine.receive(
            card("req-received-earlier"),
            ApprovalRequiredTier.TIER_2,
            emptyList(),
            receivedAtElapsedMs = receiptElapsedMs,
        )
        val pending = machine.state.value as ApprovalState.Committing
        assertEquals(ApprovalDecision.EXPIRED, pending.decision)
        assertEquals(
            ApprovalAction.Finalize(pending.pending.instanceId, "session-a", ApprovalDecision.EXPIRED),
            action,
        )
        assertEquals(receiptElapsedMs, pending.pending.receivedAtElapsedMs)
        assertEquals(
            receiptElapsedMs + APPROVAL_DEADLINE_MS,
            pending.pending.deadlineElapsedMs,
        )
    }
}
