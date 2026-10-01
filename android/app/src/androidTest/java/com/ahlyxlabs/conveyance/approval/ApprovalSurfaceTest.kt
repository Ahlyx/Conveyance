package com.ahlyxlabs.conveyance.approval

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ahlyxlabs.conveyance.storage.identity.Tier1AuthMethod
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ApprovalSurfaceTest {
    @get:Rule val compose = createComposeRule()

    private class ActiveSession : ApprovalSessionGuard {
        override fun isActive() = true
    }

    private class FakeClock(var now: Long = 1_000) : ApprovalMonotonicClock {
        override fun elapsedRealtimeMs() = now
    }

    private fun card() = ApprovalRequestCard(
        requestId = "00112233445566778899aabbccddeeff",
        opType = "authenticated_request",
        pairedPcName = "studio-pc",
        service = "github",
        method = "POST",
        endpoint = "/repos/acme/app/deployments?preview=false",
        paramsJson = "{\"environment\":\"production\",\"force\":false}",
        requestedBy = "release-client",
        timestampUnixSeconds = 1_700_000_000,
    )

    private fun machine(tier: ApprovalRequiredTier): ApprovalStateMachine {
        val machine = ApprovalStateMachine("session-ui", ActiveSession(), FakeClock())
        assertEquals(ApprovalAction.Ignored, machine.receive(card(), tier, listOf("novel_destination")))
        return machine
    }

    @Test
    fun completeSecurityRelevantRequestAndTierAreVisibleWithoutTruncation() {
        val state = machine(ApprovalRequiredTier.TIER_3).state.value
        compose.setContent {
            ApprovalSurface(
                state = state,
                authMethod = Tier1AuthMethod.PASSPHRASE,
                onApprove = {},
                onDeny = {},
                onSubmitPassphrase = { _, _ -> },
                onCancelAuthentication = {},
                onDismissTerminal = {},
            )
        }

        compose.onNodeWithText("Paired PC").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("approval_pc").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("approval_request_id").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("approval_op_type").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("approval_service").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("approval_method").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("approval_endpoint").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("approval_timestamp").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("approval_params").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("/repos/acme/app/deployments?preview=false")
            .performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("{\"environment\":\"production\",\"force\":false}")
            .performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("release-client").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("approval_tier_reason")
            .performScrollTo()
            .assertIsDisplayed()
            .assertTextContains(
                "New exact service and endpoint destination",
                substring = true,
            )
    }

    @Test
    fun approveAndDenyEmitOnlyTheirExplicitRequestIds() {
        val state = machine(ApprovalRequiredTier.TIER_2).state.value
        val approvals = mutableListOf<String>()
        val denials = mutableListOf<String>()
        compose.setContent {
            ApprovalSurface(
                state = state,
                authMethod = Tier1AuthMethod.BIOMETRIC,
                onApprove = approvals::add,
                onDeny = denials::add,
                onSubmitPassphrase = { _, _ -> },
                onCancelAuthentication = {},
                onDismissTerminal = {},
            )
        }

        compose.onNodeWithTag("approve_button").performScrollTo().performClick()
        compose.onNodeWithTag("deny_button").performScrollTo().performClick()
        val instanceId = (state as ApprovalState.AwaitingUserDecision).instanceId
        assertEquals(listOf(instanceId), approvals)
        assertEquals(listOf(instanceId), denials)
    }

    @Test
    fun tierThreeApprovalWaitsForAuthAndCancelReturnsToRetryableReview() {
        val machine = machine(ApprovalRequiredTier.TIER_3)
        var state by mutableStateOf(machine.state.value)
        var authSubmissions = 0
        compose.setContent {
            ApprovalSurface(
                state = state,
                authMethod = Tier1AuthMethod.PASSPHRASE,
                onApprove = { id ->
                    machine.approve(id, "session-ui")
                    state = machine.state.value
                },
                onDeny = { id ->
                    machine.deny(id, "session-ui")
                    state = machine.state.value
                },
                onSubmitPassphrase = { prompt, _ ->
                    authSubmissions++
                    machine.completeAuthentication(
                        prompt.instanceId,
                        prompt.sessionId,
                        prompt.attemptId,
                        ApprovalAuthOutcome.SUCCEEDED,
                    )
                    state = machine.state.value
                },
                onCancelAuthentication = { prompt ->
                    machine.completeAuthentication(
                        prompt.instanceId,
                        prompt.sessionId,
                        prompt.attemptId,
                        ApprovalAuthOutcome.CANCELLED,
                    )
                    state = machine.state.value
                },
                onDismissTerminal = {},
            )
        }

        compose.onNodeWithTag("approve_button").performScrollTo().performClick()
        assertTrue(state is ApprovalState.AwaitingAuthentication)
        assertEquals(0, authSubmissions)
        compose.onNodeWithTag("authenticate_button").assertIsNotEnabled()
        compose.onNodeWithTag("cancel_auth_button").performClick()

        val retryable = state as ApprovalState.AwaitingUserDecision
        assertEquals(ApprovalAuthStatus.CANCELLED, retryable.authStatus)
        compose.onNodeWithTag("approve_button").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("Authentication was canceled. You may retry or deny.")
            .performScrollTo().assertIsDisplayed()
        compose.onAllNodesWithTag("approval_terminal").assertCountEquals(0)
    }

    @Test
    fun expiredAndTerminalStatesCannotExposeApprovalActions() {
        compose.setContent {
            ApprovalSurface(
                state = ApprovalState.Expired("instance-expired", card().requestId),
                authMethod = Tier1AuthMethod.PASSPHRASE,
                onApprove = { error("terminal state emitted approve") },
                onDeny = { error("terminal state emitted deny") },
                onSubmitPassphrase = { _, _ -> },
                onCancelAuthentication = {},
                onDismissTerminal = {},
            )
        }
        compose.onNodeWithTag("approval_terminal").assertIsDisplayed()
        compose.onNodeWithText(
            "Request expired. An expiration response was sent to the paired PC."
        ).assertIsDisplayed()
        compose.onAllNodesWithTag("approve_button").assertCountEquals(0)
        compose.onAllNodesWithTag("deny_button").assertCountEquals(0)
    }

    @Test
    fun repeatedApproveInputCannotSubmitMoreThanOneDecision() {
        val machine = machine(ApprovalRequiredTier.TIER_2)
        var state by mutableStateOf(machine.state.value)
        var approveIntents = 0
        compose.setContent {
            ApprovalSurface(
                state = state,
                authMethod = Tier1AuthMethod.BIOMETRIC,
                onApprove = { id ->
                    approveIntents++
                    machine.approve(id, "session-ui")
                    state = machine.state.value
                },
                onDeny = {},
                onSubmitPassphrase = { _, _ -> },
                onCancelAuthentication = {},
                onDismissTerminal = {},
            )
        }

        compose.onNodeWithTag("approve_button").performScrollTo().performClick()
        compose.onNodeWithTag("approve_button").assertIsNotEnabled()
        assertEquals(1, approveIntents)
        assertTrue(state is ApprovalState.Committing)
    }

    @Test
    fun remountingAwaitingAuthenticationDoesNotSubmitOrApproveItself() {
        val machine = machine(ApprovalRequiredTier.TIER_3)
        val cardState = machine.state.value as ApprovalState.AwaitingUserDecision
        machine.approve(cardState.instanceId, "session-ui")
        var state by mutableStateOf(machine.state.value)
        var show by mutableStateOf(true)
        var submissions = 0
        compose.setContent {
            if (show) {
                ApprovalSurface(
                    state = state,
                    authMethod = Tier1AuthMethod.PASSPHRASE,
                    onApprove = { error("recreated UI must not auto-approve") },
                    onDeny = {},
                    onSubmitPassphrase = { _, _ -> submissions++ },
                    onCancelAuthentication = {},
                    onDismissTerminal = {},
                )
            }
        }

        compose.runOnIdle { show = false }
        compose.runOnIdle { show = true }
        compose.onNodeWithTag("authenticate_button").assertIsNotEnabled()
        assertTrue(state is ApprovalState.AwaitingAuthentication)
        assertEquals(0, submissions)
        assertTrue(machine.state.value !is ApprovalState.Approved)
    }
}
