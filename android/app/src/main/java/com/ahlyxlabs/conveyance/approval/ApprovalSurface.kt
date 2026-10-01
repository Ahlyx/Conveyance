package com.ahlyxlabs.conveyance.approval

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.ahlyxlabs.conveyance.storage.identity.Tier1AuthMethod
import com.ahlyxlabs.conveyance.storage.identity.Tier1PassphrasePolicy

/** Renders approval state; protocol and authorization decisions stay outside Compose. */
@Composable
fun ApprovalSurface(
    state: ApprovalState,
    authMethod: Tier1AuthMethod?,
    onApprove: (String) -> Unit,
    onDeny: (String) -> Unit,
    onSubmitPassphrase: (ApprovalAuthPrompt, ByteArray) -> Unit,
    onCancelAuthentication: (ApprovalAuthPrompt) -> Unit,
    onDismissTerminal: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val pending = when (state) {
        is ApprovalState.AwaitingUserDecision -> state
        is ApprovalState.AwaitingAuthentication -> state.pending
        is ApprovalState.Committing -> state.pending
        is ApprovalState.Finalizing -> state.pending
        else -> null
    }

    if (state is ApprovalState.AwaitingAuthentication && authMethod == Tier1AuthMethod.PASSPHRASE) {
        key(state.pending.instanceId, state.attemptId) {
            PassphraseAuthenticationDialog(
                prompt = ApprovalAuthPrompt(
                    instanceId = state.pending.instanceId,
                    sessionId = state.pending.sessionId,
                    attemptId = state.attemptId,
                    deadlineElapsedMs = state.pending.deadlineElapsedMs,
                ),
                onSubmit = onSubmitPassphrase,
                onCancel = onCancelAuthentication,
            )
        }
    }

    if (pending == null) {
        ApprovalTerminalSurface(state = state, onDismiss = onDismissTerminal, modifier = modifier)
        return
    }

    val awaitingChoice = state as? ApprovalState.AwaitingUserDecision
    val awaitingAuth = state as? ApprovalState.AwaitingAuthentication
    val busy = state is ApprovalState.Committing || state is ApprovalState.Finalizing

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Review request", style = MaterialTheme.typography.headlineMedium)
        Text("This request arrived from the paired PC. Review the complete values before deciding.")
        ApprovalField("Paired PC", pending.request.pairedPcName, "approval_pc")
        ApprovalField("Request ID", pending.request.requestId, "approval_request_id")
        ApprovalField("Operation type", pending.request.opType, "approval_op_type")
        ApprovalField("Service", pending.request.service, "approval_service")
        ApprovalField("Method", pending.request.method, "approval_method")
        ApprovalField("Endpoint", pending.request.endpoint, "approval_endpoint")
        ApprovalField(
            "PC timestamp (Unix seconds; audit metadata)",
            pending.request.timestampUnixSeconds.toString(),
            "approval_timestamp",
        )
        Text("Parameters", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold)
        SelectionContainer {
            Text(
                pending.request.paramsJson,
                modifier = Modifier.fillMaxWidth().testTag("approval_params"),
                fontFamily = FontFamily.Monospace,
            )
        }
        pending.request.requestedBy?.let {
            ApprovalField("Requested by (PC hint)", it, "approval_requested_by")
        }

        when (pending.requiredTier) {
            ApprovalRequiredTier.TIER_2 -> Text(
                "Tier 2: one explicit approval tap. No additional authentication is required.",
                modifier = Modifier.testTag("approval_tier"),
            )
            ApprovalRequiredTier.TIER_3 -> {
                Text(
                    "Tier 3: fresh ${authMethod.displayName()} authentication is required for this request.",
                    modifier = Modifier.testTag("approval_tier"),
                )
                pending.tier3Reasons.forEach { reason ->
                    Text("• ${reason.readableReason()}", modifier = Modifier.testTag("approval_tier_reason"))
                }
            }
        }

        if (awaitingAuth != null) {
            Text(
                when (authMethod) {
                    Tier1AuthMethod.BIOMETRIC -> "Complete the fresh biometric prompt to continue."
                    Tier1AuthMethod.PASSPHRASE -> "Enter the selected passphrase in the authentication dialog."
                    null -> "Authentication method is unavailable. This request cannot be approved."
                },
                modifier = Modifier.testTag("approval_auth_status"),
            )
        } else if (awaitingChoice != null) {
            when (awaitingChoice.authStatus) {
                ApprovalAuthStatus.CANCELLED -> Text("Authentication was canceled. You may retry or deny.")
                ApprovalAuthStatus.FAILED -> Text("Authentication failed. You may retry or deny.")
                else -> Unit
            }
            Text("This approval expires 60 seconds after it was received.")
        } else if (busy) {
            Text("Recording the decision and returning it to the paired PC…")
        }

        Spacer(Modifier.height(4.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Button(
                onClick = { onApprove(pending.instanceId) },
                enabled = awaitingChoice != null && authMethod != null,
                modifier = Modifier.weight(1f).testTag("approve_button"),
            ) { Text("Approve") }
            TextButton(
                onClick = { onDeny(pending.instanceId) },
                enabled = awaitingChoice != null,
                modifier = Modifier.weight(1f).testTag("deny_button"),
            ) { Text("Deny") }
        }
    }
}

@Composable
private fun ApprovalField(label: String, value: String, tag: String) {
    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Text(label, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold)
        SelectionContainer {
            Text(value, modifier = Modifier.fillMaxWidth().testTag(tag))
        }
    }
}

@Composable
private fun ApprovalTerminalSurface(
    state: ApprovalState,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val message = when (state) {
        is ApprovalState.Approved -> "Approval sent to the paired PC."
        is ApprovalState.Denied -> "Request denied and the decision was sent."
        is ApprovalState.Expired -> "Request expired. An expiration response was sent to the paired PC."
        is ApprovalState.SessionLost -> "Session ended. This request can no longer be approved."
        is ApprovalState.Cancelled -> "Approval was canceled."
        is ApprovalState.Failed -> state.safeMessage
        ApprovalState.Empty -> "No approval request is waiting."
        else -> "Approval is unavailable."
    }
    Column(modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Approval", style = MaterialTheme.typography.headlineMedium)
        Text(message, modifier = Modifier.testTag("approval_terminal"))
        TextButton(onClick = onDismiss, modifier = Modifier.testTag("approval_done_button")) {
            Text("Done")
        }
    }
}

@Composable
private fun PassphraseAuthenticationDialog(
    prompt: ApprovalAuthPrompt,
    onSubmit: (ApprovalAuthPrompt, ByteArray) -> Unit,
    onCancel: (ApprovalAuthPrompt) -> Unit,
) {
    var passphrase by remember { mutableStateOf("") }
    var submitted by remember { mutableStateOf(false) }
    val violation = Tier1PassphrasePolicy.violation(passphrase)

    AlertDialog(
        onDismissRequest = { onCancel(prompt) },
        title = { Text("Fresh passphrase required") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Re-enter the selected Tier 1 passphrase. The request stays pending if authentication is canceled or fails.")
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text("Passphrase") },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    isError = violation != null,
                    modifier = Modifier.testTag("approval_passphrase"),
                )
                violation?.let { Text(it.message, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            Button(
                enabled = violation == null && !submitted,
                onClick = {
                    val bytes = Tier1PassphrasePolicy.encode(passphrase)
                    submitted = true
                    passphrase = ""
                    try {
                        onSubmit(prompt, bytes)
                    } finally {
                        bytes.fill(0)
                    }
                },
                modifier = Modifier.testTag("authenticate_button"),
            ) { Text("Authenticate") }
        },
        dismissButton = {
            TextButton(onClick = { onCancel(prompt) }, modifier = Modifier.testTag("cancel_auth_button")) {
                Text("Cancel")
            }
        },
    )
}

private fun Tier1AuthMethod?.displayName(): String = when (this) {
    Tier1AuthMethod.BIOMETRIC -> "biometric"
    Tier1AuthMethod.PASSPHRASE -> "passphrase"
    null -> "configured Tier 1"
}

private fun String.readableReason(): String = when (this) {
    "delete_method" -> "HTTP DELETE operation"
    "novel_destination" -> "New exact service and endpoint destination"
    "configured_rule" -> "Matches a phone high-risk policy rule"
    else -> "High-risk policy requirement"
}
