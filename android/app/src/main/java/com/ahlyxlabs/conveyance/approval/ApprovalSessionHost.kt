package com.ahlyxlabs.conveyance.approval

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.ahlyxlabs.conveyance.storage.identity.Tier1AuthInput
import com.ahlyxlabs.conveyance.storage.identity.Tier1AuthMethod
import com.ahlyxlabs.conveyance.storage.keystore.BiometricGate
import kotlinx.coroutines.launch
import kotlinx.coroutines.Job

/**
 * Lifecycle-aware boundary between session authorization and Compose UI.
 * The active-session owner calls [ApprovalViewModel.attach]; this host only
 * renders immutable state and dispatches explicit user/authentication intents.
 */
@Composable
fun ApprovalSessionHost(
    viewModel: ApprovalViewModel,
    biometricGate: BiometricGate,
    modifier: Modifier = Modifier,
    idleContent: @Composable () -> Unit,
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val authMethod by viewModel.authMethod.collectAsStateWithLifecycle()
    val lifecycleOwner = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()
    var dismissedTerminalInstanceId by remember { mutableStateOf<String?>(null) }
    var passphraseAuthJob by remember { mutableStateOf<Job?>(null) }

    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) {
                passphraseAuthJob?.cancel()
                passphraseAuthJob = null
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            passphraseAuthJob?.cancel()
            passphraseAuthJob = null
        }
    }

    LaunchedEffect(viewModel, lifecycleOwner, biometricGate) {
        lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            viewModel.authPrompts.collect { prompt ->
                val awaiting = viewModel.state.value as? ApprovalState.AwaitingAuthentication
                if (awaiting?.pending?.instanceId != prompt.instanceId ||
                    awaiting.pending.sessionId != prompt.sessionId ||
                    awaiting.attemptId != prompt.attemptId
                ) return@collect

                when (authMethod) {
                    Tier1AuthMethod.BIOMETRIC ->
                        viewModel.authenticate(prompt, Tier1AuthInput.Biometric(biometricGate))
                    Tier1AuthMethod.PASSPHRASE -> Unit // The state renders an explicit passphrase dialog.
                    null -> viewModel.cancelAuthentication(prompt)
                }
            }
        }
    }

    val currentState = state
    val terminalInstanceId = when (currentState) {
        is ApprovalState.Approved -> currentState.instanceId
        is ApprovalState.Denied -> currentState.instanceId
        is ApprovalState.Expired -> currentState.instanceId
        is ApprovalState.SessionLost -> currentState.instanceId
        is ApprovalState.Cancelled -> currentState.instanceId
        is ApprovalState.Failed -> currentState.instanceId
        else -> null
    }
    if (currentState == ApprovalState.Empty || terminalInstanceId == dismissedTerminalInstanceId) {
        idleContent()
    } else {
        ApprovalSurface(
            state = currentState,
            authMethod = authMethod,
            onApprove = viewModel::approve,
            onDeny = viewModel::deny,
            onSubmitPassphrase = { prompt, bytes ->
                val input = try {
                    Tier1AuthInput.Passphrase(bytes)
                } catch (_: IllegalArgumentException) {
                    viewModel.cancelAuthentication(prompt)
                    null
                } finally {
                    bytes.fill(0)
                }
                if (input != null) {
                    passphraseAuthJob = scope.launch { viewModel.authenticate(prompt, input) }
                        .also { job -> job.invokeOnCompletion { input.close() } }
                }
            },
            onCancelAuthentication = viewModel::cancelAuthentication,
            onDismissTerminal = { dismissedTerminalInstanceId = terminalInstanceId },
            modifier = modifier,
        )
    }
}
