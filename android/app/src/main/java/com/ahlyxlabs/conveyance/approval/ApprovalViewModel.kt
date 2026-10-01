package com.ahlyxlabs.conveyance.approval

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.ahlyxlabs.conveyance.session.PhoneSession
import com.ahlyxlabs.conveyance.storage.identity.Tier1AuthInput
import com.ahlyxlabs.conveyance.storage.identity.Tier1AuthMethod
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch

/** Lifecycle holder for one authenticated session's approval runtime. */
@HiltViewModel
class ApprovalViewModel @Inject constructor(
    private val runtimeFactory: PhoneApprovalRuntimeFactory,
) : ViewModel() {
    private val _state = MutableStateFlow<ApprovalState>(ApprovalState.Empty)
    val state: StateFlow<ApprovalState> = _state.asStateFlow()

    private val _authMethod = MutableStateFlow<Tier1AuthMethod?>(null)
    val authMethod: StateFlow<Tier1AuthMethod?> = _authMethod.asStateFlow()

    private val authEffects = Channel<ApprovalAuthPrompt>(Channel.BUFFERED)
    val authPrompts = authEffects.receiveAsFlow()

    @Volatile private var runtime: PhoneApprovalRuntime? = null

    /**
     * Called by the authenticated-session owner after Noise reaches ACTIVE.
     * The same ViewModel survives Activity recreation; a replacement session
     * gets a new runtime, protocol tracker, policy snapshot, and request IDs.
     */
    @Synchronized
    fun attach(session: PhoneSession): Boolean {
        if (runtime?.sessionInstanceId == session.sessionInstanceId) return true
        runtime?.close()

        val next = runtimeFactory.create(session, viewModelScope)
        runtime = next
        _state.value = next.state.value
        _authMethod.value = next.tier1AuthMethod

        viewModelScope.launch {
            launch { next.state.collect { _state.value = it } }
            launch { next.authPrompts.collect { authEffects.send(it) } }
        }
        if (!next.start()) {
            next.close()
            runtime = null
            _authMethod.value = null
            return false
        }
        return true
    }

    fun approve(instanceId: String) {
        runtime?.approve(instanceId)
    }

    fun deny(instanceId: String) {
        runtime?.deny(instanceId)
    }

    suspend fun authenticate(prompt: ApprovalAuthPrompt, input: Tier1AuthInput) {
        val current = runtime
        if (current == null) {
            input.close()
            return
        }
        current.authenticateTier3(prompt, input)
    }

    fun cancelAuthentication(prompt: ApprovalAuthPrompt) {
        runtime?.cancelTier3Authentication(prompt)
    }

    override fun onCleared() {
        runtime?.close()
        runtime = null
        authEffects.close()
        super.onCleared()
    }
}
