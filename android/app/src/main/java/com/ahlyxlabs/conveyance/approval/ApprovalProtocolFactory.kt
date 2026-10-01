package com.ahlyxlabs.conveyance.approval

import javax.inject.Inject
import javax.inject.Singleton
import uniffi.conveyance_crypto_ffi.ApprovalProtocol

/** Creates a protocol/binding/policy instance scoped to one authenticated session. */
@Singleton
class ApprovalProtocolFactory @Inject constructor(
    private val policyStore: PhoneApprovalPolicyStore,
) {
    fun newForSession(): ApprovalProtocol = ApprovalProtocol(policyStore.loadForSession())
}
