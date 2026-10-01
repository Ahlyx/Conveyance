package com.ahlyxlabs.conveyance.approval

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PhoneApprovalPolicyStoreTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val file = File(context.filesDir, "policy.toml")

    @Test
    fun absentPolicyUsesBuiltInRulesAndExistingFileIsReadAsUtf8Snapshot() {
        val previous = file.takeIf(File::exists)?.readBytes()
        try {
            file.delete()
            assertEquals("", PhoneApprovalPolicyStore(context).loadForSession())

            val content = "# phone-owned rules\n[[high_risk]]\nmatch_service='münchen'\nmatch_endpoint='*prod*'\nrequired_tier=3\n"
            file.writeText(content, Charsets.UTF_8)
            assertEquals(content, PhoneApprovalPolicyStore(context).loadForSession())
        } finally {
            file.delete()
            if (previous != null) file.writeBytes(previous)
        }
    }

    @Test
    fun malformedUtf8FailsClosedInsteadOfReplacingBytes() {
        val previous = file.takeIf(File::exists)?.readBytes()
        try {
            file.writeBytes(byteArrayOf(0x5b, 0x5d, 0xc3.toByte(), 0x28))
            assertThrows(ApprovalPolicyLoadException::class.java) {
                PhoneApprovalPolicyStore(context).loadForSession()
            }
        } finally {
            file.delete()
            if (previous != null) file.writeBytes(previous)
        }
    }
}
