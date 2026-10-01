package com.ahlyxlabs.conveyance.approval

import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import javax.inject.Inject
import javax.inject.Singleton
import android.content.Context

/** Reads a fresh phone-owned policy snapshot at the start of each Noise session. */
@Singleton
class PhoneApprovalPolicyStore @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val policyFile = File(context.filesDir, FILE_NAME)

    /** Missing means built-in phone rules only; malformed bytes fail closed. */
    fun loadForSession(): String {
        if (!policyFile.exists()) return ""
        val bytes = try {
            policyFile.readBytes()
        } catch (error: Exception) {
            throw ApprovalPolicyLoadException(error)
        }
        return try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (error: Exception) {
            throw ApprovalPolicyLoadException(error)
        } finally {
            bytes.fill(0)
        }
    }

    private companion object {
        const val FILE_NAME = "policy.toml"
    }
}

class ApprovalPolicyLoadException(cause: Throwable) :
    Exception("phone approval policy could not be read", cause)
