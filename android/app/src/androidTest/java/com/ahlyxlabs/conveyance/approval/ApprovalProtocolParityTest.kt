package com.ahlyxlabs.conveyance.approval

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ahlyxlabs.conveyance.testutil.hexToBytes
import com.ahlyxlabs.conveyance.testutil.toHex
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.conveyance_crypto_ffi.ApprovalDecision
import uniffi.conveyance_crypto_ffi.ApprovalProtocol
import uniffi.conveyance_crypto_ffi.createSealedIdentity
import uniffi.conveyance_crypto_ffi.openSealedIdentity

/**
 * Replays Rust-emitted request/response bytes through the generated Android
 * FFI. Kotlin displays only Rust-validated fields and never rebuilds CBOR,
 * canonical JSON, or signing payloads.
 */
@RunWith(AndroidJUnit4::class)
class ApprovalProtocolParityTest {

    @Test
    fun requestDecodeAndAllSignedDecisionsMatchRustFixtureBytes() {
        val context = InstrumentationRegistry.getInstrumentation().context
        val fixture = JSONObject(
            context.assets.open("approval_fixtures.json").bufferedReader().use { it.readText() },
        )
        assertEquals(1L, fixture.getLong("schema_version"))

        val contentKey = fixture.getString("content_key_hex").hexToBytes()
        val sealed = createSealedIdentity(fixture.getString("recovery_phrase"), contentKey)
        val identity = openSealedIdentity(sealed.blob, contentKey)
        try {
            assertEquals(fixture.getString("identity_ed25519_public_hex"), identity.ed25519Public().toHex())
            val requestBytes = fixture.getString("request_cbor_hex").hexToBytes()
            val expected = fixture.getJSONObject("request")

            val requestProtocol = ApprovalProtocol("")
            try {
                val request = requestProtocol.decodeRequest(requestBytes)
                try {
                    val summary = request.summary()
                    assertEquals(expected.getString("req_id"), summary.reqId)
                    assertEquals(expected.getString("op_type"), summary.opType)
                    assertEquals(expected.getString("service"), summary.service)
                    assertEquals(expected.getString("method"), summary.method)
                    assertEquals(expected.getString("endpoint"), summary.endpoint)
                    assertEquals(expected.getString("params_json"), summary.paramsJson)
                    assertEquals(expected.getString("requested_by"), summary.requestedBy)
                    assertEquals(expected.getLong("timestamp"), summary.timestamp)
                } finally {
                    request.close()
                }
            } finally {
                requestProtocol.close()
            }

            val decisions = fixture.getJSONObject("response_cbor_hex")
            listOf(
                "approved" to ApprovalDecision.APPROVED,
                "denied" to ApprovalDecision.DENIED,
                "expired" to ApprovalDecision.EXPIRED,
            ).forEach { (name, decision) ->
                val protocol = ApprovalProtocol("")
                try {
                    val request = protocol.decodeRequest(requestBytes)
                    try {
                        val actual = protocol.signedResponse(request, decision, null, identity)
                        assertEquals("$name response bytes", decisions.getString(name), actual.toHex())
                    } finally {
                        request.close()
                    }
                } finally {
                    protocol.close()
                }
            }
        } finally {
            identity.close()
        }
    }
}
