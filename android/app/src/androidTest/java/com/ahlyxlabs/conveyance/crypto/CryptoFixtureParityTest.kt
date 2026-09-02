package com.ahlyxlabs.conveyance.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ahlyxlabs.conveyance.testutil.hexToBytes
import com.ahlyxlabs.conveyance.testutil.toHex
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The security property the UniFFI decision is paying for, made
 * observable: every vector in `crypto_fixtures.json` — emitted by
 * `conveyance-crypto` (the source of truth) — is replayed here through
 * the real FFI on the emulator and checked byte for byte.
 *
 * If a Rust primitive's behaviour changes, the fixture regenerates (its
 * drift gate is enforced separately in `cargo test` and `android.yml`)
 * and this test compares Kotlin against the new answer. If the Kotlin
 * path diverges from Rust for the same input, it fails here. Either way,
 * a Rust<->Kotlin mismatch cannot ship silently.
 *
 * Runs on `connectedDebugAndroidTest` (needs the cross-compiled
 * `libconveyance_crypto_ffi.so`).
 */
@RunWith(AndroidJUnit4::class)
class CryptoFixtureParityTest {

    private val crypto: ConveyanceCrypto = UniffiConveyanceCrypto()
    private val sealedCrypto: SealedIdentityCrypto = UniffiSealedIdentityCrypto()
    private lateinit var fixtures: JSONObject

    @Before
    fun loadFixtures() {
        val ctx = InstrumentationRegistry.getInstrumentation().context
        val text = ctx.assets.open("crypto_fixtures.json").bufferedReader().use { it.readText() }
        fixtures = JSONObject(text)
        // A bumped emitter schema without a matching test update is a bug.
        assertEquals(1L, fixtures.getLong("schema_version"))
    }

    @Test
    fun hkdfBlake2s() {
        forEachCase("hkdf_blake2s") { c ->
            val okm = crypto.hkdfBlake2s(
                c.getString("ikm_hex").hexToBytes(),
                c.getString("info_utf8").toByteArray(Charsets.US_ASCII),
                c.getInt("length"),
            )
            assertHex(c.getString("okm_hex"), okm)
        }
    }

    @Test
    fun signingPayload() {
        forEachCase("signing_payload") { c ->
            val ctx = SigningContext(c.getString("context_utf8").toByteArray(Charsets.US_ASCII))
            val payload = crypto.signingPayload(ctx, c.getString("canonical_body"))
            assertHex(c.getString("payload_hex"), payload)
        }
    }

    @Test
    fun canonicalJsonOk() {
        val group = fixtures.getJSONObject("canonical_json")
        group.getJSONArray("cases_ok").objects().forEach { c ->
            assertEquals(
                "canonicalize(${c.getString("input")})",
                c.getString("canonical"),
                crypto.canonicalize(c.getString("input")),
            )
        }
    }

    @Test
    fun canonicalJsonRejections() {
        val group = fixtures.getJSONObject("canonical_json")
        group.getJSONArray("cases_error").objects().forEach { c ->
            val input = c.getString("input")
            try {
                crypto.canonicalize(input)
                throw AssertionError("expected $input to be rejected")
            } catch (e: CryptoException.CanonicalDomainViolation) {
                // expected
            }
        }
    }

    @Test
    fun ed25519() {
        val group = fixtures.getJSONObject("ed25519")
        group.getJSONArray("cases").objects().forEach { c ->
            val secret = Ed25519SecretKey(c.getString("secret_hex").hexToBytes())
            val message = c.getString("message_hex").hexToBytes()
            val public = Ed25519PublicKey(c.getString("public_hex").hexToBytes())

            assertHex(c.getString("public_hex"), crypto.ed25519PublicKey(secret).bytes)
            val sig = crypto.sign(secret, message)
            assertHex(c.getString("signature_hex"), sig.bytes)
            assertTrue(crypto.verify(public, message, sig).isSuccess)
        }

        val fail = group.getJSONObject("verify_fail")
        val result = crypto.verify(
            Ed25519PublicKey(fail.getString("public_hex").hexToBytes()),
            fail.getString("message_hex").hexToBytes(),
            Ed25519Signature(fail.getString("signature_hex").hexToBytes()),
        )
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is CryptoException.SignatureInvalid)
    }

    @Test
    fun argon2idDek() {
        forEachCase("argon2id_dek") { c ->
            val dek = crypto.deriveDek(
                c.getString("passphrase_utf8").toByteArray(Charsets.UTF_8),
                c.getString("salt_hex").hexToBytes(),
            )
            assertHex(c.getString("dek_hex"), dek.bytes())
        }
    }

    @Test
    fun aeadChaCha20Poly1305() {
        val group = fixtures.getJSONObject("aead_chacha20poly1305")
        group.getJSONArray("cases").objects().forEach { c ->
            val key = AeadKey(c.getString("key_hex").hexToBytes())
            val nonce = AeadNonce(c.getString("nonce_hex").hexToBytes())
            val aad = c.getString("aad_hex").hexToBytes()
            val plaintext = c.getString("plaintext_hex").hexToBytes()

            val sealed = crypto.seal(key, nonce, plaintext, aad)
            assertHex(c.getString("sealed_hex"), sealed)

            val opened = crypto.open(key, nonce, sealed, aad)
            assertTrue(opened.isSuccess)
            assertArrayEquals(plaintext, opened.getOrThrow())
        }

        val t = group.getJSONObject("tamper")
        val opened = crypto.open(
            AeadKey(t.getString("key_hex").hexToBytes()),
            AeadNonce(t.getString("nonce_hex").hexToBytes()),
            t.getString("sealed_hex").hexToBytes(),
            t.getString("aad_hex").hexToBytes(),
        )
        assertTrue(opened.isFailure)
        assertTrue(opened.exceptionOrNull() is CryptoException.DecryptionFailed)
    }

    @Test
    fun recoveryDerivation() {
        val group = fixtures.getJSONObject("recovery")
        val c = group.getJSONArray("cases").getJSONObject(0)
        val keys = crypto.deriveIdentity(RecoveryPhrase(c.getString("phrase")))
        assertHex(c.getString("ed25519_secret_hex"), keys.ed25519Secret.bytes())
        assertHex(c.getString("ed25519_public_hex"), keys.ed25519Public.bytes)
        assertHex(c.getString("x25519_secret_hex"), keys.x25519Secret.bytes())
        assertHex(c.getString("x25519_public_hex"), keys.x25519Public.bytes)

        try {
            crypto.deriveIdentity(RecoveryPhrase(group.getString("bad_phrase")))
            throw AssertionError("bad phrase should be rejected")
        } catch (e: CryptoException.BadRecoveryPhrase) {
            // expected
        }
    }

    @Test
    fun sealedIdentity() {
        val g = fixtures.getJSONObject("sealed_identity")
        val phrase = RecoveryPhrase(g.getString("phrase"))
        val contentKey = g.getString("content_key_hex").hexToBytes()
        val message = g.getString("message_hex").hexToBytes()

        val sealed = sealedCrypto.createSealedIdentity(phrase, contentKey)
        assertHex(g.getString("ed25519_public_hex"), sealed.ed25519Public.bytes)
        assertHex(g.getString("x25519_public_hex"), sealed.x25519Public.bytes)

        sealedCrypto.openSealedIdentity(sealed.blob, contentKey).getOrThrow().use { id ->
            assertHex(g.getString("ed25519_public_hex"), id.ed25519PublicKey().bytes)
            assertHex(g.getString("x25519_public_hex"), id.x25519PublicKey().bytes)
            // Ed25519 is deterministic: a fixed message signs to a fixed value.
            assertHex(g.getString("signature_hex"), id.sign(message).bytes)
        }

        val wrong = sealedCrypto.openSealedIdentity(
            sealed.blob,
            g.getString("wrong_content_key_hex").hexToBytes(),
        )
        assertTrue(wrong.isFailure)
        assertTrue(wrong.exceptionOrNull() is CryptoException.DecryptionFailed)
    }

    @Test
    fun hashChain() {
        val group = fixtures.getJSONObject("hash_chain")
        assertHex(group.getString("genesis_prev_hash_hex"), crypto.genesisPrevHash())

        val single = group.getJSONObject("single")
        val singleEvent = single.getJSONObject("event").toLogEvent()
        assertEquals(single.getString("event_content_json"), crypto.eventContentJson(singleEvent))
        assertHex(
            single.getString("row_hash_hex"),
            crypto.rowHash(crypto.genesisPrevHash(), singleEvent),
        )

        when (val v = crypto.verifyChain(group.getJSONArray("intact").toChainRows())) {
            is ChainVerification.Intact -> assertEquals(4L, v.verifiedRows)
            else -> throw AssertionError("expected Intact, got $v")
        }

        assertBrokenAt(group.getJSONObject("content_tampered"), "ContentTampered")
        assertBrokenAt(group.getJSONObject("link_broken"), "LinkBroken")
    }

    @Test
    fun phoneLogRow() {
        val g = fixtures.getJSONObject("phone_log_row")
        val event = LogEvent(
            reqId = g.getString("req_id_hex").hexToBytes(),
            eventType = g.getString("event_type"),
            payloadJson = g.getString("payload_json"),
            timestamp = g.getLong("timestamp"),
        )
        assertEquals(g.getString("event_content_json"), crypto.eventContentJson(event))

        val payload = crypto.signingPayload(
            SigningContext.PHONE_LOG,
            crypto.eventContentJson(event),
        )
        assertHex(g.getString("signing_payload_hex"), payload)

        val verified = crypto.verify(
            Ed25519PublicKey(g.getString("ed25519_public_hex").hexToBytes()),
            payload,
            Ed25519Signature(g.getString("signature_hex").hexToBytes()),
        )
        assertTrue(verified.isSuccess)
    }

    // -- helpers -----------------------------------------------------------

    private fun assertBrokenAt(obj: JSONObject, kind: String) {
        val v = crypto.verifyChain(obj.getJSONArray("rows").toChainRows())
        v as? ChainVerification.Broken ?: throw AssertionError("expected Broken, got $v")
        assertEquals(obj.getLong("expect_index"), v.index)
        val actualKind = when (v.reason) {
            is ChainBreak.ContentTampered -> "ContentTampered"
            is ChainBreak.LinkBroken -> "LinkBroken"
        }
        assertEquals(kind, actualKind)
    }

    private fun forEachCase(group: String, body: (JSONObject) -> Unit) {
        fixtures.getJSONObject(group).getJSONArray("cases").objects().forEach(body)
    }

    private fun JSONObject.toLogEvent() = LogEvent(
        reqId = getString("req_id_hex").hexToBytes(),
        eventType = getString("event_type"),
        payloadJson = getString("payload_json"),
        timestamp = getLong("timestamp"),
    )

    private fun JSONArray.toChainRows(): List<ChainRow> = objects().map { r ->
        ChainRow(
            event = r.getJSONObject("event").toLogEvent(),
            prevHash = r.getString("prev_hash_hex").hexToBytes(),
            hash = r.getString("hash_hex").hexToBytes(),
        )
    }

    private fun JSONArray.objects(): List<JSONObject> =
        (0 until length()).map { getJSONObject(it) }

    private fun assertHex(expectedHex: String, actual: ByteArray) =
        assertEquals(expectedHex, actual.toHex())

    private fun assertArrayEquals(expected: ByteArray, actual: ByteArray) =
        org.junit.Assert.assertArrayEquals(expected, actual)
}
