package com.ahlyxlabs.conveyance.session

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The interop guarantee the UniFFI-for-Noise decision is paying for, made
 * observable: `noise_fixtures.json` — emitted by `conveyance-noise` (the
 * same wrapper the PC daemon drives) — is replayed here through the real
 * `.so` on the emulator and checked byte for byte.
 *
 * A wrapper-layer divergence a Kotlin-only round-trip would miss (a
 * prologue, a PSK, a role mix-up, an FFI length-prefix bug) shows up here
 * as a mismatched handshake or transport byte, before Phase 11 against
 * the real daemon.
 *
 * Uses the debug-only fixed-ephemeral entry so the handshake bytes are
 * deterministic (see `NoiseTestVectors`).
 */
@RunWith(AndroidJUnit4::class)
class NoiseHandshakeParityTest {

    private lateinit var fx: JSONObject

    @Before
    fun load() {
        val ctx = InstrumentationRegistry.getInstrumentation().context
        fx = JSONObject(
            ctx.assets.open("noise_fixtures.json").bufferedReader().use { it.readText() },
        )
        assertEquals(1L, fx.getLong("schema_version"))
        assertEquals("Noise_KK_25519_ChaChaPoly_BLAKE2s", fx.getString("pattern"))
    }

    private fun phone(k: String) = fx.getJSONObject("phone").getString(k).hex()
    private fun pc(k: String) = fx.getJSONObject("pc").getString(k).hex()
    private fun handshake(k: String) = fx.getJSONObject("handshake").getString(k)
    private fun reject(k: String) = fx.getJSONObject("reject").getString(k)

    private fun freshInitiator(pcPublic: ByteArray = pc("x25519_public_hex")): NoiseSession =
        NoiseTestVectors.initiateWithFixedEphemeral(
            phone("x25519_secret_hex"),
            pcPublic,
            phone("ephemeral_hex"),
        )

    @Test
    fun handshakeMessagesMatchByteForByte() {
        freshInitiator().use { s ->
            assertTrue(s.needsWrite())
            assertEquals(handshake("msg1_hex"), s.writeHandshakeMessage().toHex())
            assertTrue(s.readHandshakeMessage(handshake("msg2_hex").hex()).isEmpty())
            assertTrue(s.isHandshakeComplete())
            assertTrue(!s.needsWrite())
        }
    }

    @Test
    fun transportCiphertextsMatchInBothDirections() {
        freshInitiator().use { s ->
            s.writeHandshakeMessage()
            s.readHandshakeMessage(handshake("msg2_hex").hex())

            val transport = fx.getJSONObject("transport")
            val p2p = transport.getJSONArray("phone_to_pc")
            for (i in 0 until p2p.length()) {
                val c = p2p.getJSONObject(i)
                assertEquals(
                    "phone_to_pc[$i]",
                    c.getString("ciphertext_hex"),
                    s.encrypt(c.getString("plaintext_hex").hex()).toHex(),
                )
            }
            val c2p = transport.getJSONArray("pc_to_phone")
            for (i in 0 until c2p.length()) {
                val c = c2p.getJSONObject(i)
                assertArrayEquals(
                    "pc_to_phone[$i]",
                    c.getString("plaintext_hex").hex(),
                    s.decrypt(c.getString("ciphertext_hex").hex()),
                )
            }
        }
    }

    @Test
    fun wrongPcStaticFailsHandshakeGeneric() {
        freshInitiator(reject("wrong_pc_public_hex").hex()).use { s ->
            s.writeHandshakeMessage()
            assertThrows(SessionException.HandshakeFailed::class.java) {
                s.readHandshakeMessage(handshake("msg2_hex").hex())
            }
        }
    }

    @Test
    fun tamperedTransportMessageIsSessionEnded() {
        freshInitiator().use { s ->
            s.writeHandshakeMessage()
            s.readHandshakeMessage(handshake("msg2_hex").hex())
            assertThrows(SessionException.SessionEnded::class.java) {
                s.decrypt(reject("tampered_pc_to_phone_ciphertext_hex").hex())
            }
        }
    }

    private fun String.hex(): ByteArray {
        require(length % 2 == 0)
        return ByteArray(length / 2) { substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}
