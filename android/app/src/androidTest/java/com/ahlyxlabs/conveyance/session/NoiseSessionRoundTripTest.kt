package com.ahlyxlabs.conveyance.session

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * A full two-party Noise KK session through the real `.so`: the phone
 * (initiator) against a stand-in PC (responder), random ephemerals, both
 * transport directions. Complements the byte-exact parity test — this
 * one exercises the `NoiseSession` phase machine's promote logic and the
 * responder path, which the initiator-only parity replay does not.
 *
 * The `respond` entry is debug-only (the phone is never the KK responder
 * in production — see `NoiseTestVectors`).
 */
@RunWith(AndroidJUnit4::class)
class NoiseSessionRoundTripTest {

    private lateinit var fx: JSONObject

    @Before
    fun load() {
        val ctx = InstrumentationRegistry.getInstrumentation().context
        fx = JSONObject(
            ctx.assets.open("noise_fixtures.json").bufferedReader().use { it.readText() },
        )
    }

    private fun phone(k: String) = fx.getJSONObject("phone").getString(k).hex()
    private fun pc(k: String) = fx.getJSONObject("pc").getString(k).hex()

    private fun initiator(pcPublic: ByteArray = pc("x25519_public_hex")) =
        NoiseTestVectors.initiateWithFixedEphemeral(
            phone("x25519_secret_hex"),
            pcPublic,
            phone("ephemeral_hex"),
        )

    private fun responder() =
        NoiseTestVectors.respond(pc("x25519_secret_hex"), phone("x25519_public_hex"))

    @Test
    fun handshakeThenTransportBothWays() {
        initiator().use { i ->
            responder().use { r ->
                val m1 = i.writeHandshakeMessage()
                assertTrue(r.readHandshakeMessage(m1).isEmpty())
                val m2 = r.writeHandshakeMessage()
                assertTrue(i.readHandshakeMessage(m2).isEmpty())

                assertTrue(i.isHandshakeComplete())
                assertTrue(r.isHandshakeComplete())

                val toPc = "phone -> pc".toByteArray()
                assertArrayEquals(toPc, r.decrypt(i.encrypt(toPc)))
                val toPhone = "{\"decision\":\"approved\"}".toByteArray()
                assertArrayEquals(toPhone, i.decrypt(r.encrypt(toPhone)))
            }
        }
    }

    @Test
    fun wrongPeerStaticFailsGenericAtTheResponder() {
        initiator(fx.getJSONObject("reject").getString("wrong_pc_public_hex").hex()).use { i ->
            responder().use { r ->
                val m1 = i.writeHandshakeMessage()
                assertThrows(SessionException.HandshakeFailed::class.java) {
                    r.readHandshakeMessage(m1)
                }
            }
        }
    }

    @Test
    fun transportMethodBeforeHandshakeCompletesThrowsWrongPhase() {
        responder().use { r ->
            assertThrows(SessionException.WrongPhase::class.java) { r.encrypt(ByteArray(4)) }
            assertThrows(SessionException.WrongPhase::class.java) { r.decrypt(ByteArray(20)) }
        }
    }

    private fun String.hex(): ByteArray {
        require(length % 2 == 0)
        return ByteArray(length / 2) { substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
