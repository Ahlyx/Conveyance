package com.ahlyxlabs.conveyance.pairing

import android.Manifest
import androidx.annotation.RequiresPermission
import com.ahlyxlabs.conveyance.storage.identity.UnlockedPhoneSession
import com.ahlyxlabs.conveyance.storage.pairings.PairingEntity
import com.ahlyxlabs.conveyance.storage.pairings.PairingStore
import com.ahlyxlabs.conveyance.transport.framing.InboundAssembler
import com.ahlyxlabs.conveyance.transport.framing.MessageSplitter
import com.ahlyxlabs.conveyance.transport.link.LinkEvent
import com.ahlyxlabs.conveyance.transport.link.PhoneLink
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.transform
import kotlinx.coroutines.withTimeout

/** Drives the plaintext, pre-Noise pairing exchange. */
@Singleton
class PairingCoordinator @Inject constructor(
    private val protocol: PairingProtocol,
    private val pairings: PairingStore,
    private val radio: PairingRadio,
) {
    @RequiresPermission(
        allOf = [Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_ADVERTISE],
    )
    suspend fun pair(
        encodedQr: String,
        session: UnlockedPhoneSession,
        onStatus: (String) -> Unit = {},
    ): PairingEntity {
        val request = protocol.parse(encodedQr, unixNow())
        val confirm = request.createConfirm(session.identity)

        val connectTimeoutMillis = ((request.expires - unixNow()).coerceAtLeast(0) * 1_000)
            .coerceAtMost(QR_CONNECT_WINDOW_MS)
        if (connectTimeoutMillis <= 0) {
            throw PairingProtocolException(PairingProtocolException.Kind.EXPIRED)
        }

        var link: PhoneLink? = null
        try {
            onStatus("Waiting for the PC to connect…")
            link = radio.connect(connectTimeoutMillis)
            sendFramed(link, confirm.wireMessage)

            onStatus("Verifying the PC…")
            val ack = receiveOneMessage(link)
            request.verifyAck(ack)

            val now = unixNow()
            val prior = pairings.get(request.pcIdPub)
            val paired = PairingEntity(
                pcIdPub = request.pcIdPub,
                pcDhPub = request.pcDhPub,
                pcName = request.pcName,
                firstPairedAt = prior?.firstPairedAt ?: now,
                lastSessionAt = prior?.lastSessionAt,
            )
            pairings.save(paired)
            return paired
        } catch (error: TimeoutCancellationException) {
            throw PairingProtocolException(PairingProtocolException.Kind.FAILED, cause = error)
        } catch (error: CancellationException) {
            throw error
        } catch (error: PairingProtocolException) {
            throw error
        } catch (error: Exception) {
            throw PairingProtocolException(PairingProtocolException.Kind.FAILED, cause = error)
        } finally {
            link?.shutdown()
            radio.stop()
        }
    }

    private suspend fun sendFramed(link: PhoneLink, message: ByteArray) {
        val split = MessageSplitter.split(message, link.maxWriteLen, startSeq = 0)
        split.frames.forEach { link.send(it) }
    }

    private suspend fun receiveOneMessage(link: PhoneLink): ByteArray = try {
        withTimeout(ACK_TIMEOUT_MS) {
            val assembler = InboundAssembler()
            link.events.transform { event ->
                when (event) {
                    is LinkEvent.Chunk -> {
                        val messages = assembler.ingest(event.bytes)
                        if (messages.size > 1) {
                            throw PairingProtocolException(PairingProtocolException.Kind.FAILED)
                        }
                        messages.singleOrNull()?.let { emit(it) }
                    }
                    is LinkEvent.Torn -> throw PairingProtocolException(
                        PairingProtocolException.Kind.FAILED,
                    )
                }
            }.first()
        }
    } catch (error: TimeoutCancellationException) {
        throw PairingProtocolException(PairingProtocolException.Kind.FAILED, cause = error)
    }

    private companion object {
        const val ACK_TIMEOUT_MS = 10_000L
        const val QR_CONNECT_WINDOW_MS = 60_000L
    }
}

private fun unixNow(): Long = System.currentTimeMillis() / 1_000L
