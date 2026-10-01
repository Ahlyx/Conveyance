package com.ahlyxlabs.conveyance.pairing

import com.ahlyxlabs.conveyance.crypto.RustUnlockedIdentity
import com.ahlyxlabs.conveyance.crypto.UnlockedIdentity
import uniffi.conveyance_crypto_ffi.PairingFfiException
import uniffi.conveyance_crypto_ffi.PendingPairing as FfiPendingPairing
import uniffi.conveyance_crypto_ffi.parsePairingQr
import javax.inject.Inject

/** Validated QR state backed by the shared Rust pairing protocol. */
interface PairingProtocol {
    fun parse(encoded: String, nowUnixSeconds: Long): PairingRequest
}

interface PairingRequest {
    val pcName: String
    val pcIdPub: ByteArray
    val pcDhPub: ByteArray
    val expires: Long

    fun createConfirm(identity: UnlockedIdentity): PairingConfirmData
    fun verifyAck(wireMessage: ByteArray)
}

data class PairingConfirmData(
    val phoneIdPub: ByteArray,
    val phoneDhPub: ByteArray,
    val wireMessage: ByteArray,
)

class PairingProtocolException(
    val kind: Kind,
    val foundVersion: Long? = null,
    val expectedVersion: Long? = null,
    cause: Throwable? = null,
) : Exception(kind.message, cause) {
    enum class Kind(val message: String) {
        EXPIRED("The PC pairing code expired. Ask the PC to create a new code."),
        INCOMPATIBLE_VERSION("This PC uses an incompatible Conveyance protocol version."),
        FAILED("Pairing failed. Check the PC code and try again."),
    }
}

class RustPairingProtocol @Inject constructor() : PairingProtocol {
    override fun parse(encoded: String, nowUnixSeconds: Long): PairingRequest = try {
        RustPairingRequest(parsePairingQr(encoded, nowUnixSeconds))
    } catch (error: PairingFfiException.QrExpired) {
        throw PairingProtocolException(PairingProtocolException.Kind.EXPIRED, cause = error)
    } catch (error: PairingFfiException.IncompatibleVersion) {
        throw PairingProtocolException(
            kind = PairingProtocolException.Kind.INCOMPATIBLE_VERSION,
            foundVersion = error.found.toLong(),
            expectedVersion = error.expected.toLong(),
            cause = error,
        )
    } catch (error: PairingFfiException) {
        throw PairingProtocolException(PairingProtocolException.Kind.FAILED, cause = error)
    }
}

private class RustPairingRequest(
    private val ffi: FfiPendingPairing,
) : PairingRequest {
    override val pcName: String get() = ffi.pcName()
    override val pcIdPub: ByteArray get() = ffi.pcIdPub()
    override val pcDhPub: ByteArray get() = ffi.pcDhPub()
    override val expires: Long get() = ffi.expires()

    override fun createConfirm(identity: UnlockedIdentity): PairingConfirmData {
        val rustIdentity = identity as? RustUnlockedIdentity
            ?: throw PairingProtocolException(PairingProtocolException.Kind.FAILED)
        return try {
            val payload = ffi.createConfirm(rustIdentity.ffi)
            PairingConfirmData(
                phoneIdPub = payload.phoneIdPub,
                phoneDhPub = payload.phoneDhPub,
                wireMessage = payload.wireMessage,
            )
        } catch (error: PairingFfiException) {
            throw PairingProtocolException(PairingProtocolException.Kind.FAILED, cause = error)
        }
    }

    override fun verifyAck(wireMessage: ByteArray) {
        try {
            ffi.verifyAck(wireMessage)
        } catch (error: PairingFfiException) {
            throw PairingProtocolException(PairingProtocolException.Kind.FAILED, cause = error)
        }
    }
}
