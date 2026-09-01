package com.ahlyxlabs.conveyance.transport.ble

import java.util.UUID

/**
 * The pinned Conveyance GATT identifiers and the pure decisions the
 * server callback makes about incoming requests.
 *
 * UUIDs are permanent for v1 — pinned in `CONVEYANCE_SPEC.md` ("Wire
 * protocol" → BLE topology) and in `conveyance-core::transport::ids`.
 * Changing any of them breaks pairings in the wild.
 */
object ConveyanceGattProfile {

    /** Advertised primary service. */
    val SERVICE_UUID: UUID = UUID.fromString("709031fe-abea-437f-801e-dc6872723b1f")

    /** Central → phone. Write / write-without-response. */
    val PC_TO_PHONE_TX: UUID = UUID.fromString("56d373b8-1dcf-4107-894b-b4888ff0db3f")

    /** Phone → central. Notify. */
    val PHONE_TO_PC_TX: UUID = UUID.fromString("b4b10ea8-450c-47bd-93d9-065bb67e1bc9")

    /** Standard Client Characteristic Configuration Descriptor. */
    val CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    enum class CccdChange { SUBSCRIBE, UNSUBSCRIBE, IGNORE }

    /**
     * What a descriptor write means for our notify subscription. Pure:
     * UUIDs and the 2-byte CCCD value in, an intent out. `{01,00}` is
     * enable-notification, `{02,00}` enable-indication (we still only
     * notify, but treat it as a subscription), `{00,00}` disable.
     */
    fun classifyDescriptorWrite(
        descriptorUuid: UUID,
        characteristicUuid: UUID,
        value: ByteArray?,
    ): CccdChange {
        if (descriptorUuid != CCCD || characteristicUuid != PHONE_TO_PC_TX) return CccdChange.IGNORE
        val v = value ?: return CccdChange.IGNORE
        if (v.size < 2) return CccdChange.IGNORE
        val lo = v[0].toInt() and 0xFF
        val hi = v[1].toInt() and 0xFF
        return when {
            hi == 0x00 && (lo == 0x01 || lo == 0x02) -> CccdChange.SUBSCRIBE
            hi == 0x00 && lo == 0x00 -> CccdChange.UNSUBSCRIBE
            else -> CccdChange.IGNORE
        }
    }

    /** True when a characteristic write is inbound app data on `pc_to_phone_tx`. */
    fun isInboundWrite(characteristicUuid: UUID): Boolean = characteristicUuid == PC_TO_PHONE_TX
}
