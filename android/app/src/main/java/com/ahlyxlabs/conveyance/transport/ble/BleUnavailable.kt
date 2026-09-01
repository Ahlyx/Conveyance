package com.ahlyxlabs.conveyance.transport.ble

/**
 * Why the BLE peripheral could not start. Every case is reported to the
 * UI before anything is advertised — the session simply does not begin,
 * and the kill switch plus all non-BLE surfaces stay functional.
 */
sealed class BleUnavailable(val reason: String) {

    /** API 31+ runtime permission (BLUETOOTH_ADVERTISE / BLUETOOTH_CONNECT) not granted. */
    data object PermissionDenied : BleUnavailable("nearby-devices permission not granted")

    /** The Bluetooth adapter is off. */
    data object AdapterOff : BleUnavailable("bluetooth is turned off")

    /** The device's radio cannot act as a BLE advertiser (common on emulators). */
    data object AdvertisingUnsupported : BleUnavailable("this device cannot advertise over BLE")

    /** A BLE session is already advertising or connected. */
    data object AlreadyActive : BleUnavailable("a BLE session is already active")
}

/** Thrown from the start path when BLE cannot come up. */
class BleUnavailableException(val unavailable: BleUnavailable) : Exception(unavailable.reason)
