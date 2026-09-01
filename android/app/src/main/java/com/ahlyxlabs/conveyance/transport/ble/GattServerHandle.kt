package com.ahlyxlabs.conveyance.transport.ble

/**
 * The slice of `BluetoothGattServer` the [BleActor] drives. The real
 * implementation wraps `android.bluetooth.BluetoothGattServer`; tests
 * fake it, which is the only way to get deterministic
 * notify / `onNotificationSent` timing (commit 4).
 */
interface GattServerHandle {

    /**
     * Push one notification on `phone_to_pc_tx`. Returns `false` if the
     * stack rejected it outright — not connected, or the internal queue
     * is full (API 30–32 `notifyCharacteristicChanged` returning `false`,
     * or API 33+ returning a non-success status). That is terminal. A
     * `true` return is only *accepted*; delivery is confirmed later via
     * `onNotificationSent`.
     */
    fun notify(value: ByteArray): Boolean

    /** Answer a characteristic or descriptor request. */
    fun sendResponse(requestId: Int, status: Int, offset: Int, value: ByteArray?)

    /** Disconnect the central and close the server. Idempotent. */
    fun close()
}
