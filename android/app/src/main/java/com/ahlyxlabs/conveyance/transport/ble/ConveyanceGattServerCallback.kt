package com.ahlyxlabs.conveyance.transport.ble

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothProfile
import com.ahlyxlabs.conveyance.transport.ConnectionStateMachine

/**
 * Translates `BluetoothGattServer` callbacks — which arrive on binder
 * threads — into [BleActor] events. Every method does the minimum here
 * and hands off; no connection state lives in this class.
 *
 * [handle] is safe to reference from the moment this callback is built:
 * see [RealGattServerHandle]'s own doc comment for why it can exist
 * before `openGattServer` returns. [deviceSink] receives the connected
 * central (or null on disconnect) so the real handle knows whom to
 * notify / respond to.
 */
class ConveyanceGattServerCallback(
    private val actor: BleActor,
    private val handle: GattServerHandle,
    private val deviceSink: (BluetoothDevice?) -> Unit = {},
) : BluetoothGattServerCallback() {

    // Tracks the device a genuine STATE_CONNECTED landed for, so a
    // disconnect callback can be checked against it below. hasConnected
    // is tracked separately from connectedDevice being non-null: the
    // framework's device is @Volatile-visible but nothing stops it being
    // null on a real callback in principle, and a null-vs-null comparison
    // must not be mistaken for "matches the device we connected".
    @Volatile private var hasConnected = false
    @Volatile private var connectedDevice: BluetoothDevice? = null

    override fun onConnectionStateChange(device: BluetoothDevice?, status: Int, newState: Int) {
        val connected =
            newState == BluetoothProfile.STATE_CONNECTED && status == BluetoothGatt.GATT_SUCCESS
        if (connected) {
            hasConnected = true
            connectedDevice = device
            deviceSink(device)
            actor.onEvent(ConnectionStateMachine.Event.CentralConnected)
        } else {
            // A stale/duplicate disconnect callback for a device we never
            // tracked as connected (finding #5) — a documented BLE-stack
            // quirk — must not tear down a session that has nothing to
            // tear down yet. AdapterOff has no analogous risk (it comes
            // from one real ACTION_STATE_CHANGED broadcast, not a binder
            // callback) and keeps tearing down unconditionally.
            if (!hasConnected || device != connectedDevice) return
            hasConnected = false
            connectedDevice = null
            deviceSink(null)
            actor.onEvent(ConnectionStateMachine.Event.CentralDisconnected)
        }
    }

    override fun onMtuChanged(device: BluetoothDevice?, mtu: Int) {
        actor.onEvent(ConnectionStateMachine.Event.MtuChanged(mtu))
    }

    override fun onCharacteristicWriteRequest(
        device: BluetoothDevice?,
        requestId: Int,
        characteristic: BluetoothGattCharacteristic?,
        preparedWrite: Boolean,
        responseNeeded: Boolean,
        offset: Int,
        value: ByteArray?,
    ) {
        // preparedWrite (Android's reliable/queued-write mechanism —
        // preparedWrite=true writes queued for a later
        // executeReliableWrite/cancel) is not handled: onExecuteWriteRequest
        // is never overridden, so a queued write would be pushed into the
        // Framer's byte stream as if complete (corrupting framing) and the
        // central's execute-write request would never get a GATT response.
        // Deferred (10.3b remediation finding #9, tracked in
        // CONVEYANCE_PHASES.md's Phase 11 BLE carry-over): btleplug, the
        // real PC-side central, doesn't use reliable writes, and the
        // emulator doesn't exercise them either. Handle this if Phase 11
        // hardware testing with a different central ever needs it.
        val charUuid = characteristic?.uuid
        if (charUuid != null && ConveyanceGattProfile.isInboundWrite(charUuid) && value != null) {
            // Copy: the framework reuses this buffer.
            actor.onInboundBytes(value.copyOf())
        }
        // The central normally writes without response; the with-response
        // fallback still needs one or the write stalls.
        if (responseNeeded) {
            handle.sendResponse(requestId, BluetoothGatt.GATT_SUCCESS, offset, null)
        }
    }

    override fun onDescriptorWriteRequest(
        device: BluetoothDevice?,
        requestId: Int,
        descriptor: BluetoothGattDescriptor?,
        preparedWrite: Boolean,
        responseNeeded: Boolean,
        offset: Int,
        value: ByteArray?,
    ) {
        // Respond FIRST: a late or missing descriptor response leaves the
        // central's write hanging. Only then interpret the CCCD change.
        if (responseNeeded) {
            handle.sendResponse(requestId, BluetoothGatt.GATT_SUCCESS, offset, null)
        }
        val descriptorUuid = descriptor?.uuid ?: return
        val characteristicUuid = descriptor.characteristic?.uuid ?: return
        when (
            ConveyanceGattProfile.classifyDescriptorWrite(descriptorUuid, characteristicUuid, value)
        ) {
            ConveyanceGattProfile.CccdChange.SUBSCRIBE ->
                actor.onEvent(ConnectionStateMachine.Event.Subscribed)
            ConveyanceGattProfile.CccdChange.UNSUBSCRIBE ->
                actor.onEvent(ConnectionStateMachine.Event.Unsubscribed)
            ConveyanceGattProfile.CccdChange.IGNORE -> Unit
        }
    }

    override fun onNotificationSent(device: BluetoothDevice?, status: Int) {
        actor.onNotificationResult(status == BluetoothGatt.GATT_SUCCESS)
    }
}
