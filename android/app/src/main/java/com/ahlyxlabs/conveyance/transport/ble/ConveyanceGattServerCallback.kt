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

    override fun onConnectionStateChange(device: BluetoothDevice?, status: Int, newState: Int) {
        val connected =
            newState == BluetoothProfile.STATE_CONNECTED && status == BluetoothGatt.GATT_SUCCESS
        deviceSink(if (connected) device else null)
        actor.onEvent(
            if (connected) {
                ConnectionStateMachine.Event.CentralConnected
            } else {
                ConnectionStateMachine.Event.CentralDisconnected
            },
        )
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
