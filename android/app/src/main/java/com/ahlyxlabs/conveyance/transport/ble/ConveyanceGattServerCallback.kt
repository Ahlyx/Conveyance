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
 * [handle] is a supplier because the server handle only exists after
 * `openGattServer` returns, which is after this callback is constructed.
 */
class ConveyanceGattServerCallback(
    private val actor: BleActor,
    private val handle: () -> GattServerHandle?,
) : BluetoothGattServerCallback() {

    override fun onConnectionStateChange(device: BluetoothDevice?, status: Int, newState: Int) {
        val connected =
            newState == BluetoothProfile.STATE_CONNECTED && status == BluetoothGatt.GATT_SUCCESS
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
        // Inbound app data on pc_to_phone_tx is handed to the framing
        // path in commit 4. The central normally writes without response;
        // the with-response fallback still needs one or it stalls.
        if (responseNeeded) {
            handle()?.sendResponse(requestId, BluetoothGatt.GATT_SUCCESS, offset, null)
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
            handle()?.sendResponse(requestId, BluetoothGatt.GATT_SUCCESS, offset, null)
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
        // Wired to the one-notification-in-flight gate in commit 4.
    }
}
