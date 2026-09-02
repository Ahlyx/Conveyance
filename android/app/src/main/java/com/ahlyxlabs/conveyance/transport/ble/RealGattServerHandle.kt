package com.ahlyxlabs.conveyance.transport.ble

import android.Manifest
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothStatusCodes
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.annotation.RequiresPermission

/**
 * [GattServerHandle] over a real `BluetoothGattServer`.
 *
 * The connected central is set by [ConveyanceGattServerCallback] via its
 * `deviceSink` — every operation needs the `BluetoothDevice`, and it is
 * only known once a connection lands.
 *
 * `notifyCharacteristicChanged` was replaced on API 33+ by a byte-array
 * overload returning a status; the pre-33 form is used below API 33 and
 * is the only place `@Suppress("DEPRECATION")` appears.
 */
class RealGattServerHandle(
    private val server: BluetoothGattServer,
    private val notifyCharacteristic: BluetoothGattCharacteristic,
) : GattServerHandle {

    @Volatile
    var device: BluetoothDevice? = null

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    override fun notify(value: ByteArray): Boolean {
        val target = device ?: return false
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                notifyApi33(target, value)
            } else {
                @Suppress("DEPRECATION")
                run {
                    notifyCharacteristic.value = value
                    server.notifyCharacteristicChanged(target, notifyCharacteristic, false)
                }
            }
        } catch (_: SecurityException) {
            false
        }
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    private fun notifyApi33(target: BluetoothDevice, value: ByteArray): Boolean =
        server.notifyCharacteristicChanged(target, notifyCharacteristic, false, value) ==
            BluetoothStatusCodes.SUCCESS

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    override fun sendResponse(requestId: Int, status: Int, offset: Int, value: ByteArray?) {
        val target = device ?: return
        try {
            server.sendResponse(target, requestId, status, offset, value)
        } catch (_: SecurityException) {
            // Permission revoked mid-session; the connection is already doomed.
        }
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    override fun close() {
        try {
            device?.let { server.cancelConnection(it) }
            server.close()
        } catch (_: SecurityException) {
            // ignore
        } finally {
            device = null
        }
    }

    private companion object {
        // Kept for symmetry / readability; GATT_SUCCESS is 0.
        const val SUCCESS = BluetoothGatt.GATT_SUCCESS
    }
}
