package com.ahlyxlabs.conveyance.transport.ble

import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.pm.PackageManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The GATT server half works on the emulator even though advertising
 * does not: open a real `BluetoothGattServer` and register the pinned
 * Conveyance service with its two characteristics + CCCD.
 */
@RunWith(AndroidJUnit4::class)
class ConveyanceGattServerInstrumentedTest {

    @Test
    fun gattServerOpensAndAcceptsTheConveyanceService() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        assumeTrue(
            "no BLE feature",
            ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE),
        )
        val manager = ctx.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        assumeTrue("bluetooth adapter unavailable/off", manager.adapter?.isEnabled == true)

        val server = manager.openGattServer(ctx, object : BluetoothGattServerCallback() {})
        assertNotNull("openGattServer returned null", server)
        try {
            val service = BluetoothGattService(
                ConveyanceGattProfile.SERVICE_UUID,
                BluetoothGattService.SERVICE_TYPE_PRIMARY,
            )
            service.addCharacteristic(
                BluetoothGattCharacteristic(
                    ConveyanceGattProfile.PC_TO_PHONE_TX,
                    BluetoothGattCharacteristic.PROPERTY_WRITE or
                        BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                    BluetoothGattCharacteristic.PERMISSION_WRITE,
                ),
            )
            val notify = BluetoothGattCharacteristic(
                ConveyanceGattProfile.PHONE_TO_PC_TX,
                BluetoothGattCharacteristic.PROPERTY_NOTIFY,
                0,
            )
            notify.addDescriptor(
                BluetoothGattDescriptor(
                    ConveyanceGattProfile.CCCD,
                    BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE,
                ),
            )
            service.addCharacteristic(notify)

            assertTrue("addService rejected the profile", server.addService(service))
        } finally {
            server.close()
        }
    }
}
