package com.ahlyxlabs.conveyance.transport.ble

import android.content.pm.PackageManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.util.concurrent.Executors
import kotlinx.coroutines.asCoroutineDispatcher
import org.junit.Assert.assertFalse
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * [BlePeripheral.start]'s return-value contract against a real
 * `BluetoothManager`: it must not report success (`true`) for a session
 * whose [BleUnavailable] outcome already fired before `start()` returned.
 *
 * Which branch a given device takes (synchronous vs. async unavailable,
 * per [ConveyanceAdvertiserInstrumentedTest]) is hardware-dependent; this
 * only asserts the invariant that holds regardless of the branch.
 */
@RunWith(AndroidJUnit4::class)
class BlePeripheralInstrumentedTest {

    @Test
    @Suppress("MissingPermission") // API-30 CI target: not a runtime permission
    fun startReturnsFalseWhenUnavailableFiresBeforeItReturns() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        assumeTrue(ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE))

        val dispatcher = Executors.newSingleThreadExecutor { r -> Thread(r, "test-ble") }
            .asCoroutineDispatcher()
        val peripheral = BlePeripheral(
            context = ctx,
            dispatcher = dispatcher,
            permissions = BlePermissions(),
            advertiser = ConveyanceAdvertiser(ctx),
            adapterWatch = SystemAdapterWatch(ctx),
        )

        var unavailableFiredBeforeReturn = false
        val result = peripheral.start { unavailableFiredBeforeReturn = true }

        if (unavailableFiredBeforeReturn) {
            assertFalse(
                "start() reported success after already reporting unavailable",
                result,
            )
        }

        peripheral.stop() // must not throw regardless of branch
        dispatcher.close()
    }
}
