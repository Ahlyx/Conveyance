package com.ahlyxlabs.conveyance.transport.ble

import android.content.pm.PackageManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The advertiser's contract, not a live advertisement.
 *
 * On real hardware [ConveyanceAdvertiser.start] calls back `onStarted`.
 * On the CI emulator the radio cannot advertise, so it calls back
 * `onUnavailable(AdvertisingUnsupported)` — synchronously (null
 * `bluetoothLeAdvertiser`) or via `onStartFailure`. Either way exactly
 * one callback fires, promptly, and nothing throws. That is what we
 * assert; which branch runs depends on the device.
 */
@RunWith(AndroidJUnit4::class)
class ConveyanceAdvertiserInstrumentedTest {

    @Test
    @Suppress("MissingPermission") // API-30 CI target: BLUETOOTH_ADVERTISE is not a runtime permission
    fun startResolvesToExactlyOneOutcomeAndNeverThrows() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        assumeTrue(ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE))

        val advertiser = ConveyanceAdvertiser(ctx)
        val latch = CountDownLatch(1)
        val outcomes = mutableListOf<String>()

        advertiser.start(
            onStarted = { outcomes += "started"; latch.countDown() },
            onUnavailable = { outcomes += "unavailable:${it.reason}"; latch.countDown() },
        )

        assertTrue("no advertiser callback within 5s", latch.await(5, TimeUnit.SECONDS))
        assertTrue("expected exactly one outcome, got $outcomes", outcomes.size == 1)
        advertiser.stop() // must not throw regardless of branch
    }
}
