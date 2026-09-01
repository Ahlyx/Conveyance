package com.ahlyxlabs.conveyance.transport.ble

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device check that [BlePermissions.granted] agrees with the running
 * API level. The CI emulator is API 30, so this exercises the
 * install-time branch (empty [BlePermissions.required], unconditionally
 * granted); the 31+ branch is covered purely in `BlePermissionsTest`.
 */
@RunWith(AndroidJUnit4::class)
class BlePermissionsInstrumentedTest {

    @Test
    fun grantedReflectsTheRunningApiLevel() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val perms = BlePermissions()

        if (Build.VERSION.SDK_INT <= 30) {
            assertTrue("API <= 30 needs no runtime BLE permission", perms.required.isEmpty())
            assertTrue("empty requirement is always satisfied", perms.granted(ctx))
        } else {
            assertEquals(2, perms.required.size)
        }
    }
}
