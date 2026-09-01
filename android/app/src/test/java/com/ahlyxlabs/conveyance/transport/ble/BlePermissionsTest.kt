package com.ahlyxlabs.conveyance.transport.ble

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Host-JVM: the minSdk-30 / API-31 permission split logic. */
class BlePermissionsTest {

    @Test
    fun api30AndBelowNeedNoRuntimePermission() {
        assertTrue(BlePermissions.requiredFor(30).isEmpty())
        assertTrue(BlePermissions.requiredFor(29).isEmpty())
    }

    @Test
    fun api31PlusNeedAdvertiseAndConnectOnly() {
        for (sdk in intArrayOf(31, 32, 33, 34, 35)) {
            val req = BlePermissions.requiredFor(sdk)
            assertEquals(
                "sdk $sdk",
                setOf(
                    "android.permission.BLUETOOTH_ADVERTISE",
                    "android.permission.BLUETOOTH_CONNECT",
                ),
                req.toSet(),
            )
            assertFalse("no scan", req.any { it.contains("SCAN") })
            assertFalse("no location", req.any { it.contains("LOCATION") })
        }
    }
}
