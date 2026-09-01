package com.ahlyxlabs.conveyance.transport.ble

import android.bluetooth.le.AdvertiseCallback
import org.junit.Assert.assertEquals
import org.junit.Test

class ConveyanceAdvertiserTest {

    @Test
    fun alreadyStartedMapsToAlreadyActive() {
        assertEquals(
            BleUnavailable.AlreadyActive,
            ConveyanceAdvertiser.mapAdvertiseError(AdvertiseCallback.ADVERTISE_FAILED_ALREADY_STARTED),
        )
    }

    @Test
    fun everyOtherFailureMapsToAdvertisingUnsupported() {
        for (code in intArrayOf(
            AdvertiseCallback.ADVERTISE_FAILED_FEATURE_UNSUPPORTED,
            AdvertiseCallback.ADVERTISE_FAILED_DATA_TOO_LARGE,
            AdvertiseCallback.ADVERTISE_FAILED_TOO_MANY_ADVERTISERS,
            AdvertiseCallback.ADVERTISE_FAILED_INTERNAL_ERROR,
            999,
        )) {
            assertEquals(
                "code $code",
                BleUnavailable.AdvertisingUnsupported,
                ConveyanceAdvertiser.mapAdvertiseError(code),
            )
        }
    }
}
