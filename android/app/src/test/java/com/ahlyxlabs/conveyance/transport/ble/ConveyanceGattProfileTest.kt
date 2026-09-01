package com.ahlyxlabs.conveyance.transport.ble

import com.ahlyxlabs.conveyance.transport.ble.ConveyanceGattProfile.CccdChange
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class ConveyanceGattProfileTest {

    @Test
    fun uuidsMatchTheSpec() {
        assertEquals("709031fe-abea-437f-801e-dc6872723b1f", ConveyanceGattProfile.SERVICE_UUID.toString())
        assertEquals("56d373b8-1dcf-4107-894b-b4888ff0db3f", ConveyanceGattProfile.PC_TO_PHONE_TX.toString())
        assertEquals("b4b10ea8-450c-47bd-93d9-065bb67e1bc9", ConveyanceGattProfile.PHONE_TO_PC_TX.toString())
        assertEquals("00002902-0000-1000-8000-00805f9b34fb", ConveyanceGattProfile.CCCD.toString())
    }

    @Test
    fun isInboundWriteOnlyForPcToPhoneTx() {
        assertTrue(ConveyanceGattProfile.isInboundWrite(ConveyanceGattProfile.PC_TO_PHONE_TX))
        assertFalse(ConveyanceGattProfile.isInboundWrite(ConveyanceGattProfile.PHONE_TO_PC_TX))
        assertFalse(ConveyanceGattProfile.isInboundWrite(UUID.randomUUID()))
    }

    @Test
    fun cccdEnableNotificationOrIndicationIsSubscribe() {
        assertEquals(CccdChange.SUBSCRIBE, classify(byteArrayOf(0x01, 0x00)))
        assertEquals(CccdChange.SUBSCRIBE, classify(byteArrayOf(0x02, 0x00)))
    }

    @Test
    fun cccdDisableIsUnsubscribe() {
        assertEquals(CccdChange.UNSUBSCRIBE, classify(byteArrayOf(0x00, 0x00)))
    }

    @Test
    fun cccdNonsenseOrWrongTargetIsIgnored() {
        assertEquals(CccdChange.IGNORE, classify(null))
        assertEquals(CccdChange.IGNORE, classify(byteArrayOf(0x01)))
        assertEquals(CccdChange.IGNORE, classify(byteArrayOf(0x09, 0x09)))
        // Right value, wrong characteristic.
        assertEquals(
            CccdChange.IGNORE,
            ConveyanceGattProfile.classifyDescriptorWrite(
                ConveyanceGattProfile.CCCD,
                ConveyanceGattProfile.PC_TO_PHONE_TX,
                byteArrayOf(0x01, 0x00),
            ),
        )
        // Right value, wrong descriptor.
        assertEquals(
            CccdChange.IGNORE,
            ConveyanceGattProfile.classifyDescriptorWrite(
                UUID.randomUUID(),
                ConveyanceGattProfile.PHONE_TO_PC_TX,
                byteArrayOf(0x01, 0x00),
            ),
        )
    }

    private fun classify(value: ByteArray?) =
        ConveyanceGattProfile.classifyDescriptorWrite(
            ConveyanceGattProfile.CCCD,
            ConveyanceGattProfile.PHONE_TO_PC_TX,
            value,
        )
}
