package com.ahlyxlabs.conveyance.transport.ble

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothProfile
import com.ahlyxlabs.conveyance.transport.ConnectionStateMachine.Event
import com.ahlyxlabs.conveyance.transport.ConnectionStateMachine.State
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [ConveyanceGattServerCallback]'s own translation logic — the part that
 * doesn't need a real `BluetoothGattServer`/`BluetoothGattCharacteristic`
 * (those need instrumented coverage; this project has no
 * Android-stub-mocking framework, so a unit test can only exercise
 * methods taking primitives / a nullable `BluetoothDevice`).
 *
 * `handle` is a plain [GattServerHandle] here — 10.3b remediation
 * finding #7 dropped the `() -> GattServerHandle?` supplier once
 * [RealGattServerHandle] no longer needed deferred construction.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ConveyanceGattServerCallbackTest {

    private val dispatcher = StandardTestDispatcher()
    private val fake = FakeGattServerHandle()
    private val fakeWatch = FakeAdapterWatch()

    private fun actor() = BleActor(dispatcher, fakeWatch).also { it.attachServer(fake) }

    private fun BleActor.driveToSubscribed() {
        onEvent(Event.CentralConnected)
        onEvent(Event.MtuChanged(247))
        onEvent(Event.Subscribed)
    }

    @Test
    fun connectSinksTheDeviceAndDispatchesCentralConnected() = runTest(dispatcher) {
        val a = actor()
        var deviceSinkCalled = false
        var sunkDevice: BluetoothDevice? = null
        val cb = ConveyanceGattServerCallback(
            a,
            fake,
            deviceSink = { deviceSinkCalled = true; sunkDevice = it },
        )

        cb.onConnectionStateChange(null, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_CONNECTED)
        assertTrue("deviceSink must be invoked synchronously, before any dispatcher hop", deviceSinkCalled)
        assertNull(sunkDevice) // we passed a null device param; only the connected/not-connected branch is under test

        runCurrent()
        assertEquals(State.CONNECTED, a.state.value)
    }

    @Test
    fun disconnectSinksNullDeviceAndTearsDown() = runTest(dispatcher) {
        val a = actor()
        var deviceSinkCalls = 0
        val cb = ConveyanceGattServerCallback(a, fake, deviceSink = { deviceSinkCalls++ })

        cb.onConnectionStateChange(null, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_CONNECTED)
        runCurrent()
        cb.onConnectionStateChange(null, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_DISCONNECTED)
        runCurrent()

        assertEquals(2, deviceSinkCalls)
        assertEquals(State.TORN, a.state.value)
        assertEquals(1, fake.closeCount)
    }

    @Test
    fun notificationSentForwardsTheDeliveryResult() = runTest(dispatcher) {
        val a = actor()
        val cb = ConveyanceGattServerCallback(a, fake)
        a.driveToSubscribed()
        runCurrent()

        val job = launch { a.link!!.send(ByteArray(4)) }
        runCurrent()
        cb.onNotificationSent(null, BluetoothGatt.GATT_SUCCESS)
        runCurrent()

        assertTrue(job.isCompleted)
    }
}
