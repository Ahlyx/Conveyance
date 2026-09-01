package com.ahlyxlabs.conveyance.transport.ble

/** Records what [BleActor] / the callback ask of the GATT server. */
class FakeGattServerHandle : GattServerHandle {

    data class Response(val requestId: Int, val status: Int, val offset: Int, val value: ByteArray?)

    val notifications = mutableListOf<ByteArray>()
    val responses = mutableListOf<Response>()
    var closeCount = 0

    /** Flip to false to model an outright notify rejection. */
    var notifyReturns = true

    override fun notify(value: ByteArray): Boolean {
        notifications += value.copyOf()
        return notifyReturns
    }

    override fun sendResponse(requestId: Int, status: Int, offset: Int, value: ByteArray?) {
        responses += Response(requestId, status, offset, value?.copyOf())
    }

    override fun close() {
        closeCount++
    }
}
