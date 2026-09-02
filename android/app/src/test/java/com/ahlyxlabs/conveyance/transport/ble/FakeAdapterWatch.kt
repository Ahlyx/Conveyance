package com.ahlyxlabs.conveyance.transport.ble

/** Records [AdapterWatch] lifecycle and lets a test fire the adapter-off signal. */
class FakeAdapterWatch : AdapterWatch {

    var started = false
        private set
    var stopped = false
        private set

    private var onOff: (() -> Unit)? = null

    override fun start(onOff: () -> Unit) {
        started = true
        this.onOff = onOff
    }

    override fun stop() {
        stopped = true
    }

    fun triggerOff() = onOff?.invoke()
}
