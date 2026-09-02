package com.ahlyxlabs.conveyance.transport.ble

import android.bluetooth.BluetoothAdapter
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject

/**
 * Watches for the Bluetooth adapter being turned off under a live
 * connection. Registered when a BLE session starts (`BleActor.attachServer`)
 * and unregistered in teardown — never app-global.
 */
interface AdapterWatch {
    /** Begin watching; [onOff] fires once when the adapter turns off. */
    fun start(onOff: () -> Unit)

    /** Stop watching. Idempotent. */
    fun stop()
}

/** [AdapterWatch] over an `ACTION_STATE_CHANGED` broadcast receiver. */
class SystemAdapterWatch @Inject constructor(
    @ApplicationContext private val context: Context,
) : AdapterWatch {

    private var receiver: BroadcastReceiver? = null

    override fun start(onOff: () -> Unit) {
        if (receiver != null) return
        val r = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                if (intent?.action != BluetoothAdapter.ACTION_STATE_CHANGED) return
                val state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)
                if (state == BluetoothAdapter.STATE_TURNING_OFF || state == BluetoothAdapter.STATE_OFF) {
                    onOff()
                }
            }
        }
        receiver = r
        ContextCompat.registerReceiver(
            context,
            r,
            IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    override fun stop() {
        val r = receiver ?: return
        receiver = null
        runCatching { context.unregisterReceiver(r) }
    }
}
