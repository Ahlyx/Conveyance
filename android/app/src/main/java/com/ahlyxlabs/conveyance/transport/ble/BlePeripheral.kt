package com.ahlyxlabs.conveyance.transport.ble

import android.Manifest
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.content.Context
import androidx.annotation.RequiresPermission
import com.ahlyxlabs.conveyance.transport.ConnectionStateMachine
import com.ahlyxlabs.conveyance.transport.ble.di.BleDispatcher
import com.ahlyxlabs.conveyance.transport.link.PhoneLink
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.flow.StateFlow

/**
 * The BLE peripheral, assembled: GATT server + advertiser + actor.
 *
 * [start] / [stop] are the whole surface. They wire nothing to a
 * lifecycle — Phase 10.9's foreground service calls [start] when the
 * user begins a session and [stop] the instant it ends; instrumented
 * tests call them directly. The Noise session (10.4) consumes [link].
 */
@Singleton
class BlePeripheral @Inject constructor(
    @ApplicationContext private val context: Context,
    @BleDispatcher private val dispatcher: CoroutineDispatcher,
    private val permissions: BlePermissions,
    private val advertiser: ConveyanceAdvertiser,
    private val adapterWatch: AdapterWatch,
) {
    private var actor: BleActor? = null

    /** The usable link once a central connects and subscribes, else null. */
    val link: PhoneLink? get() = actor?.link

    /** The current connection state, or null when no session is active. */
    val state: StateFlow<ConnectionStateMachine.State>? get() = actor?.state

    /**
     * Open the GATT server and begin advertising. [onUnavailable] fires
     * (and the session is torn down) if permission is missing, the
     * adapter is off, or advertising fails. Returns true once the server
     * is up; an advertising failure that arrives afterwards still calls
     * [onUnavailable].
     */
    @RequiresPermission(
        allOf = [Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_ADVERTISE],
    )
    fun start(onUnavailable: (BleUnavailable) -> Unit): Boolean {
        if (actor != null) {
            onUnavailable(BleUnavailable.AlreadyActive)
            return false
        }
        if (!permissions.granted(context)) {
            onUnavailable(BleUnavailable.PermissionDenied)
            return false
        }
        val manager = context.getSystemService(BluetoothManager::class.java)
        val adapter = manager?.adapter
        if (adapter == null || !adapter.isEnabled) {
            onUnavailable(BleUnavailable.AdapterOff)
            return false
        }

        // handle is built before openGattServer() is called: the callback
        // constructed from it may start receiving binder callbacks the
        // instant openGattServer() returns, and must never find a handle
        // that hasn't been wired yet (10.3b remediation finding #7).
        // serverBox backs handle's server supplier, resolved just below;
        // a plain local var wouldn't guarantee cross-thread visibility to
        // a binder thread reading it before this method returns.
        val serverBox = ServerBox()
        val service = buildService()
        val newActor = BleActor(dispatcher, adapterWatch)
        val handle = RealGattServerHandle(
            server = { serverBox.server },
            notifyCharacteristic = service.getCharacteristic(ConveyanceGattProfile.PHONE_TO_PC_TX),
        )
        val callback = ConveyanceGattServerCallback(
            actor = newActor,
            handle = handle,
            deviceSink = { handle.device = it },
        )
        serverBox.server = runCatching { manager.openGattServer(context, callback) }.getOrNull()
        val server = serverBox.server
        if (server == null) {
            onUnavailable(BleUnavailable.AdapterOff)
            return false
        }

        val added = runCatching { server.addService(service) }.getOrDefault(false)
        if (!added) {
            server.close()
            onUnavailable(BleUnavailable.GattServiceUnavailable)
            return false
        }
        newActor.attachServer(handle)
        actor = newActor

        // advertiser.start() may call onUnavailable synchronously (adapter
        // off, permission revoked mid-call) before returning here — in
        // that case the session it just tore down via stop() must not be
        // reported as started.
        var unavailableFiredSynchronously = false
        advertiser.start(
            onStarted = {},
            onUnavailable = { reason ->
                unavailableFiredSynchronously = true
                stop()
                onUnavailable(reason)
            },
        )
        return !unavailableFiredSynchronously
    }

    /**
     * Stop advertising and tear the session down. Idempotent.
     *
     * Re-entrancy note: if this is called while a start()'s
     * advertiser.start() is still resolving, advertiser.stop() now
     * synchronously fulfills that start's outcome via the onUnavailable
     * closure above, which calls back into this method a second time,
     * from inside this call. That's deliberate and safe by construction:
     * by the time it re-enters, advertiser.stop() has already cleared
     * its own activeCallback (its early-return guard makes the nested
     * advertiser.stop() a no-op), and actor is already null on the
     * outer call's next line regardless of which invocation nulls it
     * first — so the nested call and the resuming outer call each only
     * repeat work the other already finished.
     */
    @RequiresPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
    fun stop() {
        advertiser.stop()
        actor?.shutdown()
        actor = null
    }

    private fun buildService(): BluetoothGattService {
        val service = BluetoothGattService(
            ConveyanceGattProfile.SERVICE_UUID,
            BluetoothGattService.SERVICE_TYPE_PRIMARY,
        )
        service.addCharacteristic(
            BluetoothGattCharacteristic(
                ConveyanceGattProfile.PC_TO_PHONE_TX,
                BluetoothGattCharacteristic.PROPERTY_WRITE or
                    BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                BluetoothGattCharacteristic.PERMISSION_WRITE,
            ),
        )
        val notify = BluetoothGattCharacteristic(
            ConveyanceGattProfile.PHONE_TO_PC_TX,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            0,
        )
        notify.addDescriptor(
            BluetoothGattDescriptor(
                ConveyanceGattProfile.CCCD,
                BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE,
            ),
        )
        service.addCharacteristic(notify)
        return service
    }

    /** A cross-thread-visible box for the [BluetoothGattServer] handle wiring; see [start]. */
    private class ServerBox {
        @Volatile var server: BluetoothGattServer? = null
    }
}
