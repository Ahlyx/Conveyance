package com.ahlyxlabs.conveyance.transport.ble

import android.Manifest
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.content.Context
import android.os.ParcelUuid
import androidx.annotation.RequiresPermission
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Advertises the Conveyance service UUID so the PC daemon's central scan
 * can find this phone.
 *
 * Advertising is only started while a session is being started or is
 * active, and stopped the instant it ends (spec "Foreground service and
 * battery"). This class is the start/stop mechanism; the *lifecycle* —
 * tying it to session state and a foreground service — is Phase 10.9.
 *
 * On a device whose radio cannot advertise (many emulators), [start]
 * reports [BleUnavailable.AdvertisingUnsupported] rather than crashing;
 * that is the path the CI emulator exercises.
 */
@Singleton
class ConveyanceAdvertiser @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private var activeCallback: AdvertiseCallback? = null

    /**
     * Begin advertising. [onStarted] fires on `onStartSuccess`;
     * [onUnavailable] fires for an off adapter, a radio that cannot
     * advertise, an already-running advertisement, a revoked permission,
     * or any start failure. Exactly one of the two is invoked.
     *
     * Callers must hold `BLUETOOTH_ADVERTISE` (API 31+) — checked via
     * [BlePermissions] at session start. A mid-session revocation still
     * surfaces here as [BleUnavailable.PermissionDenied].
     */
    @RequiresPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
    fun start(onStarted: () -> Unit, onUnavailable: (BleUnavailable) -> Unit) {
        if (activeCallback != null) {
            onUnavailable(BleUnavailable.AlreadyActive)
            return
        }
        val adapter = context.getSystemService(BluetoothManager::class.java)?.adapter
        if (adapter == null || !adapter.isEnabled) {
            onUnavailable(BleUnavailable.AdapterOff)
            return
        }
        val advertiser = adapter.bluetoothLeAdvertiser
        if (advertiser == null) {
            onUnavailable(BleUnavailable.AdvertisingUnsupported)
            return
        }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .setConnectable(true)
            .setTimeout(0) // we stop it explicitly on session end
            .build()
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false) // no identifying name in the clear
            .setIncludeTxPowerLevel(false)
            .addServiceUuid(ParcelUuid(ConveyanceGattProfile.SERVICE_UUID))
            .build()

        val callback = object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) = onStarted()

            override fun onStartFailure(errorCode: Int) {
                activeCallback = null
                onUnavailable(mapAdvertiseError(errorCode))
            }
        }
        activeCallback = callback
        try {
            advertiser.startAdvertising(settings, data, callback)
        } catch (_: SecurityException) {
            activeCallback = null
            onUnavailable(BleUnavailable.PermissionDenied)
        }
    }

    /** Stop advertising. No-op if not running. */
    @RequiresPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
    fun stop() {
        val callback = activeCallback ?: return
        activeCallback = null
        val advertiser = context.getSystemService(BluetoothManager::class.java)
            ?.adapter
            ?.bluetoothLeAdvertiser
        try {
            advertiser?.stopAdvertising(callback)
        } catch (_: SecurityException) {
            // Permission revoked mid-session; the advertisement is gone anyway.
        }
    }

    companion object {
        /** Pure: an `AdvertiseCallback` error code → our reason. Unit-tested. */
        internal fun mapAdvertiseError(errorCode: Int): BleUnavailable = when (errorCode) {
            AdvertiseCallback.ADVERTISE_FAILED_ALREADY_STARTED -> BleUnavailable.AlreadyActive
            // FEATURE_UNSUPPORTED, DATA_TOO_LARGE, TOO_MANY_ADVERTISERS,
            // INTERNAL_ERROR — all mean "cannot advertise right now".
            else -> BleUnavailable.AdvertisingUnsupported
        }
    }
}
