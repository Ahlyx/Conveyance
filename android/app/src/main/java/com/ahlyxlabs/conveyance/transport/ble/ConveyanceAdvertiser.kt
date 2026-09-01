package com.ahlyxlabs.conveyance.transport.ble

import android.Manifest
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.content.Context
import android.os.Handler
import android.os.Looper
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
 * On a device that cannot advertise, [start] reports
 * [BleUnavailable.AdvertisingUnsupported] rather than crashing. That
 * covers three shapes: a null `bluetoothLeAdvertiser`, `startAdvertising`
 * throwing, and — the emulator case — `startAdvertising` accepting the
 * request but never calling `onStartSuccess` / `onStartFailure`, caught
 * by [START_WATCHDOG_MS].
 */
@Singleton
class ConveyanceAdvertiser @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val mainHandler = Handler(Looper.getMainLooper())
    private var activeCallback: AdvertiseCallback? = null
    private var watchdog: Runnable? = null
    private var outcomeDelivered = false

    /**
     * Begin advertising. Exactly one of [onStarted] / [onUnavailable] is
     * invoked, within [START_WATCHDOG_MS] at the latest.
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
        outcomeDelivered = false
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
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                // Keep activeCallback: stop() needs it to stopAdvertising.
                if (consume(this)) onStarted()
            }

            override fun onStartFailure(errorCode: Int) {
                if (consume(this)) {
                    activeCallback = null
                    onUnavailable(mapAdvertiseError(errorCode))
                }
            }
        }
        activeCallback = callback

        val wd = Runnable {
            if (consume(callback)) {
                stop() // clears activeCallback and tries to stopAdvertising
                onUnavailable(BleUnavailable.AdvertisingUnsupported)
            }
        }
        watchdog = wd
        mainHandler.postDelayed(wd, START_WATCHDOG_MS)

        try {
            advertiser.startAdvertising(settings, data, callback)
        } catch (_: SecurityException) {
            if (consume(callback)) {
                activeCallback = null
                onUnavailable(BleUnavailable.PermissionDenied)
            }
        } catch (_: RuntimeException) {
            // IllegalStateException / NPE from a framework in a bad state.
            if (consume(callback)) {
                activeCallback = null
                onUnavailable(BleUnavailable.AdvertisingUnsupported)
            }
        }
    }

    /** Stop advertising. No-op if not running. */
    @RequiresPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
    fun stop() {
        watchdog?.let { mainHandler.removeCallbacks(it) }
        watchdog = null
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

    /**
     * Claim the single start outcome for [callback]: true the first time,
     * false for every later contender (a late framework callback racing
     * the watchdog, or vice versa). Also cancels the watchdog.
     */
    private fun consume(callback: AdvertiseCallback): Boolean {
        if (activeCallback !== callback || outcomeDelivered) return false
        outcomeDelivered = true
        watchdog?.let { mainHandler.removeCallbacks(it) }
        watchdog = null
        return true
    }

    companion object {
        /**
         * If neither `onStartSuccess` nor `onStartFailure` arrives in
         * this window, the radio silently cannot advertise (seen on
         * emulators). 3 s: a real advertiser reports within tens of ms.
         */
        const val START_WATCHDOG_MS = 3_000L

        /** Pure: an `AdvertiseCallback` error code → our reason. Unit-tested. */
        internal fun mapAdvertiseError(errorCode: Int): BleUnavailable = when (errorCode) {
            AdvertiseCallback.ADVERTISE_FAILED_ALREADY_STARTED -> BleUnavailable.AlreadyActive
            // FEATURE_UNSUPPORTED, DATA_TOO_LARGE, TOO_MANY_ADVERTISERS,
            // INTERNAL_ERROR — all mean "cannot advertise right now".
            else -> BleUnavailable.AdvertisingUnsupported
        }
    }
}
