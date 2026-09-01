package com.ahlyxlabs.conveyance.transport.ble

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat
import javax.inject.Inject
import javax.inject.Singleton

/**
 * The runtime BLE permissions the peripheral role needs, across the
 * minSdk-30 / API-31 split.
 *
 * The phone ADVERTISES and runs a GATT SERVER; it never scans. So:
 *  - API <= 30: `BLUETOOTH` + `BLUETOOTH_ADMIN` are install-time
 *    (declared in the manifest with `maxSdkVersion="30"`). Nothing to
 *    request at runtime — [requiredFor] returns empty.
 *  - API >= 31: `BLUETOOTH_ADVERTISE` (advertising) and `BLUETOOTH_CONNECT`
 *    (`openGattServer`, `notifyCharacteristicChanged`, reading the peer
 *    device) became runtime. `BLUETOOTH_SCAN` is NOT needed. No location
 *    permission, on any API level.
 *
 * Requested at the point the user first starts a session, not at launch.
 * Denied → [BleUnavailable.PermissionDenied]; the caller re-offers from
 * the session screen.
 */
@Singleton
class BlePermissions @Inject constructor() {

    /** Permissions for a `RequestMultiplePermissions` launcher. Empty on API <= 30. */
    val required: Array<String> = requiredFor(Build.VERSION.SDK_INT).toTypedArray()

    /** True once every entry in [required] is granted (always true on API <= 30). */
    fun granted(context: Context): Boolean = required.all {
        ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
    }

    companion object {
        /** Pure split logic, unit-tested without an Android runtime. */
        internal fun requiredFor(sdkInt: Int): List<String> =
            if (sdkInt >= Build.VERSION_CODES.S) {
                listOf(Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT)
            } else {
                emptyList()
            }
    }
}
