package com.ahlyxlabs.conveyance.pairing

import android.Manifest
import androidx.annotation.RequiresPermission
import com.ahlyxlabs.conveyance.transport.ConnectionStateMachine
import com.ahlyxlabs.conveyance.transport.ble.BlePeripheral
import com.ahlyxlabs.conveyance.transport.link.PhoneLink
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Inject
import javax.inject.Singleton
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout

/** BLE boundary kept replaceable so the pairing driver can be tested without a radio. */
interface PairingRadio {
    suspend fun connect(timeoutMillis: Long): PhoneLink

    @RequiresPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
    fun stop()
}

@Singleton
class BlePairingRadio @Inject constructor(
    private val peripheral: BlePeripheral,
) : PairingRadio {
    @RequiresPermission(
        allOf = [Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_ADVERTISE],
    )
    override suspend fun connect(timeoutMillis: Long): PhoneLink {
        if (timeoutMillis <= 0) throw PairingProtocolException(PairingProtocolException.Kind.EXPIRED)

        val unavailable = AtomicReference<com.ahlyxlabs.conveyance.transport.ble.BleUnavailable?>(null)
        if (!peripheral.start { reason -> unavailable.set(reason) }) {
            throw IllegalStateException("BLE pairing unavailable: ${unavailable.get()}")
        }

        return try {
            withTimeout(timeoutMillis) { awaitLink() }
        } catch (error: Exception) {
            peripheral.stop()
            throw error
        }
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
    override fun stop() {
        peripheral.stop()
    }

    private suspend fun awaitLink(): PhoneLink {
        while (true) {
            peripheral.link?.let { return it }
            if (peripheral.state?.value == ConnectionStateMachine.State.TORN) {
                throw IllegalStateException("BLE link closed before pairing")
            }
            delay(25)
        }
    }
}

@Module
@InstallIn(SingletonComponent::class)
abstract class PairingRadioModule {
    @Binds
    @Singleton
    abstract fun bindPairingRadio(impl: BlePairingRadio): PairingRadio
}
