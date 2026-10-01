package com.ahlyxlabs.conveyance

import android.content.pm.PackageManager
import android.annotation.SuppressLint
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.ahlyxlabs.conveyance.crypto.ConveyanceCrypto
import com.ahlyxlabs.conveyance.crypto.RecoveryPhrase
import com.ahlyxlabs.conveyance.pairing.PairingCoordinator
import com.ahlyxlabs.conveyance.pairing.PairingProtocolException
import com.ahlyxlabs.conveyance.storage.identity.IdentityVault
import com.ahlyxlabs.conveyance.storage.keystore.BiometricAuthException
import com.ahlyxlabs.conveyance.storage.keystore.BiometricGate
import com.ahlyxlabs.conveyance.storage.pairings.PairingEntity
import com.ahlyxlabs.conveyance.storage.pairings.PairingStore
import com.ahlyxlabs.conveyance.transport.ble.BlePermissions
import com.ahlyxlabs.conveyance.ui.theme.ConveyanceTheme
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

@AndroidEntryPoint
class MainActivity : FragmentActivity() {
    @Inject lateinit var crypto: ConveyanceCrypto
    @Inject lateinit var identityVault: IdentityVault
    @Inject lateinit var biometricGate: BiometricGate
    @Inject lateinit var pairingStore: PairingStore
    @Inject lateinit var pairingCoordinator: PairingCoordinator
    @Inject lateinit var blePermissions: BlePermissions

    private var screen by mutableStateOf<AppScreen>(AppScreen.Loading)
    private val savedPairings = mutableStateListOf<PairingEntity>()
    private var recoveryPhrase: RecoveryPhrase? = null
    private var pendingQr: String? = null

    private val blePermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { results ->
        val granted = blePermissions.required.all { permission ->
            results[permission] == true ||
                ContextCompat.checkSelfPermission(this, permission) == PackageManager.PERMISSION_GRANTED
        }
        if (granted) {
            pairWithPendingQr()
        } else {
            pendingQr = null
            screen = AppScreen.Failed("Bluetooth access is required to pair with a PC.")
        }
    }

    private val qrScannerLauncher = registerForActivityResult(ScanContract()) { result ->
        val content = result.contents
        if (content.isNullOrBlank()) {
            screen = AppScreen.Home
            return@registerForActivityResult
        }
        pendingQr = content
        val missing = blePermissions.required.filter { permission ->
            ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isEmpty()) pairWithPendingQr() else blePermissionLauncher.launch(missing.toTypedArray())
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen()
        super.onCreate(savedInstanceState)
        // The identity recovery phrase is shown only during first-run setup.
        // Disable capture for the app window before any Compose content draws.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()

        lifecycleScope.launch {
            refreshPairings()
            screen = AppScreen.Home
        }

        setContent {
            ConveyanceTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { insets ->
                    Surface(modifier = Modifier.padding(insets)) {
                        when (val current = screen) {
                            AppScreen.Loading -> StatusScreen("Loading Conveyance…")
                            AppScreen.Home -> HomeScreen(
                                hasIdentity = identityVault.exists(),
                                pairings = savedPairings,
                                onSetUp = ::beginIdentitySetup,
                                onScan = ::launchQrScanner,
                            )
                            is AppScreen.Recovery -> RecoveryPhraseScreen(
                                words = current.words,
                                error = current.error,
                                onWrittenDown = ::saveRecoveryPhrase,
                            )
                            is AppScreen.Working -> StatusScreen(current.message)
                            is AppScreen.Paired -> PairedScreen(
                                pcName = current.pcName,
                                onDone = { screen = AppScreen.Home },
                            )
                            is AppScreen.Failed -> FailureScreen(
                                message = current.message,
                                onDone = { screen = AppScreen.Home },
                            )
                        }
                    }
                }
            }
        }
    }

    private fun beginIdentitySetup() {
        try {
            val phrase = crypto.generateRecoveryPhrase()
            recoveryPhrase = phrase
            screen = AppScreen.Recovery(phrase.words)
        } catch (_: Exception) {
            screen = AppScreen.Failed("Could not create a recovery phrase. Try again.")
        }
    }

    private fun saveRecoveryPhrase() {
        val phrase = recoveryPhrase ?: return
        screen = AppScreen.Working("Protecting the phone identity…")
        lifecycleScope.launch {
            try {
                identityVault.createFromPhrase(phrase, biometricGate)
                recoveryPhrase = null
                refreshPairings()
                screen = AppScreen.Home
            } catch (error: CancellationException) {
                throw error
            } catch (error: BiometricAuthException) {
                screen = AppScreen.Recovery(phrase.words, "Authentication was cancelled. You can try again.")
            } catch (_: Exception) {
                screen = AppScreen.Recovery(phrase.words, "Could not protect the identity. Try again.")
            }
        }
    }

    private fun launchQrScanner() {
        val options = ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt("Scan the pairing code shown by Conveyance on your PC")
            setBeepEnabled(false)
            setOrientationLocked(false)
        }
        try {
            qrScannerLauncher.launch(options)
        } catch (_: Exception) {
            screen = AppScreen.Failed("The QR scanner is unavailable on this device.")
        }
    }

    @SuppressLint("MissingPermission")
    private fun pairWithPendingQr() {
        val qr = pendingQr ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            (ContextCompat.checkSelfPermission(
                this,
                android.Manifest.permission.BLUETOOTH_CONNECT,
            ) != PackageManager.PERMISSION_GRANTED ||
                ContextCompat.checkSelfPermission(
                    this,
                    android.Manifest.permission.BLUETOOTH_ADVERTISE,
                ) != PackageManager.PERMISSION_GRANTED)
        ) {
            pendingQr = null
            screen = AppScreen.Failed("Bluetooth access is required to pair with a PC.")
            return
        }
        screen = AppScreen.Working("Checking the PC code…")
        lifecycleScope.launch {
            try {
                val paired = pairingCoordinator.pair(qr, biometricGate) { message ->
                    screen = AppScreen.Working(message)
                }
                pendingQr = null
                refreshPairings()
                screen = AppScreen.Paired(paired.pcName)
            } catch (error: CancellationException) {
                throw error
            } catch (error: PairingProtocolException) {
                pendingQr = null
                screen = AppScreen.Failed(error.message ?: PairingProtocolException.Kind.FAILED.message)
            } catch (error: BiometricAuthException) {
                pendingQr = null
                screen = AppScreen.Failed("Authentication was cancelled. Scan the PC code to try again.")
            } catch (_: Exception) {
                pendingQr = null
                screen = AppScreen.Failed(PairingProtocolException.Kind.FAILED.message)
            }
        }
    }

    private suspend fun refreshPairings() {
        savedPairings.clear()
        savedPairings.addAll(pairingStore.all())
    }
}

private sealed interface AppScreen {
    data object Loading : AppScreen
    data object Home : AppScreen
    data class Recovery(val words: List<String>, val error: String? = null) : AppScreen
    data class Working(val message: String) : AppScreen
    data class Paired(val pcName: String) : AppScreen
    data class Failed(val message: String) : AppScreen
}

@Composable
private fun HomeScreen(
    hasIdentity: Boolean,
    pairings: List<PairingEntity>,
    onSetUp: () -> Unit,
    onScan: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize().padding(24.dp)) {
        Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(8.dp))
        Text("Pair your phone with a PC to establish a trusted Conveyance identity.")
        Spacer(Modifier.height(24.dp))
        if (!hasIdentity) {
            Text("Set up a recovery phrase before pairing. It is shown once and cannot be recovered from the app.")
            Spacer(Modifier.height(12.dp))
            Button(onClick = onSetUp) { Text("Create phone identity") }
        } else {
            Button(onClick = onScan) { Text("Pair with PC") }
        }
        Spacer(Modifier.height(24.dp))
        Text("Paired PCs", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(8.dp))
        if (pairings.isEmpty()) {
            Text("No PCs paired yet.")
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(pairings, key = { it.pcIdPub.contentHashCode() }) { pairing ->
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(pairing.pcName, style = MaterialTheme.typography.titleMedium)
                            Text("Paired ${pairing.firstPairedAt}")
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun RecoveryPhraseScreen(
    words: List<String>,
    error: String?,
    onWrittenDown: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Write down your recovery phrase", style = MaterialTheme.typography.headlineSmall)
        Text("Keep it somewhere safe. Conveyance will not show it again.")
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            words.chunked(3).forEachIndexed { rowIndex, row ->
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    row.forEachIndexed { columnIndex, word ->
                        val index = rowIndex * 3 + columnIndex + 1
                        Text(
                            text = "$index. $word",
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                        )
                    }
                }
            }
        }
        if (error != null) Text(error, color = MaterialTheme.colorScheme.error)
        Button(onClick = onWrittenDown) { Text("I've written it down") }
    }
}

@Composable
private fun StatusScreen(message: String) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text(message, textAlign = TextAlign.Center)
    }
}

@Composable
private fun PairedScreen(pcName: String, onDone: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text("Paired with $pcName", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(16.dp))
        Button(onClick = onDone) { Text("Done") }
    }
}

@Composable
private fun FailureScreen(message: String, onDone: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text(message, color = MaterialTheme.colorScheme.error)
        Spacer(Modifier.height(16.dp))
        TextButton(onClick = onDone) { Text("Back") }
    }
}
