package com.ahlyxlabs.conveyance

import android.content.pm.PackageManager
import android.annotation.SuppressLint
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.ahlyxlabs.conveyance.approval.ApprovalSessionHost
import com.ahlyxlabs.conveyance.approval.ApprovalViewModel
import com.ahlyxlabs.conveyance.crypto.ConveyanceCrypto
import com.ahlyxlabs.conveyance.crypto.RecoveryPhrase
import com.ahlyxlabs.conveyance.pairing.PairingCoordinator
import com.ahlyxlabs.conveyance.pairing.PairingProtocolException
import com.ahlyxlabs.conveyance.storage.identity.IdentityVault
import com.ahlyxlabs.conveyance.storage.identity.Tier1AuthInput
import com.ahlyxlabs.conveyance.storage.identity.Tier1AuthMethod
import com.ahlyxlabs.conveyance.storage.identity.Tier1PassphrasePolicy
import com.ahlyxlabs.conveyance.storage.identity.UnlockedPhoneSession
import com.ahlyxlabs.conveyance.storage.keystore.BiometricAuthException
import com.ahlyxlabs.conveyance.storage.keystore.BiometricGate
import com.ahlyxlabs.conveyance.storage.pairings.PairingEntity
import com.ahlyxlabs.conveyance.storage.pairings.PairingStore
import com.ahlyxlabs.conveyance.session.PhoneSession
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

    private val approvalViewModel: ApprovalViewModel by viewModels()

    private var screen by mutableStateOf<AppScreen>(AppScreen.Loading)
    private val savedPairings = mutableStateListOf<PairingEntity>()
    private var recoveryPhrase: RecoveryPhrase? = null
    private var pendingQr: String? = null
    private var pairActionInFlight = false
    private var identityActionInFlight = false

    private val blePermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { results ->
        val granted = blePermissions.required.all { permission ->
            results[permission] == true ||
                ContextCompat.checkSelfPermission(this, permission) == PackageManager.PERMISSION_GRANTED
        }
        if (granted) {
            requestPairUnlock()
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
        if (missing.isEmpty()) requestPairUnlock() else blePermissionLauncher.launch(missing.toTypedArray())
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
                        ApprovalSessionHost(
                            viewModel = approvalViewModel,
                            biometricGate = biometricGate,
                        ) {
                        when (val current = screen) {
                            AppScreen.Loading -> StatusScreen("Loading Conveyance…")
                            AppScreen.Home -> HomeScreen(
                                hasIdentity = identityVault.exists(),
                                pairings = savedPairings,
                                onSetUp = ::beginIdentitySetup,
                                onScan = ::launchQrScanner,
                                onChangeProtection = ::beginChangeAuthMethod,
                            )
                            is AppScreen.Recovery -> RecoveryPhraseScreen(
                                words = current.words,
                                error = current.error,
                                onWrittenDown = ::saveRecoveryPhrase,
                            )
                            is AppScreen.AuthSetup -> Tier1SetupScreen(
                                biometricGate = biometricGate,
                                error = current.error,
                                onSave = ::createIdentity,
                                onCancel = {
                                    recoveryPhrase = null
                                    screen = AppScreen.Home
                                },
                            )
                            is AppScreen.Unlock -> Tier1UnlockScreen(
                                biometricGate = biometricGate,
                                method = current.method,
                                error = current.error,
                                onAuthenticate = ::pairWithPendingQr,
                                onCancel = {
                                    pendingQr = null
                                    screen = AppScreen.Home
                                },
                            )
                            is AppScreen.ChangeProtection -> Tier1ChangeScreen(
                                biometricGate = biometricGate,
                                currentMethod = current.method,
                                error = current.error,
                                onChange = ::changeAuthMethod,
                                onCancel = { screen = AppScreen.Home },
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
    }

    /** Narrow hook for the authenticated-session owner; 10.9 owns session lifecycle. */
    fun attachActiveApprovalSession(session: PhoneSession): Boolean = approvalViewModel.attach(session)

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
        if (recoveryPhrase == null) return
        screen = AppScreen.AuthSetup()
    }

    private fun createIdentity(input: Tier1AuthInput) {
        if (identityActionInFlight) {
            input.close()
            return
        }
        val phrase = recoveryPhrase ?: run {
            input.close()
            return
        }
        identityActionInFlight = true
        screen = AppScreen.Working("Protecting the phone identity…")
        lifecycleScope.launch {
            try {
                identityVault.createFromPhrase(phrase, input)
                recoveryPhrase = null
                refreshPairings()
                screen = AppScreen.Home
            } catch (error: CancellationException) {
                throw error
            } catch (error: BiometricAuthException) {
                screen = AppScreen.AuthSetup("Authentication was cancelled. You can try again.")
            } catch (_: Exception) {
                screen = AppScreen.AuthSetup("Could not protect the identity. Try again.")
            } finally {
                identityActionInFlight = false
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
    private fun requestPairUnlock() {
        if (pendingQr == null) return
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
        lifecycleScope.launch {
            screen = try {
                AppScreen.Unlock(identityVault.configuredAuthMethod())
            } catch (_: Exception) {
                pendingQr = null
                AppScreen.Failed("Could not read the phone identity. Restore it before pairing.")
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun pairWithPendingQr(input: Tier1AuthInput) {
        if (pairActionInFlight) {
            input.close()
            return
        }
        val qr = pendingQr ?: run {
            input.close()
            return
        }
        pairActionInFlight = true
        screen = AppScreen.Working("Unlocking the phone identity…")
        lifecycleScope.launch {
            var session: UnlockedPhoneSession? = null
            try {
                session = identityVault.unlock(input) { completed, total ->
                    screen = AppScreen.Working("Migrating stored credentials: $completed of $total")
                }.getOrThrow()
                val paired = pairingCoordinator.pair(qr, session) { message ->
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
                screen = AppScreen.Failed("Could not unlock or pair the phone identity. Try again.")
            } finally {
                session?.close()
                pairActionInFlight = false
            }
        }
    }

    private fun beginChangeAuthMethod() {
        lifecycleScope.launch {
            screen = try {
                AppScreen.ChangeProtection(identityVault.configuredAuthMethod())
            } catch (_: Exception) {
                AppScreen.Failed("Could not read the phone identity. Restore it before changing protection.")
            }
        }
    }

    private fun changeAuthMethod(current: Tier1AuthInput, replacement: Tier1AuthInput) {
        if (identityActionInFlight) {
            current.close()
            replacement.close()
            return
        }
        identityActionInFlight = true
        screen = AppScreen.Working("Changing identity protection…")
        lifecycleScope.launch {
            try {
                identityVault.changeAuthMethod(current, replacement) { completed, total ->
                    screen = AppScreen.Working("Migrating stored credentials: $completed of $total")
                }.getOrThrow()
                screen = AppScreen.Home
            } catch (error: CancellationException) {
                throw error
            } catch (_: Exception) {
                val method = runCatching { identityVault.configuredAuthMethod() }
                    .getOrDefault(Tier1AuthMethod.BIOMETRIC)
                screen = AppScreen.ChangeProtection(
                    method = method,
                    error = "Could not change the protection method. Check authentication and try again.",
                )
            } finally {
                identityActionInFlight = false
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
    data class AuthSetup(val error: String? = null) : AppScreen
    data class Unlock(val method: Tier1AuthMethod, val error: String? = null) : AppScreen
    data class ChangeProtection(val method: Tier1AuthMethod, val error: String? = null) : AppScreen
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
    onChangeProtection: () -> Unit,
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
            Spacer(Modifier.height(8.dp))
            TextButton(onClick = onChangeProtection) { Text("Change protection method") }
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
private fun Tier1SetupScreen(
    biometricGate: BiometricGate,
    error: String?,
    onSave: (Tier1AuthInput) -> Unit,
    onCancel: () -> Unit,
) {
    var method by remember { mutableStateOf<Tier1AuthMethod?>(null) }
    var passphrase by remember { mutableStateOf("") }
    var confirmation by remember { mutableStateOf("") }
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Choose identity protection", style = MaterialTheme.typography.headlineSmall)
        Text("This protects the random vault key used for your phone identity and credentials.")
        AuthMethodOption("Biometric", method == Tier1AuthMethod.BIOMETRIC) {
            method = Tier1AuthMethod.BIOMETRIC
        }
        AuthMethodOption("Passphrase", method == Tier1AuthMethod.PASSPHRASE) {
            method = Tier1AuthMethod.PASSPHRASE
        }
        if (method == Tier1AuthMethod.PASSPHRASE) {
            Text("Use at least 12 Unicode characters and no more than 256 UTF-8 bytes. Spaces and exact characters are preserved.")
            ExactPassphraseField("Passphrase", passphrase) { passphrase = it }
            ExactPassphraseField("Confirm passphrase", confirmation) { confirmation = it }
            Tier1PassphrasePolicy.violation(passphrase)?.let {
                Text(it.message, color = MaterialTheme.colorScheme.error)
            }
            if (passphrase != confirmation) {
                Text("The two entries must match exactly.", color = MaterialTheme.colorScheme.error)
            }
        }
        if (error != null) Text(error, color = MaterialTheme.colorScheme.error)
        Button(
            enabled = method != null &&
                (method != Tier1AuthMethod.PASSPHRASE ||
                    (Tier1PassphrasePolicy.violation(passphrase) == null && passphrase == confirmation)),
            onClick = {
                val input = when (method) {
                    Tier1AuthMethod.BIOMETRIC -> Tier1AuthInput.Biometric(
                        biometricGate,
                    )
                    Tier1AuthMethod.PASSPHRASE -> passphrase.toPassphraseInput()
                    null -> return@Button
                }
                passphrase = ""
                confirmation = ""
                onSave(input)
            },
        ) { Text("Protect identity") }
        TextButton(onClick = onCancel) { Text("Cancel setup") }
    }
}

@Composable
private fun Tier1UnlockScreen(
    biometricGate: BiometricGate,
    method: Tier1AuthMethod,
    error: String?,
    onAuthenticate: (Tier1AuthInput) -> Unit,
    onCancel: () -> Unit,
) {
    var passphrase by remember { mutableStateOf("") }
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Unlock Conveyance", style = MaterialTheme.typography.headlineSmall)
        Text("Use the identity protection method already configured on this phone.")
        if (method == Tier1AuthMethod.PASSPHRASE) {
            ExactPassphraseField("Passphrase", passphrase) { passphrase = it }
            Tier1PassphrasePolicy.violation(passphrase)?.let {
                Text(it.message, color = MaterialTheme.colorScheme.error)
            }
        }
        if (error != null) Text(error, color = MaterialTheme.colorScheme.error)
        Button(
            enabled = method != Tier1AuthMethod.PASSPHRASE ||
                Tier1PassphrasePolicy.violation(passphrase) == null,
            onClick = {
                val input = when (method) {
                    Tier1AuthMethod.BIOMETRIC -> Tier1AuthInput.Biometric(biometricGate)
                    Tier1AuthMethod.PASSPHRASE -> passphrase.toPassphraseInput()
                }
                passphrase = ""
                onAuthenticate(input)
            },
        ) { Text("Unlock and continue") }
        TextButton(onClick = onCancel) { Text("Cancel") }
    }
}

@Composable
private fun Tier1ChangeScreen(
    biometricGate: BiometricGate,
    currentMethod: Tier1AuthMethod,
    error: String?,
    onChange: (Tier1AuthInput, Tier1AuthInput) -> Unit,
    onCancel: () -> Unit,
) {
    var replacementMethod by remember(currentMethod) { mutableStateOf<Tier1AuthMethod?>(null) }
    var currentPassphrase by remember { mutableStateOf("") }
    var replacementPassphrase by remember { mutableStateOf("") }
    var confirmation by remember { mutableStateOf("") }
    val passphraseMatches = replacementPassphrase == confirmation
    val currentPassphraseViolation = if (currentMethod == Tier1AuthMethod.PASSPHRASE) {
        Tier1PassphrasePolicy.violation(currentPassphrase)
    } else {
        null
    }
    val replacementPassphraseViolation = if (replacementMethod == Tier1AuthMethod.PASSPHRASE) {
        Tier1PassphrasePolicy.violation(replacementPassphrase)
    } else {
        null
    }
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Change protection method", style = MaterialTheme.typography.headlineSmall)
        Text("Re-enter the current method before applying a protection change.")
        if (currentMethod == Tier1AuthMethod.PASSPHRASE) {
            ExactPassphraseField("Current passphrase", currentPassphrase) { currentPassphrase = it }
            currentPassphraseViolation?.let {
                Text(it.message, color = MaterialTheme.colorScheme.error)
            }
        }
        Text("New method", style = MaterialTheme.typography.titleMedium)
        AuthMethodOption("Biometric", replacementMethod == Tier1AuthMethod.BIOMETRIC) {
            replacementMethod = Tier1AuthMethod.BIOMETRIC
        }
        AuthMethodOption("Passphrase", replacementMethod == Tier1AuthMethod.PASSPHRASE) {
            replacementMethod = Tier1AuthMethod.PASSPHRASE
        }
        if (replacementMethod == Tier1AuthMethod.PASSPHRASE) {
            Text("Use at least 12 Unicode characters and no more than 256 UTF-8 bytes. Spaces and exact characters are preserved.")
            ExactPassphraseField("New passphrase", replacementPassphrase) { replacementPassphrase = it }
            ExactPassphraseField("Confirm new passphrase", confirmation) { confirmation = it }
            replacementPassphraseViolation?.let {
                Text(it.message, color = MaterialTheme.colorScheme.error)
            }
            if (!passphraseMatches) {
                Text("The two entries must match exactly.", color = MaterialTheme.colorScheme.error)
            }
        }
        if (error != null) Text(error, color = MaterialTheme.colorScheme.error)
        Button(
            enabled = replacementMethod != null &&
                currentPassphraseViolation == null &&
                (replacementMethod != Tier1AuthMethod.PASSPHRASE ||
                    (replacementPassphraseViolation == null && passphraseMatches)),
            onClick = {
                val current = when (currentMethod) {
                    Tier1AuthMethod.BIOMETRIC -> Tier1AuthInput.Biometric(biometricGate)
                    Tier1AuthMethod.PASSPHRASE -> currentPassphrase.toPassphraseInput()
                }
                val replacement = when (replacementMethod) {
                    Tier1AuthMethod.BIOMETRIC -> Tier1AuthInput.Biometric(biometricGate)
                    Tier1AuthMethod.PASSPHRASE -> replacementPassphrase.toPassphraseInput()
                    null -> return@Button
                }
                currentPassphrase = ""
                replacementPassphrase = ""
                confirmation = ""
                onChange(current, replacement)
            },
        ) { Text("Re-authenticate and change") }
        TextButton(onClick = onCancel) { Text("Cancel") }
    }
}

@Composable
private fun AuthMethodOption(label: String, selected: Boolean, onClick: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Text(label, modifier = Modifier.padding(top = 12.dp))
    }
}

@Composable
private fun ExactPassphraseField(label: String, value: String, onValueChange: (String) -> Unit) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        modifier = Modifier.fillMaxWidth(),
        label = { Text(label) },
        // Preserve the exact entered text, including line breaks and whitespace.
        singleLine = false,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
    )
}

private fun String.toPassphraseInput(): Tier1AuthInput.Passphrase {
    val utf8 = Tier1PassphrasePolicy.encode(this)
    return try {
        Tier1AuthInput.Passphrase(utf8)
    } finally {
        utf8.fill(0)
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
