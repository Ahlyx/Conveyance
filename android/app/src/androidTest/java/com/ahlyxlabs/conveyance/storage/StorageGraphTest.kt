package com.ahlyxlabs.conveyance.storage

import com.ahlyxlabs.conveyance.storage.credentials.CredentialStore
import com.ahlyxlabs.conveyance.storage.identity.IdentityVault
import com.ahlyxlabs.conveyance.storage.log.ApprovalLog
import com.ahlyxlabs.conveyance.storage.pairings.PairingStore
import dagger.hilt.android.testing.HiltAndroidRule
import dagger.hilt.android.testing.HiltAndroidTest
import javax.inject.Inject
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * The whole storage graph resolves through Hilt's real
 * `SingletonComponent`: the three SQLCipher databases (one shared
 * passphrase), the identity vault, and the credential store all
 * construct and coexist. Catches DI wiring regressions (a missing
 * `@Provides`, a cycle) that per-class compilation does not.
 */
@HiltAndroidTest
class StorageGraphTest {

    @get:Rule
    val hilt = HiltAndroidRule(this)

    @Inject
    lateinit var identityVault: IdentityVault

    @Inject
    lateinit var credentialStore: CredentialStore

    @Inject
    lateinit var approvalLog: ApprovalLog

    @Inject
    lateinit var pairingStore: PairingStore

    @Before
    fun inject() = hilt.inject()

    @Test
    fun everyStorageComponentIsInjectableAndTheOperationalDbsOpen() = runBlocking {
        assertNotNull(identityVault)
        assertNotNull(credentialStore)

        // Each opens its SQLCipher database through the shared, real
        // conveyance_db-wrapped passphrase (db-key only, no Tier 1 auth).
        assertTrue(approvalLog.count() >= 0)
        assertNotNull(pairingStore.all())
        assertNotNull(credentialStore.listServices())
    }
}
