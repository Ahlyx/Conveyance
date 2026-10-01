package com.ahlyxlabs.conveyance.storage.credentials

import androidx.room.Entity
import androidx.room.PrimaryKey
import androidx.room.ColumnInfo

/**
 * One stored credential. The secret is sealed in Rust under a per-service
 * DEK. Version 1 DEKs are legacy Keystore-wrapped; version 2 DEKs are
 * ChaCha20-Poly1305-wrapped under the in-memory vault key.
 */
@Entity(tableName = "credentials")
data class CredentialEntity(
    @PrimaryKey val service: String,
    /** Rust `seal_credential` blob: version || nonce || ChaCha20-Poly1305(dek, secret). */
    val secretCiphertext: ByteArray,
    /** Versioned per-service DEK envelope. */
    val wrappedDek: ByteArray,
    /** Unix seconds. */
    val createdAt: Long,
    @ColumnInfo(defaultValue = "1")
    val dekWrapVersion: Int = LEGACY_DEK_WRAP_VERSION,
    val pendingWrappedDek: ByteArray? = null,
    val pendingMigrationId: String? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CredentialEntity) return false
        return service == other.service &&
            secretCiphertext.contentEquals(other.secretCiphertext) &&
            wrappedDek.contentEquals(other.wrappedDek) &&
            createdAt == other.createdAt &&
            dekWrapVersion == other.dekWrapVersion &&
            pendingWrappedDek.contentEqualsNullable(other.pendingWrappedDek) &&
            pendingMigrationId == other.pendingMigrationId
    }

    override fun hashCode(): Int {
        var result = service.hashCode()
        result = 31 * result + secretCiphertext.contentHashCode()
        result = 31 * result + wrappedDek.contentHashCode()
        result = 31 * result + createdAt.hashCode()
        result = 31 * result + dekWrapVersion
        result = 31 * result + (pendingWrappedDek?.contentHashCode() ?: 0)
        result = 31 * result + (pendingMigrationId?.hashCode() ?: 0)
        return result
    }

    companion object {
        const val LEGACY_DEK_WRAP_VERSION = 1
        const val VAULT_DEK_WRAP_VERSION = 2

        private fun ByteArray?.contentEqualsNullable(other: ByteArray?): Boolean =
            if (this == null) other == null else other != null && contentEquals(other)
    }
}
