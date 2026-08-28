package com.ahlyxlabs.conveyance.storage.credentials

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * One stored credential. The secret is sealed in Rust under a per-service
 * DEK; the DEK is AES-GCM-wrapped under `conveyance_tier1`. Nothing in
 * this row is plaintext.
 */
@Entity(tableName = "credentials")
data class CredentialEntity(
    @PrimaryKey val service: String,
    /** Rust `seal_credential` blob: version || nonce || ChaCha20-Poly1305(dek, secret). */
    val secretCiphertext: ByteArray,
    /** The per-service DEK, `conveyance_tier1`-wrapped (iv || AES-GCM). */
    val wrappedDek: ByteArray,
    /** Unix seconds. */
    val createdAt: Long,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CredentialEntity) return false
        return service == other.service &&
            secretCiphertext.contentEquals(other.secretCiphertext) &&
            wrappedDek.contentEquals(other.wrappedDek) &&
            createdAt == other.createdAt
    }

    override fun hashCode(): Int {
        var result = service.hashCode()
        result = 31 * result + secretCiphertext.contentHashCode()
        result = 31 * result + wrappedDek.contentHashCode()
        result = 31 * result + createdAt.hashCode()
        return result
    }
}
