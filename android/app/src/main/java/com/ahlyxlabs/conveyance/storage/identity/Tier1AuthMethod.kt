package com.ahlyxlabs.conveyance.storage.identity

/** The selected method that protects the random phone vault key. */
enum class Tier1AuthMethod(val wireTag: Byte) {
    BIOMETRIC(1),
    PASSPHRASE(2),
    ;

    companion object {
        fun fromWireTag(tag: Byte): Tier1AuthMethod =
            values().firstOrNull { it.wireTag == tag }
                ?: throw IdentityCorruptException("unsupported Tier 1 auth method")
    }
}
