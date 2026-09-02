package com.ahlyxlabs.conveyance.testutil

/**
 * The hex codec shared by the instrumented fixture-parity suites
 * (crypto, Noise, …). One implementation so a change — rejecting an
 * odd-length string, say — lands everywhere at once.
 */
fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "hex string must have even length" }
    return ByteArray(length / 2) { substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xFF) }
