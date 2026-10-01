package com.ahlyxlabs.conveyance.storage.identity

import java.nio.charset.StandardCharsets

/** Admission rules shared by the UI and the pre-KDF boundary. */
object Tier1PassphrasePolicy {
    const val MIN_UNICODE_CHARACTERS = 12
    const val MAX_UTF8_BYTES = 256

    enum class Violation(val message: String) {
        EMPTY("Passphrase must not be empty."),
        TOO_SHORT("Passphrase must contain at least 12 Unicode characters."),
        TOO_LONG("Passphrase must be no more than 256 UTF-8 bytes."),
        INVALID_UNICODE("Passphrase contains invalid Unicode input."),
    }

    /** Returns the first admission error. Character count means Unicode scalar values. */
    fun violation(text: String): Violation? {
        var scalarCount = 0
        var utf8ByteCount = 0
        var index = 0
        while (index < text.length) {
            val first = text[index]
            val codePoint: Int
            when {
                Character.isHighSurrogate(first) -> {
                    if (index + 1 >= text.length || !Character.isLowSurrogate(text[index + 1])) {
                        return Violation.INVALID_UNICODE
                    }
                    codePoint = Character.toCodePoint(first, text[index + 1])
                    index += 2
                }
                Character.isLowSurrogate(first) -> return Violation.INVALID_UNICODE
                else -> {
                    codePoint = first.code
                    index++
                }
            }
            scalarCount++
            utf8ByteCount += when {
                codePoint <= 0x7f -> 1
                codePoint <= 0x7ff -> 2
                codePoint <= 0xffff -> 3
                else -> 4
            }
            // Bound work and reject before allocating UTF-8 bytes or invoking Argon2id.
            if (utf8ByteCount > MAX_UTF8_BYTES) return Violation.TOO_LONG
        }

        return when {
            scalarCount == 0 -> Violation.EMPTY
            scalarCount < MIN_UNICODE_CHARACTERS -> Violation.TOO_SHORT
            else -> null
        }
    }

    /** Encodes valid input exactly as entered; no trimming or normalization is performed. */
    fun encode(text: String): ByteArray {
        violation(text)?.let { throw IllegalArgumentException(it.message) }
        return text.toByteArray(StandardCharsets.UTF_8)
    }

    /** Rejects malformed/oversized UTF-8 before any expensive key derivation. */
    fun requireValidUtf8(bytes: ByteArray) {
        require(bytes.size <= MAX_UTF8_BYTES) { Violation.TOO_LONG.message }
        var scalarCount = 0
        var index = 0
        while (index < bytes.size) {
            val first = bytes[index].toInt() and 0xff
            val length = when (first) {
                in 0x00..0x7f -> 1
                in 0xc2..0xdf -> if (isContinuation(bytes, index + 1)) 2 else 0
                0xe0 -> if (isBetween(bytes, index + 1, 0xa0, 0xbf) &&
                    isContinuation(bytes, index + 2)
                ) 3 else 0
                in 0xe1..0xec, in 0xee..0xef -> if (
                    isContinuation(bytes, index + 1) && isContinuation(bytes, index + 2)
                ) 3 else 0
                0xed -> if (isBetween(bytes, index + 1, 0x80, 0x9f) &&
                    isContinuation(bytes, index + 2)
                ) 3 else 0
                0xf0 -> if (isBetween(bytes, index + 1, 0x90, 0xbf) &&
                    isContinuation(bytes, index + 2) && isContinuation(bytes, index + 3)
                ) 4 else 0
                in 0xf1..0xf3 -> if (
                    isContinuation(bytes, index + 1) &&
                    isContinuation(bytes, index + 2) &&
                    isContinuation(bytes, index + 3)
                ) 4 else 0
                0xf4 -> if (isBetween(bytes, index + 1, 0x80, 0x8f) &&
                    isContinuation(bytes, index + 2) && isContinuation(bytes, index + 3)
                ) 4 else 0
                else -> 0
            }
            if (length == 0) throw IllegalArgumentException(Violation.INVALID_UNICODE.message)
            scalarCount++
            index += length
        }
        when {
            scalarCount == 0 -> throw IllegalArgumentException(Violation.EMPTY.message)
            scalarCount < MIN_UNICODE_CHARACTERS ->
                throw IllegalArgumentException(Violation.TOO_SHORT.message)
        }
    }

    private fun isContinuation(bytes: ByteArray, index: Int): Boolean =
        index < bytes.size && ((bytes[index].toInt() and 0xff) in 0x80..0xbf)

    private fun isBetween(bytes: ByteArray, index: Int, min: Int, max: Int): Boolean =
        index < bytes.size && ((bytes[index].toInt() and 0xff) in min..max)
}
