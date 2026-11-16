package com.nexlock.security.auth

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Dedicated Master PIN Validation & Salted Password Derivation Manager.
 *
 * Security Properties:
 * 1. Supports 4-digit or 6-digit numeric PINs.
 * 2. Rejects weak/predictable patterns (e.g. 0000, 1111, 1234, 4321, 123456, 654321, 1212, 1122, 2580).
 * 3. Uses PBKDF2WithHmacSHA256 (210,000 iterations, 128-bit CSPRNG salt, 256-bit output).
 * 4. Performs constant-time byte array verification via MessageDigest.isEqual().
 * 5. Zeroes temporary CharArrays after derivation and never logs PIN values.
 */
data class DerivedPinRecord(
    val saltBytes: ByteArray,
    val verifierBytes: ByteArray,
    val iterations: Int,
    val pinLength: Int
)

class PinManager(
    private val secureRandom: SecureRandom = SecureRandom()
) {
    companion object {
        const val PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256"
        const val DEFAULT_ITERATIONS = 210_000
        const val SALT_LENGTH_BYTES = 16
        const val KEY_LENGTH_BITS = 256

        private val EXPLICIT_WEAK_PINS = setOf(
            "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999",
            "1234", "4321", "2345", "5432", "3456", "6543", "4567", "7654", "5678", "8765", "6789", "9876", "0123", "3210",
            "1212", "2121", "1122", "2211", "1010", "0101", "2580", "0852", "1379",
            "000000", "111111", "222222", "333333", "444444", "555555", "666666", "777777", "888888", "999999",
            "123456", "654321", "012345", "543210", "234567", "765432", "121212", "112233", "123123", "000111"
        )
    }

    /**
     * Validates that a PIN is strictly 4 or 6 numeric digits and is not a weak or predictable sequence.
     */
    fun validatePinStrength(pin: String, expectedLength: Int? = null): PinValidationResult {
        if (pin.isEmpty() || !pin.all { it.isDigit() }) {
            return PinValidationResult.InvalidFormat("PIN must contain numeric digits (0–9) only.")
        }

        if (expectedLength != null && pin.length != expectedLength) {
            return PinValidationResult.InvalidFormat("PIN must be exactly $expectedLength digits.")
        }

        if (pin.length != 4 && pin.length != 6) {
            return PinValidationResult.InvalidFormat("PIN must be either 4 or 6 digits.")
        }

        if (pin in EXPLICIT_WEAK_PINS) {
            return PinValidationResult.WeakPattern(
                "This PIN is a commonly guessed sequence. Choose a less predictable combination."
            )
        }

        // Check all identical digits
        if (pin.toSet().size == 1) {
            return PinValidationResult.WeakPattern(
                "Repeating a single digit (such as ${pin[0]}${pin[0]}...) is not permitted."
            )
        }

        // Check strictly ascending or descending arithmetic progression (step +1 or -1)
        val diffs = pin.zipWithNext { a, b -> b.digitToInt() - a.digitToInt() }
        if (diffs.all { it == 1 } || diffs.all { it == -1 }) {
            return PinValidationResult.WeakPattern(
                "Sequential ascending or descending digits (such as 1234 or 9876) are too easy to guess."
            )
        }

        // Check ABAB or ABCABC repeating half-patterns
        val half = pin.length / 2
        if (pin.substring(0, half) == pin.substring(half)) {
            return PinValidationResult.WeakPattern(
                "Repeated pattern halves (such as ${pin.substring(0, half)} repeated) are rejected for security."
            )
        }

        // Check AABB or AABBCC adjacent pairs
        val pairsIdentical = pin.chunked(2).all { it.length == 2 && it[0] == it[1] }
        if (pairsIdentical) {
            return PinValidationResult.WeakPattern(
                "Paired digit repetitions (such as 1122) are too predictable."
            )
        }

        return PinValidationResult.Valid
    }

    /**
     * Generates a fresh 128-bit cryptographic salt and derives a 256-bit PBKDF2-HMAC-SHA256 verifier.
     */
    fun createPinRecord(
        rawPin: String,
        iterations: Int = DEFAULT_ITERATIONS
    ): DerivedPinRecord {
        val validation = validatePinStrength(rawPin)
        require(validation is PinValidationResult.Valid) {
            when (validation) {
                is PinValidationResult.WeakPattern -> validation.reason
                is PinValidationResult.InvalidFormat -> validation.reason
                else -> "Invalid PIN"
            }
        }

        val salt = ByteArray(SALT_LENGTH_BYTES)
        secureRandom.nextBytes(salt)
        val verifier = deriveKey(rawPin, salt, iterations)

        return DerivedPinRecord(
            saltBytes = salt,
            verifierBytes = verifier,
            iterations = iterations,
            pinLength = rawPin.length
        )
    }

    /**
     * Constant-time verification of a candidate PIN against a stored salt + verifier.
     */
    fun verifyPin(
        candidatePin: String,
        storedSalt: ByteArray,
        storedVerifier: ByteArray,
        iterations: Int = DEFAULT_ITERATIONS
    ): Boolean {
        if (candidatePin.length != 4 && candidatePin.length != 6) return false
        if (!candidatePin.all { it.isDigit() }) return false

        val candidateVerifier = deriveKey(candidatePin, storedSalt, iterations)
        val matches = MessageDigest.isEqual(candidateVerifier, storedVerifier)
        candidateVerifier.fill(0)
        return matches
    }

    private fun deriveKey(pin: String, salt: ByteArray, iterations: Int): ByteArray {
        val chars = pin.toCharArray()
        return try {
            val spec = PBEKeySpec(chars, salt, iterations, KEY_LENGTH_BITS)
            val factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
            factory.generateSecret(spec).encoded
        } finally {
            chars.fill('\u0000')
        }
    }
}
