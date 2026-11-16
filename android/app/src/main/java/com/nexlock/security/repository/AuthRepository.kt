package com.nexlock.security.repository

import java.util.Base64
import com.nexlock.security.auth.AuthMethod
import com.nexlock.security.auth.AuthenticationResult
import com.nexlock.security.auth.PinManager
import com.nexlock.security.auth.PinValidationResult
import com.nexlock.security.auth.SessionManager
import com.nexlock.security.security.DecryptedEnvelopeResult
import com.nexlock.security.security.EncryptedEnvelopeResult
import com.nexlock.security.security.KeyManagerContract

/**
 * Coordinates PIN creation, confirmation, verification, temporary brute-force lockout,
 * AndroidKeyStore envelope protection, and SessionManager state transitions.
 *
 * Security Invariants:
 * 1. Never stores or logs raw PINs.
 * 2. Derives a 256-bit verifier using PBKDF2-HMAC-SHA256 + 16-byte random salt, then encrypts
 *    the verifier bytes with the AndroidKeyStore AES-256-GCM master key before saving to DataStore.
 * 3. Applies temporary cooldown lockouts (30s, 60s, 300s) after reaching maxFailedAttempts,
 *    never permanently locking the user out of their own application.
 */
class AuthRepository(
    private val pinManager: PinManager,
    private val keyManager: KeyManagerContract,
    private val settingsStore: SecuritySettingsStore,
    private val sessionManager: SessionManager,
    private val epochClockMillis: () -> Long = { System.currentTimeMillis() }
) {

    fun validateCandidatePin(pin: String, expectedLength: Int? = null): PinValidationResult =
        pinManager.validatePinStrength(pin, expectedLength)

    suspend fun createOrUpdateMasterPin(
        newPin: String,
        confirmPin: String
    ): Result<Unit> {
        if (newPin != confirmPin) {
            return Result.failure(IllegalArgumentException("Confirmation PIN does not match the created PIN."))
        }

        val validation = pinManager.validatePinStrength(newPin)
        if (validation !is PinValidationResult.Valid) {
            val msg = when (validation) {
                is PinValidationResult.WeakPattern -> validation.reason
                is PinValidationResult.InvalidFormat -> validation.reason
                else -> "Invalid PIN"
            }
            return Result.failure(IllegalArgumentException(msg))
        }

        val record = pinManager.createPinRecord(newPin)
        val encrypted = keyManager.encryptPayload(record.verifierBytes)
        return when (encrypted) {
            is EncryptedEnvelopeResult.Success -> {
                val saltB64 = Base64.getEncoder().encodeToString(record.saltBytes)
                settingsStore.saveEncryptedPinVerifier(
                    saltBase64 = saltB64,
                    ivBase64 = encrypted.ivBase64,
                    ciphertextBase64 = encrypted.ciphertextBase64,
                    iterations = record.iterations,
                    pinLength = record.pinLength
                )
                sessionManager.startAuthenticatedSession(AuthMethod.MASTER_PIN)
                Result.success(Unit)
            }
            is EncryptedEnvelopeResult.KeyInvalidated -> {
                // Recover invalidated Keystore entry and retry once
                val recovered = keyManager.rotateOrRecoverMasterKey()
                if (!recovered) {
                    return Result.failure(IllegalStateException(encrypted.message))
                }
                val retry = keyManager.encryptPayload(record.verifierBytes)
                if (retry is EncryptedEnvelopeResult.Success) {
                    val saltB64 = Base64.getEncoder().encodeToString(record.saltBytes)
                    settingsStore.saveEncryptedPinVerifier(
                        saltBase64 = saltB64,
                        ivBase64 = retry.ivBase64,
                        ciphertextBase64 = retry.ciphertextBase64,
                        iterations = record.iterations,
                        pinLength = record.pinLength
                    )
                    sessionManager.startAuthenticatedSession(AuthMethod.MASTER_PIN)
                    Result.success(Unit)
                } else {
                    Result.failure(IllegalStateException("Unable to encrypt PIN verifier after Keystore recovery."))
                }
            }
            is EncryptedEnvelopeResult.Failure -> {
                Result.failure(IllegalStateException(encrypted.message))
            }
        }
    }

    suspend fun verifyMasterPin(candidatePin: String): AuthenticationResult {
        val snapshot = settingsStore.getSnapshot()
        if (!snapshot.isPinConfigured ||
            snapshot.pinSaltBase64 == null ||
            snapshot.encryptedVerifierIvBase64 == null ||
            snapshot.encryptedVerifierCiphertextBase64 == null
        ) {
            return AuthenticationResult.Error("Master PIN has not been configured yet.")
        }

        val nowEpoch = epochClockMillis()
        if (snapshot.lockoutUntilEpochMillis > nowEpoch) {
            val remainingSec = ((snapshot.lockoutUntilEpochMillis - nowEpoch) + 999L) / 1000L
            return AuthenticationResult.LockedOut(
                remainingLockoutSeconds = remainingSec,
                failedAttempts = snapshot.failedAttempts,
                message = "Too many incorrect attempts. Try again in ${remainingSec}s."
            )
        }

        val decrypted = keyManager.decryptPayload(
            ivBase64 = snapshot.encryptedVerifierIvBase64,
            ciphertextBase64 = snapshot.encryptedVerifierCiphertextBase64
        )

        val storedVerifierBytes = when (decrypted) {
            is DecryptedEnvelopeResult.Success -> decrypted.plaintext
            is DecryptedEnvelopeResult.KeyInvalidated -> {
                return AuthenticationResult.KeyInvalidated(decrypted.message)
            }
            is DecryptedEnvelopeResult.Failure -> {
                return AuthenticationResult.Error(decrypted.message)
            }
        }

        val saltBytes = Base64.getDecoder().decode(snapshot.pinSaltBase64)
        val isCorrect = pinManager.verifyPin(
            candidatePin = candidatePin,
            storedSalt = saltBytes,
            storedVerifier = storedVerifierBytes,
            iterations = snapshot.pbkdf2Iterations
        )

        if (isCorrect) {
            settingsStore.resetFailedAttempts()
            sessionManager.startAuthenticatedSession(AuthMethod.MASTER_PIN)
            return AuthenticationResult.Success(
                method = AuthMethod.MASTER_PIN,
                timestampElapsedMillis = nowEpoch
            )
        }

        // Increment failed attempts and calculate temporary lockout if threshold reached
        val nextFailed = snapshot.failedAttempts + 1
        val maxAllowed = snapshot.maxFailedAttempts.coerceAtLeast(3)
        if (nextFailed >= maxAllowed) {
            // Tiered temporary cooldown (30s -> 60s -> 300s cap), never permanent lockout
            val tier = (nextFailed - maxAllowed)
            val cooldownMillis = when {
                tier <= 0 -> 30_000L
                tier == 1 -> 60_000L
                else -> 300_000L
            }
            val lockoutUntil = nowEpoch + cooldownMillis
            settingsStore.recordFailedAttempt(nextFailed, lockoutUntil)
            val remainingSec = cooldownMillis / 1000L
            return AuthenticationResult.LockedOut(
                remainingLockoutSeconds = remainingSec,
                failedAttempts = nextFailed,
                message = "Maximum failed attempts ($maxAllowed) reached. Temporarily locked for ${remainingSec}s."
            )
        } else {
            settingsStore.recordFailedAttempt(nextFailed, 0L)
            val remainingAttempts = maxAllowed - nextFailed
            return AuthenticationResult.IncorrectPin(
                failedAttempts = nextFailed,
                remainingBeforeLockout = remainingAttempts,
                message = "Incorrect PIN. $remainingAttempts attempt(s) remaining before temporary cooldown."
            )
        }
    }

    suspend fun changeMasterPin(
        currentPin: String,
        newPin: String,
        confirmNewPin: String
    ): Result<Unit> {
        val verifyCurrent = verifyMasterPin(currentPin)
        if (verifyCurrent !is AuthenticationResult.Success) {
            val reason = when (verifyCurrent) {
                is AuthenticationResult.IncorrectPin -> verifyCurrent.message
                is AuthenticationResult.LockedOut -> verifyCurrent.message
                is AuthenticationResult.KeyInvalidated -> verifyCurrent.recoveryMessage
                else -> "Current Master PIN verification failed."
            }
            return Result.failure(IllegalArgumentException(reason))
        }
        return createOrUpdateMasterPin(newPin, confirmNewPin)
    }

    suspend fun onBiometricPromptResult(result: AuthenticationResult): AuthenticationResult {
        if (result is AuthenticationResult.Success) {
            settingsStore.resetFailedAttempts()
            sessionManager.startAuthenticatedSession(AuthMethod.BIOMETRIC_PROMPT)
        }
        return result
    }
}
