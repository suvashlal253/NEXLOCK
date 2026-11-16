package com.nexlock.security.auth

/**
 * Session timeout options required by NEXLOCK Phase 2.
 * Uses monotonic elapsed time via SystemClock.elapsedRealtime().
 */
enum class SessionTimeoutOption(
    val id: String,
    val label: String,
    val durationMillis: Long
) {
    IMMEDIATELY("IMMEDIATELY", "Immediately", 0L),
    SECONDS_15("SECONDS_15", "15 seconds", 15_000L),
    SECONDS_30("SECONDS_30", "30 seconds", 30_000L),
    MINUTE_1("MINUTE_1", "1 minute", 60_000L),
    MINUTES_5("MINUTES_5", "5 minutes", 300_000L);

    companion object {
        fun fromId(id: String?): SessionTimeoutOption =
            entries.find { it.id == id } ?: MINUTE_1
    }
}

/**
 * Result of validating a candidate Master PIN for strength & format.
 */
sealed class PinValidationResult {
    data object Valid : PinValidationResult()
    data class WeakPattern(val reason: String) : PinValidationResult()
    data class InvalidFormat(val reason: String) : PinValidationResult()
}

/**
 * Hardware & enrollment state reported by AndroidX BiometricManager.
 */
enum class BiometricCapabilityStatus(val description: String) {
    AVAILABLE("Biometric hardware ready and fingerprint enrolled"),
    NO_HARDWARE("No biometric sensor hardware present on this device"),
    HARDWARE_UNAVAILABLE("Biometric sensor is temporarily unavailable"),
    NONE_ENROLLED("No fingerprint/biometric credential enrolled in Android Settings"),
    SECURITY_UPDATE_REQUIRED("Security update required for biometric sensor"),
    UNKNOWN("Biometric status unknown")
}

/**
 * Outcome of an authentication attempt (PIN or BiometricPrompt).
 */
sealed class AuthenticationResult {
    data class Success(val method: AuthMethod, val timestampElapsedMillis: Long) : AuthenticationResult()
    data class IncorrectPin(
        val failedAttempts: Int,
        val remainingBeforeLockout: Int,
        val message: String
    ) : AuthenticationResult()
    data class LockedOut(
        val remainingLockoutSeconds: Long,
        val failedAttempts: Int,
        val message: String
    ) : AuthenticationResult()
    data class BiometricCanceled(val reason: String) : AuthenticationResult()
    data class BiometricFailed(val reason: String, val allowPinFallback: Boolean = true) : AuthenticationResult()
    data class BiometricLockout(val isPermanent: Boolean, val reason: String) : AuthenticationResult()
    data class KeyInvalidated(val recoveryMessage: String) : AuthenticationResult()
    data class Error(val reason: String) : AuthenticationResult()
}

enum class AuthMethod {
    MASTER_PIN,
    BIOMETRIC_PROMPT
}

/**
 * Complete UI state exposed by AuthenticationViewModel via StateFlow.
 */
data class AuthenticationState(
    val isPinConfigured: Boolean = false,
    val isAuthenticated: Boolean = false,
    val lastAuthMethod: AuthMethod? = null,
    val sessionEstablishedElapsedMillis: Long? = null,
    val sessionRemainingSeconds: Long = 0L,
    val sessionTimeoutOption: SessionTimeoutOption = SessionTimeoutOption.MINUTE_1,
    val pinLength: Int = 6,
    val failedAttempts: Int = 0,
    val maxFailedAttemptsBeforeLockout: Int = 5,
    val isTemporarilyLockedOut: Boolean = false,
    val lockoutRemainingSeconds: Long = 0L,
    val biometricEnabledInSettings: Boolean = false,
    val biometricCapability: BiometricCapabilityStatus = BiometricCapabilityStatus.AVAILABLE,
    val keystoreHealthy: Boolean = true,
    val keystoreStatusNote: String = "AndroidKeyStore AES-256-GCM Master Key Active",
    val isProcessing: Boolean = false,
    val errorMessage: String? = null,
    val successMessage: String? = null
)
