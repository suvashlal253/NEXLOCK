package com.nexlock.security.repository

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.nexlock.security.auth.SessionTimeoutOption
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

private val Context.securityDataStore by preferencesDataStore(name = "nexlock_security_auth_store")

data class StoredSecuritySettings(
    val isPinConfigured: Boolean = false,
    val pinSaltBase64: String? = null,
    val encryptedVerifierIvBase64: String? = null,
    val encryptedVerifierCiphertextBase64: String? = null,
    val pbkdf2Iterations: Int = 210_000,
    val pinLength: Int = 6,
    val failedAttempts: Int = 0,
    val maxFailedAttempts: Int = 5,
    val lockoutUntilEpochMillis: Long = 0L,
    val biometricEnabled: Boolean = false,
    val sessionTimeoutOption: SessionTimeoutOption = SessionTimeoutOption.MINUTE_1
)

interface SecuritySettingsStore {
    val settingsFlow: Flow<StoredSecuritySettings>
    suspend fun getSnapshot(): StoredSecuritySettings
    suspend fun saveEncryptedPinVerifier(
        saltBase64: String,
        ivBase64: String,
        ciphertextBase64: String,
        iterations: Int,
        pinLength: Int
    )
    suspend fun recordFailedAttempt(newCount: Int, lockoutUntilEpochMillis: Long)
    suspend fun resetFailedAttempts()
    suspend fun setMaxFailedAttempts(maxAttempts: Int)
    suspend fun setBiometricEnabled(enabled: Boolean)
    suspend fun setSessionTimeout(option: SessionTimeoutOption)
}

class SecuritySettingsRepository(
    private val context: Context
) : SecuritySettingsStore {

    companion object {
        private val KEY_PIN_CONFIGURED = booleanPreferencesKey("pin_configured")
        private val KEY_PIN_SALT_B64 = stringPreferencesKey("pin_salt_b64")
        private val KEY_VERIFIER_IV_B64 = stringPreferencesKey("verifier_iv_b64")
        private val KEY_VERIFIER_CIPHERTEXT_B64 = stringPreferencesKey("verifier_ciphertext_b64")
        private val KEY_PBKDF2_ITERATIONS = intPreferencesKey("pbkdf2_iterations")
        private val KEY_PIN_LENGTH = intPreferencesKey("pin_length")
        private val KEY_FAILED_ATTEMPTS = intPreferencesKey("failed_attempts")
        private val KEY_MAX_FAILED_ATTEMPTS = intPreferencesKey("max_failed_attempts")
        private val KEY_LOCKOUT_UNTIL_EPOCH = longPreferencesKey("lockout_until_epoch")
        private val KEY_BIOMETRIC_ENABLED = booleanPreferencesKey("biometric_enabled")
        private val KEY_SESSION_TIMEOUT = stringPreferencesKey("session_timeout_option")
    }

    override val settingsFlow: Flow<StoredSecuritySettings> = context.securityDataStore.data.map { prefs ->
        StoredSecuritySettings(
            isPinConfigured = prefs[KEY_PIN_CONFIGURED] ?: false,
            pinSaltBase64 = prefs[KEY_PIN_SALT_B64],
            encryptedVerifierIvBase64 = prefs[KEY_VERIFIER_IV_B64],
            encryptedVerifierCiphertextBase64 = prefs[KEY_VERIFIER_CIPHERTEXT_B64],
            pbkdf2Iterations = prefs[KEY_PBKDF2_ITERATIONS] ?: 210_000,
            pinLength = prefs[KEY_PIN_LENGTH] ?: 6,
            failedAttempts = prefs[KEY_FAILED_ATTEMPTS] ?: 0,
            maxFailedAttempts = prefs[KEY_MAX_FAILED_ATTEMPTS] ?: 5,
            lockoutUntilEpochMillis = prefs[KEY_LOCKOUT_UNTIL_EPOCH] ?: 0L,
            biometricEnabled = prefs[KEY_BIOMETRIC_ENABLED] ?: false,
            sessionTimeoutOption = SessionTimeoutOption.fromId(prefs[KEY_SESSION_TIMEOUT])
        )
    }

    override suspend fun getSnapshot(): StoredSecuritySettings = settingsFlow.first()

    override suspend fun saveEncryptedPinVerifier(
        saltBase64: String,
        ivBase64: String,
        ciphertextBase64: String,
        iterations: Int,
        pinLength: Int
    ) {
        context.securityDataStore.edit { prefs ->
            prefs[KEY_PIN_CONFIGURED] = true
            prefs[KEY_PIN_SALT_B64] = saltBase64
            prefs[KEY_VERIFIER_IV_B64] = ivBase64
            prefs[KEY_VERIFIER_CIPHERTEXT_B64] = ciphertextBase64
            prefs[KEY_PBKDF2_ITERATIONS] = iterations
            prefs[KEY_PIN_LENGTH] = pinLength
            prefs[KEY_FAILED_ATTEMPTS] = 0
            prefs[KEY_LOCKOUT_UNTIL_EPOCH] = 0L
        }
    }

    override suspend fun recordFailedAttempt(newCount: Int, lockoutUntilEpochMillis: Long) {
        context.securityDataStore.edit { prefs ->
            prefs[KEY_FAILED_ATTEMPTS] = newCount
            prefs[KEY_LOCKOUT_UNTIL_EPOCH] = lockoutUntilEpochMillis
        }
    }

    override suspend fun resetFailedAttempts() {
        context.securityDataStore.edit { prefs ->
            prefs[KEY_FAILED_ATTEMPTS] = 0
            prefs[KEY_LOCKOUT_UNTIL_EPOCH] = 0L
        }
    }

    override suspend fun setMaxFailedAttempts(maxAttempts: Int) {
        context.securityDataStore.edit { prefs ->
            prefs[KEY_MAX_FAILED_ATTEMPTS] = maxAttempts.coerceIn(3, 10)
        }
    }

    override suspend fun setBiometricEnabled(enabled: Boolean) {
        context.securityDataStore.edit { prefs ->
            prefs[KEY_BIOMETRIC_ENABLED] = enabled
        }
    }

    override suspend fun setSessionTimeout(option: SessionTimeoutOption) {
        context.securityDataStore.edit { prefs ->
            prefs[KEY_SESSION_TIMEOUT] = option.id
        }
    }
}
