package com.nexlock.security.repository

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.nexlock.security.auth.SessionTimeoutOption
import com.nexlock.security.model.AccentColorPreset
import com.nexlock.security.model.AppListDensity
import com.nexlock.security.model.AppSortOrder
import com.nexlock.security.model.KeypadStyle
import com.nexlock.security.model.LockMode
import com.nexlock.security.model.LockScreenBackgroundStyle
import com.nexlock.security.model.ThemePreference
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
    val sessionTimeoutOption: SessionTimeoutOption = SessionTimeoutOption.MINUTE_1,
    // Phase 6 Lock Mode & Personalization Preferences
    val lockMode: LockMode = LockMode.NORMAL,
    val themePreference: ThemePreference = ThemePreference.DARK,
    val accentColorPreset: AccentColorPreset = AccentColorPreset.NEXLOCK_BLUE,
    val appListDensity: AppListDensity = AppListDensity.COMFORTABLE,
    val appSortOrder: AppSortOrder = AppSortOrder.NAME_ASC,
    val showAppIconOnLockScreen: Boolean = true,
    val showAppNameOnLockScreen: Boolean = true,
    val lockScreenBackgroundStyle: LockScreenBackgroundStyle = LockScreenBackgroundStyle.OBSIDIAN_GRADIENT,
    val enableLockScreenAnimations: Boolean = true,
    val keypadStyle: KeypadStyle = KeypadStyle.ROUNDED_MODERN,
    val languageCode: String = "en"
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
    // Phase 6 setters
    suspend fun setLockMode(mode: LockMode)
    suspend fun setThemePreference(theme: ThemePreference)
    suspend fun setAccentColorPreset(accent: AccentColorPreset)
    suspend fun setAppListDensity(density: AppListDensity)
    suspend fun setAppSortOrder(sortOrder: AppSortOrder)
    suspend fun setLockScreenPersonalization(
        showAppIcon: Boolean,
        showAppName: Boolean,
        backgroundStyle: LockScreenBackgroundStyle,
        enableAnimations: Boolean,
        keypadStyle: KeypadStyle
    )
    suspend fun setLanguageCode(languageCode: String)
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
        // Phase 6 keys
        private val KEY_LOCK_MODE = stringPreferencesKey("phase6_lock_mode")
        private val KEY_THEME_PREFERENCE = stringPreferencesKey("phase6_theme_pref")
        private val KEY_ACCENT_COLOR_PRESET = stringPreferencesKey("phase6_accent_preset")
        private val KEY_APP_LIST_DENSITY = stringPreferencesKey("phase6_app_list_density")
        private val KEY_APP_SORT_ORDER = stringPreferencesKey("phase6_app_sort_order")
        private val KEY_LOCK_SHOW_APP_ICON = booleanPreferencesKey("phase6_lock_show_app_icon")
        private val KEY_LOCK_SHOW_APP_NAME = booleanPreferencesKey("phase6_lock_show_app_name")
        private val KEY_LOCK_BG_STYLE = stringPreferencesKey("phase6_lock_bg_style")
        private val KEY_LOCK_ANIMATIONS = booleanPreferencesKey("phase6_lock_animations")
        private val KEY_LOCK_KEYPAD_STYLE = stringPreferencesKey("phase6_lock_keypad_style")
        private val KEY_LANGUAGE_CODE = stringPreferencesKey("phase6_language_code")
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
            sessionTimeoutOption = SessionTimeoutOption.fromId(prefs[KEY_SESSION_TIMEOUT]),
            lockMode = LockMode.fromId(prefs[KEY_LOCK_MODE]),
            themePreference = ThemePreference.fromId(prefs[KEY_THEME_PREFERENCE]),
            accentColorPreset = AccentColorPreset.fromId(prefs[KEY_ACCENT_COLOR_PRESET]),
            appListDensity = AppListDensity.fromId(prefs[KEY_APP_LIST_DENSITY]),
            appSortOrder = AppSortOrder.fromId(prefs[KEY_APP_SORT_ORDER]),
            showAppIconOnLockScreen = prefs[KEY_LOCK_SHOW_APP_ICON] ?: true,
            showAppNameOnLockScreen = prefs[KEY_LOCK_SHOW_APP_NAME] ?: true,
            lockScreenBackgroundStyle = LockScreenBackgroundStyle.fromId(prefs[KEY_LOCK_BG_STYLE]),
            enableLockScreenAnimations = prefs[KEY_LOCK_ANIMATIONS] ?: true,
            keypadStyle = KeypadStyle.fromId(prefs[KEY_LOCK_KEYPAD_STYLE]),
            languageCode = prefs[KEY_LANGUAGE_CODE] ?: "en"
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

    override suspend fun setLockMode(mode: LockMode) {
        context.securityDataStore.edit { prefs ->
            prefs[KEY_LOCK_MODE] = mode.id
        }
    }

    override suspend fun setThemePreference(theme: ThemePreference) {
        context.securityDataStore.edit { prefs ->
            prefs[KEY_THEME_PREFERENCE] = theme.id
        }
    }

    override suspend fun setAccentColorPreset(accent: AccentColorPreset) {
        context.securityDataStore.edit { prefs ->
            prefs[KEY_ACCENT_COLOR_PRESET] = accent.id
        }
    }

    override suspend fun setAppListDensity(density: AppListDensity) {
        context.securityDataStore.edit { prefs ->
            prefs[KEY_APP_LIST_DENSITY] = density.id
        }
    }

    override suspend fun setAppSortOrder(sortOrder: AppSortOrder) {
        context.securityDataStore.edit { prefs ->
            prefs[KEY_APP_SORT_ORDER] = sortOrder.id
        }
    }

    override suspend fun setLockScreenPersonalization(
        showAppIcon: Boolean,
        showAppName: Boolean,
        backgroundStyle: LockScreenBackgroundStyle,
        enableAnimations: Boolean,
        keypadStyle: KeypadStyle
    ) {
        context.securityDataStore.edit { prefs ->
            prefs[KEY_LOCK_SHOW_APP_ICON] = showAppIcon
            prefs[KEY_LOCK_SHOW_APP_NAME] = showAppName
            prefs[KEY_LOCK_BG_STYLE] = backgroundStyle.id
            prefs[KEY_LOCK_ANIMATIONS] = enableAnimations
            prefs[KEY_LOCK_KEYPAD_STYLE] = keypadStyle.id
        }
    }

    override suspend fun setLanguageCode(languageCode: String) {
        context.securityDataStore.edit { prefs ->
            prefs[KEY_LANGUAGE_CODE] = if (languageCode == "bn") "bn" else "en"
        }
    }
}

