package com.nexlock.security.database

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.nexlock.security.model.ReLockPolicy
import com.nexlock.security.ui.theme.ThemeMode
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore(name = "nexlock_preferences")

data class UserPreferencesState(
    val onboardingCompleted: Boolean = false,
    val themeMode: ThemeMode = ThemeMode.DARK,
    val globalReLockPolicy: ReLockPolicy = ReLockPolicy.IMMEDIATELY,
    val biometricPreferenceEnabled: Boolean = true,
    val pinLength: Int = 6,
    val randomizeKeypad: Boolean = false,
    val hidePinRipple: Boolean = false
)

class PreferencesManager(private val context: Context) {
    companion object {
        private val KEY_ONBOARDING_DONE = booleanPreferencesKey("onboarding_completed")
        private val KEY_THEME_MODE = stringPreferencesKey("theme_mode")
        private val KEY_RELOCK_POLICY = stringPreferencesKey("relock_policy")
        private val KEY_BIOMETRIC_PREF = booleanPreferencesKey("biometric_pref_enabled")
        private val KEY_PIN_LENGTH = intPreferencesKey("pin_length")
        private val KEY_RANDOMIZE_KEYPAD = booleanPreferencesKey("randomize_keypad")
        private val KEY_HIDE_PIN_RIPPLE = booleanPreferencesKey("hide_pin_ripple")
    }

    val preferencesFlow: Flow<UserPreferencesState> = context.dataStore.data.map { prefs ->
        UserPreferencesState(
            onboardingCompleted = prefs[KEY_ONBOARDING_DONE] ?: false,
            themeMode = runCatching {
                ThemeMode.valueOf(prefs[KEY_THEME_MODE] ?: ThemeMode.DARK.name)
            }.getOrDefault(ThemeMode.DARK),
            globalReLockPolicy = runCatching {
                ReLockPolicy.valueOf(prefs[KEY_RELOCK_POLICY] ?: ReLockPolicy.IMMEDIATELY.name)
            }.getOrDefault(ReLockPolicy.IMMEDIATELY),
            biometricPreferenceEnabled = prefs[KEY_BIOMETRIC_PREF] ?: true,
            pinLength = prefs[KEY_PIN_LENGTH] ?: 6,
            randomizeKeypad = prefs[KEY_RANDOMIZE_KEYPAD] ?: false,
            hidePinRipple = prefs[KEY_HIDE_PIN_RIPPLE] ?: false
        )
    }

    suspend fun setOnboardingCompleted(completed: Boolean) {
        context.dataStore.edit { it[KEY_ONBOARDING_DONE] = completed }
    }

    suspend fun setThemeMode(mode: ThemeMode) {
        context.dataStore.edit { it[KEY_THEME_MODE] = mode.name }
    }

    suspend fun setGlobalReLockPolicy(policy: ReLockPolicy) {
        context.dataStore.edit { it[KEY_RELOCK_POLICY] = policy.name }
    }

    suspend fun setBiometricPreference(enabled: Boolean) {
        context.dataStore.edit { it[KEY_BIOMETRIC_PREF] = enabled }
    }

    suspend fun setRandomizeKeypad(enabled: Boolean) {
        context.dataStore.edit { it[KEY_RANDOMIZE_KEYPAD] = enabled }
    }

    suspend fun setHidePinRipple(enabled: Boolean) {
        context.dataStore.edit { it[KEY_HIDE_PIN_RIPPLE] = enabled }
    }
}
