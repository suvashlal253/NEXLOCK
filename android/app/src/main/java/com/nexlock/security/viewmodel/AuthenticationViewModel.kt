package com.nexlock.security.viewmodel

import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.nexlock.security.auth.AuthenticationResult
import com.nexlock.security.auth.AuthenticationState
import com.nexlock.security.auth.BiometricGateway
import com.nexlock.security.auth.PinValidationResult
import com.nexlock.security.auth.SessionManager
import com.nexlock.security.auth.SessionTimeoutOption
import com.nexlock.security.repository.AuthRepository
import com.nexlock.security.repository.SecuritySettingsStore
import com.nexlock.security.security.KeyManagerContract
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class AuthenticationViewModel(
    private val authRepository: AuthRepository,
    private val settingsStore: SecuritySettingsStore,
    private val sessionManager: SessionManager,
    private val biometricGateway: BiometricGateway,
    private val keyManager: KeyManagerContract
) : ViewModel() {

    private val feedbackFlow = MutableStateFlow<Pair<String?, String?>>(null to null) // error to success
    private val tickerFlow = MutableStateFlow(System.currentTimeMillis())

    init {
        // Periodic 1-second ticker to update session countdowns and temporary lockout timers
        viewModelScope.launch {
            while (true) {
                delay(1_000L)
                sessionManager.evaluateAndExpireIfNecessary()
                tickerFlow.value = System.currentTimeMillis()
            }
        }
    }

    val authState: StateFlow<AuthenticationState> = combine(
        settingsStore.settingsFlow,
        sessionManager.sessionFlow,
        feedbackFlow,
        tickerFlow
    ) { settings, session, feedback, nowEpoch ->
        val lockoutRemaining = if (settings.lockoutUntilEpochMillis > nowEpoch) {
            ((settings.lockoutUntilEpochMillis - nowEpoch) + 999L) / 1000L
        } else {
            0L
        }

        AuthenticationState(
            isPinConfigured = settings.isPinConfigured,
            isAuthenticated = session.isAuthenticated,
            lastAuthMethod = session.lastAuthMethod,
            sessionEstablishedElapsedMillis = session.authenticatedAtElapsedMillis,
            sessionRemainingSeconds = sessionManager.remainingSessionSeconds(),
            sessionTimeoutOption = settings.sessionTimeoutOption,
            pinLength = settings.pinLength,
            failedAttempts = settings.failedAttempts,
            maxFailedAttemptsBeforeLockout = settings.maxFailedAttempts,
            isTemporarilyLockedOut = lockoutRemaining > 0L,
            lockoutRemainingSeconds = lockoutRemaining,
            biometricEnabledInSettings = settings.biometricEnabled,
            biometricCapability = biometricGateway.queryBiometricCapability(),
            keystoreHealthy = keyManager.isKeyHealthy(),
            errorMessage = feedback.first,
            successMessage = feedback.second
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = AuthenticationState()
    )

    fun validatePinDraft(pin: String, expectedLength: Int): PinValidationResult =
        authRepository.validateCandidatePin(pin, expectedLength)

    fun createMasterPin(
        newPin: String,
        confirmPin: String,
        onSuccess: () -> Unit
    ) {
        viewModelScope.launch {
            val result = authRepository.createOrUpdateMasterPin(newPin, confirmPin)
            result.fold(
                onSuccess = {
                    feedbackFlow.value = null to "Master PIN securely derived (PBKDF2-HMAC-SHA256) and sealed with AndroidKeyStore."
                    onSuccess()
                },
                onFailure = { err ->
                    feedbackFlow.value = (err.message ?: "PIN creation failed") to null
                }
            )
        }
    }

    fun authenticateWithPin(
        pin: String,
        onSuccess: () -> Unit
    ) {
        viewModelScope.launch {
            when (val res = authRepository.verifyMasterPin(pin)) {
                is AuthenticationResult.Success -> {
                    feedbackFlow.value = null to "Master PIN verified. Session unlocked."
                    onSuccess()
                }
                is AuthenticationResult.IncorrectPin -> {
                    feedbackFlow.value = res.message to null
                }
                is AuthenticationResult.LockedOut -> {
                    feedbackFlow.value = res.message to null
                }
                is AuthenticationResult.KeyInvalidated -> {
                    feedbackFlow.value = res.recoveryMessage to null
                }
                is AuthenticationResult.Error -> {
                    feedbackFlow.value = res.reason to null
                }
                else -> Unit
            }
        }
    }

    fun authenticateWithBiometric(
        activity: FragmentActivity,
        onSuccess: () -> Unit
    ) {
        biometricGateway.authenticateWithBiometricPrompt(
            activity = activity,
            title = "NEXLOCK Master Authentication",
            subtitle = "Verify your fingerprint to unlock NEXLOCK"
        ) { result ->
            viewModelScope.launch {
                val processed = authRepository.onBiometricPromptResult(result)
                when (processed) {
                    is AuthenticationResult.Success -> {
                        feedbackFlow.value = null to "Biometric authentication succeeded."
                        onSuccess()
                    }
                    is AuthenticationResult.BiometricCanceled -> {
                        feedbackFlow.value = processed.reason to null
                    }
                    is AuthenticationResult.BiometricFailed -> {
                        feedbackFlow.value = processed.reason to null
                    }
                    is AuthenticationResult.BiometricLockout -> {
                        feedbackFlow.value = processed.reason to null
                    }
                    else -> Unit
                }
            }
        }
    }

    fun changeMasterPin(
        currentPin: String,
        newPin: String,
        confirmPin: String,
        onSuccess: () -> Unit
    ) {
        viewModelScope.launch {
            val res = authRepository.changeMasterPin(currentPin, newPin, confirmPin)
            res.fold(
                onSuccess = {
                    feedbackFlow.value = null to "Master PIN updated with a fresh cryptographic salt."
                    onSuccess()
                },
                onFailure = { err ->
                    feedbackFlow.value = (err.message ?: "Failed to change PIN") to null
                }
            )
        }
    }

    fun setSessionTimeout(option: SessionTimeoutOption) {
        viewModelScope.launch {
            settingsStore.setSessionTimeout(option)
            sessionManager.setSessionTimeoutOption(option)
            feedbackFlow.value = null to "Session timeout updated to ${option.label}."
        }
    }

    fun setMaxFailedAttempts(maxAttempts: Int) {
        viewModelScope.launch {
            settingsStore.setMaxFailedAttempts(maxAttempts)
            feedbackFlow.value = null to "Lockout threshold set to $maxAttempts failed attempts."
        }
    }

    fun setBiometricEnabled(enabled: Boolean) {
        viewModelScope.launch {
            settingsStore.setBiometricEnabled(enabled)
            feedbackFlow.value = null to if (enabled) {
                "AndroidX BiometricPrompt unlock enabled."
            } else {
                "Biometric unlock disabled; Master PIN required."
            }
        }
    }

    fun lockSessionNow() {
        sessionManager.invalidateSession()
        feedbackFlow.value = null to "Session locked immediately."
    }

    fun clearFeedback() {
        feedbackFlow.value = null to null
    }
}
