package com.nexlock.security.auth

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

/**
 * Abstraction for biometric hardware availability and native AndroidX BiometricPrompt execution.
 * Allows unit tests to mock BiometricGateway while production uses AndroidX BiometricPrompt.
 */
interface BiometricGateway {
    fun queryBiometricCapability(): BiometricCapabilityStatus
    fun authenticateWithBiometricPrompt(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
        onResult: (AuthenticationResult) -> Unit
    )
}

class NexLockBiometricManager(
    private val appContext: Context
) : BiometricGateway {

    override fun queryBiometricCapability(): BiometricCapabilityStatus {
        val manager = BiometricManager.from(appContext)
        return when (manager.canAuthenticate(BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS ->
                BiometricCapabilityStatus.AVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ->
                BiometricCapabilityStatus.NO_HARDWARE
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
                BiometricCapabilityStatus.HARDWARE_UNAVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                BiometricCapabilityStatus.NONE_ENROLLED
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED ->
                BiometricCapabilityStatus.SECURITY_UPDATE_REQUIRED
            else ->
                BiometricCapabilityStatus.UNKNOWN
        }
    }

    /**
     * Displays the genuine Android system BiometricPrompt dialog.
     * Never collects fingerprint images or simulates fake sensor success.
     * Provides an explicit negative button for Master PIN fallback.
     */
    override fun authenticateWithBiometricPrompt(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
        onResult: (AuthenticationResult) -> Unit
    ) {
        val capability = queryBiometricCapability()
        if (capability != BiometricCapabilityStatus.AVAILABLE) {
            onResult(
                AuthenticationResult.BiometricFailed(
                    reason = capability.description,
                    allowPinFallback = true
                )
            )
            return
        }

        val executor = ContextCompat.getMainExecutor(activity)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                onResult(
                    AuthenticationResult.Success(
                        method = AuthMethod.BIOMETRIC_PROMPT,
                        timestampElapsedMillis = android.os.SystemClock.elapsedRealtime()
                    )
                )
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                onResult(
                    AuthenticationResult.BiometricFailed(
                        reason = "Fingerprint not recognized by Android system sensor. Try again or use Master PIN.",
                        allowPinFallback = true
                    )
                )
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                when (errorCode) {
                    BiometricPrompt.ERROR_USER_CANCELED,
                    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                    BiometricPrompt.ERROR_CANCELED -> {
                        onResult(
                            AuthenticationResult.BiometricCanceled(
                                "Biometric prompt dismissed (${errString}). Enter Master PIN to continue."
                            )
                        )
                    }
                    BiometricPrompt.ERROR_LOCKOUT -> {
                        onResult(
                            AuthenticationResult.BiometricLockout(
                                isPermanent = false,
                                reason = "Too many failed biometric attempts. Sensor temporarily locked for 30 seconds; use Master PIN."
                            )
                        )
                    }
                    BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> {
                        onResult(
                            AuthenticationResult.BiometricLockout(
                                isPermanent = true,
                                reason = "Biometric sensor locked until device credential is verified. Use your NEXLOCK Master PIN."
                            )
                        )
                    }
                    else -> {
                        onResult(
                            AuthenticationResult.BiometricFailed(
                                reason = errString.toString(),
                                allowPinFallback = true
                            )
                        )
                    }
                }
            }
        }

        val biometricPrompt = BiometricPrompt(activity, executor, callback)
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .setNegativeButtonText("Use Master PIN")
            .setConfirmationRequired(false)
            .build()

        biometricPrompt.authenticate(promptInfo)
    }
}
