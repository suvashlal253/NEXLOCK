package com.nexlock.security.security

import com.nexlock.security.model.PermissionStatusItem

/**
 * Modular Architecture Contracts for Phases 2–5.
 *
 * Security Honesty Policy:
 * In Phase 1, these modules define strict boundaries and document exact Android OS behavior
 * without executing fake security actions or storing plaintext credentials.
 */
object PhaseArchitectureContracts {

    // Authentication & Keystore Module (Phase 2 Implemented)
    interface MasterAuthContract {
        val isImplementedInCurrentPhase: Boolean get() = true
        val implementationNote: String
            get() = "Phase 2 Active: PBKDF2WithHmacSHA256 (210,000 iterations, 16-byte CSPRNG salt) backed by AndroidKeyStore AES-256-GCM envelope encryption, AndroidX BiometricPrompt, and monotonic SessionManager."
    }

    // App Discovery Module (Phase 3 Implemented)
    interface AppDiscoveryContract {
        val isImplementedInCurrentPhase: Boolean get() = true
        val implementationNote: String
            get() = "Phase 3 Active: Queries Android PackageManager on Dispatchers.IO with Android 11+ <queries> visibility, LruCache Drawable icon memory cache, automatic 10-category classification, Room locked_apps unique index, and PackageChangeReceiver."
    }

    // App Monitoring & Lock Engine Module (Phase 4 Implemented)
    interface AppMonitoringEngineContract {
        val isImplementedInCurrentPhase: Boolean get() = true
        val implementationNote: String
            get() = "Phase 4 Active: Uses UsageStatsManager.queryEvents() inside a transparent ForegroundService (specialUse), enforces monotonic per-package re-lock sessions, and launches AppLockActivity. Never uses AccessibilityService surveillance."
    }

    // Encrypted Private Vault Module (Phase 5 Target)
    interface EncryptedVaultContract {
        val isImplementedInCurrentPhase: Boolean get() = false
        val implementationNote: String
            get() = "Phase 5 encrypts imported media files via Jetpack Security EncryptedFile (AES256_GCM_HKDF_4KB) inside app-private storage."
    }

    fun getDocumentedPermissions(): List<PermissionStatusItem> = listOf(
        PermissionStatusItem(
            id = "usage_stats",
            title = "Usage Access (PACKAGE_USAGE_STATS)",
            androidPermission = "android.permission.PACKAGE_USAGE_STATS",
            whyRequired = "Required in Phase 4 so NEXLOCK can detect when a protected application enters the foreground via UsageStatsManager.queryEvents().",
            limitationNote = "Android requires the user to manually grant this in System Settings > Special App Access > Usage Access. Polling interval respects battery and background execution limits.",
            isGrantedInPreview = false,
            phaseImplemented = "Phase 4 (Lock Engine)"
        ),
        PermissionStatusItem(
            id = "overlay_window",
            title = "Display Over Other Apps (SYSTEM_ALERT_WINDOW)",
            androidPermission = "android.permission.SYSTEM_ALERT_WINDOW",
            whyRequired = "Required in Phase 4 to display the NEXLOCK authentication screen immediately over a protected application when it launches.",
            limitationNote = "Android OS system dialogs, status bars, or safe-mode boot cannot be overridden by third-party overlays. NEXLOCK never claims overlay protection is unbypassable against ADB or OS-level resets.",
            isGrantedInPreview = false,
            phaseImplemented = "Phase 4 (Lock Engine)"
        ),
        PermissionStatusItem(
            id = "biometric_hardware",
            title = "Biometric Hardware (USE_BIOMETRIC)",
            androidPermission = "android.permission.USE_BIOMETRIC",
            whyRequired = "Required in Phase 2 to invoke the native AndroidX BiometricPrompt hardware-backed fingerprint sensor.",
            limitationNote = "NEXLOCK never captures, accesses, or stores raw fingerprint images. Verification occurs strictly inside the device Trusted Execution Environment (TEE).",
            isGrantedInPreview = true,
            phaseImplemented = "Phase 2 (Biometric & Keystore)"
        ),
        PermissionStatusItem(
            id = "foreground_service",
            title = "Foreground Monitoring Notification (FOREGROUND_SERVICE)",
            androidPermission = "android.permission.FOREGROUND_SERVICE_SPECIAL_USE",
            whyRequired = "Required in Phase 4 so Android 14+ allows continuous foreground app detection without being terminated by background restrictions.",
            limitationNote = "Displays a persistent, transparent user notification when protection monitoring is active. NEXLOCK never uses hidden AccessibilityService surveillance.",
            isGrantedInPreview = false,
            phaseImplemented = "Phase 4 (Lock Engine)"
        )
    )
}
