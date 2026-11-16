package com.nexlock.security.monitoring

import com.nexlock.security.auth.AuthMethod

/**
 * Configurable Re-Lock durations required in NEXLOCK Phase 4:
 * - Immediately (0s)
 * - After 5 seconds (5,000ms)
 * - After 15 seconds (15,000ms)
 * - After 30 seconds (30,000ms)
 * - After 1 minute (60,000ms)
 * - After 5 minutes (300,000ms)
 *
 * Uses monotonic elapsed time (SystemClock.elapsedRealtime()) so wall-clock adjustments
 * cannot bypass or extend unlocked package sessions.
 */
enum class ReLockDurationOption(
    val id: String,
    val label: String,
    val durationMillis: Long,
    val description: String
) {
    IMMEDIATELY(
        id = "IMMEDIATELY",
        label = "Immediately",
        durationMillis = 0L,
        description = "Re-locks as soon as the user switches away from the protected app."
    ),
    SECONDS_5(
        id = "SECONDS_5",
        label = "After 5 seconds",
        durationMillis = 5_000L,
        description = "Keeps the protected app unlocked for 5 seconds after leaving it."
    ),
    SECONDS_15(
        id = "SECONDS_15",
        label = "After 15 seconds",
        durationMillis = 15_000L,
        description = "Allows quick app switching for 15 seconds before requiring re-authentication."
    ),
    SECONDS_30(
        id = "SECONDS_30",
        label = "After 30 seconds",
        durationMillis = 30_000L,
        description = "Maintains the package session for 30 seconds after leaving the foreground."
    ),
    MINUTE_1(
        id = "MINUTE_1",
        label = "After 1 minute",
        durationMillis = 60_000L,
        description = "Keeps the package unlocked for 1 minute after switching away."
    ),
    MINUTES_5(
        id = "MINUTES_5",
        label = "After 5 minutes",
        durationMillis = 300_000L,
        description = "Keeps the package unlocked for 5 minutes unless the screen turns off."
    );

    companion object {
        fun fromId(id: String?): ReLockDurationOption =
            entries.find { it.id == id } ?: IMMEDIATELY
    }
}

enum class UsageTransitionType {
    ACTIVITY_RESUMED,
    ACTIVITY_PAUSED,
    SCREEN_INTERACTIVE,
    SCREEN_NON_INTERACTIVE,
    KEYGUARD_SHOWN
}

data class ForegroundTransitionEvent(
    val packageName: String,
    val className: String? = null,
    val transitionType: UsageTransitionType,
    val timestampMillis: Long
)

data class PermissionHealthState(
    val usageAccessGranted: Boolean = false,
    val overlayPermissionGranted: Boolean = false,
    val notificationPermissionGranted: Boolean = true,
    val isOverlayRequiredForBackgroundStart: Boolean = true,
    val isNotificationPermissionRequired: Boolean = true
) {
    /**
     * Usage Access is strictly mandatory for UsageStatsManager foreground detection.
     * Overlay permission is required on Android 10+ (API 29+) to reliably launch AppLockActivity
     * from a background/foreground monitoring service.
     */
    val canRunMonitoringEngine: Boolean
        get() = usageAccessGranted && (!isOverlayRequiredForBackgroundStart || overlayPermissionGranted)
}

enum class MonitoringServiceState(val label: String) {
    RUNNING("Running"),
    STOPPED("Stopped"),
    STARTING("Starting"),
    FAILED_TO_START("Failed to Start")
}

/**
 * Honest operational status of the App Lock Engine.
 * Never reports ACTIVE when required permissions are missing, when the service is stopped,
 * or when 0 applications are selected for protection.
 */
enum class EngineOperationalStatus(
    val badgeLabel: String,
    val description: String,
    val isOperational: Boolean
) {
    ACTIVE(
        badgeLabel = "Active",
        description = "Monitoring service is running with required permissions and actively enforcing lock policies.",
        isOperational = true
    ),
    PAUSED_MISSING_PERMISSIONS(
        badgeLabel = "Paused (Permissions Required)",
        description = "Monitoring is paused because Usage Access or Display Over Other Apps permission is not granted.",
        isOperational = false
    ),
    PAUSED_BY_USER(
        badgeLabel = "Paused by User",
        description = "Protection engine was manually paused by the user. Selected apps are not currently intercepted.",
        isOperational = false
    ),
    PAUSED_NO_LOCKED_APPS(
        badgeLabel = "Idle (No Apps Selected)",
        description = "Monitoring service is standing by because no installed applications are currently marked as locked.",
        isOperational = false
    ),
    DEGRADED_OS_RESTRICTION(
        badgeLabel = "Degraded (OS Restriction)",
        description = "Android restricted background service execution or UsageEvents delivery. Open NEXLOCK to resume monitoring.",
        isOperational = false
    )
}

/**
 * Tracks a temporary per-package unlock session established after the user passes
 * Master PIN or BiometricPrompt authentication for a specific protected application.
 */
data class PackageUnlockSession(
    val packageName: String,
    val unlockedAtElapsedMillis: Long,
    val lastForegroundElapsedMillis: Long,
    val backgroundedAtElapsedMillis: Long? = null,
    val authMethod: AuthMethod
)

sealed class LockEnforcementDecision {
    data class AllowExcluded(val packageName: String, val reason: String) : LockEnforcementDecision()
    data class AllowUnprotected(val packageName: String) : LockEnforcementDecision()
    data class AllowActiveSession(
        val packageName: String,
        val remainingMillis: Long?
    ) : LockEnforcementDecision()
    data class RequireAuthentication(
        val packageName: String,
        val reason: String
    ) : LockEnforcementDecision()
    data class SuppressDuplicateChallenge(
        val packageName: String
    ) : LockEnforcementDecision()
}

data class ExcludedPackageRule(
    val packageNamePattern: String,
    val label: String,
    val reason: String
)

/**
 * Safe Exclusion & Recovery Protection Registry (Section 9).
 *
 * Ensures NEXLOCK never locks itself, Android System Settings, Permission Controllers,
 * System UI, Biometric dialogs, Emergency Dialers, or the active Home Launcher,
 * guaranteeing the user always has a safe recovery path.
 */
object ExcludedSystemPackages {

    const val NEXLOCK_PACKAGE = "com.nexlock.security"

    val defaultExcludedRules: List<ExcludedPackageRule> = listOf(
        ExcludedPackageRule(
            packageNamePattern = NEXLOCK_PACKAGE,
            label = "NEXLOCK Security Engine",
            reason = "Prevents recursive self-locking when AppLockActivity or NEXLOCK settings are displayed."
        ),
        ExcludedPackageRule(
            packageNamePattern = "com.android.systemui",
            label = "Android System UI",
            reason = "Required for Notification Shade, Quick Settings, Recents overview, and Biometric system dialogs."
        ),
        ExcludedPackageRule(
            packageNamePattern = "com.android.settings",
            label = "Android System Settings",
            reason = "Excluded by default for safe recovery so users can always manage permissions and device settings."
        ),
        ExcludedPackageRule(
            packageNamePattern = "com.google.android.permissioncontroller",
            label = "Android Permission Controller",
            reason = "Required so runtime permission grants and special app access screens are never blocked."
        ),
        ExcludedPackageRule(
            packageNamePattern = "com.android.permissioncontroller",
            label = "AOSP Permission Controller",
            reason = "Required so runtime permission dialogs remain accessible."
        ),
        ExcludedPackageRule(
            packageNamePattern = "com.google.android.packageinstaller",
            label = "Android Package Installer",
            reason = "Required for safe app installation and uninstallation flows."
        ),
        ExcludedPackageRule(
            packageNamePattern = "com.android.packageinstaller",
            label = "AOSP Package Installer",
            reason = "Required for safe package management."
        ),
        ExcludedPackageRule(
            packageNamePattern = "com.android.server.telecom",
            label = "Android Telecom & Emergency Service",
            reason = "Critical safety requirement: never obstruct incoming calls or emergency calling interfaces."
        ),
        ExcludedPackageRule(
            packageNamePattern = "com.android.incallui",
            label = "In-Call User Interface",
            reason = "Ensures active phone and emergency calls are never obscured."
        ),
        ExcludedPackageRule(
            packageNamePattern = "com.google.android.dialer",
            label = "Phone & Emergency Dialer",
            reason = "Excluded to guarantee uninterrupted access to emergency calls."
        ),
        ExcludedPackageRule(
            packageNamePattern = "com.android.emergency",
            label = "Android Emergency Information",
            reason = "Critical emergency interface exclusion."
        )
    )

    private val exactExcludedSet: Set<String> =
        defaultExcludedRules.map { it.packageNamePattern }.toSet()

    fun isPackageExcluded(
        packageName: String,
        activeHomeLauncherPackages: Set<String> = emptySet()
    ): Boolean {
        if (packageName.isBlank()) return true
        if (packageName in exactExcludedSet) return true
        if (packageName in activeHomeLauncherPackages) return true
        if (packageName.contains("biometric", ignoreCase = true) &&
            packageName.startsWith("com.android.")
        ) {
            return true
        }
        if (packageName.endsWith(".permissioncontroller") ||
            packageName.endsWith(".packageinstaller")
        ) {
            return true
        }
        return false
    }

    fun getExclusionReason(
        packageName: String,
        activeHomeLauncherPackages: Set<String> = emptySet()
    ): String? {
        if (packageName in activeHomeLauncherPackages) {
            return "Active Android Home Launcher is excluded so you can always navigate your device."
        }
        return defaultExcludedRules.find { it.packageNamePattern == packageName }?.reason
            ?: if (isPackageExcluded(packageName, activeHomeLauncherPackages)) {
                "Excluded critical Android system/recovery component."
            } else {
                null
            }
    }
}

/**
 * Complete UI & telemetry state exposed by the Phase 4 Protection Engine to the Dashboard
 * and Permission Health screens.
 */
data class ProtectionEngineState(
    val permissionHealth: PermissionHealthState = PermissionHealthState(),
    val serviceState: MonitoringServiceState = MonitoringServiceState.STOPPED,
    val operationalStatus: EngineOperationalStatus = EngineOperationalStatus.PAUSED_MISSING_PERMISSIONS,
    val isMonitoringEnabledByUser: Boolean = true,
    val lockOnScreenOff: Boolean = true,
    val reLockDurationOption: ReLockDurationOption = ReLockDurationOption.IMMEDIATELY,
    val currentForegroundPackage: String? = null,
    val activeChallengePackage: String? = null,
    val lastDetectedPackage: String? = null,
    val lastMonitoringEventEpochMillis: Long? = null,
    val adaptivePollingIntervalMillis: Long = 500L,
    val isScreenInteractive: Boolean = true,
    val activeUnlockedPackages: Map<String, PackageUnlockSession> = emptyMap(),
    val totalInstalledCount: Int = 0,
    val selectedLockedCount: Int = 0,
    val configuredOperationalCount: Int = 0,
    val excludedPackages: List<ExcludedPackageRule> = ExcludedSystemPackages.defaultExcludedRules,
    val statusBannerMessage: String? = null
)
