package com.nexlock.security.monitoring

import com.nexlock.security.auth.SessionManager
import com.nexlock.security.model.SecurityEventSeverity
import com.nexlock.security.notifications.NotificationDeduplicator
import com.nexlock.security.notifications.SecurityAlertCategory
import com.nexlock.security.repository.SecurityEventRepository
import com.nexlock.security.repository.SecurityEventType

enum class SensitiveSettingAction(val displayName: String) {
    CHANGE_MASTER_PIN("Change Master PIN"),
    DISABLE_BIOMETRIC_AUTH("Disable Biometric Authentication"),
    DISABLE_INTRUDER_DETECTION("Disable Intruder Detection"),
    DISABLE_PROTECTION_MONITORING("Disable App Protection Monitoring"),
    CHANGE_FAILED_ATTEMPT_THRESHOLD("Change Failed-Attempt Threshold"),
    DELETE_INTRUDER_IMAGES("Delete Encrypted Intruder Images"),
    CLEAR_SECURITY_LOGS("Clear Security Activity Logs"),
    CHANGE_RELOCK_POLICY("Change App Re-Lock Policy")
}

sealed class SettingsAuthorizationDecision {
    data object AuthorizedByActiveSession : SettingsAuthorizationDecision()
    data class RequiresMasterAuthentication(val action: SensitiveSettingAction, val reason: String) :
        SettingsAuthorizationDecision()
}

data class QuickLockResult(
    val executed: Boolean,
    val duplicateSuppressed: Boolean,
    val revokedPackageSessionCount: Int,
    val masterSessionLocked: Boolean,
    val confirmationMessage: String
)

data class ProtectionHealthReport(
    val usageAccessHealthy: Boolean,
    val overlayPermissionHealthy: Boolean,
    val monitoringServiceHealthy: Boolean,
    val engineOperational: Boolean,
    val configIntegrityHealthy: Boolean,
    val selectedProtectedAppsCount: Int,
    val uninstalledProtectedPackages: List<String>,
    val detectedIssues: List<String>,
    val overallHealthStatus: String
)

/**
 * Phase 5 ProtectionHealthMonitor:
 *
 * 1. Application-level tamper and health detection across permissions, service state, engine state,
 *    cryptographic configuration integrity, and uninstalled protected packages.
 * 2. Honest Android Security Boundaries: Explicitly documents that standard Android applications
 *    cannot prevent OS Force-Stop, Application Uninstall, Safe Mode boot, Root/ADB tampering, or
 *    Factory Reset, and never uses hidden APIs or deceptive Device Admin tricks.
 * 3. Implements Panic Lock / Quick Lock (immediately revoking all temporary package unlock sessions
 *    and locking the Master Session, with duplicate-invocation suppression).
 * 4. Implements Secure Settings session-based authorization reusing Phase 2 SessionManager.
 */
class ProtectionHealthMonitor(
    private val appLockEngine: AppLockEngine,
    private val sessionManager: SessionManager,
    private val securityEventRepository: SecurityEventRepository? = null,
    private val notificationDeduplicator: NotificationDeduplicator = NotificationDeduplicator(),
    private val monotonicClockMillis: () -> Long = { System.currentTimeMillis() }
) {
    companion object {
        private const val QUICK_LOCK_DEDUP_WINDOW_MS = 750L

        val DOCUMENTED_TAMPER_LIMITATIONS = listOf(
            "Android Force-Stop: A user with device access can force-stop third-party apps in System Settings.",
            "Application Uninstall: Standard Play-compliant apps cannot block OS uninstallation.",
            "Safe Mode Boot: Android Safe Mode disables all third-party services at boot.",
            "Root & ADB Tampering: Privileged shell or root access can bypass user-space app locks.",
            "Factory Reset: Hardware recovery resets wipe all local app data."
        )
    }

    private var lastQuickLockMonotonicMs: Long = -10_000L

    fun evaluateHealth(
        permissionHealth: PermissionHealthState,
        serviceState: MonitoringServiceState,
        isMonitoringEnabledByUser: Boolean,
        isPinConfigured: Boolean,
        isKeystoreHealthy: Boolean,
        selectedProtectedPackages: Set<String>,
        currentlyInstalledPackages: Set<String>
    ): ProtectionHealthReport {
        val issues = mutableListOf<String>()

        if (!permissionHealth.usageAccessGranted) {
            issues.add("Usage Access permission (PACKAGE_USAGE_STATS) is revoked.")
            notificationDeduplicator.shouldDispatch(SecurityAlertCategory.USAGE_ACCESS_REVOKED)
        }
        if (!permissionHealth.overlayPermissionGranted) {
            issues.add("Display Over Other Apps permission (SYSTEM_ALERT_WINDOW) is revoked.")
            notificationDeduplicator.shouldDispatch(SecurityAlertCategory.OVERLAY_PERMISSION_REVOKED)
        }

        val serviceHealthy = serviceState == MonitoringServiceState.RUNNING
        if (isMonitoringEnabledByUser && permissionHealth.canRunMonitoringEngine && !serviceHealthy && selectedProtectedPackages.isNotEmpty()) {
            issues.add("Monitoring service unexpectedly stopped while protection is enabled.")
            notificationDeduplicator.shouldDispatch(SecurityAlertCategory.MONITORING_UNEXPECTEDLY_STOPPED)
        }

        val configIntegrityHealthy = isPinConfigured && isKeystoreHealthy
        if (!isPinConfigured) {
            issues.add("Master PIN is not configured.")
        }
        if (!isKeystoreHealthy) {
            issues.add("AndroidKeyStore AES-256-GCM key requires recovery rotation.")
        }

        val uninstalledProtected = selectedProtectedPackages
            .filter { it !in currentlyInstalledPackages }
            .sorted()
        if (uninstalledProtected.isNotEmpty()) {
            issues.add("${uninstalledProtected.size} protected application(s) were uninstalled: ${uninstalledProtected.joinToString(", ")}")
        }

        val operationalStatus = MonitoringPermissionManager.evaluateOperationalStatus(
            permissionHealth = permissionHealth,
            serviceState = serviceState,
            isMonitoringEnabledByUser = isMonitoringEnabledByUser,
            selectedLockedCount = selectedProtectedPackages.size
        )

        val engineOperational = operationalStatus.isOperational && configIntegrityHealthy

        val overallStatus = when {
            engineOperational && issues.isEmpty() -> "HEALTHY_OPERATIONAL"
            !permissionHealth.canRunMonitoringEngine || !configIntegrityHealthy -> "ACTION_REQUIRED"
            !isMonitoringEnabledByUser -> "PAUSED_BY_USER"
            else -> "DEGRADED"
        }

        return ProtectionHealthReport(
            usageAccessHealthy = permissionHealth.usageAccessGranted,
            overlayPermissionHealthy = permissionHealth.overlayPermissionGranted,
            monitoringServiceHealthy = serviceHealthy,
            engineOperational = engineOperational,
            configIntegrityHealthy = configIntegrityHealthy,
            selectedProtectedAppsCount = selectedProtectedPackages.size,
            uninstalledProtectedPackages = uninstalledProtected,
            detectedIssues = issues,
            overallHealthStatus = overallStatus
        )
    }

    /**
     * Panic Lock / Quick Lock:
     * Immediately invalidates all temporary per-package unlock sessions in AppLockEngine and
     * locks the Master Session in SessionManager. Confirms state only after verifying the engine's
     * unlocked session map is empty.
     */
    @Synchronized
    suspend fun executeQuickLock(triggeredByScreenOff: Boolean = false): QuickLockResult {
        val now = monotonicClockMillis()
        val activeBefore = appLockEngine.unlockedSessionsFlow.value.size
        val masterActiveBefore = sessionManager.isSessionValid()

        if (!triggeredByScreenOff &&
            (now - lastQuickLockMonotonicMs) < QUICK_LOCK_DEDUP_WINDOW_MS &&
            activeBefore == 0 &&
            !masterActiveBefore
        ) {
            return QuickLockResult(
                executed = false,
                duplicateSuppressed = true,
                revokedPackageSessionCount = 0,
                masterSessionLocked = true,
                confirmationMessage = "Quick Lock already active (0 unlocked sessions)."
            )
        }

        lastQuickLockMonotonicMs = now
        appLockEngine.revokeAllPackageSessions()
        sessionManager.lockSessionImmediately()

        val confirmedEmpty = appLockEngine.unlockedSessionsFlow.value.isEmpty()
        val confirmedMasterLocked = !sessionManager.isSessionValid()

        if (confirmedEmpty && confirmedMasterLocked) {
            val triggerReason = if (triggeredByScreenOff) "Automatic Screen-Off Quick Lock" else "Manual Dashboard Quick Lock"
            securityEventRepository?.recordSecurityEvent(
                eventType = SecurityEventType.QUICK_LOCK_EXECUTED.code,
                title = "Quick Lock Confirmed ($triggerReason)",
                detail = "Revoked $activeBefore temporary app unlock session(s) and locked master session.",
                severity = SecurityEventSeverity.INFO,
                metadata = "revokedPackageSessions=$activeBefore;trigger=$triggerReason"
            )
        }

        return QuickLockResult(
            executed = confirmedEmpty && confirmedMasterLocked,
            duplicateSuppressed = false,
            revokedPackageSessionCount = activeBefore,
            masterSessionLocked = confirmedMasterLocked,
            confirmationMessage = if (confirmedEmpty && confirmedMasterLocked) {
                "Quick Lock confirmed: All protected applications re-locked ($activeBefore active session(s) invalidated)."
            } else {
                "Quick Lock state verification failed."
            }
        )
    }

    /**
     * Reuses Phase 2 SessionManager to protect critical settings changes.
     * Prevents repeated authentication prompts during a valid authenticated session and requires
     * re-authentication once the session expires.
     */
    fun authorizeSensitiveSettingChange(action: SensitiveSettingAction): SettingsAuthorizationDecision {
        return if (sessionManager.isSessionValid()) {
            sessionManager.touchActivity()
            SettingsAuthorizationDecision.AuthorizedByActiveSession
        } else {
            SettingsAuthorizationDecision.RequiresMasterAuthentication(
                action = action,
                reason = "Master PIN or Biometric authentication is required to ${action.displayName.lowercase()}."
            )
        }
    }
}
