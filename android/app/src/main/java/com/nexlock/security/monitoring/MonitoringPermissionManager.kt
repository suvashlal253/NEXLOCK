package com.nexlock.security.monitoring

import android.Manifest
import android.app.AppOpsManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Process
import android.provider.Settings
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

/**
 * Contract for checking and launching required Android special permissions for Phase 4.
 * Allows unit tests to inject deterministic permission states.
 */
interface PermissionHealthGateway {
    fun queryPermissionHealth(): PermissionHealthState
    fun resolveHomeLauncherPackages(): Set<String>
    fun buildUsageAccessSettingsIntent(): Intent
    fun buildOverlayPermissionSettingsIntent(): Intent
    fun buildAppNotificationSettingsIntent(): Intent
}

class MonitoringPermissionManager(
    private val context: Context
) : PermissionHealthGateway {

    override fun queryPermissionHealth(): PermissionHealthState {
        val usageGranted = isUsageAccessGranted()
        val overlayGranted = isOverlayPermissionGranted()
        val notificationRequired = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
        val notificationGranted = isNotificationPermissionGranted()

        return PermissionHealthState(
            usageAccessGranted = usageGranted,
            overlayPermissionGranted = overlayGranted,
            notificationPermissionGranted = notificationGranted,
            isOverlayRequiredForBackgroundStart = true,
            isNotificationPermissionRequired = notificationRequired
        )
    }

    /**
     * Checks Usage Access (android.permission.PACKAGE_USAGE_STATS) via AppOpsManager.
     * Never assumes permission was granted until verified on return from Settings.
     */
    fun isUsageAccessGranted(): Boolean {
        return try {
            val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
                ?: return false
            val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                appOps.unsafeCheckOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    Process.myUid(),
                    context.packageName
                )
            } else {
                @Suppress("DEPRECATION")
                appOps.checkOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    Process.myUid(),
                    context.packageName
                )
            }
            when (mode) {
                AppOpsManager.MODE_ALLOWED -> true
                AppOpsManager.MODE_DEFAULT -> {
                    context.checkCallingOrSelfPermission(Manifest.permission.PACKAGE_USAGE_STATS) ==
                        PackageManager.PERMISSION_GRANTED
                }
                else -> false
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Checks Display Over Other Apps (android.permission.SYSTEM_ALERT_WINDOW)
     * via Settings.canDrawOverlays(context).
     */
    fun isOverlayPermissionGranted(): Boolean {
        return try {
            Settings.canDrawOverlays(context)
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Checks POST_NOTIFICATIONS runtime permission on Android 13+ (API 33+)
     * and NotificationManagerCompat channel readiness.
     */
    fun isNotificationPermissionGranted(): Boolean {
        return try {
            val runtimeGranted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                ContextCompat.checkSelfPermission(
                    context,
                    Manifest.permission.POST_NOTIFICATIONS
                ) == PackageManager.PERMISSION_GRANTED
            } else {
                true
            }
            runtimeGranted && NotificationManagerCompat.from(context).areNotificationsEnabled()
        } catch (e: Exception) {
            false
        }
    }

    override fun resolveHomeLauncherPackages(): Set<String> {
        return try {
            val homeIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME)
            val pm = context.packageManager
            val resolveInfos = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.queryIntentActivities(homeIntent, PackageManager.ResolveInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                pm.queryIntentActivities(homeIntent, 0)
            }
            resolveInfos.mapNotNull { it.activityInfo?.packageName }.toSet()
        } catch (e: Exception) {
            emptySet()
        }
    }

    override fun buildUsageAccessSettingsIntent(): Intent {
        return Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS).apply {
            data = Uri.parse("package:${context.packageName}")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
    }

    override fun buildOverlayPermissionSettingsIntent(): Intent {
        return Intent(
            Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
            Uri.parse("package:${context.packageName}")
        ).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
    }

    override fun buildAppNotificationSettingsIntent(): Intent {
        return Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
            putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
    }

    companion object {
        /**
         * Pure evaluation function used by both production and unit tests to compute
         * the honest EngineOperationalStatus.
         *
         * Invariant: NEVER returns EngineOperationalStatus.ACTIVE when required permissions
         * are missing, when the service is not running, or when no apps are locked.
         */
        fun evaluateOperationalStatus(
            permissionHealth: PermissionHealthState,
            serviceState: MonitoringServiceState,
            isMonitoringEnabledByUser: Boolean,
            selectedLockedCount: Int
        ): EngineOperationalStatus {
            if (!permissionHealth.canRunMonitoringEngine) {
                return EngineOperationalStatus.PAUSED_MISSING_PERMISSIONS
            }
            if (!isMonitoringEnabledByUser) {
                return EngineOperationalStatus.PAUSED_BY_USER
            }
            if (selectedLockedCount <= 0) {
                return EngineOperationalStatus.PAUSED_NO_LOCKED_APPS
            }
            return when (serviceState) {
                MonitoringServiceState.RUNNING -> EngineOperationalStatus.ACTIVE
                MonitoringServiceState.STARTING -> EngineOperationalStatus.PAUSED_BY_USER
                MonitoringServiceState.STOPPED -> EngineOperationalStatus.PAUSED_BY_USER
                MonitoringServiceState.FAILED_TO_START -> EngineOperationalStatus.DEGRADED_OS_RESTRICTION
            }
        }
    }
}
