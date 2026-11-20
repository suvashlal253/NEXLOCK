package com.nexlock.security.notifications

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.nexlock.security.MainActivity

enum class SecurityAlertCategory(
    val isCritical: Boolean,
    val defaultCooldownMillis: Long
) {
    MULTIPLE_INCORRECT_PIN(isCritical = true, defaultCooldownMillis = 15_000L),
    INTRUDER_DETECTED(isCritical = true, defaultCooldownMillis = 15_000L),
    MONITORING_UNEXPECTEDLY_STOPPED(isCritical = true, defaultCooldownMillis = 30_000L),
    USAGE_ACCESS_REVOKED(isCritical = true, defaultCooldownMillis = 30_000L),
    OVERLAY_PERMISSION_REVOKED(isCritical = true, defaultCooldownMillis = 30_000L),
    SECURITY_CONFIGURATION_CHANGED(isCritical = false, defaultCooldownMillis = 10_000L),
    SUSPICIOUS_AUTH_ACTIVITY(isCritical = true, defaultCooldownMillis = 20_000L)
}

data class SecurityNotificationRecord(
    val id: Int,
    val category: SecurityAlertCategory,
    val dedupKey: String,
    val title: String,
    val body: String,
    val timestampMillis: Long
)

/**
 * Phase 5 Deduplication Engine for Security Notifications.
 * Pure, testable class that prevents duplicate notification spam for the same event within
 * its cooldown window and respects the user's non-critical notification preference.
 */
class NotificationDeduplicator(
    private val clockMillis: () -> Long = { System.currentTimeMillis() }
) {
    private val lastEmittedByKey = mutableMapOf<String, Long>()

    @Synchronized
    fun shouldDispatch(
        category: SecurityAlertCategory,
        targetKey: String = "global",
        nonCriticalAlertsEnabled: Boolean = true
    ): Boolean {
        if (!category.isCritical && !nonCriticalAlertsEnabled) {
            return false
        }
        val compositeKey = "${category.name}:$targetKey"
        val now = clockMillis()
        val previous = lastEmittedByKey[compositeKey]
        if (previous != null && (now - previous) < category.defaultCooldownMillis) {
            return false
        }
        lastEmittedByKey[compositeKey] = now
        return true
    }

    @Synchronized
    fun resetAll() {
        lastEmittedByKey.clear()
    }
}

/**
 * Phase 5 SecurityNotificationManager:
 *
 * 1. Registers Android 8.0+ NotificationChannels (Critical Security Alerts & Operational Status).
 * 2. Respects Android 13+ POST_NOTIFICATIONS runtime permission.
 * 3. Uses NotificationCompat.VISIBILITY_PRIVATE with redacted public lock-screen text so
 *    sensitive package names or private details are never exposed on the lock screen.
 * 4. Deduplicates repeated events via NotificationDeduplicator.
 */
class SecurityNotificationManager(
    private val appContext: Context,
    private val deduplicator: NotificationDeduplicator = NotificationDeduplicator()
) {
    companion object {
        const val CHANNEL_CRITICAL_ALERTS = "nexlock_critical_security_alerts"
        const val CHANNEL_OPERATIONAL_ALERTS = "nexlock_operational_status_alerts"
        private const val PUBLIC_LOCKSCREEN_FALLBACK_TEXT = "NEXLOCK security notice. Unlock device to view details."
    }

    private var nonCriticalNotificationsEnabled: Boolean = true

    init {
        ensureNotificationChannelsCreated()
    }

    fun setNonCriticalNotificationsEnabled(enabled: Boolean) {
        nonCriticalNotificationsEnabled = enabled
    }

    fun ensureNotificationChannelsCreated() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = appContext.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return

        val criticalChannel = NotificationChannel(
            CHANNEL_CRITICAL_ALERTS,
            "Critical Security & Intruder Alerts",
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "Alerts for intruder detection, permission revocation, and unexpected monitoring stops."
            lockscreenVisibility = NotificationCompat.VISIBILITY_PRIVATE
        }

        val operationalChannel = NotificationChannel(
            CHANNEL_OPERATIONAL_ALERTS,
            "Security Configuration Notices",
            NotificationManager.IMPORTANCE_DEFAULT
        ).apply {
            description = "Non-critical notifications when security policies or settings are updated."
            lockscreenVisibility = NotificationCompat.VISIBILITY_PRIVATE
        }

        nm.createNotificationChannel(criticalChannel)
        nm.createNotificationChannel(operationalChannel)
    }

    fun hasNotificationPermission(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(
                appContext,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            NotificationManagerCompat.from(appContext).areNotificationsEnabled()
        }
    }

    fun notifySecurityAlert(
        category: SecurityAlertCategory,
        targetKey: String = "global",
        title: String,
        privacyConsciousBody: String
    ): SecurityNotificationRecord? {
        if (!deduplicator.shouldDispatch(category, targetKey, nonCriticalNotificationsEnabled)) {
            return null
        }

        val record = SecurityNotificationRecord(
            id = (category.name + ":" + targetKey).hashCode(),
            category = category,
            dedupKey = "${category.name}:$targetKey",
            title = title,
            body = privacyConsciousBody,
            timestampMillis = System.currentTimeMillis()
        )

        if (!hasNotificationPermission()) {
            return record
        }

        val channelId = if (category.isCritical) CHANNEL_CRITICAL_ALERTS else CHANNEL_OPERATIONAL_ALERTS
        val openAppIntent = Intent(appContext, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            appContext,
            record.id,
            openAppIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // Redacted public notification for the device lock screen
        val publicLockScreenNotification = NotificationCompat.Builder(appContext, channelId)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentTitle("NEXLOCK Security Alert")
            .setContentText(PUBLIC_LOCKSCREEN_FALLBACK_TEXT)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .build()

        val notification = NotificationCompat.Builder(appContext, channelId)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentTitle(title)
            .setContentText(privacyConsciousBody)
            .setStyle(NotificationCompat.BigTextStyle().bigText(privacyConsciousBody))
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(publicLockScreenNotification)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .setPriority(
                if (category.isCritical) NotificationCompat.PRIORITY_HIGH
                else NotificationCompat.PRIORITY_DEFAULT
            )
            .build()

        runCatching {
            NotificationManagerCompat.from(appContext).notify(record.id, notification)
        }
        return record
    }
}
