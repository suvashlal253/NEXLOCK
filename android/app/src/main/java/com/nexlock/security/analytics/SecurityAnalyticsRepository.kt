package com.nexlock.security.analytics

import com.nexlock.security.database.IntruderImageDao
import com.nexlock.security.database.LockScheduleDao
import com.nexlock.security.database.LockedAppsDao
import com.nexlock.security.database.SecurityEventDao
import com.nexlock.security.model.IntruderImageEntity
import com.nexlock.security.model.LockScheduleEntity
import com.nexlock.security.model.LockedAppEntity
import com.nexlock.security.model.SecurityEventEntity
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter

data class DailySecurityActivityPoint(
    val dateIso: String,
    val label: String,
    val successfulUnlocks: Int,
    val failedAttempts: Int,
    val intruderAlerts: Int
)

data class SecurityAnalyticsSnapshot(
    val computedAtEpochMillis: Long,
    val totalProtectedApps: Int,
    val activeSchedulesCount: Int,
    val totalSuccessfulAuthentications: Int,
    val totalFailedPinAttempts: Int,
    val totalFailedBiometricAttempts: Int,
    val totalIntruderEvents: Int,
    val totalIntruderCaptures: Int,
    val totalMonitoringInterruptions: Int,
    val activity7Days: List<DailySecurityActivityPoint>,
    val activity30Days: List<DailySecurityActivityPoint>,
    val recentEvents: List<SecurityEventEntity>
)

/**
 * Phase 6 SecurityAnalyticsRepository (Section 6).
 *
 * Computes real security metrics directly from Room database tables (`security_events`,
 * `locked_apps`, `intruder_images`, `lock_schedules`). Never generates fake statistics.
 * Handles empty datasets cleanly with zero-initialized series.
 */
class SecurityAnalyticsRepository(
    private val securityEventDao: SecurityEventDao? = null,
    private val lockedAppsDao: LockedAppsDao? = null,
    private val intruderImageDao: IntruderImageDao? = null,
    private val lockScheduleDao: LockScheduleDao? = null
) {
    suspend fun loadAnalyticsSnapshot(
        nowEpochMillis: Long = System.currentTimeMillis(),
        zoneId: ZoneId = ZoneId.systemDefault()
    ): SecurityAnalyticsSnapshot {
        val events = securityEventDao?.getAllEventsSnapshot() ?: emptyList()
        val lockedApps = lockedAppsDao?.getAllLockedAppsSnapshot() ?: emptyList()
        val intruderImages = intruderImageDao?.getAllIntruderImagesSnapshot() ?: emptyList()
        val schedules = lockScheduleDao?.getAllSchedulesSnapshot() ?: emptyList()

        return computeAnalyticsFromRecords(
            events = events,
            lockedApps = lockedApps,
            intruderImages = intruderImages,
            schedules = schedules,
            nowEpochMillis = nowEpochMillis,
            zoneId = zoneId
        )
    }

    companion object {
        private val SUCCESS_EVENT_TYPES = setOf(
            "UNLOCK_SUCCESS",
            "PIN_VERIFIED",
            "BIOMETRIC_SUCCESS",
            "APP_UNLOCKED"
        )

        private val FAILED_PIN_EVENT_TYPES = setOf(
            "FAILED_PIN",
            "PIN_FAILED",
            "AUTH_FAILED_PIN"
        )

        private val FAILED_BIOMETRIC_EVENT_TYPES = setOf(
            "FAILED_BIOMETRIC",
            "BIOMETRIC_FAILED",
            "AUTH_FAILED_BIOMETRIC"
        )

        private val INTRUDER_EVENT_TYPES = setOf(
            "INTRUDER_DETECTED",
            "LOCKOUT_TRIGGERED",
            "INTRUDER_THRESHOLD_REACHED"
        )

        private val MONITORING_INTERRUPTION_EVENT_TYPES = setOf(
            "SERVICE_INTERRUPTED",
            "PERMISSION_REVOKED",
            "MONITORING_DEGRADED",
            "OVERLAY_PERMISSION_MISSING",
            "USAGE_STATS_MISSING"
        )

        fun computeAnalyticsFromRecords(
            events: List<SecurityEventEntity>,
            lockedApps: List<LockedAppEntity>,
            intruderImages: List<IntruderImageEntity>,
            schedules: List<LockScheduleEntity>,
            nowEpochMillis: Long = System.currentTimeMillis(),
            zoneId: ZoneId = ZoneId.systemDefault()
        ): SecurityAnalyticsSnapshot {
            val totalProtectedApps = lockedApps.count { it.isLocked }
            val activeSchedulesCount = schedules.count { it.isEnabled }

            var successCount = 0
            var failedPinCount = 0
            var failedBiometricCount = 0
            var intruderEventCount = 0
            var monitoringInterruptionCount = 0

            for (ev in events) {
                val type = ev.eventType.uppercase()
                val method = ev.authenticationMethod?.uppercase() ?: ""
                when {
                    type in SUCCESS_EVENT_TYPES -> successCount++
                    type in FAILED_PIN_EVENT_TYPES || (type == "AUTH_FAILED" && method == "PIN") -> failedPinCount++
                    type in FAILED_BIOMETRIC_EVENT_TYPES || (type == "AUTH_FAILED" && method == "BIOMETRIC") -> failedBiometricCount++
                    type in INTRUDER_EVENT_TYPES -> intruderEventCount++
                    type in MONITORING_INTERRUPTION_EVENT_TYPES -> monitoringInterruptionCount++
                }
            }

            val today: LocalDate = Instant.ofEpochMilli(nowEpochMillis).atZone(zoneId).toLocalDate()
            val activity7Days = buildDailySeries(events, today, daysCount = 7, zoneId = zoneId)
            val activity30Days = buildDailySeries(events, today, daysCount = 30, zoneId = zoneId)

            return SecurityAnalyticsSnapshot(
                computedAtEpochMillis = nowEpochMillis,
                totalProtectedApps = totalProtectedApps,
                activeSchedulesCount = activeSchedulesCount,
                totalSuccessfulAuthentications = successCount,
                totalFailedPinAttempts = failedPinCount,
                totalFailedBiometricAttempts = failedBiometricCount,
                totalIntruderEvents = intruderEventCount,
                totalIntruderCaptures = intruderImages.size,
                totalMonitoringInterruptions = monitoringInterruptionCount,
                activity7Days = activity7Days,
                activity30Days = activity30Days,
                recentEvents = events.sortedByDescending { it.timestampMillis }.take(15)
            )
        }

        private fun buildDailySeries(
            events: List<SecurityEventEntity>,
            endDate: LocalDate,
            daysCount: Int,
            zoneId: ZoneId
        ): List<DailySecurityActivityPoint> {
            val shortFormatter = DateTimeFormatter.ofPattern("MMM d")
            val eventsByDate = events.groupBy { ev ->
                Instant.ofEpochMilli(ev.timestampMillis).atZone(zoneId).toLocalDate()
            }

            val series = ArrayList<DailySecurityActivityPoint>(daysCount)
            for (offset in (daysCount - 1) downTo 0) {
                val date = endDate.minusDays(offset.toLong())
                val dayEvents = eventsByDate[date] ?: emptyList()

                var successes = 0
                var failures = 0
                var intruders = 0
                for (ev in dayEvents) {
                    val type = ev.eventType.uppercase()
                    when {
                        type in SUCCESS_EVENT_TYPES -> successes++
                        type in FAILED_PIN_EVENT_TYPES || type in FAILED_BIOMETRIC_EVENT_TYPES || type == "AUTH_FAILED" -> failures++
                        type in INTRUDER_EVENT_TYPES -> intruders++
                    }
                }

                series.add(
                    DailySecurityActivityPoint(
                        dateIso = date.toString(),
                        label = date.format(shortFormatter),
                        successfulUnlocks = successes,
                        failedAttempts = failures,
                        intruderAlerts = intruders
                    )
                )
            }
            return series
        }
    }
}
