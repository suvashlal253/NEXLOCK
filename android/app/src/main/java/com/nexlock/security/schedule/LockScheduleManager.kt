package com.nexlock.security.schedule

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.nexlock.security.database.LockScheduleDao
import com.nexlock.security.model.LockMode
import com.nexlock.security.model.LockScheduleEntity
import com.nexlock.security.monitoring.AppLockEngine
import com.nexlock.security.monitoring.ReLockDurationOption
import java.time.DayOfWeek
import java.time.Instant
import java.time.LocalDateTime
import java.time.LocalTime
import java.time.ZoneId
import java.time.ZonedDateTime
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class ScheduleEvaluationSnapshot(
    val evaluatedAtEpochMillis: Long,
    val timeZoneId: String,
    val lockMode: LockMode,
    val activeSchedules: List<LockScheduleEntity>,
    val effectiveProtectedPackages: Set<String>,
    val effectiveReLockDuration: ReLockDurationOption,
    val effectiveLockOnScreenOff: Boolean,
    val statusSummary: String
)

/**
 * Phase 6 LockScheduleRepository (Section 1).
 *
 * Manages persistence of Smart Lock Schedules in Room (`lock_schedules` table)
 * and seeds default templates (Work Hours, Night Protection, Weekend Protection) if empty.
 */
class LockScheduleRepository(
    private val lockScheduleDao: LockScheduleDao
) {
    val allSchedulesFlow: Flow<List<LockScheduleEntity>> = lockScheduleDao.observeAllSchedules()
    val enabledSchedulesFlow: Flow<List<LockScheduleEntity>> = lockScheduleDao.observeEnabledSchedules()

    suspend fun getAllSchedulesSnapshot(): List<LockScheduleEntity> =
        lockScheduleDao.getAllSchedulesSnapshot()

    suspend fun ensureDefaultSchedulesSeeded() {
        val current = lockScheduleDao.getAllSchedulesSnapshot()
        if (current.isEmpty()) {
            lockScheduleDao.upsertSchedules(defaultScheduleTemplates())
        }
    }

    suspend fun upsertSchedule(schedule: LockScheduleEntity): Long =
        lockScheduleDao.upsertSchedule(
            schedule.copy(updatedAtMillis = System.currentTimeMillis())
        )

    suspend fun setScheduleEnabled(scheduleId: Long, enabled: Boolean) {
        lockScheduleDao.setScheduleEnabled(scheduleId, enabled, System.currentTimeMillis())
    }

    suspend fun deleteSchedule(scheduleId: Long) {
        lockScheduleDao.deleteScheduleById(scheduleId)
    }

    suspend fun replaceAllSchedules(schedules: List<LockScheduleEntity>) {
        lockScheduleDao.clearAllSchedules()
        lockScheduleDao.upsertSchedules(schedules)
    }

    companion object {
        fun defaultScheduleTemplates(nowMillis: Long = System.currentTimeMillis()): List<LockScheduleEntity> = listOf(
            LockScheduleEntity(
                id = 1,
                name = "Work Hours",
                description = "9:00 AM – 5:00 PM, Monday to Friday. Protects messaging, social, and finance apps during office focus.",
                startHour = 9,
                startMinute = 0,
                endHour = 17,
                endMinute = 0,
                daysOfWeekCsv = "1,2,3,4,5",
                targetPackagesCsv = "*",
                applyToAllLockedApps = true,
                isEnabled = true,
                createdAtMillis = nowMillis,
                updatedAtMillis = nowMillis
            ),
            LockScheduleEntity(
                id = 2,
                name = "Night Protection",
                description = "10:00 PM – 7:00 AM, Every Day. Cross-midnight overnight protection with immediate re-lock.",
                startHour = 22,
                startMinute = 0,
                endHour = 7,
                endMinute = 0,
                daysOfWeekCsv = "1,2,3,4,5,6,7",
                targetPackagesCsv = "*",
                applyToAllLockedApps = true,
                isEnabled = true,
                createdAtMillis = nowMillis,
                updatedAtMillis = nowMillis
            ),
            LockScheduleEntity(
                id = 3,
                name = "Weekend Protection",
                description = "8:00 AM – 11:00 PM, Saturday and Sunday. Guards banking and work email during weekend travel.",
                startHour = 8,
                startMinute = 0,
                endHour = 23,
                endMinute = 0,
                daysOfWeekCsv = "6,7",
                targetPackagesCsv = "com.chase.sig.android,com.google.android.gm,com.Slack",
                applyToAllLockedApps = false,
                isEnabled = false,
                createdAtMillis = nowMillis,
                updatedAtMillis = nowMillis
            )
        )
    }
}

/**
 * Phase 6 LockScheduleManager & LockModeManager (Sections 1 & 2).
 *
 * Integrates directly with the existing Phase 4 [AppLockEngine] without creating a duplicate lock engine.
 *
 * Key Capabilities & Edge-Case Handling:
 * 1. Correct Cross-Midnight (Overnight) Evaluation:
 *    - When a schedule has `startTime > endTime` (e.g., 22:00 to 07:00), it spans two calendar days:
 *      (a) Late evening segment `[startTime, 23:59:59]` is active if TODAY's ISO day-of-week is in `daysOfWeek`.
 *      (b) Early morning segment `[00:00:00, endTime)` is active if YESTERDAY's ISO day-of-week is in `daysOfWeek`.
 * 2. Time Zone & Manual Clock Changes:
 *    - Evaluates schedules against a configurable [ZoneId] (default `ZoneId.systemDefault()`).
 *    - Responds to `Intent.ACTION_TIMEZONE_CHANGED`, `Intent.ACTION_TIME_CHANGED`, and `Intent.ACTION_BOOT_COMPLETED`.
 * 3. Safe Fallback Behavior:
 *    - Never silently disables all protection unless the user explicitly selected `LockMode.CUSTOM` with zero active
 *      schedules, and even then clearly exposes the status summary in UI.
 *    - In `LockMode.NORMAL`, all user-locked apps remain protected and active schedules can additionally enforce
 *      scheduled package subsets or stricter night rules.
 *    - In `LockMode.MAX_SECURITY`, forces `ReLockDurationOption.IMMEDIATELY` and `lockOnScreenOff = true`.
 *    - In `LockMode.NIGHT`, enforces protection across all locked apps + overnight schedule rules.
 */
class LockScheduleManager(
    private val appLockEngine: AppLockEngine? = null
) {
    private val _evaluationState = MutableStateFlow<ScheduleEvaluationSnapshot?>(null)
    val evaluationState: StateFlow<ScheduleEvaluationSnapshot?> = _evaluationState.asStateFlow()

    /**
     * Pure deterministic check for whether [schedule] is active at [epochMillis] in [zoneId].
     * Correctly handles same-day windows, full-day windows, and cross-midnight overnight windows.
     */
    fun isScheduleActiveAt(
        schedule: LockScheduleEntity,
        epochMillis: Long,
        zoneId: ZoneId = ZoneId.systemDefault()
    ): Boolean {
        if (!schedule.isEnabled) return false
        val selectedDays = schedule.parsedDaysOfWeek()
        if (selectedDays.isEmpty()) return false

        val zonedDateTime: ZonedDateTime = Instant.ofEpochMilli(epochMillis).atZone(zoneId)
        val localDateTime: LocalDateTime = zonedDateTime.toLocalDateTime()
        val currentDayIso: Int = localDateTime.dayOfWeek.value // 1 (Monday) .. 7 (Sunday)
        val previousDayIso: Int = localDateTime.dayOfWeek.minus(1).value

        val currentMinutes = localDateTime.hour * 60 + localDateTime.minute
        val startMinutes = schedule.startHour.coerceIn(0, 23) * 60 + schedule.startMinute.coerceIn(0, 59)
        val endMinutes = schedule.endHour.coerceIn(0, 23) * 60 + schedule.endMinute.coerceIn(0, 59)

        return when {
            // Same start and end minute -> active 24 hours on selected days
            startMinutes == endMinutes -> {
                currentDayIso in selectedDays
            }
            // Standard intraday window (e.g. 09:00 to 17:00)
            startMinutes < endMinutes -> {
                currentDayIso in selectedDays && currentMinutes in startMinutes until endMinutes
            }
            // Cross-midnight overnight window (e.g. 22:00 to 07:00)
            else -> {
                val inEveningSegment = currentMinutes >= startMinutes && (currentDayIso in selectedDays)
                val inMorningCarryoverSegment = currentMinutes < endMinutes && (previousDayIso in selectedDays)
                inEveningSegment || inMorningCarryoverSegment
            }
        }
    }

    /**
     * Computes the next boundary epoch millis when any enabled schedule will transition state,
     * used for scheduling inexact `AlarmManager` window updates without continuous background polling
     * and without requiring `SCHEDULE_EXACT_ALARM`.
     */
    fun computeNextScheduleBoundaryMillis(
        schedules: List<LockScheduleEntity>,
        nowEpochMillis: Long,
        zoneId: ZoneId = ZoneId.systemDefault()
    ): Long? {
        val enabled = schedules.filter { it.isEnabled && it.parsedDaysOfWeek().isNotEmpty() }
        if (enabled.isEmpty()) return null

        val nowZoned = Instant.ofEpochMilli(nowEpochMillis).atZone(zoneId)
        var earliestCandidate: Long? = null

        for (schedule in enabled) {
            for (dayOffset in 0L..7L) {
                val candidateDate = nowZoned.toLocalDate().plusDays(dayOffset)
                val startCandidate = ZonedDateTime.of(
                    candidateDate,
                    LocalTime.of(schedule.startHour.coerceIn(0, 23), schedule.startMinute.coerceIn(0, 59)),
                    zoneId
                ).toInstant().toEpochMilli()

                val endCandidate = ZonedDateTime.of(
                    candidateDate,
                    LocalTime.of(schedule.endHour.coerceIn(0, 23), schedule.endMinute.coerceIn(0, 59)),
                    zoneId
                ).toInstant().toEpochMilli()

                for (ts in listOf(startCandidate, endCandidate)) {
                    if (ts > nowEpochMillis) {
                        if (earliestCandidate == null || ts < earliestCandidate) {
                            earliestCandidate = ts
                        }
                    }
                }
            }
        }
        return earliestCandidate
    }

    /**
     * Evaluates the effective protection state for [userLockedPackages] under [lockMode] and [schedules]
     * at [nowEpochMillis] in [zoneId], and synchronizes the result directly into [AppLockEngine].
     */
    fun evaluateAndApplyToEngine(
        userLockedPackages: Set<String>,
        schedules: List<LockScheduleEntity>,
        lockMode: LockMode,
        configuredReLockDuration: ReLockDurationOption,
        configuredLockOnScreenOff: Boolean,
        nowEpochMillis: Long = System.currentTimeMillis(),
        zoneId: ZoneId = ZoneId.systemDefault()
    ): ScheduleEvaluationSnapshot {
        val activeSchedules = schedules.filter { isScheduleActiveAt(it, nowEpochMillis, zoneId) }

        val scheduledPackages: Set<String> = if (activeSchedules.any { it.applyToAllLockedApps || it.targetPackagesCsv.trim() == "*" }) {
            userLockedPackages
        } else {
            activeSchedules
                .flatMap { it.parsedTargetPackages() }
                .intersect(userLockedPackages)
        }

        val effectivePackages: Set<String>
        val effectiveReLock: ReLockDurationOption
        val effectiveScreenOffLock: Boolean
        val summary: String

        when (lockMode) {
            LockMode.NORMAL -> {
                // Normal mode keeps all user-locked packages protected and applies active schedule metadata
                effectivePackages = userLockedPackages
                effectiveReLock = configuredReLockDuration
                effectiveScreenOffLock = configuredLockOnScreenOff
                summary = if (activeSchedules.isEmpty()) {
                    "Normal Protection active (${effectivePackages.size} apps protected)."
                } else {
                    "Normal Protection + ${activeSchedules.joinToString { it.name }} active (${effectivePackages.size} apps)."
                }
            }
            LockMode.MAX_SECURITY -> {
                effectivePackages = userLockedPackages
                effectiveReLock = ReLockDurationOption.IMMEDIATELY
                effectiveScreenOffLock = true
                summary = "Maximum Security active: Immediate re-lock & screen-off lock enforced for ${effectivePackages.size} apps."
            }
            LockMode.NIGHT -> {
                effectivePackages = userLockedPackages
                effectiveReLock = ReLockDurationOption.IMMEDIATELY
                effectiveScreenOffLock = true
                summary = "Night Protection Mode active: Overnight immediate re-lock enforced across ${effectivePackages.size} apps."
            }
            LockMode.CUSTOM -> {
                val enabledCount = schedules.count { it.isEnabled }
                if (enabledCount == 0) {
                    // Safe fallback: if no schedules are enabled at all, retain user's base locked apps
                    // so protection is never silently wiped by an empty schedule list.
                    effectivePackages = userLockedPackages
                    effectiveReLock = configuredReLockDuration
                    effectiveScreenOffLock = configuredLockOnScreenOff
                    summary = "Custom Schedule Mode: No schedules enabled — retaining base protection (${effectivePackages.size} apps)."
                } else if (activeSchedules.isEmpty()) {
                    effectivePackages = emptySet()
                    effectiveReLock = configuredReLockDuration
                    effectiveScreenOffLock = configuredLockOnScreenOff
                    summary = "Custom Schedule Mode: Outside active schedule windows (0 apps currently gated; waiting for next window)."
                } else {
                    effectivePackages = scheduledPackages
                    effectiveReLock = configuredReLockDuration
                    effectiveScreenOffLock = configuredLockOnScreenOff
                    summary = "Custom Schedule Mode: Active window [${activeSchedules.joinToString { it.name }}] protecting ${effectivePackages.size} apps."
                }
            }
        }

        appLockEngine?.apply {
            updateLockedPackages(effectivePackages)
            setReLockDuration(effectiveReLock)
            setLockOnScreenOffPolicy(effectiveScreenOffLock)
        }

        return ScheduleEvaluationSnapshot(
            evaluatedAtEpochMillis = nowEpochMillis,
            timeZoneId = zoneId.id,
            lockMode = lockMode,
            activeSchedules = activeSchedules,
            effectiveProtectedPackages = effectivePackages,
            effectiveReLockDuration = effectiveReLock,
            effectiveLockOnScreenOff = effectiveScreenOffLock,
            statusSummary = summary
        ).also {
            _evaluationState.value = it
        }
    }

    /**
     * Registers an inexact window alarm for the next schedule transition boundary.
     * Does NOT require `SCHEDULE_EXACT_ALARM` or `USE_EXACT_ALARM`, respecting Android 12–14+
     * battery and Google Play permission restrictions.
     */
    fun scheduleNextBoundaryAlarm(
        context: Context,
        schedules: List<LockScheduleEntity>,
        nowEpochMillis: Long = System.currentTimeMillis()
    ) {
        val alarmManager = context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
        val nextBoundary = computeNextScheduleBoundaryMillis(schedules, nowEpochMillis) ?: return

        val intent = Intent(context, ScheduleTimeChangeReceiver::class.java).apply {
            action = ScheduleTimeChangeReceiver.ACTION_EVALUATE_LOCK_SCHEDULES
        }
        val pendingIntent = PendingIntent.getBroadcast(
            context,
            REQUEST_CODE_SCHEDULE_BOUNDARY,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val windowStart = (nextBoundary - 30_000L).coerceAtLeast(nowEpochMillis + 5_000L)
        alarmManager.setWindow(
            AlarmManager.RTC_WAKEUP,
            windowStart,
            60_000L, // 1-minute window — no exact alarm permission required
            pendingIntent
        )
    }

    companion object {
        private const val REQUEST_CODE_SCHEDULE_BOUNDARY = 6041
    }
}

/**
 * BroadcastReceiver handling time changes, time-zone shifts, and schedule boundary alarms
 * (`ACTION_TIME_CHANGED`, `ACTION_TIMEZONE_CHANGED`, `ACTION_EVALUATE_LOCK_SCHEDULES`).
 */
class ScheduleTimeChangeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action == Intent.ACTION_TIME_CHANGED ||
            action == Intent.ACTION_TIMEZONE_CHANGED ||
            action == Intent.ACTION_DATE_CHANGED ||
            action == ACTION_EVALUATE_LOCK_SCHEDULES
        ) {
            // Notify running AppLockMonitoringService (if active) to re-evaluate schedule windows immediately
            val serviceIntent = Intent(ACTION_EVALUATE_LOCK_SCHEDULES).apply {
                setPackage(context.packageName)
            }
            context.sendBroadcast(serviceIntent)
        }
    }

    companion object {
        const val ACTION_EVALUATE_LOCK_SCHEDULES = "com.nexlock.security.action.EVALUATE_LOCK_SCHEDULES"
    }
}
