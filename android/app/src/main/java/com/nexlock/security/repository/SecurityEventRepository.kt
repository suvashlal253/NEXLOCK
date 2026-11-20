package com.nexlock.security.repository

import com.nexlock.security.database.SecurityEventDao
import com.nexlock.security.model.SecurityEventEntity
import com.nexlock.security.model.SecurityEventSeverity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

enum class SecurityEventType(
    val code: String,
    val displayLabel: String,
    val defaultSeverity: SecurityEventSeverity
) {
    AUTH_PIN_SUCCESS("AUTH_PIN_SUCCESS", "Successful PIN Authentication", SecurityEventSeverity.INFO),
    AUTH_BIOMETRIC_SUCCESS("AUTH_BIOMETRIC_SUCCESS", "Successful Biometric Authentication", SecurityEventSeverity.INFO),
    AUTH_PIN_INCORRECT("AUTH_PIN_INCORRECT", "Incorrect Master PIN", SecurityEventSeverity.WARNING),
    AUTH_FAILED("AUTH_FAILED", "Failed Authentication Attempt", SecurityEventSeverity.WARNING),
    INTRUDER_DETECTED("INTRUDER_DETECTED", "Intruder Detection Triggered", SecurityEventSeverity.CRITICAL),
    INTRUDER_IMAGE_CAPTURED("INTRUDER_IMAGE_CAPTURED", "Intruder Selfie Captured (Encrypted)", SecurityEventSeverity.CRITICAL),
    APP_PROTECTION_ENABLED("CONFIG_LOCK_ENABLED", "Application Protection Enabled", SecurityEventSeverity.INFO),
    APP_PROTECTION_DISABLED("CONFIG_LOCK_DISABLED", "Application Protection Disabled", SecurityEventSeverity.WARNING),
    MONITORING_STARTED("MONITORING_RESUMED", "Protection Monitoring Started", SecurityEventSeverity.INFO),
    MONITORING_PAUSED("MONITORING_PAUSED", "Protection Monitoring Paused", SecurityEventSeverity.WARNING),
    PERMISSION_REVOKED("PERMISSION_REVOKED", "Required Permission Revoked", SecurityEventSeverity.CRITICAL),
    SECURITY_SETTINGS_MODIFIED("PREF_UPDATED", "Security Settings Modified", SecurityEventSeverity.INFO),
    MASTER_PIN_CHANGED("PIN_ROTATED", "Master PIN Changed", SecurityEventSeverity.INFO),
    QUICK_LOCK_EXECUTED("QUICK_LOCK_EXECUTED", "Quick Lock / Panic Lock Executed", SecurityEventSeverity.INFO)
}

enum class EventSortOrder {
    NEWEST_FIRST,
    OLDEST_FIRST
}

enum class EventDateFilter(val label: String) {
    ALL_TIME("All Time"),
    TODAY("Today (Last 24h)"),
    LAST_7_DAYS("Last 7 Days"),
    LAST_30_DAYS("Last 30 Days")
}

/**
 * Phase 5 SecurityEventRepository:
 *
 * Manages the chronological security activity timeline in Room (security_events table).
 *
 * Privacy & Security Guarantees:
 * - Sanitizes descriptions and metadata to ensure raw PIN digits, keys, or passwords are never stored.
 * - Supports filtering by eventType, severity, and date range, plus sorting by Newest/Oldest.
 * - Supports deleting individual events and clearing all logs after explicit confirmation.
 */
class SecurityEventRepository(
    private val securityEventDao: SecurityEventDao,
    private val clockMillis: () -> Long = { System.currentTimeMillis() }
) {
    companion object {
        private val RAW_PIN_PATTERN = Regex("""\b(?:pin|passcode|secret)\s*[:=]\s*\d{4,8}\b""", RegexOption.IGNORE_CASE)

        fun sanitizeNonSensitiveText(input: String): String {
            return RAW_PIN_PATTERN.replace(input, "[REDACTED_CREDENTIAL]")
        }

        fun filterAndSortEvents(
            events: List<SecurityEventEntity>,
            eventTypeFilter: String? = null,
            severityFilter: SecurityEventSeverity? = null,
            dateFilter: EventDateFilter = EventDateFilter.ALL_TIME,
            sortOrder: EventSortOrder = EventSortOrder.NEWEST_FIRST,
            nowMillis: Long = System.currentTimeMillis()
        ): List<SecurityEventEntity> {
            val minTimestamp = when (dateFilter) {
                EventDateFilter.ALL_TIME -> 0L
                EventDateFilter.TODAY -> nowMillis - 24L * 60L * 60L * 1000L
                EventDateFilter.LAST_7_DAYS -> nowMillis - 7L * 24L * 60L * 60L * 1000L
                EventDateFilter.LAST_30_DAYS -> nowMillis - 30L * 24L * 60L * 60L * 1000L
            }

            val filtered = events.filter { ev ->
                val matchesType = eventTypeFilter.isNullOrBlank() ||
                    eventTypeFilter == "ALL" ||
                    ev.eventType.equals(eventTypeFilter, ignoreCase = true)
                val matchesSeverity = severityFilter == null ||
                    ev.severity.equals(severityFilter.name, ignoreCase = true)
                val matchesDate = ev.timestampMillis >= minTimestamp
                matchesType && matchesSeverity && matchesDate
            }

            return when (sortOrder) {
                EventSortOrder.NEWEST_FIRST -> filtered.sortedByDescending { it.timestampMillis }
                EventSortOrder.OLDEST_FIRST -> filtered.sortedBy { it.timestampMillis }
            }
        }
    }

    fun observeEvents(
        eventTypeFilter: String? = null,
        severityFilter: SecurityEventSeverity? = null,
        dateFilter: EventDateFilter = EventDateFilter.ALL_TIME,
        sortOrder: EventSortOrder = EventSortOrder.NEWEST_FIRST
    ): Flow<List<SecurityEventEntity>> {
        return securityEventDao.observeRecentEvents().map { list ->
            filterAndSortEvents(
                events = list,
                eventTypeFilter = eventTypeFilter,
                severityFilter = severityFilter,
                dateFilter = dateFilter,
                sortOrder = sortOrder,
                nowMillis = clockMillis()
            )
        }
    }

    suspend fun recordSecurityEvent(
        eventType: String,
        title: String,
        detail: String,
        packageName: String? = null,
        authenticationMethod: String? = null,
        severity: SecurityEventSeverity = SecurityEventSeverity.INFO,
        metadata: String = ""
    ): SecurityEventEntity {
        val entity = SecurityEventEntity(
            eventType = eventType,
            packageName = packageName,
            authenticationMethod = authenticationMethod,
            title = sanitizeNonSensitiveText(title),
            detail = sanitizeNonSensitiveText(detail),
            severity = severity.name,
            metadata = sanitizeNonSensitiveText(metadata),
            timestampMillis = clockMillis()
        )
        val id = securityEventDao.insertEvent(entity)
        return entity.copy(id = id)
    }

    suspend fun deleteEventById(eventId: Long) {
        securityEventDao.deleteEventById(eventId)
    }

    suspend fun clearAllEventsWithConfirmation(confirmedByUser: Boolean): Boolean {
        if (!confirmedByUser) return false
        securityEventDao.clearEvents()
        return true
    }
}
