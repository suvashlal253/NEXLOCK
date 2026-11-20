package com.nexlock.security.intruder

import com.nexlock.security.database.IntruderImageDao
import com.nexlock.security.model.IntruderImageEntity
import com.nexlock.security.model.SecurityEventSeverity
import com.nexlock.security.notifications.NotificationDeduplicator
import com.nexlock.security.notifications.SecurityAlertCategory
import com.nexlock.security.repository.SecurityEventRepository
import com.nexlock.security.repository.SecurityEventType
import com.nexlock.security.vault.SecureFileRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class IntruderThresholdOption(val attempts: Int, val label: String) {
    ATTEMPTS_3(3, "3 failed attempts"),
    ATTEMPTS_5(5, "5 failed attempts"),
    ATTEMPTS_10(10, "10 failed attempts");

    companion object {
        fun fromAttempts(count: Int): IntruderThresholdOption =
            entries.firstOrNull { it.attempts == count } ?: ATTEMPTS_3
    }
}

enum class ObservedAuthFailureType {
    INCORRECT_MASTER_PIN,
    BIOMETRIC_MISMATCH,
    BIOMETRIC_LOCKOUT,
    BIOMETRIC_USER_CANCELED,
    USER_DISMISSED_CHALLENGE
}

data class IntruderDetectionSettings(
    val isEnabled: Boolean = true,
    val thresholdOption: IntruderThresholdOption = IntruderThresholdOption.ATTEMPTS_3,
    val resetCounterOnSuccess: Boolean = true,
    val intruderSelfieEnabled: Boolean = false,
    val hasExplicitCameraConsent: Boolean = false,
    val maxStoredImages: Int = 20
)

data class FailedAttemptRecord(
    val timestampMillis: Long,
    val targetPackageName: String?,
    val authenticationMethod: String,
    val consecutiveCountAfterAttempt: Int
)

sealed class IntruderCaptureOutcome {
    data class CapturedEncrypted(
        val relativePath: String,
        val ivBase64: String,
        val byteSize: Long
    ) : IntruderCaptureOutcome()

    data class Skipped(val reason: String) : IntruderCaptureOutcome()
}

interface IntruderSelfieCaptureGateway {
    suspend fun captureAndEncryptFrontSelfieIfPermitted(
        settings: IntruderDetectionSettings
    ): IntruderCaptureOutcome
}

data class IntruderEvaluationResult(
    val countedAsFailure: Boolean,
    val consecutiveFailures: Int,
    val thresholdReached: Boolean,
    val intruderTriggered: Boolean,
    val captureOutcome: IntruderCaptureOutcome? = null,
    val recordedEventId: Long? = null
)

/**
 * In-memory and persisted tracker for consecutive failed authentication attempts.
 * Never stores raw PIN digits or sensitive credentials.
 */
class FailedAttemptRepository(
    private val clockMillis: () -> Long = { System.currentTimeMillis() }
) {
    private val _consecutiveFailuresFlow = MutableStateFlow(0)
    val consecutiveFailuresFlow: StateFlow<Int> = _consecutiveFailuresFlow.asStateFlow()

    private val _recentFailedAttemptsFlow = MutableStateFlow<List<FailedAttemptRecord>>(emptyList())
    val recentFailedAttemptsFlow: StateFlow<List<FailedAttemptRecord>> = _recentFailedAttemptsFlow.asStateFlow()

    @Synchronized
    fun recordFailure(
        targetPackageName: String?,
        authenticationMethod: String
    ): FailedAttemptRecord {
        val nextCount = _consecutiveFailuresFlow.value + 1
        _consecutiveFailuresFlow.value = nextCount
        val record = FailedAttemptRecord(
            timestampMillis = clockMillis(),
            targetPackageName = targetPackageName,
            authenticationMethod = authenticationMethod,
            consecutiveCountAfterAttempt = nextCount
        )
        _recentFailedAttemptsFlow.value = (listOf(record) + _recentFailedAttemptsFlow.value).take(100)
        return record
    }

    @Synchronized
    fun resetConsecutiveFailures() {
        _consecutiveFailuresFlow.value = 0
    }
}

/**
 * Phase 5 IntruderDetectionManager:
 *
 * 1. Tracks consecutive failed Master PIN and Biometric authentication attempts.
 * 2. Explicitly ignores user biometric cancellations or ordinary dismissals so they are never
 *    counted as failed PIN/intruder attempts.
 * 3. Triggers Intruder Detection alerts and optional consented front-camera encrypted capture
 *    when consecutiveFailures >= settings.thresholdOption.attempts.
 * 4. Enforces maxStoredImages retention on encrypted intruder selfies.
 */
class IntruderDetectionManager(
    private val failedAttemptRepository: FailedAttemptRepository = FailedAttemptRepository(),
    private val securityEventRepository: SecurityEventRepository? = null,
    private val intruderImageDao: IntruderImageDao? = null,
    private val secureFileRepository: SecureFileRepository? = null,
    private val selfieCaptureGateway: IntruderSelfieCaptureGateway? = null,
    private val notificationDeduplicator: NotificationDeduplicator = NotificationDeduplicator(),
    private val clockMillis: () -> Long = { System.currentTimeMillis() }
) {
    private val _settingsFlow = MutableStateFlow(IntruderDetectionSettings())
    val settingsFlow: StateFlow<IntruderDetectionSettings> = _settingsFlow.asStateFlow()

    val consecutiveFailuresFlow: StateFlow<Int> = failedAttemptRepository.consecutiveFailuresFlow

    fun observeIntruderImages(): Flow<List<IntruderImageEntity>>? =
        intruderImageDao?.observeIntruderImages()

    fun updateSettings(transform: (IntruderDetectionSettings) -> IntruderDetectionSettings) {
        _settingsFlow.value = transform(_settingsFlow.value)
    }

    suspend fun onAuthenticationObserved(
        failureType: ObservedAuthFailureType?,
        isSuccess: Boolean,
        authenticationMethod: String,
        targetPackageName: String? = null
    ): IntruderEvaluationResult {
        val settings = _settingsFlow.value

        if (isSuccess) {
            if (settings.resetCounterOnSuccess) {
                failedAttemptRepository.resetConsecutiveFailures()
            }
            val eventType = if (authenticationMethod.contains("BIOMETRIC", ignoreCase = true)) {
                SecurityEventType.AUTH_BIOMETRIC_SUCCESS.code
            } else {
                SecurityEventType.AUTH_PIN_SUCCESS.code
            }
            val ev = securityEventRepository?.recordSecurityEvent(
                eventType = eventType,
                title = "Authentication Succeeded ($authenticationMethod)",
                detail = if (targetPackageName != null) {
                    "Authenticated access to protected package $targetPackageName."
                } else {
                    "Authenticated NEXLOCK master security session."
                },
                packageName = targetPackageName,
                authenticationMethod = authenticationMethod,
                severity = SecurityEventSeverity.INFO,
                metadata = "consecutiveFailuresReset=${settings.resetCounterOnSuccess}"
            )
            return IntruderEvaluationResult(
                countedAsFailure = false,
                consecutiveFailures = failedAttemptRepository.consecutiveFailuresFlow.value,
                thresholdReached = false,
                intruderTriggered = false,
                recordedEventId = ev?.id
            )
        }

        // Biometric cancellation or ordinary user dismissal must NOT count as a failed PIN/intruder attempt
        if (failureType == ObservedAuthFailureType.BIOMETRIC_USER_CANCELED ||
            failureType == ObservedAuthFailureType.USER_DISMISSED_CHALLENGE
        ) {
            return IntruderEvaluationResult(
                countedAsFailure = false,
                consecutiveFailures = failedAttemptRepository.consecutiveFailuresFlow.value,
                thresholdReached = false,
                intruderTriggered = false
            )
        }

        // Count real failed authentication attempt
        val attemptRecord = failedAttemptRepository.recordFailure(
            targetPackageName = targetPackageName,
            authenticationMethod = authenticationMethod
        )
        val currentFailures = attemptRecord.consecutiveCountAfterAttempt
        val threshold = settings.thresholdOption.attempts
        val thresholdReached = currentFailures >= threshold
        val intruderTriggered = settings.isEnabled && thresholdReached

        val failureEventCode = if (failureType == ObservedAuthFailureType.INCORRECT_MASTER_PIN) {
            SecurityEventType.AUTH_PIN_INCORRECT.code
        } else {
            SecurityEventType.AUTH_FAILED.code
        }

        val failureEvent = securityEventRepository?.recordSecurityEvent(
            eventType = failureEventCode,
            title = "Failed Authentication Attempt (#$currentFailures)",
            detail = "Failed $authenticationMethod verification" +
                (if (targetPackageName != null) " for $targetPackageName." else "."),
            packageName = targetPackageName,
            authenticationMethod = authenticationMethod,
            severity = if (thresholdReached) SecurityEventSeverity.CRITICAL else SecurityEventSeverity.WARNING,
            metadata = "consecutiveFailures=$currentFailures;threshold=$threshold"
        )

        var captureOutcome: IntruderCaptureOutcome? = null

        if (intruderTriggered) {
            securityEventRepository?.recordSecurityEvent(
                eventType = SecurityEventType.INTRUDER_DETECTED.code,
                title = "Intruder Detection Triggered ($currentFailures Failed Attempts)",
                detail = "Reached configured threshold ($threshold attempts) via $authenticationMethod" +
                    (if (targetPackageName != null) " while accessing $targetPackageName." else "."),
                packageName = targetPackageName,
                authenticationMethod = authenticationMethod,
                severity = SecurityEventSeverity.CRITICAL,
                metadata = "threshold=$threshold;consecutiveFailures=$currentFailures"
            )

            notificationDeduplicator.shouldDispatch(
                category = SecurityAlertCategory.INTRUDER_DETECTED,
                targetKey = targetPackageName ?: "master_lock"
            )

            captureOutcome = if (settings.intruderSelfieEnabled && settings.hasExplicitCameraConsent) {
                selfieCaptureGateway?.captureAndEncryptFrontSelfieIfPermitted(settings)
                    ?: IntruderCaptureOutcome.Skipped("Camera capture gateway unavailable in current context.")
            } else {
                IntruderCaptureOutcome.Skipped("Intruder Selfie disabled or camera consent not granted.")
            }

            when (val outcome = captureOutcome) {
                is IntruderCaptureOutcome.CapturedEncrypted -> {
                    val entity = IntruderImageEntity(
                        timestampMillis = clockMillis(),
                        targetPackageName = targetPackageName,
                        consecutiveFailures = currentFailures,
                        authenticationMethod = authenticationMethod,
                        encryptedFilePath = outcome.relativePath,
                        encryptionIvBase64 = outcome.ivBase64,
                        byteSize = outcome.byteSize,
                        captureStatus = "CAPTURED_ENCRYPTED_AES256_GCM"
                    )
                    intruderImageDao?.insertIntruderImage(entity)
                    enforceMaxStoredIntruderImages(settings.maxStoredImages)
                    securityEventRepository?.recordSecurityEvent(
                        eventType = SecurityEventType.INTRUDER_IMAGE_CAPTURED.code,
                        title = "Intruder Selfie Captured & Encrypted (AES-256-GCM)",
                        detail = "Stored encrypted intruder snapshot locally in private storage (${outcome.byteSize} bytes).",
                        packageName = targetPackageName,
                        authenticationMethod = authenticationMethod,
                        severity = SecurityEventSeverity.CRITICAL,
                        metadata = "encryptedPath=${outcome.relativePath}"
                    )
                }
                is IntruderCaptureOutcome.Skipped -> {
                    val entity = IntruderImageEntity(
                        timestampMillis = clockMillis(),
                        targetPackageName = targetPackageName,
                        consecutiveFailures = currentFailures,
                        authenticationMethod = authenticationMethod,
                        encryptedFilePath = null,
                        encryptionIvBase64 = null,
                        byteSize = 0L,
                        captureStatus = "EVENT_ONLY: ${outcome.reason}"
                    )
                    intruderImageDao?.insertIntruderImage(entity)
                }
                null -> Unit
            }
        }

        return IntruderEvaluationResult(
            countedAsFailure = true,
            consecutiveFailures = currentFailures,
            thresholdReached = thresholdReached,
            intruderTriggered = intruderTriggered,
            captureOutcome = captureOutcome,
            recordedEventId = failureEvent?.id
        )
    }

    private suspend fun enforceMaxStoredIntruderImages(maxAllowed: Int) {
        val dao = intruderImageDao ?: return
        val limit = maxAllowed.coerceIn(1, 100)
        val all = dao.getAllIntruderImagesSnapshot()
        if (all.size > limit) {
            val toDelete = all.drop(limit)
            for (old in toDelete) {
                secureFileRepository?.deleteEncryptedFileAtRelativePath(old.encryptedFilePath)
                dao.deleteIntruderImageById(old.id)
            }
        }
    }

    suspend fun deleteAllIntruderRecordsAndEncryptedFiles() {
        val dao = intruderImageDao ?: return
        val all = dao.getAllIntruderImagesSnapshot()
        for (item in all) {
            secureFileRepository?.deleteEncryptedFileAtRelativePath(item.encryptedFilePath)
        }
        dao.clearAllIntruderImages()
    }
}
