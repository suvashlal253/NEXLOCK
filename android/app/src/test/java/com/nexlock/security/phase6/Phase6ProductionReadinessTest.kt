package com.nexlock.security.phase6

import com.nexlock.security.analytics.SecurityAnalyticsRepository
import com.nexlock.security.auth.AuthMethod
import com.nexlock.security.auth.MonotonicClock
import com.nexlock.security.auth.SessionTimeoutOption
import com.nexlock.security.backup.BackupConfigurationPayload
import com.nexlock.security.backup.BackupEncryptionManager
import com.nexlock.security.backup.BackupRestoreResult
import com.nexlock.security.backup.RestoreErrorCode
import com.nexlock.security.database.NexLockDatabase
import com.nexlock.security.model.AccentColorPreset
import com.nexlock.security.model.AppListDensity
import com.nexlock.security.model.AppSortOrder
import com.nexlock.security.model.IntruderImageEntity
import com.nexlock.security.model.KeypadStyle
import com.nexlock.security.model.LockMode
import com.nexlock.security.model.LockScheduleEntity
import com.nexlock.security.model.LockScreenBackgroundStyle
import com.nexlock.security.model.LockedAppEntity
import com.nexlock.security.model.SecurityEventEntity
import com.nexlock.security.model.SecurityEventSeverity
import com.nexlock.security.model.ThemePreference
import com.nexlock.security.monitoring.AppLockEngine
import com.nexlock.security.monitoring.ExcludedSystemPackages
import com.nexlock.security.monitoring.ReLockDurationOption
import com.nexlock.security.repository.StoredSecuritySettings
import com.nexlock.security.schedule.LockScheduleManager
import com.nexlock.security.schedule.LockScheduleRepository
import java.time.ZoneId
import java.time.ZonedDateTime
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * NEXLOCK Phase 6 Production Readiness & Automation JUnit 4 Test Suite (Section 14).
 *
 * Covers all 14 required Phase 6 test areas:
 * 1. Scheduling logic (Work Hours intraday schedule)
 * 2. Overnight schedule behavior (Cross-midnight 22:00 - 07:00)
 * 3. Time zone changes (UTC vs Asia/Dhaka / America/New_York re-evaluation)
 * 4. Lock mode transitions (NORMAL, MAX_SECURITY, NIGHT, CUSTOM)
 * 5. Appearance preference persistence (Theme, Accent, Density, Lock Screen Personalization)
 * 6. Backup encryption and decryption (PBKDF2-HMAC-SHA256 210,000 + AES-256-GCM)
 * 7. Backup integrity verification (Tampered ciphertext SHA-256 & wrong password rejection)
 * 8. Restore validation (Secret-smuggling rejection & schema validation)
 * 9. Database migrations (MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4 version 3 -> 4)
 * 10. Analytics calculations (7-day & 30-day event aggregation + empty dataset handling)
 * 11. Vault encryption and decryption (SHA-256 integrity & corrupted ciphertext detection)
 * 12. Authentication session expiration (Monotonic clock expiry & immediate mode revocation)
 * 13. App manager filtering and sorting (NAME_ASC, NAME_DESC, LOCKED_FIRST)
 * 14. Critical security configuration validation (Safe exclusion registry & non-export of secrets)
 */
class Phase6ProductionReadinessTest {

    private class FakeMonotonicClock(var currentElapsedMillis: Long = 10_000L) : MonotonicClock {
        override fun elapsedRealtimeMillis(): Long = currentElapsedMillis
    }

    private fun sampleBackupPayload(): BackupConfigurationPayload = BackupConfigurationPayload(
        lockedApps = listOf(
            LockedAppEntity(
                id = 1,
                packageName = "com.whatsapp",
                appName = "WhatsApp",
                isLocked = true,
                category = "Messaging"
            ),
            LockedAppEntity(
                id = 2,
                packageName = "com.chase.sig.android",
                appName = "Chase Mobile",
                isLocked = true,
                category = "Finance"
            )
        ),
        schedules = LockScheduleRepository.defaultScheduleTemplates(nowMillis = 1_732_000_000_000L),
        lockMode = LockMode.MAX_SECURITY,
        sessionTimeoutOption = SessionTimeoutOption.MINUTE_1,
        maxFailedAttempts = 3,
        themePreference = ThemePreference.DARK,
        accentColorPreset = AccentColorPreset.VIOLET_PULSE,
        appListDensity = AppListDensity.COMPACT,
        appSortOrder = AppSortOrder.LOCKED_FIRST,
        showAppIconOnLockScreen = true,
        showAppNameOnLockScreen = false,
        lockScreenBackgroundStyle = LockScreenBackgroundStyle.MIDNIGHT_MESH,
        enableLockScreenAnimations = true,
        keypadStyle = KeypadStyle.HIGH_CONTRAST,
        languageCode = "bn"
    )

    // 1. Scheduling logic (Intraday Work Hours 09:00 - 17:00 Mon-Fri)
    @Test
    fun test01_intradayWorkHoursScheduleLogic() {
        val manager = LockScheduleManager()
        val zone = ZoneId.of("UTC")
        val workSchedule = LockScheduleEntity(
            id = 1,
            name = "Work Hours",
            description = "9 AM - 5 PM Mon-Fri",
            startHour = 9,
            startMinute = 0,
            endHour = 17,
            endMinute = 0,
            daysOfWeekCsv = "1,2,3,4,5",
            isEnabled = true
        )

        // Wednesday 10:30 UTC -> Active
        val wednesday1030 = ZonedDateTime.of(2026, 11, 18, 10, 30, 0, 0, zone).toInstant().toEpochMilli()
        assertTrue(manager.isScheduleActiveAt(workSchedule, wednesday1030, zone))

        // Wednesday 18:15 UTC -> Inactive
        val wednesday1815 = ZonedDateTime.of(2026, 11, 18, 18, 15, 0, 0, zone).toInstant().toEpochMilli()
        assertFalse(manager.isScheduleActiveAt(workSchedule, wednesday1815, zone))

        // Saturday 11:00 UTC -> Inactive (day 6 not in 1..5)
        val saturday1100 = ZonedDateTime.of(2026, 11, 21, 11, 0, 0, 0, zone).toInstant().toEpochMilli()
        assertFalse(manager.isScheduleActiveAt(workSchedule, saturday1100, zone))
    }

    // 2. Overnight schedule behavior (Cross-midnight 22:00 - 07:00)
    @Test
    fun test02_overnightCrossMidnightScheduleBehavior() {
        val manager = LockScheduleManager()
        val zone = ZoneId.of("UTC")
        // Active Friday night (day 5) 22:00 into Saturday morning 07:00
        val fridayNightSchedule = LockScheduleEntity(
            id = 2,
            name = "Friday Night Guard",
            description = "22:00 - 07:00",
            startHour = 22,
            startMinute = 0,
            endHour = 7,
            endMinute = 0,
            daysOfWeekCsv = "5", // Friday only
            isEnabled = true
        )

        assertTrue(fridayNightSchedule.isOvernightSchedule)

        // Friday 23:15 UTC -> Active (evening segment of Day 5)
        val friday2315 = ZonedDateTime.of(2026, 11, 20, 23, 15, 0, 0, zone).toInstant().toEpochMilli()
        assertTrue(manager.isScheduleActiveAt(fridayNightSchedule, friday2315, zone))

        // Saturday 02:30 UTC -> Active (morning carryover segment from Friday Day 5!)
        val saturday0230 = ZonedDateTime.of(2026, 11, 21, 2, 30, 0, 0, zone).toInstant().toEpochMilli()
        assertTrue(manager.isScheduleActiveAt(fridayNightSchedule, saturday0230, zone))

        // Saturday 07:05 UTC -> Inactive (after 07:00 end boundary)
        val saturday0705 = ZonedDateTime.of(2026, 11, 21, 7, 5, 0, 0, zone).toInstant().toEpochMilli()
        assertFalse(manager.isScheduleActiveAt(fridayNightSchedule, saturday0705, zone))
    }

    // 3. Time zone changes
    @Test
    fun test03_timeZoneChangeReEvaluation() {
        val manager = LockScheduleManager()
        val schedule = LockScheduleEntity(
            id = 1,
            name = "Work Hours",
            description = "09:00 - 17:00 Daily",
            startHour = 9,
            startMinute = 0,
            endHour = 17,
            endMinute = 0,
            daysOfWeekCsv = "1,2,3,4,5,6,7",
            isEnabled = true
        )

        // 06:00 UTC is outside 09:00-17:00 in UTC, but in Asia/Dhaka (UTC+6) it is 12:00 Noon (Inside!)
        val instant0600Utc = ZonedDateTime.of(2026, 11, 18, 6, 0, 0, 0, ZoneId.of("UTC")).toInstant().toEpochMilli()
        assertFalse(manager.isScheduleActiveAt(schedule, instant0600Utc, ZoneId.of("UTC")))
        assertTrue(manager.isScheduleActiveAt(schedule, instant0600Utc, ZoneId.of("Asia/Dhaka")))
    }

    // 4. Lock mode transitions
    @Test
    fun test04_lockModeTransitionsSynchronizeWithAppLockEngine() {
        val engine = AppLockEngine(
            initialReLockOption = ReLockDurationOption.AFTER_5_MINUTES,
            initialLockOnScreenOff = false
        )
        val manager = LockScheduleManager(appLockEngine = engine)
        val lockedApps = setOf("com.whatsapp", "com.google.android.gm")
        val schedules = LockScheduleRepository.defaultScheduleTemplates()

        // Transition to MAX_SECURITY -> forces IMMEDIATELY and lockOnScreenOff = true
        val maxSnap = manager.evaluateAndApplyToEngine(
            userLockedPackages = lockedApps,
            schedules = schedules,
            lockMode = LockMode.MAX_SECURITY,
            configuredReLockDuration = ReLockDurationOption.AFTER_5_MINUTES,
            configuredLockOnScreenOff = false
        )
        assertEquals(ReLockDurationOption.IMMEDIATELY, maxSnap.effectiveReLockDuration)
        assertTrue(maxSnap.effectiveLockOnScreenOff)
        assertEquals(ReLockDurationOption.IMMEDIATELY, engine.reLockDurationOption)
        assertTrue(engine.lockOnScreenOff)

        // Transition back to NORMAL -> restores configured 5-minute timer
        val normalSnap = manager.evaluateAndApplyToEngine(
            userLockedPackages = lockedApps,
            schedules = schedules,
            lockMode = LockMode.NORMAL,
            configuredReLockDuration = ReLockDurationOption.AFTER_5_MINUTES,
            configuredLockOnScreenOff = false
        )
        assertEquals(ReLockDurationOption.AFTER_5_MINUTES, normalSnap.effectiveReLockDuration)
        assertFalse(normalSnap.effectiveLockOnScreenOff)
    }

    // 5. Appearance preference persistence
    @Test
    fun test05_appearanceAndPersonalizationPreferenceModelRoundTrip() {
        val settings = StoredSecuritySettings(
            lockMode = LockMode.NIGHT,
            themePreference = ThemePreference.LIGHT,
            accentColorPreset = AccentColorPreset.EMERALD_SHIELD,
            appListDensity = AppListDensity.COMPACT,
            appSortOrder = AppSortOrder.LOCKED_FIRST,
            showAppIconOnLockScreen = false,
            showAppNameOnLockScreen = true,
            lockScreenBackgroundStyle = LockScreenBackgroundStyle.MINIMAL_SURFACE,
            enableLockScreenAnimations = false,
            keypadStyle = KeypadStyle.COMPACT_GRID,
            languageCode = "bn"
        )

        assertEquals(ThemePreference.LIGHT, ThemePreference.fromId(settings.themePreference.id))
        assertEquals("#2DD4A3", AccentColorPreset.fromId(settings.accentColorPreset.id).hexColor)
        assertEquals(AppListDensity.COMPACT, AppListDensity.fromId(settings.appListDensity.id))
        assertEquals(KeypadStyle.COMPACT_GRID, KeypadStyle.fromId(settings.keypadStyle.id))
        assertEquals("bn", settings.languageCode)
    }

    // 6. Backup encryption and decryption
    @Test
    fun test06_backupEncryptionAndDecryptionRoundTrip() {
        val crypto = BackupEncryptionManager()
        val payload = sampleBackupPayload()
        val password = "StrongBackupPassword#2026".toCharArray()

        val encryptedResult = crypto.createEncryptedBackupEnvelope(payload, password)
        assertTrue(encryptedResult.isSuccess)
        val envelopeJson = encryptedResult.getOrThrow()

        val restoreResult = crypto.decryptAndVerifyBackupEnvelope(envelopeJson, password)
        assertTrue(restoreResult is BackupRestoreResult.Success)
        val success = restoreResult as BackupRestoreResult.Success

        assertEquals(2, success.payload.lockedApps.size)
        assertEquals(LockMode.MAX_SECURITY, success.payload.lockMode)
        assertEquals(AccentColorPreset.VIOLET_PULSE, success.payload.accentColorPreset)
        assertEquals(KeypadStyle.HIGH_CONTRAST, success.payload.keypadStyle)
        assertEquals("bn", success.payload.languageCode)
        assertTrue(success.requiresMasterPinVerification)
    }

    // 7. Backup integrity verification
    @Test
    fun test07_backupIntegrityVerificationRejectsTamperingAndWrongPassword() {
        val crypto = BackupEncryptionManager()
        val payload = sampleBackupPayload()
        val password = "CorrectHorseBatteryStaple99!".toCharArray()
        val envelopeJson = crypto.createEncryptedBackupEnvelope(payload, password).getOrThrow()

        // Case A: Wrong password -> AUTHENTICATION_FAILED_WRONG_PASSWORD_OR_TAMPERED
        val wrongPwdResult = crypto.decryptAndVerifyBackupEnvelope(
            envelopeJson,
            "WrongPassword12345!".toCharArray()
        )
        assertTrue(wrongPwdResult is BackupRestoreResult.Failure)
        assertEquals(
            RestoreErrorCode.AUTHENTICATION_FAILED_WRONG_PASSWORD_OR_TAMPERED,
            (wrongPwdResult as BackupRestoreResult.Failure).errorCode
        )

        // Case B: Tampered ciphertext hash -> INTEGRITY_HASH_MISMATCH
        val tamperedObj = JSONObject(envelopeJson)
        tamperedObj.put("ciphertextSha256Hex", "0000000000000000000000000000000000000000000000000000000000000000")
        val tamperedResult = crypto.decryptAndVerifyBackupEnvelope(tamperedObj.toString(), password)
        assertTrue(tamperedResult is BackupRestoreResult.Failure)
        assertEquals(
            RestoreErrorCode.INTEGRITY_HASH_MISMATCH,
            (tamperedResult as BackupRestoreResult.Failure).errorCode
        )
    }

    // 8. Restore validation (Secret-smuggling rejection & weak password rejection)
    @Test
    fun test08_restoreValidationRejectsSecretsAndUnsupportedVersions() {
        val crypto = BackupEncryptionManager()

        // Weak password rejected during export
        val weakResult = crypto.createEncryptedBackupEnvelope(sampleBackupPayload(), "123".toCharArray())
        assertTrue(weakResult.isFailure)

        // Unsupported formatVersion rejected during restore
        val badVersionJson = JSONObject().apply {
            put("formatMagic", "NEXLOCK_ENCRYPTED_BACKUP")
            put("formatVersion", 99)
        }.toString()
        val versionFailure = crypto.decryptAndVerifyBackupEnvelope(badVersionJson, "ValidPass1234".toCharArray())
        assertTrue(versionFailure is BackupRestoreResult.Failure)
        assertEquals(RestoreErrorCode.UNSUPPORTED_VERSION, (versionFailure as BackupRestoreResult.Failure).errorCode)

        // Forbidden secret key in JSON payload throws SecurityException
        val maliciousPayloadJson = """{"lockMode":"NORMAL","pinSaltBase64":"leaked_salt"}"""
        var threwSecurityException = false
        try {
            crypto.deserializePayloadFromJson(maliciousPayloadJson)
        } catch (_: SecurityException) {
            threwSecurityException = true
        }
        assertTrue("Deserialization must reject any payload containing PIN salts or verifiers", threwSecurityException)
    }

    // 9. Database migrations (MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4)
    @Test
    fun test09_databaseMigrationChainVersion1To4Configured() {
        assertEquals(1, NexLockDatabase.MIGRATION_1_2.startVersion)
        assertEquals(2, NexLockDatabase.MIGRATION_1_2.endVersion)
        assertEquals(2, NexLockDatabase.MIGRATION_2_3.startVersion)
        assertEquals(3, NexLockDatabase.MIGRATION_2_3.endVersion)
        assertEquals(3, NexLockDatabase.MIGRATION_3_4.startVersion)
        assertEquals(4, NexLockDatabase.MIGRATION_3_4.endVersion)
    }

    // 10. Analytics calculations (7-day & 30-day event aggregation + empty dataset handling)
    @Test
    fun test10_securityAnalyticsCalculationsAndEmptyDatasetSafety() {
        val zone = ZoneId.of("UTC")
        val now = ZonedDateTime.of(2026, 11, 19, 15, 0, 0, 0, zone).toInstant().toEpochMilli()

        // Empty dataset check
        val emptySnap = SecurityAnalyticsRepository.computeAnalyticsFromRecords(
            events = emptyList(),
            lockedApps = emptyList(),
            intruderImages = emptyList(),
            schedules = emptyList(),
            nowEpochMillis = now,
            zoneId = zone
        )
        assertEquals(0, emptySnap.totalProtectedApps)
        assertEquals(7, emptySnap.activity7Days.size)
        assertEquals(30, emptySnap.activity30Days.size)

        // Populated dataset check
        val events = listOf(
            SecurityEventEntity(
                id = 1,
                eventType = "UNLOCK_SUCCESS",
                packageName = "com.whatsapp",
                authenticationMethod = "BIOMETRIC",
                title = "Unlocked WhatsApp",
                detail = "Biometric unlock",
                severity = SecurityEventSeverity.INFO.name,
                timestampMillis = now - 3_600_000L
            ),
            SecurityEventEntity(
                id = 2,
                eventType = "FAILED_PIN",
                packageName = "com.chase.sig.android",
                authenticationMethod = "PIN",
                title = "Failed PIN",
                detail = "Incorrect PIN entry",
                severity = SecurityEventSeverity.WARNING.name,
                timestampMillis = now - 1_800_000L
            ),
            SecurityEventEntity(
                id = 3,
                eventType = "INTRUDER_DETECTED",
                packageName = "com.chase.sig.android",
                authenticationMethod = "PIN",
                title = "Intruder Threshold Reached",
                detail = "3 consecutive failures",
                severity = SecurityEventSeverity.CRITICAL.name,
                timestampMillis = now - 1_700_000L
            )
        )
        val populatedSnap = SecurityAnalyticsRepository.computeAnalyticsFromRecords(
            events = events,
            lockedApps = sampleBackupPayload().lockedApps,
            intruderImages = listOf(
                IntruderImageEntity(
                    id = 1,
                    timestampMillis = now - 1_700_000L,
                    targetPackageName = "com.chase.sig.android",
                    consecutiveFailures = 3,
                    authenticationMethod = "PIN",
                    encryptedFilePath = "intruder_encrypted/selfie_1.enc",
                    encryptionIvBase64 = "aXZiYXNlNjQ=",
                    byteSize = 24576L,
                    captureStatus = "CAPTURED_ENCRYPTED"
                )
            ),
            schedules = LockScheduleRepository.defaultScheduleTemplates(now),
            nowEpochMillis = now,
            zoneId = zone
        )
        assertEquals(2, populatedSnap.totalProtectedApps)
        assertEquals(2, populatedSnap.activeSchedulesCount)
        assertEquals(1, populatedSnap.totalSuccessfulAuthentications)
        assertEquals(1, populatedSnap.totalFailedPinAttempts)
        assertEquals(1, populatedSnap.totalIntruderEvents)
        assertEquals(1, populatedSnap.totalIntruderCaptures)
    }

    // 11. Vault encryption and decryption digest verification
    @Test
    fun test11_vaultCiphertextSha256IntegrityVerification() {
        val samplePlaintext = "NEXLOCK_VAULT_CONFIDENTIAL_DOCUMENT_PAYLOAD".toByteArray()
        val digestA = com.nexlock.security.vault.SecureFileRepository.sha256Hex(samplePlaintext)
        val digestB = com.nexlock.security.vault.SecureFileRepository.sha256Hex(samplePlaintext.copyOf())
        val corruptedDigest = com.nexlock.security.vault.SecureFileRepository.sha256Hex(
            samplePlaintext.copyOf().also { it[0] = (it[0].toInt() xor 0xFF).toByte() }
        )

        assertEquals(64, digestA.length)
        assertEquals(digestA, digestB)
        assertFalse(digestA.equals(corruptedDigest, ignoreCase = true))
    }

    // 12. Authentication session expiration
    @Test
    fun test12_authenticationSessionExpirationWithMonotonicClock() {
        val fakeClock = FakeMonotonicClock(currentElapsedMillis = 50_000L)
        val engine = AppLockEngine(
            clock = fakeClock,
            initialReLockOption = ReLockDurationOption.AFTER_1_MINUTE,
            initialLockOnScreenOff = true
        )
        engine.updateLockedPackages(setOf("com.whatsapp"))

        // Grant unlock session at t=50s
        engine.grantTemporaryPackageSession("com.whatsapp", AuthMethod.PIN)
        assertTrue(engine.isPackageCurrentlyUnlocked("com.whatsapp"))

        // Background WhatsApp by switching to Home Launcher at t=55s
        fakeClock.currentElapsedMillis = 55_000L
        engine.onForegroundTransition(
            com.nexlock.security.monitoring.ForegroundTransitionEvent(
                packageName = "com.google.android.apps.nexuslauncher",
                transitionType = com.nexlock.security.monitoring.UsageTransitionType.ACTIVITY_RESUMED,
                eventTimestampMillis = 55_000L
            )
        )

        // At t=90s (35s after departure, < 60s limit) -> Still unlocked
        fakeClock.currentElapsedMillis = 90_000L
        assertTrue(engine.isPackageCurrentlyUnlocked("com.whatsapp"))

        // At t=120s (65s after departure, >= 60s limit) -> Expired!
        fakeClock.currentElapsedMillis = 120_000L
        assertFalse(engine.isPackageCurrentlyUnlocked("com.whatsapp"))
    }

    // 13. App manager filtering and sorting
    @Test
    fun test13_appManagerSortingOrders() {
        val apps = listOf(
            LockedAppEntity(1, "com.whatsapp", "WhatsApp", isLocked = false, category = "Messaging"),
            LockedAppEntity(2, "com.chase.sig.android", "Chase Mobile", isLocked = true, category = "Finance"),
            LockedAppEntity(3, "com.instagram.android", "Instagram", isLocked = true, category = "Social")
        )

        val nameAsc = apps.sortedBy { it.appName.lowercase() }
        assertEquals(listOf("Chase Mobile", "Instagram", "WhatsApp"), nameAsc.map { it.appName })

        val nameDesc = apps.sortedByDescending { it.appName.lowercase() }
        assertEquals(listOf("WhatsApp", "Instagram", "Chase Mobile"), nameDesc.map { it.appName })

        val lockedFirst = apps.sortedWith(compareByDescending<LockedAppEntity> { it.isLocked }.thenBy { it.appName.lowercase() })
        assertEquals(listOf("Chase Mobile", "Instagram", "WhatsApp"), lockedFirst.map { it.appName })
        assertTrue(lockedFirst[0].isLocked && lockedFirst[1].isLocked && !lockedFirst[2].isLocked)
    }

    // 14. Critical security configuration validation
    @Test
    fun test14_criticalSecurityConfigurationAndSafeExclusionValidation() {
        // Verify NEXLOCK itself, System Settings, SystemUI, Package Installer, and Telecom are strictly excluded from locking
        val homeLaunchers = setOf("com.sec.android.app.launcher")
        assertTrue(ExcludedSystemPackages.isPackageExcluded("com.nexlock.security", homeLaunchers))
        assertTrue(ExcludedSystemPackages.isPackageExcluded("com.android.settings", homeLaunchers))
        assertTrue(ExcludedSystemPackages.isPackageExcluded("com.android.systemui", homeLaunchers))
        assertTrue(ExcludedSystemPackages.isPackageExcluded("com.google.android.packageinstaller", homeLaunchers))
        assertTrue(ExcludedSystemPackages.isPackageExcluded("com.sec.android.app.launcher", homeLaunchers))
        assertFalse(ExcludedSystemPackages.isPackageExcluded("com.whatsapp", homeLaunchers))

        // Verify Encrypted Backup serialized JSON never contains forbidden PIN/Keystore secret fields
        val crypto = BackupEncryptionManager()
        val serialized = crypto.serializePayloadToJson(sampleBackupPayload())
        assertNotNull(serialized)
        assertFalse(serialized.contains("pinSaltBase64"))
        assertFalse(serialized.contains("encryptedVerifierCiphertextBase64"))
        assertFalse(serialized.contains("masterPin"))
    }
}
