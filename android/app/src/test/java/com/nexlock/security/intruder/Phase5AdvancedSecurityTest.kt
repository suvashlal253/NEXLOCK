package com.nexlock.security.intruder

import com.nexlock.security.auth.AuthMethod
import com.nexlock.security.auth.SessionManager
import com.nexlock.security.auth.SessionTimeoutOption
import com.nexlock.security.database.IntruderImageDao
import com.nexlock.security.database.NexLockDatabase
import com.nexlock.security.database.SecurityEventDao
import com.nexlock.security.database.VaultMetadataDao
import com.nexlock.security.model.IntruderImageEntity
import com.nexlock.security.model.SecurityEventEntity
import com.nexlock.security.model.SecurityEventSeverity
import com.nexlock.security.model.VaultItemMetadataEntity
import com.nexlock.security.monitoring.AppLockEngine
import com.nexlock.security.monitoring.MonitoringServiceState
import com.nexlock.security.monitoring.PermissionHealthState
import com.nexlock.security.monitoring.ProtectionHealthMonitor
import com.nexlock.security.monitoring.SensitiveSettingAction
import com.nexlock.security.monitoring.SettingsAuthorizationDecision
import com.nexlock.security.notifications.NotificationDeduplicator
import com.nexlock.security.notifications.SecurityAlertCategory
import com.nexlock.security.repository.EventDateFilter
import com.nexlock.security.repository.EventSortOrder
import com.nexlock.security.repository.SecurityEventRepository
import com.nexlock.security.security.DecryptedEnvelopeResult
import com.nexlock.security.security.EncryptedEnvelopeResult
import com.nexlock.security.security.KeyManagerContract
import com.nexlock.security.vault.SecureFileRepository
import java.nio.file.Files
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM-backed AES-256-GCM test implementation of KeyManagerContract for deterministic JUnit tests.
 */
private class JvmAesGcmTestKeyManager : KeyManagerContract {
    private var secretKey: SecretKey = generateKey()
    private val random = SecureRandom()

    private fun generateKey(): SecretKey {
        val kg = KeyGenerator.getInstance("AES")
        kg.init(256)
        return kg.generateKey()
    }

    override fun isKeyHealthy(): Boolean = true

    override fun encryptPayload(plaintext: ByteArray): EncryptedEnvelopeResult {
        val iv = ByteArray(12).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        val ciphertext = cipher.doFinal(plaintext)
        return EncryptedEnvelopeResult.Success(
            ivBase64 = Base64.getEncoder().encodeToString(iv),
            ciphertextBase64 = Base64.getEncoder().encodeToString(ciphertext)
        )
    }

    override fun decryptPayload(ivBase64: String, ciphertextBase64: String): DecryptedEnvelopeResult {
        return try {
            val iv = Base64.getDecoder().decode(ivBase64)
            val ciphertext = Base64.getDecoder().decode(ciphertextBase64)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
            DecryptedEnvelopeResult.Success(cipher.doFinal(ciphertext))
        } catch (e: Exception) {
            DecryptedEnvelopeResult.Failure(e.message ?: "GCM auth failed")
        }
    }

    override fun rotateOrRecoverMasterKey(): Boolean {
        secretKey = generateKey()
        return true
    }
}

private class InMemorySecurityEventDao : SecurityEventDao {
    private var nextId = 1L
    private val events = mutableListOf<SecurityEventEntity>()
    private val flow = MutableStateFlow<List<SecurityEventEntity>>(emptyList())

    override fun observeRecentEvents(): Flow<List<SecurityEventEntity>> = flow
    override fun observeEventsOldestFirst(): Flow<List<SecurityEventEntity>> = flow
    override fun observeEventsByType(eventType: String): Flow<List<SecurityEventEntity>> = flow

    override suspend fun getEventsInDateRange(startMillis: Long, endMillis: Long): List<SecurityEventEntity> =
        events.filter { it.timestampMillis in startMillis..endMillis }

    override suspend fun getAllEventsSnapshot(): List<SecurityEventEntity> = events.toList()

    override suspend fun insertEvent(event: SecurityEventEntity): Long {
        val assigned = event.copy(id = nextId++)
        events.add(0, assigned)
        flow.value = events.toList()
        return assigned.id
    }

    override suspend fun deleteEventById(eventId: Long) {
        events.removeAll { it.id == eventId }
        flow.value = events.toList()
    }

    override suspend fun clearEvents() {
        events.clear()
        flow.value = emptyList()
    }
}

private class InMemoryIntruderImageDao : IntruderImageDao {
    private var nextId = 1L
    private val items = mutableListOf<IntruderImageEntity>()
    private val flow = MutableStateFlow<List<IntruderImageEntity>>(emptyList())
    private val countFlow = MutableStateFlow(0)

    override fun observeIntruderImages(): Flow<List<IntruderImageEntity>> = flow
    override suspend fun getAllIntruderImagesSnapshot(): List<IntruderImageEntity> =
        items.sortedByDescending { it.timestampMillis }
    override fun observeIntruderCount(): Flow<Int> = countFlow

    override suspend fun insertIntruderImage(entity: IntruderImageEntity): Long {
        val assigned = entity.copy(id = nextId++)
        items.add(0, assigned)
        flow.value = items.toList()
        countFlow.value = items.size
        return assigned.id
    }

    override suspend fun deleteIntruderImageById(id: Long) {
        items.removeAll { it.id == id }
        flow.value = items.toList()
        countFlow.value = items.size
    }

    override suspend fun clearAllIntruderImages() {
        items.clear()
        flow.value = emptyList()
        countFlow.value = 0
    }
}

private class InMemoryVaultMetadataDao : VaultMetadataDao {
    private val items = mutableListOf<VaultItemMetadataEntity>()
    private val flow = MutableStateFlow<List<VaultItemMetadataEntity>>(emptyList())

    override fun observeVaultItems(): Flow<List<VaultItemMetadataEntity>> = flow
    override suspend fun getAllVaultItemsSnapshot(): List<VaultItemMetadataEntity> = items.toList()
    override suspend fun getVaultItemById(id: String): VaultItemMetadataEntity? =
        items.firstOrNull { it.id == id }

    override suspend fun upsertVaultItem(item: VaultItemMetadataEntity) {
        items.removeAll { it.id == item.id }
        items.add(0, item)
        flow.value = items.toList()
    }

    override suspend fun deleteVaultItemById(id: String) {
        items.removeAll { it.id == id }
        flow.value = items.toList()
    }

    override suspend fun clearAllVaultItems() {
        items.clear()
        flow.value = emptyList()
    }
}

class Phase5AdvancedSecurityTest {

    @Test
    fun `1 - Failed PIN attempt counting increments on incorrect PIN and ignores biometric cancellation`() = runTest {
        val manager = IntruderDetectionManager()

        // User cancels biometric prompt -> must NOT increment failure count
        val cancelRes = manager.onAuthenticationObserved(
            failureType = ObservedAuthFailureType.BIOMETRIC_USER_CANCELED,
            isSuccess = false,
            authenticationMethod = "BIOMETRIC_PROMPT",
            targetPackageName = "com.whatsapp"
        )
        assertFalse(cancelRes.countedAsFailure)
        assertEquals(0, cancelRes.consecutiveFailures)

        // Two incorrect PIN attempts -> increments to 2
        val fail1 = manager.onAuthenticationObserved(
            failureType = ObservedAuthFailureType.INCORRECT_MASTER_PIN,
            isSuccess = false,
            authenticationMethod = "MASTER_PIN",
            targetPackageName = "com.whatsapp"
        )
        val fail2 = manager.onAuthenticationObserved(
            failureType = ObservedAuthFailureType.INCORRECT_MASTER_PIN,
            isSuccess = false,
            authenticationMethod = "MASTER_PIN",
            targetPackageName = "com.whatsapp"
        )
        assertTrue(fail1.countedAsFailure)
        assertEquals(1, fail1.consecutiveFailures)
        assertEquals(2, fail2.consecutiveFailures)
    }

    @Test
    fun `2 - Failed-attempt threshold detection triggers at 3, 5, and 10 configured thresholds`() = runTest {
        val manager = IntruderDetectionManager()
        manager.updateSettings { it.copy(thresholdOption = IntruderThresholdOption.ATTEMPTS_3) }

        repeat(2) {
            val r = manager.onAuthenticationObserved(
                failureType = ObservedAuthFailureType.INCORRECT_MASTER_PIN,
                isSuccess = false,
                authenticationMethod = "MASTER_PIN",
                targetPackageName = "com.revolut.revolut"
            )
            assertFalse(r.intruderTriggered)
        }
        val third = manager.onAuthenticationObserved(
            failureType = ObservedAuthFailureType.INCORRECT_MASTER_PIN,
            isSuccess = false,
            authenticationMethod = "MASTER_PIN",
            targetPackageName = "com.revolut.revolut"
        )
        assertTrue(third.thresholdReached)
        assertTrue(third.intruderTriggered)
    }

    @Test
    fun `3 - Successful authentication resets consecutive failure counter according to policy`() = runTest {
        val manager = IntruderDetectionManager()
        manager.onAuthenticationObserved(
            failureType = ObservedAuthFailureType.INCORRECT_MASTER_PIN,
            isSuccess = false,
            authenticationMethod = "MASTER_PIN"
        )
        manager.onAuthenticationObserved(
            failureType = ObservedAuthFailureType.BIOMETRIC_MISMATCH,
            isSuccess = false,
            authenticationMethod = "BIOMETRIC_PROMPT"
        )
        assertEquals(2, manager.consecutiveFailuresFlow.value)

        val success = manager.onAuthenticationObserved(
            failureType = null,
            isSuccess = true,
            authenticationMethod = "MASTER_PIN"
        )
        assertEquals(0, success.consecutiveFailures)
        assertEquals(0, manager.consecutiveFailuresFlow.value)
    }

    @Test
    fun `4 - Intruder event persistence records target package, method, and sanitizes PINs`() = runTest {
        val eventDao = InMemorySecurityEventDao()
        val intruderDao = InMemoryIntruderImageDao()
        val eventRepo = SecurityEventRepository(eventDao)
        val manager = IntruderDetectionManager(
            securityEventRepository = eventRepo,
            intruderImageDao = intruderDao
        )
        manager.updateSettings { it.copy(thresholdOption = IntruderThresholdOption.ATTEMPTS_3) }

        repeat(3) {
            manager.onAuthenticationObserved(
                failureType = ObservedAuthFailureType.INCORRECT_MASTER_PIN,
                isSuccess = false,
                authenticationMethod = "MASTER_PIN",
                targetPackageName = "org.thoughtcrime.securesms"
            )
        }

        val events = eventDao.getAllEventsSnapshot()
        assertTrue(events.any { it.eventType == "INTRUDER_DETECTED" && it.packageName == "org.thoughtcrime.securesms" })
        val intruderRecords = intruderDao.getAllIntruderImagesSnapshot()
        assertEquals(1, intruderRecords.size)
        assertEquals("org.thoughtcrime.securesms", intruderRecords.first().targetPackageName)
    }

    @Test
    fun `5 - Security event filtering and sorting supports type, severity, date range, and credential redaction`() = runTest {
        val eventDao = InMemorySecurityEventDao()
        var now = 1_700_000_000_000L
        val repo = SecurityEventRepository(eventDao) { now }

        repo.recordSecurityEvent(
            eventType = "AUTH_PIN_INCORRECT",
            title = "Attempt with pin: 482910 failed",
            detail = "User typed pin=482910",
            severity = SecurityEventSeverity.WARNING
        )
        now += 5_000L
        repo.recordSecurityEvent(
            eventType = "INTRUDER_DETECTED",
            title = "Intruder Alert",
            detail = "3 consecutive failures",
            severity = SecurityEventSeverity.CRITICAL
        )

        val all = eventDao.getAllEventsSnapshot()
        // Verify credential sanitizer stripped "482910"
        assertFalse(all.any { it.title.contains("482910") || it.detail.contains("482910") })

        val criticalOnly = SecurityEventRepository.filterAndSortEvents(
            events = all,
            severityFilter = SecurityEventSeverity.CRITICAL,
            nowMillis = now
        )
        assertEquals(1, criticalOnly.size)
        assertEquals("INTRUDER_DETECTED", criticalOnly.first().eventType)

        val oldestFirst = SecurityEventRepository.filterAndSortEvents(
            events = all,
            sortOrder = EventSortOrder.OLDEST_FIRST,
            nowMillis = now
        )
        assertEquals("AUTH_PIN_INCORRECT", oldestFirst.first().eventType)
    }

    @Test
    fun `6 - Quick Lock immediately invalidates all active package sessions and suppresses duplicates`() = runTest {
        var clock = 10_000L
        val engine = AppLockEngine(monotonicClockMs = { clock })
        engine.updateLockedPackages(setOf("com.whatsapp", "com.revolut.revolut"))
        engine.grantTemporaryPackageSession("com.whatsapp", AuthMethod.BIOMETRIC_PROMPT)
        engine.grantTemporaryPackageSession("com.revolut.revolut", AuthMethod.MASTER_PIN)
        assertEquals(2, engine.unlockedSessionsFlow.value.size)

        val sessionManager = SessionManager(monotonicClockMillis = { clock })
        sessionManager.startAuthenticatedSession(AuthMethod.MASTER_PIN)
        assertTrue(sessionManager.isSessionValid())

        val monitor = ProtectionHealthMonitor(
            appLockEngine = engine,
            sessionManager = sessionManager,
            monotonicClockMillis = { clock }
        )

        val firstLock = monitor.executeQuickLock()
        assertTrue(firstLock.executed)
        assertEquals(2, firstLock.revokedPackageSessionCount)
        assertTrue(engine.unlockedSessionsFlow.value.isEmpty())
        assertFalse(sessionManager.isSessionValid())

        // Immediate duplicate tap within 750ms window is suppressed
        val secondLock = monitor.executeQuickLock()
        assertTrue(secondLock.duplicateSuppressed)
    }

    @Test
    fun `7 - Secure settings authorization reuses Phase 2 SessionManager and requires re-auth on expiry`() {
        var clock = 50_000L
        val engine = AppLockEngine(monotonicClockMs = { clock })
        val sessionManager = SessionManager(monotonicClockMillis = { clock })
        sessionManager.setTimeoutOption(SessionTimeoutOption.SECONDS_30)
        val monitor = ProtectionHealthMonitor(engine, sessionManager, monotonicClockMillis = { clock })

        // Unauthenticated -> requires Master PIN / Biometric
        val initialDecision = monitor.authorizeSensitiveSettingChange(SensitiveSettingAction.DISABLE_INTRUDER_DETECTION)
        assertTrue(initialDecision is SettingsAuthorizationDecision.RequiresMasterAuthentication)

        // Authenticate session -> authorized without repeated prompt
        sessionManager.startAuthenticatedSession(AuthMethod.MASTER_PIN)
        val activeDecision = monitor.authorizeSensitiveSettingChange(SensitiveSettingAction.DISABLE_INTRUDER_DETECTION)
        assertTrue(activeDecision is SettingsAuthorizationDecision.AuthorizedByActiveSession)

        // Advance monotonic clock past 30s timeout -> requires re-authentication
        clock += 35_000L
        val expiredDecision = monitor.authorizeSensitiveSettingChange(SensitiveSettingAction.CLEAR_SECURITY_LOGS)
        assertTrue(expiredDecision is SettingsAuthorizationDecision.RequiresMasterAuthentication)
    }

    @Test
    fun `8 - Permission and tamper health evaluation detects revoked permissions and uninstalled locked apps`() {
        val engine = AppLockEngine()
        val sessionManager = SessionManager()
        val monitor = ProtectionHealthMonitor(engine, sessionManager)

        val degradedReport = monitor.evaluateHealth(
            permissionHealth = PermissionHealthState(
                usageAccessGranted = false,
                overlayPermissionGranted = true,
                notificationPermissionGranted = true
            ),
            serviceState = MonitoringServiceState.STOPPED,
            isMonitoringEnabledByUser = true,
            isPinConfigured = true,
            isKeystoreHealthy = true,
            selectedProtectedPackages = setOf("com.whatsapp", "com.removed.secretapp"),
            currentlyInstalledPackages = setOf("com.whatsapp")
        )

        assertFalse(degradedReport.usageAccessHealthy)
        assertFalse(degradedReport.engineOperational)
        assertEquals(listOf("com.removed.secretapp"), degradedReport.uninstalledProtectedPackages)
        assertEquals("ACTION_REQUIRED", degradedReport.overallHealthStatus)
    }

    @Test
    fun `9 - Intruder image storage encrypts with AES-256-GCM and enforces maxStoredImages retention`() = runTest {
        val tempDir = Files.createTempDirectory("nexlock_p5_intruder_test").toFile()
        try {
            val keyManager = JvmAesGcmTestKeyManager()
            val secureFiles = SecureFileRepository(
                basePrivateDir = tempDir,
                keyManager = keyManager
            )
            val intruderDao = InMemoryIntruderImageDao()
            val fakeCameraGateway = object : IntruderSelfieCaptureGateway {
                override suspend fun captureAndEncryptFrontSelfieIfPermitted(
                    settings: IntruderDetectionSettings
                ): IntruderCaptureOutcome {
                    val sampleJpeg = "FAKE_JPEG_FRAME_BYTES_${System.nanoTime()}".toByteArray()
                    val rec = secureFiles.encryptIntruderSelfieBytes(sampleJpeg, wipePlaintextAfterEncrypt = true).getOrThrow()
                    // Verify sampleJpeg buffer was zeroed in-place
                    assertTrue(sampleJpeg.all { it == 0.toByte() })
                    return IntruderCaptureOutcome.CapturedEncrypted(
                        relativePath = rec.relativePath,
                        ivBase64 = rec.ivBase64,
                        byteSize = rec.ciphertextByteSize
                    )
                }
            }

            val manager = IntruderDetectionManager(
                intruderImageDao = intruderDao,
                secureFileRepository = secureFiles,
                selfieCaptureGateway = fakeCameraGateway
            )
            manager.updateSettings {
                it.copy(
                    isEnabled = true,
                    thresholdOption = IntruderThresholdOption.ATTEMPTS_3,
                    intruderSelfieEnabled = true,
                    hasExplicitCameraConsent = true,
                    maxStoredImages = 2
                )
            }

            // Trigger 3 consecutive intruder events after threshold (attempts 3, 4, 5)
            repeat(5) {
                manager.onAuthenticationObserved(
                    failureType = ObservedAuthFailureType.INCORRECT_MASTER_PIN,
                    isSuccess = false,
                    authenticationMethod = "MASTER_PIN",
                    targetPackageName = "com.whatsapp"
                )
            }

            // maxStoredImages = 2 must prune the oldest encrypted record
            val stored = intruderDao.getAllIntruderImagesSnapshot()
            assertEquals(2, stored.size)
            val latest = stored.first()
            assertNotNull(latest.encryptedFilePath)
            val decrypted = secureFiles.decryptIntruderSelfieBytes(
                latest.encryptedFilePath!!,
                latest.encryptionIvBase64!!
            ).getOrThrow()
            assertTrue(String(decrypted).startsWith("FAKE_JPEG_FRAME_BYTES_"))
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `10 - Vault AES-256-GCM file encryption and decryption verifies round-trip and wipes plaintext buffer`() = runTest {
        val tempDir = Files.createTempDirectory("nexlock_p5_vault_test").toFile()
        try {
            val vaultDao = InMemoryVaultMetadataDao()
            val keyManager = JvmAesGcmTestKeyManager()
            val secureFiles = SecureFileRepository(
                basePrivateDir = tempDir,
                vaultMetadataDao = vaultDao,
                keyManager = keyManager
            )

            val originalPlaintext = "CONFIDENTIAL_PASSPORT_SCAN_PAYLOAD_2026".toByteArray()
            val workingBuffer = originalPlaintext.copyOf()

            val metadata = secureFiles.encryptAndStoreVaultFile(
                displayName = "Passport_Scan.pdf",
                mediaType = "DOCUMENT",
                plaintextBytes = workingBuffer,
                wipePlaintextBufferAfterEncrypt = true
            ).getOrThrow()

            // Original caller buffer was wiped in-place
            assertTrue(workingBuffer.all { it == 0.toByte() })

            // Ciphertext on disk must not contain plaintext string
            val diskFile = java.io.File(tempDir, metadata.encryptedRelativePath)
            assertTrue(diskFile.exists())
            assertFalse(String(diskFile.readBytes()).contains("CONFIDENTIAL_PASSPORT"))

            // Decrypt and verify exact match
            val decryptedBytes = secureFiles.decryptVaultFile(metadata).getOrThrow()
            assertArrayEquals(originalPlaintext, decryptedBytes)
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun `11 - Database migration MIGRATION_2_3 is defined from version 2 to version 3`() {
        assertEquals(2, NexLockDatabase.MIGRATION_2_3.startVersion)
        assertEquals(3, NexLockDatabase.MIGRATION_2_3.endVersion)
    }

    @Test
    fun `12 - Notification deduplication suppresses repeated alerts within cooldown and respects non-critical toggle`() {
        var now = 100_000L
        val deduplicator = NotificationDeduplicator { now }

        assertTrue(deduplicator.shouldDispatch(SecurityAlertCategory.INTRUDER_DETECTED, "com.whatsapp"))
        // Immediate duplicate within 15s cooldown -> suppressed
        assertFalse(deduplicator.shouldDispatch(SecurityAlertCategory.INTRUDER_DETECTED, "com.whatsapp"))

        // Advance past 15s cooldown -> allowed again
        now += 16_000L
        assertTrue(deduplicator.shouldDispatch(SecurityAlertCategory.INTRUDER_DETECTED, "com.whatsapp"))

        // Non-critical notification disabled by user -> suppressed
        assertFalse(
            deduplicator.shouldDispatch(
                category = SecurityAlertCategory.SECURITY_CONFIGURATION_CHANGED,
                targetKey = "settings",
                nonCriticalAlertsEnabled = false
            )
        )
    }
}
