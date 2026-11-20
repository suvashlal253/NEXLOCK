export interface KotlinSourceFile {
  path: string;
  moduleGroup: string;
  description: string;
  code: string;
}

export const KOTLIN_SOURCE_FILES: KotlinSourceFile[] = [
  {
    path: 'android/app/src/main/java/com/nexlock/security/schedule/LockScheduleManager.kt',
    moduleGroup: 'Phase 6 · Smart Lock Scheduler & Lock Modes',
    description:
      'Evaluates intraday (09:00–17:00) and cross-midnight (22:00–07:00) schedules with previous-day carryover, handles time-zone and clock shifts, synchronizes effective packages with AppLockEngine across 4 Lock Modes, and schedules inexact AlarmManager window transitions without requiring SCHEDULE_EXACT_ALARM.',
    code: `class LockScheduleManager(
    private val scheduleRepository: LockScheduleRepository,
    private val appLockEngine: AppLockEngine? = null,
    private val zoneIdProvider: () -> ZoneId = { ZoneId.systemDefault() }
) {
    fun isScheduleActiveAt(schedule: LockScheduleEntity, dateTime: ZonedDateTime): Boolean {
        if (!schedule.isEnabled) return false
        val currentMinute = dateTime.hour * 60 + dateTime.minute
        return if (!schedule.isOvernightSchedule) {
            currentDay in activeDays && currentMinute in schedule.startMinuteOfDay until schedule.endMinuteOfDay
        } else {
            // Cross-midnight evaluation checks both tonight's window and yesterday's carryover window
            val startedTonight = currentDay in activeDays && currentMinute >= schedule.startMinuteOfDay
            val carriedFromYesterday = previousDay in activeDays && currentMinute < schedule.endMinuteOfDay
            startedTonight || carriedFromYesterday
        }
    }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/backup/EncryptedBackupManager.kt',
    moduleGroup: 'Phase 6 · PBKDF2 + AES-256-GCM Encrypted Backup & Restore',
    description:
      'Password-protected configuration backup and restore via Storage Access Framework (Uri). Uses PBKDF2WithHmacSHA256 (210,000 iterations + 128-bit salt) and AES/GCM/NoPadding (96-bit IV + 128-bit AEAD tag) with SHA-256 integrity checks. Strictly excludes PINs, verifiers, Keystore keys, and biometric data.',
    code: `class BackupEncryptionManager(
    private val secureRandom: SecureRandom = SecureRandom()
) {
    fun encryptPayload(payload: BackupConfigurationPayload, passphrase: CharArray): EncryptedBackupContainer {
        val salt = ByteArray(16).also { secureRandom.nextBytes(it) }
        val iv = ByteArray(12).also { secureRandom.nextBytes(it) }
        val secretKey = deriveAesKey(passphrase, salt, 210_000)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        val ciphertextWithTag = cipher.doFinal(plaintextBytes)
        // Verifies SHA-256 digests and rejects any payload containing forbidden authentication fields...
    }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/analytics/SecurityAnalyticsRepository.kt',
    moduleGroup: 'Phase 6 · Real 7-Day & 30-Day Security Analytics',
    description:
      'Computes real 7-day and 30-day security metrics directly from Room (security_events, locked_apps, intruder_images, lock_schedules) including daily trend series, most frequently targeted app, and recent unlock timestamps.',
    code: `class SecurityAnalyticsRepository(
    private val securityEventDao: SecurityEventDao,
    private val lockedAppsDao: LockedAppsDao,
    private val intruderImageDao: IntruderImageDao,
    private val lockScheduleDao: LockScheduleDao
) {
    fun observeAnalyticsSnapshot(): Flow<SecurityAnalyticsSnapshot> = combine(
        securityEventDao.observeRecentEvents(500),
        lockedAppsDao.observeAllLockedApps(),
        intruderImageDao.observeAllIntruderImages(),
        lockScheduleDao.observeAllSchedules()
    ) { events, lockedApps, intruderImages, schedules ->
        computeSnapshot(events, lockedApps, intruderImages, schedules, clockMillis())
    }
}`,
  },
  {
    path: 'android/app/src/test/java/com/nexlock/security/phase6/Phase6ProductionReadinessTest.kt',
    moduleGroup: 'Phase 6 · JUnit 4 Production Readiness Suite (14 Tests)',
    description:
      '14 JUnit 4 tests verifying schedule creation, cross-midnight evaluation, time-zone changes, Lock Modes, theme/personalization persistence, AES-256-GCM backup/restore round-trip, wrong password rejection, tampered backup rejection, real analytics, app sorting, uninstalled app recovery, and Room v3->v4 migration.',
    code: `class Phase6ProductionReadinessTest {
    @Test fun test2_crossMidnightScheduleEvaluatesEveningAndEarlyMorningCarryoverCorrectly() { ... }
    @Test fun test7_encryptedBackupAndRestoreRoundTripRestoresConfigurationAndExcludesSecrets() { ... }
    @Test fun test8_wrongBackupPasswordFailsCleanlyWithAuthenticationException() { ... }
    @Test fun test9_corruptedOrTamperedBackupFileIsRejectedSafely() { ... }
    @Test fun test13_roomMigrationV3ToV4PreservesExistingTablesAndCreatesLockSchedules() { ... }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/intruder/IntruderDetectionManager.kt',
    moduleGroup: 'Phase 5 · Intruder Detection System',
    description:
      'Coordinates FailedAttemptRepository, configurable 3/5/10 failed-attempt thresholds, biometric cancellation exclusion (USER_CANCELED ignored), SecurityEventRepository logging, and optional consented IntruderSelfieManager capture.',
    code: `class IntruderDetectionManager(
    private val failedAttemptRepository: FailedAttemptRepository,
    private val securityEventRepository: SecurityEventRepository,
    private val intruderSelfieManager: IntruderSelfieManager? = null,
    private val notificationManager: SecurityNotificationManager? = null
) {
    suspend fun recordFailedAuthentication(
        targetPackageName: String,
        authenticationMethod: String,
        isUserCanceledBiometric: Boolean = false,
        foregroundLifecycleOwner: LifecycleOwner? = null
    ): FailedAttemptOutcome {
        val outcome = failedAttemptRepository.recordFailedAttempt(
            targetPackageName = targetPackageName,
            authenticationMethod = authenticationMethod,
            isUserCancellation = isUserCanceledBiometric
        )
        // Logs FAILED_PIN / FAILED_BIOMETRIC and triggers INTRUDER_THRESHOLD_REACHED...
        return outcome
    }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/intruder/IntruderSelfieManager.kt',
    moduleGroup: 'Phase 5 · Consented CameraX Intruder Selfie',
    description:
      'Captures a single front-camera image via CameraX (ProcessCameraProvider + ImageCapture) only when user consent, CAMERA permission, and a foreground LifecycleOwner are active; encrypts via AES-256-GCM into filesDir/intruder_encrypted/. Falls back cleanly to EVENT_ONLY when backgrounded.',
    code: `class IntruderSelfieManager(
    private val appContext: Context,
    private val secureFileRepository: SecureFileRepository
) {
    suspend fun captureAndEncryptIntruderSelfie(
        lifecycleOwner: LifecycleOwner?,
        userConsented: Boolean,
        targetPackageName: String,
        authenticationMethod: String,
        failedAttemptCount: Int
    ): IntruderCaptureResult = withContext(Dispatchers.Main) {
        if (!userConsented) return@withContext eventOnly(IntruderCaptureFailureReason.USER_CONSENT_NOT_GRANTED)
        if (!isCameraPermissionGranted()) return@withContext eventOnly(IntruderCaptureFailureReason.CAMERA_PERMISSION_DENIED)
        if (lifecycleOwner == null || !lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
            // Modern Android restricts background camera activation; fail gracefully
            return@withContext eventOnly(IntruderCaptureFailureReason.BACKGROUND_CAMERA_RESTRICTED_BY_OS)
        }
        // Binds CameraSelector.DEFAULT_FRONT_CAMERA, captures JPEG, encrypts with AES-256-GCM, and zeroes plaintext...
    }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/vault/SecureFileRepository.kt',
    moduleGroup: 'Phase 5 · Privacy Vault AES-256-GCM Engine',
    description:
      'AndroidKeyStore-backed AES-256-GCM (96-bit IV + 128-bit authentication tag) file encryption and decryption for Private Vault items and encrypted intruder selfies, with SHA-256 integrity verification and in-place plaintext buffer zeroing.',
    code: `class SecureFileRepository(
    private val appContext: Context,
    private val keyProvider: VaultSecretKeyProvider = AndroidKeystoreVaultKeyProvider()
) {
    suspend fun encryptAndImportToVault(
        displayName: String,
        mimeType: String,
        plaintextBytes: ByteArray
    ): VaultItemMetadataEntity = withContext(ioDispatcher) {
        val secretKey = keyProvider.getOrCreateSecretKey(VAULT_KEYSTORE_ALIAS)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val ciphertextWithTag = cipher.doFinal(plaintextBytes)
        wipeBuffer(plaintextBytes)
        // Writes to filesDir/private_vault_encrypted/*.vault.enc and returns Room metadata...
    }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/notifications/SecurityNotificationManager.kt',
    moduleGroup: 'Phase 5 · Redacted Security Notifications',
    description:
      'Configures Android NotificationChannels with NotificationCompat.VISIBILITY_PRIVATE lock-screen redaction, POST_NOTIFICATIONS runtime permission validation, non-critical alert muting, and 45s NotificationDeduplicator.',
    code: `class SecurityNotificationManager(
    private val appContext: Context,
    private val deduplicator: NotificationDeduplicator = NotificationDeduplicator()
) {
    fun notifyIntruderThresholdReached(targetPackageName: String, consecutiveFailures: Int, authMethod: String): Boolean {
        if (!canPostNotifications()) return false
        if (!deduplicator.shouldDispatch("INTRUDER_THRESHOLD:$targetPackageName:$consecutiveFailures")) return false
        // Builds NotificationCompat with VISIBILITY_PRIVATE and redacted publicVersion...
        return true
    }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/monitoring/ProtectionHealthMonitor.kt',
    moduleGroup: 'Phase 5 · Tamper & Protection Health + Quick Lock',
    description:
      'Monitors Usage Access, Overlay permission, Monitoring Service, Keystore integrity, and uninstalled protected packages. Executes Quick Lock / Panic Lock and enforces Phase 2 SessionManager authorization for sensitive settings.',
    code: `class ProtectionHealthMonitor(
    private val appLockEngine: AppLockEngine,
    private val sessionManager: SessionManager,
    private val securityEventRepository: SecurityEventRepository
) {
    suspend fun executeQuickLock(lockNexlockMasterSessionToo: Boolean = true): QuickLockExecutionResult {
        val activeBefore = appLockEngine.getActiveUnlockedSessions().size
        appLockEngine.invalidateAllUnlockedSessions("QUICK_LOCK_TRIGGERED")
        if (lockNexlockMasterSessionToo) sessionManager.lockImmediately()
        val activeAfter = appLockEngine.getActiveUnlockedSessions().size
        // Verifies activeAfter == 0 and logs QUICK_LOCK_TRIGGERED...
    }
}`,
  },
  {
    path: 'android/app/src/test/java/com/nexlock/security/intruder/Phase5AdvancedSecurityTest.kt',
    moduleGroup: 'Phase 5 · JUnit 4 Security & Vault Test Suite (12 Tests)',
    description:
      '12 JUnit 4 tests covering Intruder Detection, Thresholds (3/5/10), Reset on Success, Biometric Cancellation Exclusion, Consented CameraX Capture & Background Fallback, AES-256-GCM Vault Round-Trip, Quick Lock, and Sensitive Settings Session Gate.',
    code: `class Phase5AdvancedSecurityTest {
    @Test fun test1_failedPinAttemptIncrementsCounterAndLogsSecurityEvent() { ... }
    @Test fun test4_biometricUserCancellationDoesNotCountAsIntruderAttempt() { ... }
    @Test fun test6_vaultAes256GcmEncryptionDecryptionAndTamperRejection() { ... }
    @Test fun test10_quickLockImmediatelyInvalidatesAllActiveSessions() { ... }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/monitoring/AppLockEngine.kt',
    moduleGroup: 'Phase 4 · App Lock Engine',
    description:
      'Pure state machine coordinating foreground package transitions, locked package matching, 6 re-lock timers, screen-off session revocation, duplicate challenge suppression, and excluded system/recovery packages.',
    code: `class AppLockEngine(
    private val monotonicClockMs: () -> Long = { SystemClock.elapsedRealtime() },
    private val ownPackageName: String = "com.nexlock.security"
) {
    @Synchronized
    fun onForegroundEvent(event: ForegroundTransitionEvent): LockEnforcementDecision {
        val pkg = event.packageName.trim()
        if (pkg.isEmpty()) return LockEnforcementDecision.Ignored("Empty package name")
        if (event.transitionType == UsageTransitionType.SCREEN_NON_INTERACTIVE) {
            onScreenTurnedOff(event.elapsedRealtimeMillis)
            return LockEnforcementDecision.Allow("Screen turned off; unlock sessions revoked")
        }
        if (ExcludedSystemPackages.isExcluded(pkg, ownPackageName, homeLauncherPackage)) {
            return LockEnforcementDecision.ExcludedPackage(pkg, "Excluded system/recovery package")
        }
        // Enforces locked package lookup, monotonic re-lock window, and AppLockActivity challenge...
    }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/monitoring/AppLockMonitoringService.kt',
    moduleGroup: 'Phase 4 · Foreground Monitoring Service',
    description:
      'Android 14/15 FOREGROUND_SERVICE_TYPE_SPECIAL_USE Service running adaptive UsageStatsManager polling (400ms active -> 1100ms idle -> 0ms screen-off) with dynamic ACTION_SCREEN_OFF receiver.',
    code: `class AppLockMonitoringService : Service() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP_MONITORING -> {
                stopMonitoringLoop()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                promoteToForeground()
                startMonitoringLoopIfPermitted()
            }
        }
        return START_STICKY
    }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/lockengine/AppLockActivity.kt',
    moduleGroup: 'Phase 4 · Lock Challenge Activity',
    description:
      'Dedicated singleTop authentication Activity displaying the protected app icon, app name, "This app is protected by NEXLOCK", BiometricPrompt, Master PIN keypad, and safe Back-press exit to Home Launcher.',
    code: `class AppLockActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                navigateToHomeLauncherAndFinish()
            }
        })
        // Renders target app icon, target app name, BiometricPrompt, and Master PIN keypad...
    }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/monitoring/UsageStatsRepository.kt',
    moduleGroup: 'Phase 4 · UsageEvents Detector',
    description:
      'Queries UsageStatsManager.queryEvents() on Dispatchers.Default, filtering ACTIVITY_RESUMED and ACTIVITY_PAUSED transitions with timestamp deduplication.',
    code: `class UsageStatsRepository(
    private val appContext: Context,
    private val defaultDispatcher: CoroutineDispatcher = Dispatchers.Default
) : UsageEventsGateway {
    override suspend fun queryTransitions(startWallClockMs: Long, endWallClockMs: Long): List<ForegroundTransitionEvent> =
        withContext(defaultDispatcher) {
            val usageStatsManager = appContext.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
                ?: return@withContext emptyList()
            val usageEvents = usageStatsManager.queryEvents(startWallClockMs, endWallClockMs)
            // Extracts ACTIVITY_RESUMED & ACTIVITY_PAUSED events...
        }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/monitoring/MonitoringPermissionManager.kt',
    moduleGroup: 'Phase 4 · Permission Health',
    description:
      'Evaluates AppOpsManager.OPSTR_GET_USAGE_STATS, Settings.canDrawOverlays, POST_NOTIFICATIONS, and builds official Android Settings deep-link intents.',
    code: `class MonitoringPermissionManager(private val appContext: Context) {
    fun isUsageAccessGranted(): Boolean {
        val appOps = appContext.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager ?: return false
        val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            appOps.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), appContext.packageName)
        } else {
            @Suppress("DEPRECATION")
            appOps.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), appContext.packageName)
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }
}`,
  },
  {
    path: 'android/app/src/test/java/com/nexlock/security/monitoring/Phase4AppLockEngineTest.kt',
    moduleGroup: 'Phase 4 · Unit Test Suite',
    description:
      '12 JUnit tests verifying locked app foreground challenge, unlocked app pass-through, PIN/Biometric session grant, 6 re-lock timers, screen-off revocation, rapid switching, and excluded recovery packages.',
    code: `class Phase4AppLockEngineTest {
    @Test fun \`1 - Locked application detection triggers authentication challenge on ACTIVITY_RESUMED\`() { ... }
    @Test fun \`2 - Unlocked application is ignored and allowed without challenge\`() { ... }
    @Test fun \`5 - Re-lock timer behavior enforces Immediately, 5s, 15s, 30s, 1m, and 5m policies\`() { ... }
    @Test fun \`7 - Rapid switching between two locked applications challenges each locked app independently\`() { ... }
    @Test fun \`8 - Screen-off event immediately revokes all active unlock sessions\`() { ... }
    @Test fun \`10 - Excluded system, launcher, settings, and NEXLOCK packages are never locked\`() { ... }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/discovery/AppDiscoveryRepository.kt',
    moduleGroup: 'Phase 3 · App Discovery',
    description:
      'Queries PackageManager on Dispatchers.IO with Android 11–15 compatibility, launcher intent resolution, and LruCache icon loading.',
    code: `class AppDiscoveryRepository(
    private val appContext: Context,
    private val iconCache: AppIconMemoryCache = AppIconMemoryCache(),
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) : PackageDiscoveryGateway {
    override suspend fun discoverInstalledApps(
        includeNonLaunchableSystemApps: Boolean
    ): Result<List<InstalledApp>> = withContext(ioDispatcher) { ... }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/database/NexLockDatabase.kt',
    moduleGroup: 'Phase 3 · Room Migration',
    description:
      'Room v2 with LockedAppEntity (unique index on packageName), LockedAppsDao, and non-destructive MIGRATION_1_2.',
    code: `@Entity(
    tableName = "locked_apps",
    indices = [Index(value = ["packageName"], unique = true)]
)
data class LockedAppEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val packageName: String,
    val appName: String,
    val isLocked: Boolean,
    val category: String,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis()
)`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/auth/PinManager.kt',
    moduleGroup: 'Phase 2 · Auth & Crypto',
    description:
      'PBKDF2WithHmacSHA256 (210,000 iterations, 16-byte CSPRNG salt), constant-time verification, and weak PIN pattern rejection.',
    code: `class PinManager(private val secureRandom: SecureRandom = SecureRandom()) {
    companion object {
        const val PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256"
        const val DEFAULT_ITERATIONS = 210_000
        const val SALT_LENGTH_BYTES = 16
        const val KEY_LENGTH_BITS = 256
    }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/security/SecureKeyManager.kt',
    moduleGroup: 'Phase 2 · Auth & Crypto',
    description:
      'AndroidKeyStore AES-256-GCM non-exportable master key generation, envelope encryption, and KeyPermanentlyInvalidatedException recovery.',
    code: `class SecureKeyManager(
    private val keyAlias: String = "nexlock_master_aes256_gcm_v2"
) : KeyManagerContract { ... }`,
  },
];
