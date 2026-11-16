export interface KotlinSourceFile {
  path: string;
  moduleGroup: string;
  description: string;
  code: string;
}

export const KOTLIN_SOURCE_FILES: KotlinSourceFile[] = [
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
