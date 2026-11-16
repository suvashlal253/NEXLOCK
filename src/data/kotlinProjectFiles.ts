export interface KotlinSourceFile {
  path: string;
  moduleGroup: string;
  description: string;
  code: string;
}

export const KOTLIN_SOURCE_FILES: KotlinSourceFile[] = [
  {
    path: 'android/app/src/main/java/com/nexlock/security/discovery/AppDiscoveryRepository.kt',
    moduleGroup: 'Phase 3 · App Discovery',
    description: 'Queries PackageManager on Dispatchers.IO with Android 11–15 compatibility, launcher intent resolution, and LruCache icon loading.',
    code: `class AppDiscoveryRepository(
    private val appContext: Context,
    private val iconCache: AppIconMemoryCache = AppIconMemoryCache(),
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) : PackageDiscoveryGateway {

    override suspend fun discoverInstalledApps(
        includeNonLaunchableSystemApps: Boolean
    ): Result<List<InstalledApp>> = withContext(ioDispatcher) {
        runCatching {
            val pm = appContext.packageManager
            val ownPackage = appContext.packageName
            val launcherIntent = Intent(Intent.ACTION_MAIN, null).apply {
                addCategory(Intent.CATEGORY_LAUNCHER)
            }
            val launchableActivities = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.queryIntentActivities(launcherIntent, PackageManager.ResolveInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                pm.queryIntentActivities(launcherIntent, 0)
            }
            // Maps ApplicationInfo, versionName, AppCategory.fromMetadata, and cached Drawable icon...
        }
    }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/discovery/DiscoveryModels.kt',
    moduleGroup: 'Phase 3 · App Discovery',
    description: 'Defines InstalledApp, AppCategory (10 automatic metadata categories), AppFilter, ProtectionStatus, and AppManagerUiState.',
    code: `enum class AppCategory(val displayName: String) {
    SOCIAL_MEDIA("Social Media"),
    COMMUNICATION("Communication"),
    ENTERTAINMENT("Entertainment"),
    FINANCE("Finance"),
    SHOPPING("Shopping"),
    PRODUCTIVITY("Productivity"),
    GAMES("Games"),
    PHOTOGRAPHY("Photography"),
    TOOLS("Tools"),
    OTHER("Other");
}

data class InstalledApp(
    val packageName: String,
    val appName: String,
    val icon: Drawable? = null,
    val isSystemApp: Boolean,
    val isLaunchable: Boolean,
    val isLocked: Boolean,
    val isVisible: Boolean = true,
    val category: AppCategory = AppCategory.OTHER,
    val versionName: String = "1.0",
    val isInstalled: Boolean = true,
    val protectionStatus: ProtectionStatus = ProtectionStatus.UNPROTECTED
)`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/discovery/AppIconMemoryCache.kt',
    moduleGroup: 'Phase 3 · App Discovery',
    description: 'Thread-safe in-memory LruCache<String, Drawable> preventing repeated PackageManager IPC calls during LazyColumn scrolling.',
    code: `class AppIconMemoryCache(maxEntries: Int = 180) {
    private val cache = object : LruCache<String, Drawable>(maxEntries) {}

    fun getOrLoadIcon(packageName: String, packageManager: PackageManager): Drawable? {
        synchronized(cache) { cache.get(packageName)?.let { return it } }
        val loaded = try {
            packageManager.getApplicationIcon(packageName)
        } catch (_: Exception) {
            null
        }
        if (loaded != null) {
            synchronized(cache) { cache.put(packageName, loaded) }
        }
        return loaded
    }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/discovery/PackageChangeReceiver.kt',
    moduleGroup: 'Phase 3 · App Discovery',
    description: 'Lifecycle BroadcastReceiver for ACTION_PACKAGE_ADDED, ACTION_PACKAGE_REMOVED, and ACTION_PACKAGE_REPLACED.',
    code: `class PackageChangeReceiver(
    private val onPackageChanged: (PackageChangeEvent) -> Unit
) : BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) {
        val action = intent?.action ?: return
        val pkg = intent.data?.schemeSpecificPart?.takeIf { it.isNotBlank() } ?: return
        val isReplacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
        when (action) {
            Intent.ACTION_PACKAGE_ADDED ->
                if (isReplacing) onPackageChanged(PackageChangeEvent.Updated(pkg))
                else onPackageChanged(PackageChangeEvent.Installed(pkg))
            Intent.ACTION_PACKAGE_REPLACED -> onPackageChanged(PackageChangeEvent.Updated(pkg))
            Intent.ACTION_PACKAGE_REMOVED ->
                if (!isReplacing) onPackageChanged(PackageChangeEvent.Uninstalled(pkg))
        }
    }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/database/NexLockDatabase.kt',
    moduleGroup: 'Phase 3 · Room Migration',
    description: 'Room v2 with LockedAppEntity (unique index on packageName), LockedAppsDao, and non-destructive MIGRATION_1_2.',
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
)

val MIGRATION_1_2 = object : Migration(1, 2) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("CREATE TABLE IF NOT EXISTS \`locked_apps\` (...)")
        db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS \`index_locked_apps_packageName\` ON \`locked_apps\` (\`packageName\`)")
    }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/viewmodel/AppManagerViewModel.kt',
    moduleGroup: 'Phase 3 · ViewModel & Repository',
    description: 'Coordinates discovery, search, 4 filter tabs, 10 categories, bulk lock confirmation, Master Auth check, and package broadcasts.',
    code: `class AppManagerViewModel(
    private val discoveryGateway: PackageDiscoveryGateway,
    private val lockedAppsStore: LockedAppsStore,
    private val isMasterPinConfiguredProvider: () -> Boolean = { true },
    private val isSessionAuthenticatedProvider: () -> Boolean = { true }
) : ViewModel() {
    // Combines discoveredAppsFlow, lockedAppsStore.lockedAppsFlow, searchQueryFlow, selectedFilterFlow, selectedCategoryFlow
}`,
  },
  {
    path: 'android/app/src/test/java/com/nexlock/security/discovery/Phase3AppDiscoveryTest.kt',
    moduleGroup: 'Phase 3 · Unit Test Suite',
    description: '17 JUnit tests covering discovery, empty list, missing icons, search, filters, bulk lock, unique index, uninstall, update, and 250-app scale.',
    code: `class Phase3AppDiscoveryTest {
    @Test fun \`1 - Installed application discovery retrieves user and launchable system packages\`() { ... }
    @Test fun \`2 - Empty application list is handled gracefully without crash\`() { ... }
    @Test fun \`3 - Missing application icons return null safely so UI renders vector fallback\`() { ... }
    @Test fun \`12 - Duplicate package prevention enforces unique packageName constraint\`() { ... }
    @Test fun \`13 - Application uninstallation flags previously locked package and rejects replacement package name\`() { ... }
    @Test fun \`17 - Large application list (250 packages) merges and filters efficiently\`() { ... }
}`,
  },
  {
    path: 'android/app/src/main/java/com/nexlock/security/auth/PinManager.kt',
    moduleGroup: 'Phase 2 · Auth & Crypto',
    description: 'PBKDF2WithHmacSHA256 (210,000 iterations, 16-byte CSPRNG salt), constant-time verification, and weak PIN pattern rejection.',
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
    description: 'AndroidKeyStore AES-256-GCM non-exportable master key generation, envelope encryption, and KeyPermanentlyInvalidatedException recovery.',
    code: `class SecureKeyManager(
    private val keyAlias: String = "nexlock_master_aes256_gcm_v2"
) : KeyManagerContract { ... }`,
  },
];
