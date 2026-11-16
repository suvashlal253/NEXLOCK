package com.nexlock.security.discovery

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Abstraction for discovering installed Android packages so unit tests can supply
 * deterministic package lists, visibility restrictions, and uninstalls.
 */
interface PackageDiscoveryGateway {
    suspend fun discoverInstalledApps(includeNonLaunchableSystemApps: Boolean = false): Result<List<InstalledApp>>
    suspend fun getAppDetails(packageName: String): Result<InstalledApp?>
    fun launchApplication(packageName: String): Result<Unit>
    fun evictCachedIcon(packageName: String)
}

class AppDiscoveryRepository(
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

            // 1. Query all launchable packages via ACTION_MAIN + CATEGORY_LAUNCHER
            val launcherIntent = Intent(Intent.ACTION_MAIN, null).apply {
                addCategory(Intent.CATEGORY_LAUNCHER)
            }
            val launchableActivities = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.queryIntentActivities(
                    launcherIntent,
                    PackageManager.ResolveInfoFlags.of(0L)
                )
            } else {
                @Suppress("DEPRECATION")
                pm.queryIntentActivities(launcherIntent, 0)
            }

            val launchablePackageSet = launchableActivities
                .mapNotNull { it.activityInfo?.packageName }
                .toSet()

            // 2. Retrieve installed ApplicationInfo records visible under Android 11+ package visibility rules
            val appInfos: List<ApplicationInfo> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledApplications(
                    PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA.toLong())
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledApplications(PackageManager.GET_META_DATA)
            }

            val discovered = mutableListOf<InstalledApp>()

            for (appInfo in appInfos) {
                val pkg = appInfo.packageName ?: continue
                // Never allow NEXLOCK to lock itself in the app list
                if (pkg == ownPackage) continue

                val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                    (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
                val isLaunchable = pkg in launchablePackageSet

                if (!includeNonLaunchableSystemApps && isSystem && !isLaunchable) {
                    continue
                }

                val appLabel = try {
                    pm.getApplicationLabel(appInfo).toString().takeIf { it.isNotBlank() } ?: pkg
                } catch (_: Exception) {
                    pkg
                }

                val versionName = try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(0L)).versionName ?: "1.0"
                    } else {
                        @Suppress("DEPRECATION")
                        pm.getPackageInfo(pkg, 0).versionName ?: "1.0"
                    }
                } catch (_: Exception) {
                    "1.0"
                }

                val androidCat = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    appInfo.category
                } else {
                    ApplicationInfo.CATEGORY_UNDEFINED
                }

                val category = AppCategory.fromMetadata(androidCat, pkg)
                val icon = iconCache.getOrLoadIcon(pkg, pm)

                discovered.add(
                    InstalledApp(
                        packageName = pkg,
                        appName = appLabel,
                        icon = icon,
                        isSystemApp = isSystem,
                        isLaunchable = isLaunchable,
                        isLocked = false,
                        isVisible = true,
                        category = category,
                        versionName = versionName,
                        isInstalled = true
                    )
                )
            }

            discovered.sortedBy { it.appName.lowercase() }
        }
    }

    override suspend fun getAppDetails(packageName: String): Result<InstalledApp?> =
        withContext(ioDispatcher) {
            runCatching {
                val pm = appContext.packageManager
                val appInfo = try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        pm.getApplicationInfo(
                            packageName,
                            PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA.toLong())
                        )
                    } else {
                        @Suppress("DEPRECATION")
                        pm.getApplicationInfo(packageName, PackageManager.GET_META_DATA)
                    }
                } catch (_: PackageManager.NameNotFoundException) {
                    return@runCatching null
                }

                val label = runCatching { pm.getApplicationLabel(appInfo).toString() }
                    .getOrDefault(packageName)
                val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                    (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
                val isLaunchable = pm.getLaunchIntentForPackage(packageName) != null
                val versionName = runCatching {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0L)).versionName ?: "1.0"
                    } else {
                        @Suppress("DEPRECATION")
                        pm.getPackageInfo(packageName, 0).versionName ?: "1.0"
                    }
                }.getOrDefault("1.0")

                val androidCat = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    appInfo.category
                } else {
                    ApplicationInfo.CATEGORY_UNDEFINED
                }

                iconCache.evictPackage(packageName)
                val refreshedIcon = iconCache.getOrLoadIcon(packageName, pm)

                InstalledApp(
                    packageName = packageName,
                    appName = label,
                    icon = refreshedIcon,
                    isSystemApp = isSystem,
                    isLaunchable = isLaunchable,
                    isLocked = false,
                    isVisible = true,
                    category = AppCategory.fromMetadata(androidCat, packageName),
                    versionName = versionName,
                    isInstalled = true
                )
            }
        }

    override fun launchApplication(packageName: String): Result<Unit> = runCatching {
        val pm = appContext.packageManager
        val launchIntent = pm.getLaunchIntentForPackage(packageName)
            ?: throw IllegalStateException("Package $packageName does not expose a launchable MAIN activity.")
        launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        appContext.startActivity(launchIntent)
    }

    override fun evictCachedIcon(packageName: String) {
        iconCache.evictPackage(packageName)
    }
}
