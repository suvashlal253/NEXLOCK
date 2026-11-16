package com.nexlock.security.repository

import com.nexlock.security.database.LockedAppsDao
import com.nexlock.security.database.SecurityEventDao
import com.nexlock.security.discovery.AppCategory
import com.nexlock.security.discovery.InstalledApp
import com.nexlock.security.discovery.ProtectionStatus
import com.nexlock.security.model.LockedAppEntity
import com.nexlock.security.model.SecurityEventEntity
import kotlinx.coroutines.flow.Flow

/**
 * Repository managing persistent app lock selections in Room (`locked_apps` table)
 * and merging them with real installed application metadata from AppDiscoveryRepository.
 */
interface LockedAppsStore {
    val lockedAppsFlow: Flow<List<LockedAppEntity>>
    suspend fun getSnapshot(): List<LockedAppEntity>
    suspend fun setAppLockState(
        app: InstalledApp,
        isLocked: Boolean,
        isMasterAuthConfigured: Boolean
    )
    suspend fun bulkSetLockState(
        apps: List<InstalledApp>,
        isLocked: Boolean
    )
    suspend fun unlockAllApps()
    suspend fun removeStalePackage(packageName: String, appName: String)
}

class LockedAppsRepository(
    private val lockedAppsDao: LockedAppsDao,
    private val securityEventDao: SecurityEventDao? = null,
    private val clockMillis: () -> Long = { System.currentTimeMillis() }
) : LockedAppsStore {

    override val lockedAppsFlow: Flow<List<LockedAppEntity>> =
        lockedAppsDao.observeAllLockedApps()

    override suspend fun getSnapshot(): List<LockedAppEntity> =
        lockedAppsDao.getAllLockedAppsSnapshot()

    override suspend fun setAppLockState(
        app: InstalledApp,
        isLocked: Boolean,
        isMasterAuthConfigured: Boolean
    ) {
        val now = clockMillis()
        val existing = lockedAppsDao.getByPackageName(app.packageName)

        if (isLocked) {
            val entity = LockedAppEntity(
                id = existing?.id ?: 0L,
                packageName = app.packageName,
                appName = app.appName,
                isLocked = true,
                category = app.category.displayName,
                createdAt = existing?.createdAt ?: now,
                updatedAt = now
            )
            lockedAppsDao.upsertLockedApp(entity)
            securityEventDao?.insertEvent(
                SecurityEventEntity(
                    eventType = "APP_LOCK_SELECTED",
                    packageName = app.packageName,
                    title = "${app.appName} Selected for Protection",
                    detail = if (isMasterAuthConfigured) {
                        "Protection configured in Room locked_apps (${app.packageName}). Active foreground enforcement activates in Phase 4."
                    } else {
                        "Saved in Room locked_apps (${app.packageName}). Configure Master PIN to complete setup."
                    },
                    timestampMillis = now
                )
            )
        } else {
            lockedAppsDao.deleteByPackageName(app.packageName)
            securityEventDao?.insertEvent(
                SecurityEventEntity(
                    eventType = "APP_LOCK_REMOVED",
                    packageName = app.packageName,
                    title = "${app.appName} Removed from Protected List",
                    detail = "Deleted lock policy entry for ${app.packageName} from Room database.",
                    timestampMillis = now
                )
            )
        }
    }

    override suspend fun bulkSetLockState(
        apps: List<InstalledApp>,
        isLocked: Boolean
    ) {
        val now = clockMillis()
        if (isLocked) {
            val existingByPkg = lockedAppsDao.getAllLockedAppsSnapshot().associateBy { it.packageName }
            val entities = apps.map { app ->
                val prev = existingByPkg[app.packageName]
                LockedAppEntity(
                    id = prev?.id ?: 0L,
                    packageName = app.packageName,
                    appName = app.appName,
                    isLocked = true,
                    category = app.category.displayName,
                    createdAt = prev?.createdAt ?: now,
                    updatedAt = now
                )
            }
            lockedAppsDao.upsertLockedApps(entities)
            securityEventDao?.insertEvent(
                SecurityEventEntity(
                    eventType = "BULK_LOCK_CONFIGURED",
                    packageName = null,
                    title = "Bulk Lock Configured (${apps.size} Applications)",
                    detail = "Persisted ${apps.size} eligible packages to Room locked_apps table.",
                    timestampMillis = now
                )
            )
        } else {
            apps.forEach { app ->
                lockedAppsDao.deleteByPackageName(app.packageName)
            }
            securityEventDao?.insertEvent(
                SecurityEventEntity(
                    eventType = "BULK_UNLOCK_COMPLETED",
                    packageName = null,
                    title = "Bulk Unlock Executed (${apps.size} Applications)",
                    detail = "Removed ${apps.size} packages from Room locked_apps table.",
                    timestampMillis = now
                )
            )
        }
    }

    override suspend fun unlockAllApps() {
        val now = clockMillis()
        val lockedSnapshot = lockedAppsDao.getAllLockedAppsSnapshot().filter { it.isLocked }
        lockedSnapshot.forEach { entry ->
            lockedAppsDao.deleteByPackageName(entry.packageName)
        }
        securityEventDao?.insertEvent(
            SecurityEventEntity(
                eventType = "UNLOCK_ALL_APPS",
                packageName = null,
                title = "All Protected Applications Unlocked",
                detail = "Cleared ${lockedSnapshot.size} lock policies after Master Authentication verification.",
                timestampMillis = now
            )
        )
    }

    override suspend fun removeStalePackage(packageName: String, appName: String) {
        lockedAppsDao.deleteByPackageName(packageName)
        securityEventDao?.insertEvent(
            SecurityEventEntity(
                eventType = "UNINSTALLED_APP_CLEANUP",
                packageName = packageName,
                title = "Removed Uninstalled App Policy ($appName)",
                detail = "Cleared stale Room entry for uninstalled package $packageName.",
                timestampMillis = clockMillis()
            )
        )
    }

    companion object {
        /**
         * Merges discovered InstalledApp records from PackageManager with persisted LockedAppEntity rows.
         * Also identifies previously locked packages that are no longer installed on the device.
         */
        fun mergeDiscoveredWithLocked(
            discoveredApps: List<InstalledApp>,
            lockedEntities: List<LockedAppEntity>,
            isMasterPinConfigured: Boolean
        ): Pair<List<InstalledApp>, List<InstalledApp>> {
            val lockedMap = lockedEntities.filter { it.isLocked }.associateBy { it.packageName }
            val discoveredPkgSet = discoveredApps.map { it.packageName }.toSet()

            val mergedInstalled = discoveredApps.map { app ->
                val lockedRow = lockedMap[app.packageName]
                val isLocked = lockedRow != null
                val status = when {
                    !app.isInstalled || !app.isVisible ->
                        ProtectionStatus.PROTECTION_TEMPORARILY_UNAVAILABLE
                    isLocked && isMasterPinConfigured ->
                        ProtectionStatus.PROTECTION_CONFIGURED
                    isLocked && !isMasterPinConfigured ->
                        ProtectionStatus.SELECTED_FOR_PROTECTION
                    else ->
                        ProtectionStatus.UNPROTECTED
                }
                app.copy(
                    isLocked = isLocked,
                    protectionStatus = status,
                    createdAtMillis = lockedRow?.createdAt ?: app.createdAtMillis,
                    updatedAtMillis = lockedRow?.updatedAt ?: app.updatedAtMillis
                )
            }

            // Detect previously locked packages that were uninstalled
            val uninstalledLocked = lockedMap.values
                .filter { it.packageName !in discoveredPkgSet }
                .map { stale ->
                    InstalledApp(
                        packageName = stale.packageName,
                        appName = stale.appName,
                        icon = null,
                        isSystemApp = false,
                        isLaunchable = false,
                        isLocked = true,
                        isVisible = false,
                        category = AppCategory.fromDisplayName(stale.category),
                        versionName = "Uninstalled",
                        isInstalled = false,
                        protectionStatus = ProtectionStatus.PROTECTION_TEMPORARILY_UNAVAILABLE,
                        createdAtMillis = stale.createdAt,
                        updatedAtMillis = stale.updatedAt
                    )
                }

            return mergedInstalled to uninstalledLocked
        }
    }
}
