package com.nexlock.security.monitoring

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.nexlock.security.auth.AuthMethod
import com.nexlock.security.database.LockedAppsDao
import com.nexlock.security.database.NexLockDatabase
import com.nexlock.security.database.SecurityEventDao
import com.nexlock.security.model.SecurityEventEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

private val Context.engineDataStore by preferencesDataStore(name = "nexlock_phase4_engine_store")

data class EnginePersistedConfig(
    val isMonitoringEnabledByUser: Boolean = true,
    val reLockDurationOption: ReLockDurationOption = ReLockDurationOption.IMMEDIATELY,
    val lockOnScreenOff: Boolean = true
)

/**
 * Coordinates the Phase 4 AppLockEngine, PermissionHealthGateway, Room LockedAppsDao,
 * SecurityEventDao, and persistent engine configuration.
 */
class AppLockEngineRepository(
    private val appContext: Context,
    private val lockedAppsDao: LockedAppsDao,
    private val securityEventDao: SecurityEventDao,
    private val permissionGateway: PermissionHealthGateway = MonitoringPermissionManager(appContext),
    val engine: AppLockEngine = AppLockEngine()
) {
    private val repositoryScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    companion object {
        private val KEY_MONITORING_ENABLED = booleanPreferencesKey("monitoring_enabled_by_user")
        private val KEY_RELOCK_DURATION = stringPreferencesKey("relock_duration_option")
        private val KEY_LOCK_ON_SCREEN_OFF = booleanPreferencesKey("lock_on_screen_off")

        @Volatile
        private var INSTANCE: AppLockEngineRepository? = null

        fun getInstance(context: Context): AppLockEngineRepository {
            return INSTANCE ?: synchronized(this) {
                val appCtx = context.applicationContext
                val db = NexLockDatabase.getInstance(appCtx)
                INSTANCE ?: AppLockEngineRepository(
                    appContext = appCtx,
                    lockedAppsDao = db.lockedAppsDao(),
                    securityEventDao = db.securityEventDao()
                ).also { INSTANCE = it }
            }
        }
    }

    private val _permissionHealthFlow = MutableStateFlow(permissionGateway.queryPermissionHealth())
    private val _serviceStateFlow = MutableStateFlow(MonitoringServiceState.STOPPED)
    private val _runtimeTelemetryFlow = MutableStateFlow(RuntimeEngineTelemetry())

    private data class RuntimeEngineTelemetry(
        val currentForegroundPackage: String? = null,
        val activeChallengePackage: String? = null,
        val lastDetectedPackage: String? = null,
        val lastMonitoringEventEpochMillis: Long? = null,
        val adaptivePollingIntervalMillis: Long = 400L,
        val isScreenInteractive: Boolean = true,
        val totalInstalledCount: Int = 0,
        val statusBannerMessage: String? = null
    )

    val persistedConfigFlow = appContext.engineDataStore.data.map { prefs ->
        EnginePersistedConfig(
            isMonitoringEnabledByUser = prefs[KEY_MONITORING_ENABLED] ?: true,
            reLockDurationOption = ReLockDurationOption.fromId(prefs[KEY_RELOCK_DURATION]),
            lockOnScreenOff = prefs[KEY_LOCK_ON_SCREEN_OFF] ?: true
        )
    }

    init {
        // Keep AppLockEngine synchronized with Room locked_apps and DataStore config
        repositoryScope.launch {
            engine.updateHomeLauncherPackages(permissionGateway.resolveHomeLauncherPackages())
            lockedAppsDao.observeAllLockedApps().collect { entities ->
                val lockedSet = entities.filter { it.isLocked }.map { it.packageName }.toSet()
                engine.updateLockedPackages(lockedSet)
            }
        }
        repositoryScope.launch {
            persistedConfigFlow.collect { cfg ->
                engine.setReLockDuration(cfg.reLockDurationOption)
                engine.setLockOnScreenOffPolicy(cfg.lockOnScreenOff)
            }
        }
    }

    val engineStateFlow: StateFlow<ProtectionEngineState> = combine(
        _permissionHealthFlow,
        _serviceStateFlow,
        persistedConfigFlow,
        lockedAppsDao.observeAllLockedApps(),
        engine.unlockedSessionsFlow
    ) { perms, serviceState, cfg, lockedEntities, unlockedSessions ->
        val telemetry = _runtimeTelemetryFlow.value
        val selectedLockedCount = lockedEntities.count { it.isLocked }
        val operationalStatus = MonitoringPermissionManager.evaluateOperationalStatus(
            permissionHealth = perms,
            serviceState = serviceState,
            isMonitoringEnabledByUser = cfg.isMonitoringEnabledByUser,
            selectedLockedCount = selectedLockedCount
        )
        val configuredOperationalCount = if (operationalStatus.isOperational) {
            selectedLockedCount
        } else {
            0
        }

        ProtectionEngineState(
            permissionHealth = perms,
            serviceState = serviceState,
            operationalStatus = operationalStatus,
            isMonitoringEnabledByUser = cfg.isMonitoringEnabledByUser,
            lockOnScreenOff = cfg.lockOnScreenOff,
            reLockDurationOption = cfg.reLockDurationOption,
            currentForegroundPackage = telemetry.currentForegroundPackage,
            activeChallengePackage = engine.activeChallengePackage,
            lastDetectedPackage = telemetry.lastDetectedPackage,
            lastMonitoringEventEpochMillis = telemetry.lastMonitoringEventEpochMillis,
            adaptivePollingIntervalMillis = telemetry.adaptivePollingIntervalMillis,
            isScreenInteractive = telemetry.isScreenInteractive,
            activeUnlockedPackages = unlockedSessions,
            totalInstalledCount = telemetry.totalInstalledCount,
            selectedLockedCount = selectedLockedCount,
            configuredOperationalCount = configuredOperationalCount,
            excludedPackages = ExcludedSystemPackages.defaultExcludedRules,
            statusBannerMessage = telemetry.statusBannerMessage
        )
    }.stateIn(
        scope = repositoryScope,
        started = SharingStarted.Eagerly,
        initialValue = ProtectionEngineState(
            permissionHealth = _permissionHealthFlow.value
        )
    )

    fun refreshPermissionHealth(): PermissionHealthState {
        val updated = permissionGateway.queryPermissionHealth()
        _permissionHealthFlow.value = updated
        engine.updateHomeLauncherPackages(permissionGateway.resolveHomeLauncherPackages())
        if (!updated.canRunMonitoringEngine && _serviceStateFlow.value == MonitoringServiceState.RUNNING) {
            _runtimeTelemetryFlow.value = _runtimeTelemetryFlow.value.copy(
                statusBannerMessage = "Required permissions were revoked in Android Settings. Monitoring paused."
            )
        }
        return updated
    }

    fun updateServiceState(
        newState: MonitoringServiceState,
        bannerMessage: String? = null
    ) {
        _serviceStateFlow.value = newState
        if (bannerMessage != null) {
            _runtimeTelemetryFlow.value = _runtimeTelemetryFlow.value.copy(
                statusBannerMessage = bannerMessage
            )
        }
    }

    fun updateTotalInstalledCount(count: Int) {
        _runtimeTelemetryFlow.value = _runtimeTelemetryFlow.value.copy(totalInstalledCount = count)
    }

    fun recordForegroundEvaluation(
        event: ForegroundTransitionEvent,
        decision: LockEnforcementDecision,
        adaptivePollMillis: Long
    ) {
        _runtimeTelemetryFlow.value = _runtimeTelemetryFlow.value.copy(
            currentForegroundPackage = engine.currentForegroundAppPackage,
            activeChallengePackage = engine.activeChallengePackage,
            lastDetectedPackage = event.packageName,
            lastMonitoringEventEpochMillis = event.timestampMillis,
            adaptivePollingIntervalMillis = adaptivePollMillis
        )

        if (decision is LockEnforcementDecision.RequireAuthentication) {
            repositoryScope.launch {
                securityEventDao.insertEvent(
                    SecurityEventEntity(
                        eventType = "LOCK_CHALLENGE_TRIGGERED",
                        packageName = decision.packageName,
                        title = "Protected App Intercepted (${decision.packageName})",
                        detail = "NEXLOCK launched AppLockActivity authentication challenge."
                    )
                )
            }
        }
    }

    fun onScreenInteractiveChanged(interactive: Boolean) {
        if (!interactive) {
            engine.onScreenTurnedOffOrDeviceLocked()
        }
        _runtimeTelemetryFlow.value = _runtimeTelemetryFlow.value.copy(
            isScreenInteractive = interactive,
            activeChallengePackage = engine.activeChallengePackage
        )
    }

    fun grantPackageAccessAfterAuthentication(
        packageName: String,
        authMethod: AuthMethod
    ) {
        engine.grantTemporaryPackageSession(packageName, authMethod)
        _runtimeTelemetryFlow.value = _runtimeTelemetryFlow.value.copy(
            activeChallengePackage = engine.activeChallengePackage,
            statusBannerMessage = "Unlocked $packageName (${engine.reLockDurationOption.label})."
        )
        repositoryScope.launch {
            securityEventDao.insertEvent(
                SecurityEventEntity(
                    eventType = "PACKAGE_SESSION_GRANTED",
                    packageName = packageName,
                    title = "Unlocked $packageName via ${authMethod.name}",
                    detail = "Temporary package session active (${engine.reLockDurationOption.label})."
                )
            )
        }
    }

    fun onChallengeDismissed(packageName: String) {
        engine.onChallengeDismissedOrAborted(packageName)
        _runtimeTelemetryFlow.value = _runtimeTelemetryFlow.value.copy(
            activeChallengePackage = engine.activeChallengePackage
        )
    }

    suspend fun setMonitoringEnabledByUser(enabled: Boolean) {
        appContext.engineDataStore.edit { prefs ->
            prefs[KEY_MONITORING_ENABLED] = enabled
        }
        if (!enabled) {
            engine.revokeAllPackageSessions()
        }
        securityEventDao.insertEvent(
            SecurityEventEntity(
                eventType = if (enabled) "MONITORING_RESUMED" else "MONITORING_PAUSED",
                packageName = null,
                title = if (enabled) "Protection Monitoring Resumed" else "Protection Monitoring Paused by User",
                detail = if (enabled) {
                    "User enabled foreground application monitoring."
                } else {
                    "User paused foreground application monitoring."
                }
            )
        )
    }

    suspend fun setReLockDuration(option: ReLockDurationOption) {
        appContext.engineDataStore.edit { prefs ->
            prefs[KEY_RELOCK_DURATION] = option.id
        }
        engine.setReLockDuration(option)
    }

    suspend fun setLockOnScreenOff(enabled: Boolean) {
        appContext.engineDataStore.edit { prefs ->
            prefs[KEY_LOCK_ON_SCREEN_OFF] = enabled
        }
        engine.setLockOnScreenOffPolicy(enabled)
    }

    suspend fun shouldAutoStartMonitoringOnBoot(): Boolean {
        val cfg = persistedConfigFlow.first()
        val perms = refreshPermissionHealth()
        val lockedCount = lockedAppsDao.observeLockedCount().first()
        return cfg.isMonitoringEnabledByUser && perms.canRunMonitoringEngine && lockedCount > 0
    }
}
