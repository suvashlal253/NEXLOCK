package com.nexlock.security.viewmodel

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.nexlock.security.monitoring.AppLockEngineRepository
import com.nexlock.security.monitoring.AppLockMonitoringService
import com.nexlock.security.monitoring.MonitoringPermissionManager
import com.nexlock.security.monitoring.PermissionHealthState
import com.nexlock.security.monitoring.ProtectionEngineState
import com.nexlock.security.monitoring.ReLockDurationOption
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

/**
 * ViewModel for Phase 4 App Lock Engine, Permission Health Onboarding, and
 * Foreground Monitoring Service lifecycle controls.
 */
class ProtectionEngineViewModel(
    private val appContext: Context,
    private val engineRepository: AppLockEngineRepository = AppLockEngineRepository.getInstance(appContext),
    private val permissionManager: MonitoringPermissionManager = MonitoringPermissionManager(appContext)
) : ViewModel() {

    val engineState: StateFlow<ProtectionEngineState> = engineRepository.engineStateFlow

    fun refreshPermissionsAndSyncService(): PermissionHealthState {
        val perms = engineRepository.refreshPermissionHealth()
        val currentState = engineRepository.engineStateFlow.value
        if (perms.canRunMonitoringEngine &&
            currentState.isMonitoringEnabledByUser &&
            currentState.selectedLockedCount > 0
        ) {
            AppLockMonitoringService.startMonitoringService(appContext)
        } else if (!perms.canRunMonitoringEngine) {
            AppLockMonitoringService.stopMonitoringService(appContext)
        }
        return perms
    }

    fun startProtectionEngine() {
        viewModelScope.launch {
            engineRepository.setMonitoringEnabledByUser(true)
            val perms = engineRepository.refreshPermissionHealth()
            if (perms.canRunMonitoringEngine) {
                AppLockMonitoringService.startMonitoringService(appContext)
            }
        }
    }

    fun pauseProtectionEngine() {
        viewModelScope.launch {
            engineRepository.setMonitoringEnabledByUser(false)
            AppLockMonitoringService.stopMonitoringService(appContext)
        }
    }

    fun setReLockDuration(option: ReLockDurationOption) {
        viewModelScope.launch {
            engineRepository.setReLockDuration(option)
        }
    }

    fun setLockOnScreenOff(enabled: Boolean) {
        viewModelScope.launch {
            engineRepository.setLockOnScreenOff(enabled)
        }
    }

    fun openUsageAccessSettings(context: Context) {
        runCatching {
            context.startActivity(permissionManager.buildUsageAccessSettingsIntent())
        }
    }

    fun openOverlayPermissionSettings(context: Context) {
        runCatching {
            context.startActivity(permissionManager.buildOverlayPermissionSettingsIntent())
        }
    }

    fun openNotificationSettings(context: Context) {
        runCatching {
            context.startActivity(permissionManager.buildAppNotificationSettingsIntent())
        }
    }
}
