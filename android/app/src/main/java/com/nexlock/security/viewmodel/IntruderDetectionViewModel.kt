package com.nexlock.security.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.nexlock.security.intruder.IntruderDetectionManager
import com.nexlock.security.intruder.IntruderDetectionSettings
import com.nexlock.security.intruder.IntruderThresholdOption
import com.nexlock.security.model.IntruderImageEntity
import com.nexlock.security.model.SecurityEventEntity
import com.nexlock.security.model.SecurityEventSeverity
import com.nexlock.security.model.VaultItemMetadataEntity
import com.nexlock.security.monitoring.ProtectionHealthMonitor
import com.nexlock.security.monitoring.QuickLockResult
import com.nexlock.security.monitoring.SensitiveSettingAction
import com.nexlock.security.monitoring.SettingsAuthorizationDecision
import com.nexlock.security.repository.EventDateFilter
import com.nexlock.security.repository.EventSortOrder
import com.nexlock.security.repository.SecurityEventRepository
import com.nexlock.security.vault.SecureFileRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

data class SecurityTimelineFilterState(
    val eventTypeFilter: String = "ALL",
    val severityFilter: SecurityEventSeverity? = null,
    val dateFilter: EventDateFilter = EventDateFilter.ALL_TIME,
    val sortOrder: EventSortOrder = EventSortOrder.NEWEST_FIRST
)

/**
 * Phase 5 IntruderDetectionViewModel:
 *
 * Exposes reactive StateFlows for:
 * - Intruder Detection settings & consecutive failure counter
 * - Encrypted Intruder Selfie records
 * - Security Activity Timeline (filtering by event type, severity, date range, and sorting newest/oldest)
 * - Quick Lock / Panic Lock execution
 * - Secure Settings authorization via Phase 2 SessionManager
 * - Privacy Vault AES-256-GCM encrypted file items
 */
class IntruderDetectionViewModel(
    private val intruderManager: IntruderDetectionManager,
    private val securityEventRepository: SecurityEventRepository,
    private val protectionHealthMonitor: ProtectionHealthMonitor,
    private val secureFileRepository: SecureFileRepository
) : ViewModel() {

    val intruderSettingsFlow: StateFlow<IntruderDetectionSettings> = intruderManager.settingsFlow
    val consecutiveFailuresFlow: StateFlow<Int> = intruderManager.consecutiveFailuresFlow

    private val _timelineFilterFlow = MutableStateFlow(SecurityTimelineFilterState())
    val timelineFilterFlow: StateFlow<SecurityTimelineFilterState> = _timelineFilterFlow.asStateFlow()

    private val _lastQuickLockResultFlow = MutableStateFlow<QuickLockResult?>(null)
    val lastQuickLockResultFlow: StateFlow<QuickLockResult?> = _lastQuickLockResultFlow.asStateFlow()

    private val _pendingAuthActionFlow = MutableStateFlow<SensitiveSettingAction?>(null)
    val pendingAuthActionFlow: StateFlow<SensitiveSettingAction?> = _pendingAuthActionFlow.asStateFlow()

    val filteredEventsFlow: StateFlow<List<SecurityEventEntity>> = combine(
        securityEventRepository.observeEvents(),
        _timelineFilterFlow
    ) { allEvents, filter ->
        SecurityEventRepository.filterAndSortEvents(
            events = allEvents,
            eventTypeFilter = filter.eventTypeFilter,
            severityFilter = filter.severityFilter,
            dateFilter = filter.dateFilter,
            sortOrder = filter.sortOrder
        )
    }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    val intruderImagesFlow: StateFlow<List<IntruderImageEntity>> =
        (intruderManager.observeIntruderImages() ?: MutableStateFlow(emptyList()))
            .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    val vaultItemsFlow: StateFlow<List<VaultItemMetadataEntity>> =
        (secureFileRepository.observeVaultMetadata() ?: MutableStateFlow(emptyList()))
            .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    fun setTimelineFilter(update: (SecurityTimelineFilterState) -> SecurityTimelineFilterState) {
        _timelineFilterFlow.value = update(_timelineFilterFlow.value)
    }

    fun executeQuickLock() {
        viewModelScope.launch {
            _lastQuickLockResultFlow.value = protectionHealthMonitor.executeQuickLock(triggeredByScreenOff = false)
        }
    }

    fun setIntruderDetectionEnabled(enabled: Boolean): Boolean {
        if (!enabled) {
            val auth = protectionHealthMonitor.authorizeSensitiveSettingChange(
                SensitiveSettingAction.DISABLE_INTRUDER_DETECTION
            )
            if (auth is SettingsAuthorizationDecision.RequiresMasterAuthentication) {
                _pendingAuthActionFlow.value = auth.action
                return false
            }
        }
        intruderManager.updateSettings { it.copy(isEnabled = enabled) }
        return true
    }

    fun setIntruderThreshold(option: IntruderThresholdOption): Boolean {
        val auth = protectionHealthMonitor.authorizeSensitiveSettingChange(
            SensitiveSettingAction.CHANGE_FAILED_ATTEMPT_THRESHOLD
        )
        if (auth is SettingsAuthorizationDecision.RequiresMasterAuthentication) {
            _pendingAuthActionFlow.value = auth.action
            return false
        }
        intruderManager.updateSettings { it.copy(thresholdOption = option) }
        return true
    }

    fun setIntruderSelfieConsentAndEnabled(consented: Boolean, enabled: Boolean) {
        intruderManager.updateSettings {
            it.copy(
                hasExplicitCameraConsent = consented,
                intruderSelfieEnabled = consented && enabled
            )
        }
    }

    fun deleteAllIntruderImages(): Boolean {
        val auth = protectionHealthMonitor.authorizeSensitiveSettingChange(
            SensitiveSettingAction.DELETE_INTRUDER_IMAGES
        )
        if (auth is SettingsAuthorizationDecision.RequiresMasterAuthentication) {
            _pendingAuthActionFlow.value = auth.action
            return false
        }
        viewModelScope.launch {
            intruderManager.deleteAllIntruderRecordsAndEncryptedFiles()
        }
        return true
    }

    fun deleteSingleSecurityEvent(eventId: Long) {
        viewModelScope.launch {
            securityEventRepository.deleteEventById(eventId)
        }
    }

    fun clearAllSecurityLogsWithConfirmation(confirmed: Boolean): Boolean {
        if (!confirmed) return false
        val auth = protectionHealthMonitor.authorizeSensitiveSettingChange(
            SensitiveSettingAction.CLEAR_SECURITY_LOGS
        )
        if (auth is SettingsAuthorizationDecision.RequiresMasterAuthentication) {
            _pendingAuthActionFlow.value = auth.action
            return false
        }
        viewModelScope.launch {
            securityEventRepository.clearAllEventsWithConfirmation(true)
        }
        return true
    }

    fun clearPendingAuthAction() {
        _pendingAuthActionFlow.value = null
    }
}
