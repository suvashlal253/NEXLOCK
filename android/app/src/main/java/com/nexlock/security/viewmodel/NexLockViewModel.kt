package com.nexlock.security.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.nexlock.security.database.UserPreferencesState
import com.nexlock.security.model.ProtectedAppEntity
import com.nexlock.security.model.ReLockPolicy
import com.nexlock.security.model.SecurityEventEntity
import com.nexlock.security.repository.NexLockRepository
import com.nexlock.security.security.PhaseArchitectureContracts
import com.nexlock.security.ui.theme.ThemeMode
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

data class NexLockUiState(
    val apps: List<ProtectedAppEntity> = emptyList(),
    val events: List<SecurityEventEntity> = emptyList(),
    val preferences: UserPreferencesState = UserPreferencesState(),
    val searchQuery: String = "",
    val selectedCategory: String = "All",
    val draftPin: String = "",
    val confirmPinInput: String = "",
    val selectedAppPackage: String = "com.whatsapp",
    val permissions: List<com.nexlock.security.model.PermissionStatusItem> =
        PhaseArchitectureContracts.getDocumentedPermissions()
)

class NexLockViewModel(
    private val repository: NexLockRepository
) : ViewModel() {

    private val searchQueryFlow = MutableStateFlow("")
    private val selectedCategoryFlow = MutableStateFlow("All")
    private val draftPinFlow = MutableStateFlow("")
    private val selectedAppPackageFlow = MutableStateFlow("com.whatsapp")

    val uiState: StateFlow<NexLockUiState> = combine(
        repository.allAppsFlow,
        repository.recentEventsFlow,
        repository.userPreferencesFlow,
        searchQueryFlow,
        selectedCategoryFlow
    ) { apps, events, prefs, query, category ->
        NexLockUiState(
            apps = apps,
            events = events,
            preferences = prefs,
            searchQuery = query,
            selectedCategory = category,
            draftPin = draftPinFlow.value,
            selectedAppPackage = selectedAppPackageFlow.value
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = NexLockUiState()
    )

    init {
        viewModelScope.launch {
            repository.seedInitialMockCatalogIfEmpty()
        }
    }

    fun updateSearchQuery(query: String) {
        searchQueryFlow.value = query
    }

    fun selectCategory(category: String) {
        selectedCategoryFlow.value = category
    }

    fun selectAppForConfig(packageName: String) {
        selectedAppPackageFlow.value = packageName
    }

    fun toggleAppLock(app: ProtectedAppEntity) {
        viewModelScope.launch {
            repository.updateAppProtection(app.copy(isLocked = !app.isLocked))
        }
    }

    fun updateAppConfig(
        app: ProtectedAppEntity,
        allowBiometric: Boolean,
        hideNotificationsPreview: Boolean,
        customReLockPolicy: String?
    ) {
        viewModelScope.launch {
            repository.updateAppProtection(
                app.copy(
                    allowBiometric = allowBiometric,
                    hideNotificationsPreview = hideNotificationsPreview,
                    customReLockPolicy = customReLockPolicy
                )
            )
        }
    }

    fun setThemeMode(mode: ThemeMode) {
        viewModelScope.launch {
            repository.setThemeMode(mode)
        }
    }

    fun setGlobalReLockPolicy(policy: ReLockPolicy) {
        viewModelScope.launch {
            repository.setGlobalReLockPolicy(policy)
        }
    }

    fun setBiometricPreference(enabled: Boolean) {
        viewModelScope.launch {
            repository.setBiometricPreference(enabled)
        }
    }

    fun setRandomizeKeypad(enabled: Boolean) {
        viewModelScope.launch {
            repository.setRandomizeKeypad(enabled)
        }
    }

    fun setHidePinRipple(enabled: Boolean) {
        viewModelScope.launch {
            repository.setHidePinRipple(enabled)
        }
    }

    fun completeOnboarding() {
        viewModelScope.launch {
            repository.setOnboardingCompleted(true)
        }
    }

    fun clearHistory() {
        viewModelScope.launch {
            repository.clearActivityHistory()
        }
    }
}
