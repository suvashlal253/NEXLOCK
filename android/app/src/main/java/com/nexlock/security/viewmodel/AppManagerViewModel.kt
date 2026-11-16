package com.nexlock.security.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.nexlock.security.discovery.AppCategory
import com.nexlock.security.discovery.AppFilter
import com.nexlock.security.discovery.AppManagerUiState
import com.nexlock.security.discovery.InstalledApp
import com.nexlock.security.discovery.PackageChangeEvent
import com.nexlock.security.discovery.PackageDiscoveryGateway
import com.nexlock.security.repository.LockedAppsRepository
import com.nexlock.security.repository.LockedAppsStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/**
 * Phase 3 AppManagerViewModel.
 *
 * Responsibilities:
 * 1. Performs off-main-thread PackageManager discovery via PackageDiscoveryGateway.
 * 2. Reactively merges discovered packages with Room `locked_apps` Flow.
 * 3. Provides instant search by appName or packageName, filter tabs (All, Locked, Unlocked, System Apps),
 *    and automatic 10-category filtering.
 * 4. Enforces Phase 2 Master Authentication before allowing disabling of protection or bulk changes.
 * 5. Handles package installation, update, and uninstallation events without trusting replacement
 *    packages of a different packageName.
 */
class AppManagerViewModel(
    private val discoveryGateway: PackageDiscoveryGateway,
    private val lockedAppsStore: LockedAppsStore,
    private val isMasterPinConfiguredProvider: () -> Boolean = { true },
    private val isSessionAuthenticatedProvider: () -> Boolean = { true }
) : ViewModel() {

    private val discoveredAppsFlow = MutableStateFlow<List<InstalledApp>>(emptyList())
    private val searchQueryFlow = MutableStateFlow("")
    private val selectedFilterFlow = MutableStateFlow(AppFilter.ALL)
    private val selectedCategoryFlow = MutableStateFlow<AppCategory?>(null)
    private val multiSelectStateFlow = MutableStateFlow<Pair<Boolean, Set<String>>>(false to emptySet())
    private val loadingStateFlow = MutableStateFlow<Triple<Boolean, Boolean, Boolean>>(
        Triple(false, false, false) // isLoading, isRefreshing, requiresBulkLockConfirmation
    )
    private val feedbackFlow = MutableStateFlow<Pair<String?, String?>>(null to null) // error to status

    val uiState: StateFlow<AppManagerUiState> = combine(
        discoveredAppsFlow,
        lockedAppsStore.lockedAppsFlow,
        searchQueryFlow,
        selectedFilterFlow,
        selectedCategoryFlow
    ) { discovered, lockedEntities, query, filter, category ->
        val (mergedApps, uninstalledLocked) = LockedAppsRepository.mergeDiscoveredWithLocked(
            discoveredApps = discovered,
            lockedEntities = lockedEntities,
            isMasterPinConfigured = isMasterPinConfiguredProvider()
        )

        val trimmedQuery = query.trim().lowercase()
        val filtered = mergedApps.filter { app ->
            val matchesSearch = trimmedQuery.isEmpty() ||
                app.appName.lowercase().contains(trimmedQuery) ||
                app.packageName.lowercase().contains(trimmedQuery)

            val matchesTab = when (filter) {
                AppFilter.ALL -> true
                AppFilter.LOCKED -> app.isLocked
                AppFilter.UNLOCKED -> !app.isLocked
                AppFilter.SYSTEM_APPS -> app.isSystemApp
            }

            val matchesCategory = category == null || app.category == category
            matchesSearch && matchesTab && matchesCategory
        }

        AppManagerUiState(
            installedApps = mergedApps,
            filteredApps = filtered,
            uninstalledLockedApps = uninstalledLocked,
            searchQuery = query,
            selectedFilter = filter,
            selectedCategory = category,
            isMultiSelectMode = multiSelectStateFlow.value.first,
            selectedPackageNames = multiSelectStateFlow.value.second,
            totalInstalledCount = mergedApps.size,
            totalLockedCount = mergedApps.count { it.isLocked },
            isLoading = loadingStateFlow.value.first,
            isRefreshing = loadingStateFlow.value.second,
            requiresBulkLockConfirmation = loadingStateFlow.value.third,
            errorMessage = feedbackFlow.value.first,
            statusMessage = feedbackFlow.value.second
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = AppManagerUiState(isLoading = true)
    )

    init {
        refreshInstalledApps(isInitialLoad = true)
    }

    fun refreshInstalledApps(isInitialLoad: Boolean = false) {
        viewModelScope.launch {
            loadingStateFlow.value = Triple(
                isInitialLoad,
                !isInitialLoad,
                loadingStateFlow.value.third
            )
            val result = discoveryGateway.discoverInstalledApps(includeNonLaunchableSystemApps = false)
            result.fold(
                onSuccess = { apps ->
                    discoveredAppsFlow.value = apps
                    loadingStateFlow.value = Triple(false, false, loadingStateFlow.value.third)
                },
                onFailure = { err ->
                    loadingStateFlow.value = Triple(false, false, loadingStateFlow.value.third)
                    feedbackFlow.value = (err.message ?: "Failed to query PackageManager") to null
                }
            )
        }
    }

    fun updateSearchQuery(query: String) {
        searchQueryFlow.value = query
    }

    fun clearSearch() {
        searchQueryFlow.value = ""
    }

    fun selectFilter(filter: AppFilter) {
        selectedFilterFlow.value = filter
    }

    fun selectCategory(category: AppCategory?) {
        selectedCategoryFlow.value = category
    }

    fun toggleMultiSelectMode() {
        val current = multiSelectStateFlow.value.first
        multiSelectStateFlow.value = (!current) to emptySet()
    }

    fun togglePackageSelection(packageName: String) {
        val (mode, currentSet) = multiSelectStateFlow.value
        val nextSet = if (packageName in currentSet) {
            currentSet - packageName
        } else {
            currentSet + packageName
        }
        multiSelectStateFlow.value = true to nextSet
    }

    fun clearSelection() {
        multiSelectStateFlow.value = multiSelectStateFlow.value.first to emptySet()
    }

    fun setAppLock(app: InstalledApp, targetLocked: Boolean) {
        viewModelScope.launch {
            if (!app.isInstalled || !app.isVisible) {
                feedbackFlow.value = "Cannot configure protection: ${app.appName} is not currently installed or visible." to null
                return@launch
            }

            if (targetLocked && !isMasterPinConfiguredProvider()) {
                feedbackFlow.value = "Configure your NEXLOCK Master PIN first so protected applications have an authentication credential." to null
                return@launch
            }

            if (!targetLocked && isMasterPinConfiguredProvider() && !isSessionAuthenticatedProvider()) {
                feedbackFlow.value = "Master Authentication is required before disabling protection for ${app.appName}." to null
                return@launch
            }

            lockedAppsStore.setAppLockState(
                app = app,
                isLocked = targetLocked,
                isMasterAuthConfigured = isMasterPinConfiguredProvider()
            )
            // Re-trigger state emission
            discoveredAppsFlow.value = discoveredAppsFlow.value.toList()
            feedbackFlow.value = null to if (targetLocked) {
                "${app.appName} selected & configured in Room database (Phase 4 foreground lock engine required for active OS interception)."
            } else {
                "${app.appName} removed from protected list."
            }
        }
    }

    fun requestLockAllEligibleConfirmation() {
        loadingStateFlow.value = loadingStateFlow.value.copy(third = true)
    }

    fun cancelLockAllEligibleConfirmation() {
        loadingStateFlow.value = loadingStateFlow.value.copy(third = false)
    }

    fun confirmLockAllEligibleApps() {
        viewModelScope.launch {
            loadingStateFlow.value = loadingStateFlow.value.copy(third = false)
            if (!isMasterPinConfiguredProvider()) {
                feedbackFlow.value = "Create a Master PIN before locking all eligible applications." to null
                return@launch
            }
            if (!isSessionAuthenticatedProvider()) {
                feedbackFlow.value = "Authenticate your Master Session before performing bulk lock modifications." to null
                return@launch
            }
            val eligible = discoveredAppsFlow.value.filter { it.isLaunchable && it.isInstalled }
            lockedAppsStore.bulkSetLockState(eligible, isLocked = true)
            discoveredAppsFlow.value = discoveredAppsFlow.value.toList()
            feedbackFlow.value = null to "Configured lock policy for ${eligible.size} eligible applications."
        }
    }

    fun unlockAllApps() {
        viewModelScope.launch {
            if (isMasterPinConfiguredProvider() && !isSessionAuthenticatedProvider()) {
                feedbackFlow.value = "Master Authentication is required to unlock all protected applications." to null
                return@launch
            }
            lockedAppsStore.unlockAllApps()
            discoveredAppsFlow.value = discoveredAppsFlow.value.toList()
            feedbackFlow.value = null to "All application lock policies have been cleared."
        }
    }

    fun applyBulkSelectionLock(targetLocked: Boolean) {
        viewModelScope.launch {
            if (isMasterPinConfiguredProvider() && !isSessionAuthenticatedProvider()) {
                feedbackFlow.value = "Master Authentication is required for bulk app lock changes." to null
                return@launch
            }
            val selectedPkgs = multiSelectStateFlow.value.second
            val selectedApps = discoveredAppsFlow.value.filter { it.packageName in selectedPkgs }
            if (selectedApps.isEmpty()) return@launch
            lockedAppsStore.bulkSetLockState(selectedApps, isLocked = targetLocked)
            multiSelectStateFlow.value = false to emptySet()
            discoveredAppsFlow.value = discoveredAppsFlow.value.toList()
            feedbackFlow.value = null to if (targetLocked) {
                "Configured lock policies for ${selectedApps.size} selected applications."
            } else {
                "Removed lock policies for ${selectedApps.size} selected applications."
            }
        }
    }

    fun onPackageBroadcastEvent(event: PackageChangeEvent) {
        viewModelScope.launch {
            when (event) {
                is PackageChangeEvent.Installed -> {
                    val details = discoveryGateway.getAppDetails(event.packageName).getOrNull()
                    if (details != null) {
                        val updated = (discoveredAppsFlow.value.filterNot { it.packageName == event.packageName } + details)
                            .sortedBy { it.appName.lowercase() }
                        discoveredAppsFlow.value = updated
                        feedbackFlow.value = null to "Detected newly installed application: ${details.appName} (${details.packageName})."
                    }
                }
                is PackageChangeEvent.Updated -> {
                    discoveryGateway.evictCachedIcon(event.packageName)
                    val details = discoveryGateway.getAppDetails(event.packageName).getOrNull()
                    if (details != null) {
                        discoveredAppsFlow.value = discoveredAppsFlow.value.map {
                            if (it.packageName == event.packageName) details else it
                        }
                        feedbackFlow.value = null to "Refreshed application metadata for updated package ${details.appName}."
                    }
                }
                is PackageChangeEvent.Uninstalled -> {
                    discoveryGateway.evictCachedIcon(event.packageName)
                    val wasLocked = lockedAppsStore.getSnapshot().any {
                        it.packageName == event.packageName && it.isLocked
                    }
                    discoveredAppsFlow.value = discoveredAppsFlow.value.filterNot {
                        it.packageName == event.packageName
                    }
                    if (wasLocked) {
                        feedbackFlow.value = null to "Warning: Previously protected package (${event.packageName}) was uninstalled."
                    }
                }
            }
        }
    }

    fun removeStaleUninstalledPackage(packageName: String, appName: String) {
        viewModelScope.launch {
            lockedAppsStore.removeStalePackage(packageName, appName)
            discoveredAppsFlow.value = discoveredAppsFlow.value.toList()
            feedbackFlow.value = null to "Removed uninstalled package $appName ($packageName) from protected list."
        }
    }
}
