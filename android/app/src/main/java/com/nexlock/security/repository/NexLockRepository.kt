package com.nexlock.security.repository

import com.nexlock.security.database.PreferencesManager
import com.nexlock.security.database.ProtectedAppDao
import com.nexlock.security.database.SecurityEventDao
import com.nexlock.security.database.UserPreferencesState
import com.nexlock.security.model.ProtectedAppEntity
import com.nexlock.security.model.ReLockPolicy
import com.nexlock.security.model.SecurityEventEntity
import com.nexlock.security.ui.theme.ThemeMode
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first

class NexLockRepository(
    private val protectedAppDao: ProtectedAppDao,
    private val securityEventDao: SecurityEventDao,
    private val preferencesManager: PreferencesManager
) {
    val allAppsFlow: Flow<List<ProtectedAppEntity>> = protectedAppDao.observeAllApps()
    val recentEventsFlow: Flow<List<SecurityEventEntity>> = securityEventDao.observeRecentEvents()
    val userPreferencesFlow: Flow<UserPreferencesState> = preferencesManager.preferencesFlow

    suspend fun seedInitialMockCatalogIfEmpty() {
        val existing = protectedAppDao.observeAllApps().first()
        if (existing.isNotEmpty()) return

        val catalog = listOf(
            ProtectedAppEntity("com.google.android.apps.photos", "Google Photos", "Media & Gallery", isLocked = true),
            ProtectedAppEntity("com.whatsapp", "WhatsApp Messenger", "Messaging", isLocked = true),
            ProtectedAppEntity("org.thoughtcrime.securesms", "Signal Private Messenger", "Messaging", isLocked = true),
            ProtectedAppEntity("com.google.android.gm", "Gmail", "Email & Work", isLocked = true),
            ProtectedAppEntity("com.revolut.revolut", "Revolut Banking", "Finance", isLocked = true),
            ProtectedAppEntity("com.coinbase.android", "Coinbase Wallet", "Finance", isLocked = false),
            ProtectedAppEntity("com.Slack", "Slack Enterprise", "Email & Work", isLocked = false),
            ProtectedAppEntity("com.google.android.apps.docs", "Google Drive", "Cloud Storage", isLocked = true),
            ProtectedAppEntity("com.instagram.android", "Instagram", "Social", isLocked = false),
            ProtectedAppEntity("com.android.settings", "System Settings", "System", isLocked = true)
        )
        protectedAppDao.upsertAll(catalog)

        securityEventDao.insertEvent(
            SecurityEventEntity(
                eventType = "PHASE1_INIT",
                packageName = null,
                title = "Phase 1 Local Database Initialized",
                detail = "Room database & DataStore preferences seeded with sample app catalog for UI configuration."
            )
        )
    }

    suspend fun updateAppProtection(app: ProtectedAppEntity) {
        protectedAppDao.upsertApp(app.copy(updatedAtEpochMillis = System.currentTimeMillis()))
        securityEventDao.insertEvent(
            SecurityEventEntity(
                eventType = if (app.isLocked) "CONFIG_LOCK_SELECTED" else "CONFIG_LOCK_REMOVED",
                packageName = app.packageName,
                title = if (app.isLocked) "${app.appName} marked for Lock Policy" else "${app.appName} removed from Lock Policy",
                detail = "Saved to Room database (Phase 4 foreground lock engine required for active OS interception)."
            )
        )
    }

    suspend fun setOnboardingCompleted(completed: Boolean) =
        preferencesManager.setOnboardingCompleted(completed)

    suspend fun setThemeMode(mode: ThemeMode) =
        preferencesManager.setThemeMode(mode)

    suspend fun setGlobalReLockPolicy(policy: ReLockPolicy) =
        preferencesManager.setGlobalReLockPolicy(policy)

    suspend fun setBiometricPreference(enabled: Boolean) =
        preferencesManager.setBiometricPreference(enabled)

    suspend fun setRandomizeKeypad(enabled: Boolean) =
        preferencesManager.setRandomizeKeypad(enabled)

    suspend fun setHidePinRipple(enabled: Boolean) =
        preferencesManager.setHidePinRipple(enabled)

    suspend fun clearActivityHistory() =
        securityEventDao.clearEvents()
}
