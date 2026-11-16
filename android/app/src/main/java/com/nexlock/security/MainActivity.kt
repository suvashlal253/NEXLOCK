package com.nexlock.security

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.nexlock.security.auth.NexLockBiometricManager
import com.nexlock.security.auth.PinManager
import com.nexlock.security.auth.SessionManager
import com.nexlock.security.database.NexLockDatabase
import com.nexlock.security.database.PreferencesManager
import com.nexlock.security.discovery.AppDiscoveryRepository
import com.nexlock.security.discovery.PackageChangeReceiver
import com.nexlock.security.monitoring.AppLockEngineRepository
import com.nexlock.security.repository.AuthRepository
import com.nexlock.security.repository.LockedAppsRepository
import com.nexlock.security.repository.NexLockRepository
import com.nexlock.security.repository.SecuritySettingsRepository
import com.nexlock.security.security.SecureKeyManager
import com.nexlock.security.ui.navigation.NexLockAppRoot
import com.nexlock.security.ui.theme.NexLockTheme
import com.nexlock.security.viewmodel.AppManagerViewModel
import com.nexlock.security.viewmodel.AuthenticationViewModel
import com.nexlock.security.viewmodel.NexLockViewModel
import com.nexlock.security.viewmodel.ProtectionEngineViewModel

class MainActivity : FragmentActivity() {

    private lateinit var sessionManager: SessionManager
    private lateinit var appManagerViewModel: AppManagerViewModel
    private lateinit var protectionEngineViewModel: ProtectionEngineViewModel
    private var packageChangeReceiver: PackageChangeReceiver? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val database = NexLockDatabase.getInstance(applicationContext)
        val preferencesManager = PreferencesManager(applicationContext)
        val repository = NexLockRepository(
            protectedAppDao = database.protectedAppDao(),
            securityEventDao = database.securityEventDao(),
            preferencesManager = preferencesManager
        )

        // Phase 2 Real Authentication & Security Infrastructure
        val pinManager = PinManager()
        val secureKeyManager = SecureKeyManager()
        val securitySettingsRepository = SecuritySettingsRepository(applicationContext)
        sessionManager = SessionManager()
        val biometricManager = NexLockBiometricManager(applicationContext)
        val authRepository = AuthRepository(
            pinManager = pinManager,
            keyManager = secureKeyManager,
            settingsStore = securitySettingsRepository,
            sessionManager = sessionManager
        )

        // Phase 3 Installed App Discovery & LockedAppsRepository
        val appDiscoveryRepository = AppDiscoveryRepository(applicationContext)
        val lockedAppsRepository = LockedAppsRepository(
            lockedAppsDao = database.lockedAppsDao(),
            securityEventDao = database.securityEventDao()
        )

        // Phase 4 Real App Lock Engine & Monitoring Service Coordinator
        val engineRepository = AppLockEngineRepository.getInstance(applicationContext)

        val viewModel = ViewModelProvider(
            this,
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return NexLockViewModel(repository) as T
                }
            }
        )[NexLockViewModel::class.java]

        val authViewModel = ViewModelProvider(
            this,
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return AuthenticationViewModel(
                        authRepository = authRepository,
                        settingsStore = securitySettingsRepository,
                        sessionManager = sessionManager,
                        biometricGateway = biometricManager,
                        keyManager = secureKeyManager
                    ) as T
                }
            }
        )[AuthenticationViewModel::class.java]

        appManagerViewModel = ViewModelProvider(
            this,
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return AppManagerViewModel(
                        discoveryGateway = appDiscoveryRepository,
                        lockedAppsStore = lockedAppsRepository,
                        isMasterPinConfiguredProvider = { authViewModel.authState.value.isPinConfigured },
                        isSessionAuthenticatedProvider = { authViewModel.authState.value.isAuthenticated }
                    ) as T
                }
            }
        )[AppManagerViewModel::class.java]

        protectionEngineViewModel = ViewModelProvider(
            this,
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return ProtectionEngineViewModel(
                        appContext = applicationContext,
                        engineRepository = engineRepository
                    ) as T
                }
            }
        )[ProtectionEngineViewModel::class.java]

        // Dynamically register PackageChangeReceiver for install/update/uninstall events
        packageChangeReceiver = PackageChangeReceiver.register(this) { event ->
            appManagerViewModel.onPackageBroadcastEvent(event)
        }

        setContent {
            val state by viewModel.uiState.collectAsState()
            NexLockTheme(themeMode = state.preferences.themeMode) {
                NexLockAppRoot(
                    viewModel = viewModel,
                    authViewModel = authViewModel,
                    appManagerViewModel = appManagerViewModel,
                    protectionEngineViewModel = protectionEngineViewModel,
                    activity = this@MainActivity
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Reconcile any package changes and recheck Usage Access / Overlay permissions on return from Settings
        if (::appManagerViewModel.isInitialized) {
            appManagerViewModel.refreshInstalledApps(isInitialLoad = false)
        }
        if (::protectionEngineViewModel.isInitialized) {
            protectionEngineViewModel.refreshPermissionsAndSyncService()
        }
    }

    override fun onStop() {
        super.onStop()
        if (::sessionManager.isInitialized) {
            sessionManager.evaluateAndExpireIfNecessary(onBackgroundTransition = true)
        }
    }

    override fun onDestroy() {
        packageChangeReceiver?.let {
            runCatching { unregisterReceiver(it) }
        }
        packageChangeReceiver = null
        super.onDestroy()
    }
}
