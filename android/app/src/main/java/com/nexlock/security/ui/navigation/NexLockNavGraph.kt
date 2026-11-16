package com.nexlock.security.ui.navigation

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.FolderSpecial
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.fragment.app.FragmentActivity
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.nexlock.security.ui.screens.NexLockPhase1ScreenHost
import com.nexlock.security.viewmodel.AppManagerViewModel
import com.nexlock.security.viewmodel.AuthenticationViewModel
import com.nexlock.security.viewmodel.NexLockViewModel
import com.nexlock.security.viewmodel.ProtectionEngineViewModel

enum class NexLockRoute(val route: String, val title: String) {
    SPLASH("splash", "Splash Screen"),
    ONBOARDING("onboarding", "Onboarding"),
    CREATE_PIN("create_pin", "Create Master PIN"),
    CONFIRM_PIN("confirm_pin", "Confirm Master PIN"),
    CHANGE_PIN("change_pin", "Change Master PIN"),
    BIOMETRIC_SETUP("biometric_setup", "Biometric Setup"),
    PERMISSION_SETUP("permission_setup", "Permission Setup"),
    HOME("home", "Home Dashboard"),
    APPS("apps", "Installed Applications"),
    APP_CONFIG("app_config", "App Lock Configuration"),
    AUTH_SCREEN("auth_screen", "Authentication Screen"),
    VAULT("vault", "Private Vault"),
    SECURITY_ACTIVITY("security_activity", "Security Activity"),
    SECURITY_SETTINGS("security_settings", "Security Settings"),
    THEME_SETTINGS("theme_settings", "Theme Settings"),
    ABOUT("about", "About NEXLOCK")
}

data class BottomNavDestination(
    val route: NexLockRoute,
    val label: String,
    val icon: ImageVector
)

val bottomNavDestinations = listOf(
    BottomNavDestination(NexLockRoute.HOME, "Home", Icons.Outlined.Home),
    BottomNavDestination(NexLockRoute.APPS, "Apps", Icons.Outlined.Apps),
    BottomNavDestination(NexLockRoute.VAULT, "Vault", Icons.Outlined.FolderSpecial),
    BottomNavDestination(NexLockRoute.SECURITY_ACTIVITY, "Security", Icons.Outlined.Security),
    BottomNavDestination(NexLockRoute.SECURITY_SETTINGS, "Settings", Icons.Outlined.Settings)
)

@Composable
fun NexLockAppRoot(
    viewModel: NexLockViewModel,
    authViewModel: AuthenticationViewModel,
    appManagerViewModel: AppManagerViewModel,
    protectionEngineViewModel: ProtectionEngineViewModel,
    activity: FragmentActivity
) {
    val navController = rememberNavController()
    val uiState by viewModel.uiState.collectAsState()
    val authState by authViewModel.authState.collectAsState()
    val appManagerState by appManagerViewModel.uiState.collectAsState()
    val engineState by protectionEngineViewModel.engineState.collectAsState()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route ?: NexLockRoute.SPLASH.route

    val showBottomBar = bottomNavDestinations.any { it.route.route == currentRoute }

    Scaffold(
        bottomBar = {
            if (showBottomBar) {
                NavigationBar {
                    bottomNavDestinations.forEach { dest ->
                        val selected = currentRoute == dest.route.route
                        NavigationBarItem(
                            selected = selected,
                            onClick = {
                                navController.navigate(dest.route.route) {
                                    popUpTo(navController.graph.findStartDestination().id) {
                                        saveState = true
                                    }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            },
                            icon = { Icon(dest.icon, contentDescription = dest.label) },
                            label = { Text(dest.label) }
                        )
                    }
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = NexLockRoute.SPLASH.route,
            modifier = Modifier.padding(innerPadding)
        ) {
            NexLockRoute.entries.forEach { screenRoute ->
                composable(screenRoute.route) {
                    NexLockPhase1ScreenHost(
                        route = screenRoute,
                        uiState = uiState,
                        authState = authState,
                        appManagerState = appManagerState,
                        engineState = engineState,
                        viewModel = viewModel,
                        authViewModel = authViewModel,
                        appManagerViewModel = appManagerViewModel,
                        protectionEngineViewModel = protectionEngineViewModel,
                        activity = activity,
                        onNavigate = { target -> navController.navigate(target.route) }
                    )
                }
            }
        }
    }
}
