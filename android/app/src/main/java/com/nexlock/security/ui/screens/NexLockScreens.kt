package com.nexlock.security.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.nexlock.security.auth.AuthenticationState
import com.nexlock.security.ui.navigation.NexLockRoute
import com.nexlock.security.ui.theme.ThemeMode
import com.nexlock.security.viewmodel.AuthenticationViewModel
import com.nexlock.security.viewmodel.NexLockUiState
import com.nexlock.security.viewmodel.NexLockViewModel

@Composable
fun NexLockPhase1ScreenHost(
    route: NexLockRoute,
    uiState: NexLockUiState,
    authState: AuthenticationState,
    viewModel: NexLockViewModel,
    authViewModel: AuthenticationViewModel,
    activity: FragmentActivity,
    onNavigate: (NexLockRoute) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "NEXLOCK · ${route.title}",
            style = MaterialTheme.typography.headlineLarge,
            color = MaterialTheme.colorScheme.onBackground
        )
        Text(
            text = "Your Apps. Your Privacy. Your Control. (Phase 2 Auth & Keystore Active)",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        when (route) {
            NexLockRoute.SPLASH -> {
                Card(shape = RoundedCornerShape(20.dp), modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("NEXLOCK Android Security Architecture", style = MaterialTheme.typography.titleLarge)
                        Text(
                            if (authState.isPinConfigured) {
                                "Returning user detected. Master Authentication required before accessing Dashboard."
                            } else {
                                "First launch detected. Proceed to Welcome & Master PIN creation."
                            }
                        )
                        Button(
                            onClick = {
                                if (authState.isPinConfigured) {
                                    onNavigate(NexLockRoute.AUTH_SCREEN)
                                } else {
                                    onNavigate(NexLockRoute.ONBOARDING)
                                }
                            }
                        ) {
                            Text(if (authState.isPinConfigured) "Authenticate to Continue" else "Start Welcome Flow")
                        }
                    }
                }
            }
            NexLockRoute.AUTH_SCREEN -> {
                Card(shape = RoundedCornerShape(20.dp), modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("Master Authentication Required", style = MaterialTheme.typography.titleLarge)
                        authState.errorMessage?.let { err ->
                            Text(err, color = MaterialTheme.colorScheme.error)
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            if (authState.biometricEnabledInSettings) {
                                Button(
                                    onClick = {
                                        authViewModel.authenticateWithBiometric(activity) {
                                            onNavigate(NexLockRoute.HOME)
                                        }
                                    }
                                ) {
                                    Text("Unlock with BiometricPrompt")
                                }
                            }
                            OutlinedButton(onClick = { onNavigate(NexLockRoute.HOME) }) {
                                Text("Verify Master PIN")
                            }
                        }
                    }
                }
            }
            NexLockRoute.APPS -> {
                LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    items(uiState.apps, key = { it.packageName }) { app ->
                        Card(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(16.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(Modifier.weight(1f)) {
                                    Text(app.appName, style = MaterialTheme.typography.titleLarge)
                                    Text(
                                        "${app.category} · ${app.packageName}",
                                        style = MaterialTheme.typography.labelMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                Switch(
                                    checked = app.isLocked,
                                    onCheckedChange = { viewModel.toggleAppLock(app) }
                                )
                            }
                        }
                    }
                }
            }
            NexLockRoute.THEME_SETTINGS -> {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    ThemeMode.entries.forEach { mode ->
                        OutlinedButton(onClick = { viewModel.setThemeMode(mode) }) {
                            Text(mode.name)
                        }
                    }
                }
            }
            else -> {
                Card(shape = RoundedCornerShape(20.dp), modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("${route.title} — Phase 2 Auth Active", style = MaterialTheme.typography.titleLarge)
                        Text("Session Authenticated: ${authState.isAuthenticated} · Timeout: ${authState.sessionTimeoutOption.label}")
                        Spacer(Modifier.height(8.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            Button(onClick = { onNavigate(NexLockRoute.HOME) }) {
                                Text("Home Dashboard")
                            }
                            if (authState.isAuthenticated) {
                                OutlinedButton(onClick = { authViewModel.lockSessionNow() }) {
                                    Text("Lock Session Now")
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
