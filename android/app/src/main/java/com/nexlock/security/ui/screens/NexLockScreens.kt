package com.nexlock.security.ui.screens

import android.graphics.drawable.Drawable
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Android
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.LockOpen
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import androidx.fragment.app.FragmentActivity
import com.nexlock.security.auth.AuthenticationState
import com.nexlock.security.auth.SessionTimeoutOption
import com.nexlock.security.discovery.AppCategory
import com.nexlock.security.discovery.AppFilter
import com.nexlock.security.discovery.AppManagerUiState
import com.nexlock.security.monitoring.MonitoringServiceState
import com.nexlock.security.monitoring.ProtectionEngineState
import com.nexlock.security.monitoring.ReLockDurationOption
import com.nexlock.security.ui.navigation.NexLockRoute
import com.nexlock.security.ui.theme.ThemeMode
import com.nexlock.security.viewmodel.AppManagerViewModel
import com.nexlock.security.viewmodel.AuthenticationViewModel
import com.nexlock.security.viewmodel.NexLockUiState
import com.nexlock.security.viewmodel.NexLockViewModel
import com.nexlock.security.viewmodel.ProtectionEngineViewModel

@Composable
fun NexLockPhase1ScreenHost(
    route: NexLockRoute,
    uiState: NexLockUiState,
    authState: AuthenticationState,
    appManagerState: AppManagerUiState,
    engineState: ProtectionEngineState,
    viewModel: NexLockViewModel,
    authViewModel: AuthenticationViewModel,
    appManagerViewModel: AppManagerViewModel,
    protectionEngineViewModel: ProtectionEngineViewModel,
    activity: FragmentActivity,
    onNavigate: (NexLockRoute) -> Unit
) {
    var draftPin by remember { mutableStateOf("") }
    var confirmPin by remember { mutableStateOf("") }
    var verifyPinInput by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Header Row
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "NEXLOCK · ${route.title}",
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onBackground,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "Your Apps. Your Privacy. Your Control.",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            if (authState.isAuthenticated) {
                OutlinedButton(onClick = {
                    authViewModel.lockSessionNow()
                    onNavigate(NexLockRoute.AUTH_SCREEN)
                }) {
                    Icon(Icons.Outlined.Lock, contentDescription = "Lock Session", modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Lock")
                }
            }
        }

        // Global Feedback Banner
        val feedbackErr = authState.errorMessage ?: appManagerState.errorMessage
        val feedbackOk = authState.successMessage ?: appManagerState.feedbackMessage ?: engineState.statusBannerMessage
        if (feedbackErr != null) {
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF3B1824)),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = feedbackErr,
                        color = Color(0xFFFF8A8A),
                        style = MaterialTheme.typography.labelMedium,
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(onClick = {
                        authViewModel.clearFeedback()
                        appManagerViewModel.clearMessages()
                    }) {
                        Text("Dismiss")
                    }
                }
            }
        } else if (feedbackOk != null) {
            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF12352E)),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = feedbackOk,
                        color = Color(0xFF2DD4A3),
                        style = MaterialTheme.typography.labelMedium,
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(onClick = {
                        authViewModel.clearFeedback()
                        appManagerViewModel.clearMessages()
                    }) {
                        Text("OK")
                    }
                }
            }
        }

        when (route) {
            NexLockRoute.SPLASH -> {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Card(
                        shape = RoundedCornerShape(24.dp),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(24.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(14.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Outlined.Shield,
                                contentDescription = "NEXLOCK Shield",
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(56.dp)
                            )
                            Text("NEXLOCK", style = MaterialTheme.typography.headlineLarge)
                            Text(
                                text = if (authState.isPinConfigured) {
                                    "Master PIN configured (PBKDF2-HMAC-SHA256 + AndroidKeyStore). Authenticate to unlock your dashboard."
                                } else {
                                    "Welcome to NEXLOCK. Create your Master PIN, grant Usage Access & Overlay permissions, and protect your apps."
                                },
                                style = MaterialTheme.typography.bodyLarge,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Button(
                                modifier = Modifier.fillMaxWidth(),
                                onClick = {
                                    if (authState.isPinConfigured) {
                                        onNavigate(NexLockRoute.AUTH_SCREEN)
                                    } else {
                                        onNavigate(NexLockRoute.ONBOARDING)
                                    }
                                }
                            ) {
                                Text(if (authState.isPinConfigured) "Unlock NEXLOCK" else "Get Started")
                            }
                        }
                    }
                }
            }

            NexLockRoute.ONBOARDING -> {
                Card(
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("Hardware-Backed App Privacy", style = MaterialTheme.typography.titleLarge)
                        Text(
                            "1. Create a strong 4 or 6 digit Master PIN (PBKDF2-HMAC-SHA256 + AndroidKeyStore AES-256-GCM).\n" +
                                "2. Enable AndroidX BiometricPrompt fingerprint authentication.\n" +
                                "3. Grant Usage Access & Display Over Other Apps so the Phase 4 App Lock Engine can intercept protected apps.",
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Button(
                            modifier = Modifier.fillMaxWidth(),
                            onClick = { onNavigate(NexLockRoute.CREATE_PIN) }
                        ) {
                            Text("Create Master PIN")
                        }
                    }
                }
            }

            NexLockRoute.CREATE_PIN, NexLockRoute.CONFIRM_PIN, NexLockRoute.CHANGE_PIN -> {
                Card(
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("Setup Master PIN (4 or 6 digits)", style = MaterialTheme.typography.titleLarge)
                        Text(
                            "Weak patterns like 0000, 1111, or 123456 are automatically rejected. Your PIN is derived using 210,000 PBKDF2-HMAC-SHA256 iterations and sealed with AndroidKeyStore.",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        OutlinedTextField(
                            value = draftPin,
                            onValueChange = { if (it.length <= 6 && it.all(Char::isDigit)) draftPin = it },
                            label = { Text("Enter 4 or 6 digit Master PIN") },
                            visualTransformation = PasswordVisualTransformation(),
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        OutlinedTextField(
                            value = confirmPin,
                            onValueChange = { if (it.length <= 6 && it.all(Char::isDigit)) confirmPin = it },
                            label = { Text("Confirm Master PIN") },
                            visualTransformation = PasswordVisualTransformation(),
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Button(
                            modifier = Modifier.fillMaxWidth(),
                            onClick = {
                                authViewModel.createMasterPin(draftPin, confirmPin) {
                                    draftPin = ""
                                    confirmPin = ""
                                    viewModel.completeOnboarding()
                                    onNavigate(NexLockRoute.PERMISSION_SETUP)
                                }
                            }
                        ) {
                            Text("Save Master PIN & Configure Permissions")
                        }
                    }
                }
            }

            NexLockRoute.PERMISSION_SETUP -> {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Card(
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text("Phase 4 Permission Health & Onboarding", style = MaterialTheme.typography.titleLarge)
                            Text(
                                "NEXLOCK requires Usage Access to detect when a protected app enters the foreground via UsageStatsManager, and Display Over Other Apps to launch the authentication screen.",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )

                            // 1. Usage Access
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(Modifier.weight(1f)) {
                                    Text("Usage Access (PACKAGE_USAGE_STATS)", fontWeight = FontWeight.SemiBold)
                                    Text(
                                        if (engineState.permissionHealth.usageAccessGranted) "Granted" else "Not Granted",
                                        color = if (engineState.permissionHealth.usageAccessGranted) Color(0xFF2DD4A3) else Color(0xFFFF8A8A),
                                        style = MaterialTheme.typography.labelMedium
                                    )
                                }
                                OutlinedButton(onClick = { protectionEngineViewModel.openUsageAccessSettings(activity) }) {
                                    Text(if (engineState.permissionHealth.usageAccessGranted) "Verify" else "Grant")
                                }
                            }

                            // 2. Display Over Other Apps
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(Modifier.weight(1f)) {
                                    Text("Overlay Permission (SYSTEM_ALERT_WINDOW)", fontWeight = FontWeight.SemiBold)
                                    Text(
                                        if (engineState.permissionHealth.overlayPermissionGranted) "Granted" else "Not Granted",
                                        color = if (engineState.permissionHealth.overlayPermissionGranted) Color(0xFF2DD4A3) else Color(0xFFFF8A8A),
                                        style = MaterialTheme.typography.labelMedium
                                    )
                                }
                                OutlinedButton(onClick = { protectionEngineViewModel.openOverlayPermissionSettings(activity) }) {
                                    Text(if (engineState.permissionHealth.overlayPermissionGranted) "Verify" else "Grant")
                                }
                            }

                            // 3. Notification Permission
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(Modifier.weight(1f)) {
                                    Text("Foreground Service Notification", fontWeight = FontWeight.SemiBold)
                                    val notifStatus = when {
                                        !engineState.permissionHealth.isNotificationPermissionRequired -> "Not Required"
                                        engineState.permissionHealth.notificationPermissionGranted -> "Granted"
                                        else -> "Not Granted"
                                    }
                                    Text(
                                        notifStatus,
                                        color = if (engineState.permissionHealth.notificationPermissionGranted) Color(0xFF2DD4A3) else Color(0xFFFFC861),
                                        style = MaterialTheme.typography.labelMedium
                                    )
                                }
                                OutlinedButton(onClick = { protectionEngineViewModel.openNotificationSettings(activity) }) {
                                    Text("Settings")
                                }
                            }

                            // 4. Service & Engine Health Summary
                            Text(
                                "Monitoring Service: ${engineState.serviceState.label} · App Lock Engine: ${if (engineState.operationalStatus.isOperational) "Active" else "Paused"}",
                                style = MaterialTheme.typography.labelMedium,
                                color = if (engineState.operationalStatus.isOperational) Color(0xFF2DD4A3) else Color(0xFFFFC861)
                            )

                            Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
                                Button(
                                    modifier = Modifier.weight(1f),
                                    onClick = {
                                        protectionEngineViewModel.refreshPermissionsAndSyncService()
                                        onNavigate(NexLockRoute.HOME)
                                    }
                                ) {
                                    Text("Recheck & Continue")
                                }
                            }
                        }
                    }
                }
            }

            NexLockRoute.AUTH_SCREEN -> {
                Card(
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("Master Authentication", style = MaterialTheme.typography.titleLarge)
                        if (authState.isTemporarilyLockedOut) {
                            Text(
                                "Temporarily locked due to failed attempts. Wait ${authState.lockoutRemainingSeconds}s.",
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                        OutlinedTextField(
                            value = verifyPinInput,
                            onValueChange = { if (it.length <= 6 && it.all(Char::isDigit)) verifyPinInput = it },
                            label = { Text("Enter Master PIN") },
                            visualTransformation = PasswordVisualTransformation(),
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
                            Button(
                                modifier = Modifier.weight(1f),
                                onClick = {
                                    authViewModel.authenticateWithPin(verifyPinInput) {
                                        verifyPinInput = ""
                                        onNavigate(NexLockRoute.HOME)
                                    }
                                }
                            ) {
                                Text("Verify PIN")
                            }
                            OutlinedButton(
                                modifier = Modifier.weight(1f),
                                onClick = {
                                    authViewModel.authenticateWithBiometric(activity) {
                                        onNavigate(NexLockRoute.HOME)
                                    }
                                }
                            ) {
                                Icon(Icons.Outlined.Fingerprint, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Biometric")
                            }
                        }
                    }
                }
            }

            NexLockRoute.HOME -> {
                val isEngineOperational = engineState.operationalStatus.isOperational
                val operationalCount = if (isEngineOperational) appManagerState.lockedCount else 0

                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    // Honest Protection Status Banner when Paused or Missing Permissions
                    if (!isEngineOperational) {
                        Card(
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFF332612)),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text(
                                    text = "Protection Status: ${engineState.operationalStatus.badgeLabel}",
                                    style = MaterialTheme.typography.titleLarge,
                                    color = Color(0xFFFFC861)
                                )
                                Text(
                                    text = engineState.operationalStatus.description,
                                    style = MaterialTheme.typography.labelMedium,
                                    color = Color(0xFFF5F7FF)
                                )
                                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                                    if (!engineState.permissionHealth.canRunMonitoringEngine) {
                                        Button(onClick = { onNavigate(NexLockRoute.PERMISSION_SETUP) }) {
                                            Text("Complete Permission Setup")
                                        }
                                    } else if (!engineState.isMonitoringEnabledByUser ||
                                        engineState.serviceState != MonitoringServiceState.RUNNING
                                    ) {
                                        Button(onClick = { protectionEngineViewModel.startProtectionEngine() }) {
                                            Text("Start Protection Engine")
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Protection Dashboard Card (Section 11)
                    Card(
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Text("Phase 4 App Lock Engine Dashboard", style = MaterialTheme.typography.titleLarge)
                            Text(
                                "1. Total Installed Apps: ${appManagerState.totalDiscoveredCount}\n" +
                                    "2. Selected for Protection: ${appManagerState.lockedCount}\n" +
                                    "3. Protection Operational: $operationalCount\n" +
                                    "4. Monitoring Service: ${engineState.serviceState.label}\n" +
                                    "5. Engine Status: ${engineState.operationalStatus.badgeLabel}\n" +
                                    "6. Re-Lock Policy: ${engineState.reLockDurationOption.label} (Screen-Off Lock: ${if (engineState.lockOnScreenOff) "On" else "Off"})",
                                style = MaterialTheme.typography.bodyLarge
                            )
                            Text(
                                "Permissions — Usage Access: ${if (engineState.permissionHealth.usageAccessGranted) "Granted" else "Not Granted"} · " +
                                    "Overlay: ${if (engineState.permissionHealth.overlayPermissionGranted) "Granted" else "Not Granted"} · " +
                                    "Notifications: ${if (engineState.permissionHealth.notificationPermissionGranted) "Granted" else "Not Granted"}",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Row(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                modifier = Modifier.horizontalScroll(rememberScrollState())
                            ) {
                                Button(onClick = { onNavigate(NexLockRoute.APPS) }) {
                                    Text("Select Apps (${appManagerState.totalDiscoveredCount})")
                                }
                                OutlinedButton(onClick = { onNavigate(NexLockRoute.PERMISSION_SETUP) }) {
                                    Text("Permission Health")
                                }
                                if (engineState.serviceState == MonitoringServiceState.RUNNING) {
                                    OutlinedButton(onClick = { protectionEngineViewModel.pauseProtectionEngine() }) {
                                        Text("Pause Protection")
                                    }
                                } else {
                                    OutlinedButton(onClick = { protectionEngineViewModel.startProtectionEngine() }) {
                                        Text("Start Protection")
                                    }
                                }
                            }
                        }
                    }

                    if (appManagerState.uninstalledLockedApps.isNotEmpty()) {
                        Card(
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFF332612)),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text("Uninstalled Locked Apps Detected", style = MaterialTheme.typography.titleLarge, color = Color(0xFFFFC861))
                                appManagerState.uninstalledLockedApps.forEach { stale ->
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text("${stale.appName} (${stale.packageName})", style = MaterialTheme.typography.labelMedium)
                                        TextButton(onClick = { appManagerViewModel.removeStaleUninstalledApp(stale) }) {
                                            Text("Remove")
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            NexLockRoute.APPS -> {
                if (appManagerState.requiresBulkLockConfirmation) {
                    AlertDialog(
                        onDismissRequest = { appManagerViewModel.cancelLockAllEligibleApps() },
                        title = { Text("Lock All Eligible Apps?") },
                        text = {
                            Text("This will mark all discovered user-launchable applications as Selected for Protection in the local Room database.")
                        },
                        confirmButton = {
                            Button(onClick = { appManagerViewModel.confirmLockAllEligibleApps() }) {
                                Text("Confirm Lock All")
                            }
                        },
                        dismissButton = {
                            TextButton(onClick = { appManagerViewModel.cancelLockAllEligibleApps() }) {
                                Text("Cancel")
                            }
                        }
                    )
                }

                Column(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = appManagerState.searchQuery,
                            onValueChange = { appManagerViewModel.onSearchQueryChange(it) },
                            placeholder = { Text("Search app or package name...") },
                            leadingIcon = { Icon(Icons.Outlined.Search, contentDescription = null) },
                            singleLine = true,
                            modifier = Modifier.weight(1f)
                        )
                        IconButton(onClick = { appManagerViewModel.refreshInstalledApps(isInitialLoad = false) }) {
                            Icon(Icons.Outlined.Refresh, contentDescription = "Refresh Installed Apps")
                        }
                    }

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        AppFilter.entries.forEach { filter ->
                            FilterChip(
                                selected = appManagerState.selectedFilter == filter,
                                onClick = { appManagerViewModel.onFilterChange(filter) },
                                label = { Text(filter.label) }
                            )
                        }
                    }

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        FilterChip(
                            selected = appManagerState.selectedCategory == null,
                            onClick = { appManagerViewModel.onCategoryChange(null) },
                            label = { Text("All Categories") }
                        )
                        AppCategory.entries.forEach { cat ->
                            FilterChip(
                                selected = appManagerState.selectedCategory == cat,
                                onClick = { appManagerViewModel.onCategoryChange(cat) },
                                label = { Text(cat.displayName) }
                            )
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Showing ${appManagerState.filteredApps.size} of ${appManagerState.totalDiscoveredCount} apps (${appManagerState.lockedCount} selected)",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            TextButton(onClick = { appManagerViewModel.requestLockAllEligibleApps() }) {
                                Text("Lock All")
                            }
                            if (appManagerState.lockedCount > 0) {
                                TextButton(onClick = { appManagerViewModel.unlockAllApps() }) {
                                    Text("Unlock All")
                                }
                            }
                        }
                    }

                    if (appManagerState.isLoading) {
                        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                            CircularProgressIndicator()
                        }
                    } else if (appManagerState.filteredApps.isEmpty()) {
                        Card(
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(Modifier.padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                                Text("No matching applications found", style = MaterialTheme.typography.titleLarge)
                                Text(
                                    "Try clearing your search query or switching filter tabs.",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    } else {
                        LazyColumn(
                            modifier = Modifier.weight(1f),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            items(
                                items = appManagerState.filteredApps,
                                key = { it.packageName }
                            ) { app ->
                                val statusText = when {
                                    !app.isLocked -> "Unprotected"
                                    engineState.operationalStatus.isOperational -> "Protection Operational"
                                    else -> "Selected (Monitoring Paused)"
                                }
                                Card(
                                    shape = RoundedCornerShape(16.dp),
                                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            appManagerViewModel.openAppDetails(app.packageName)
                                            onNavigate(NexLockRoute.APP_CONFIG)
                                        }
                                ) {
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(14.dp),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        AppDrawableIcon(drawable = app.icon)
                                        Spacer(Modifier.width(12.dp))
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(
                                                text = app.appName,
                                                style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.SemiBold),
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis
                                            )
                                            Text(
                                                text = app.packageName,
                                                style = MaterialTheme.typography.labelMedium,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis
                                            )
                                            Text(
                                                text = "${app.category.displayName} · $statusText",
                                                style = MaterialTheme.typography.labelMedium,
                                                color = if (app.isLocked && engineState.operationalStatus.isOperational) {
                                                    Color(0xFF2DD4A3)
                                                } else if (app.isLocked) {
                                                    Color(0xFFFFC861)
                                                } else {
                                                    MaterialTheme.colorScheme.primary
                                                }
                                            )
                                        }
                                        Switch(
                                            checked = app.isLocked,
                                            onCheckedChange = { appManagerViewModel.toggleAppLock(app) }
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }

            NexLockRoute.APP_CONFIG -> {
                val detailApp = appManagerState.filteredApps.find {
                    it.packageName == appManagerState.selectedDetailPackage
                } ?: appManagerState.allApps.find {
                    it.packageName == appManagerState.selectedDetailPackage
                } ?: appManagerState.allApps.firstOrNull()

                Card(
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        if (detailApp != null) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                AppDrawableIcon(drawable = detailApp.icon)
                                Spacer(Modifier.width(12.dp))
                                Column {
                                    Text(detailApp.appName, style = MaterialTheme.typography.titleLarge)
                                    Text(detailApp.packageName, style = MaterialTheme.typography.labelMedium)
                                }
                            }
                            Text("Category: ${detailApp.category.displayName}")
                            Text("Type: ${if (detailApp.isSystemApp) "System Application" else "User Installed Application"}")
                            Text("Version: ${detailApp.versionName ?: "N/A"}")
                            Text("Re-Lock Policy: ${engineState.reLockDurationOption.label}")
                            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                                Button(onClick = { appManagerViewModel.toggleAppLock(detailApp) }) {
                                    Icon(
                                        if (detailApp.isLocked) Icons.Outlined.LockOpen else Icons.Outlined.Lock,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp)
                                    )
                                    Spacer(Modifier.width(6.dp))
                                    Text(if (detailApp.isLocked) "Unlock Application" else "Lock Application")
                                }
                                if (detailApp.isLaunchable) {
                                    OutlinedButton(onClick = { appManagerViewModel.launchApp(detailApp.packageName) }) {
                                        Text("Open App")
                                    }
                                }
                            }
                        } else {
                            Text("Select an application from the Installed Apps list.")
                        }
                    }
                }
            }

            NexLockRoute.SECURITY_SETTINGS -> {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Card(
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text("Phase 4 App Lock Engine & Re-Lock Settings", style = MaterialTheme.typography.titleLarge)

                            Text("Protected App Re-Lock Timer", style = MaterialTheme.typography.labelMedium)
                            Row(
                                modifier = Modifier.horizontalScroll(rememberScrollState()),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                ReLockDurationOption.entries.forEach { option ->
                                    FilterChip(
                                        selected = engineState.reLockDurationOption == option,
                                        onClick = { protectionEngineViewModel.setReLockDuration(option) },
                                        label = { Text(option.label) }
                                    )
                                }
                            }

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("Immediately Re-Lock When Screen Turns Off")
                                Switch(
                                    checked = engineState.lockOnScreenOff,
                                    onCheckedChange = { protectionEngineViewModel.setLockOnScreenOff(it) }
                                )
                            }

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("Enable AndroidX BiometricPrompt")
                                Switch(
                                    checked = authState.biometricEnabledInSettings,
                                    onCheckedChange = { authViewModel.setBiometricEnabled(it) }
                                )
                            }

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("Show Non-Launchable System Apps")
                                Switch(
                                    checked = appManagerState.includeSystemApps,
                                    onCheckedChange = { appManagerViewModel.onToggleIncludeSystemApps(it) }
                                )
                            }

                            Text("NEXLOCK Master Session Auto-Lock", style = MaterialTheme.typography.labelMedium)
                            Row(
                                modifier = Modifier.horizontalScroll(rememberScrollState()),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                SessionTimeoutOption.entries.forEach { option ->
                                    FilterChip(
                                        selected = authState.sessionTimeoutOption == option,
                                        onClick = { authViewModel.setSessionTimeout(option) },
                                        label = { Text(option.label) }
                                    )
                                }
                            }

                            Text("Interface Theme", style = MaterialTheme.typography.labelMedium)
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                ThemeMode.entries.forEach { mode ->
                                    FilterChip(
                                        selected = uiState.preferences.themeMode == mode,
                                        onClick = { viewModel.setThemeMode(mode) },
                                        label = { Text(mode.name) }
                                    )
                                }
                            }

                            OutlinedButton(
                                onClick = { onNavigate(NexLockRoute.PERMISSION_SETUP) },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Open Permission Health & Onboarding")
                            }
                        }
                    }

                    // Excluded Packages & Recovery Protection Card (Section 9)
                    Card(
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text("Excluded Applications & Recovery Protection", style = MaterialTheme.typography.titleLarge)
                            Text(
                                "To prevent self-lockout and guarantee access to emergency calling and permission recovery, NEXLOCK automatically excludes:",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            engineState.excludedPackages.take(6).forEach { rule ->
                                Text(
                                    "• ${rule.label} (${rule.packageNamePattern}): ${rule.reason}",
                                    style = MaterialTheme.typography.labelMedium
                                )
                            }
                        }
                    }
                }
            }

            else -> {
                Card(
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("${route.title} — NEXLOCK Phase 4 Active", style = MaterialTheme.typography.titleLarge)
                        Text(
                            "Engine: ${engineState.operationalStatus.badgeLabel} · Selected Apps: ${appManagerState.lockedCount} · Operational: ${engineState.configuredOperationalCount}",
                            style = MaterialTheme.typography.bodyLarge
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            Button(onClick = { onNavigate(NexLockRoute.APPS) }) {
                                Text("Installed Apps")
                            }
                            OutlinedButton(onClick = { onNavigate(NexLockRoute.HOME) }) {
                                Text("Dashboard")
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AppDrawableIcon(drawable: Drawable?) {
    val imageBitmap: ImageBitmap? = remember(drawable) {
        drawable?.let {
            runCatching {
                val width = it.intrinsicWidth.coerceAtLeast(96).coerceAtMost(192)
                val height = it.intrinsicHeight.coerceAtLeast(96).coerceAtMost(192)
                it.toBitmap(width = width, height = height).asImageBitmap()
            }.getOrNull()
        }
    }

    if (imageBitmap != null) {
        Image(
            bitmap = imageBitmap,
            contentDescription = "App Icon",
            modifier = Modifier
                .size(44.dp)
                .clip(RoundedCornerShape(12.dp))
        )
    } else {
        Box(
            modifier = Modifier
                .size(44.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.16f)),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = Icons.Outlined.Android,
                contentDescription = "Fallback App Icon",
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(24.dp)
            )
        }
    }
}
