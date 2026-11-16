package com.nexlock.security.lockengine

import android.content.Context
import android.content.Intent
import android.graphics.drawable.Drawable
import android.os.Bundle
import androidx.activity.OnBackPressedCallback
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Android
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
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
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.nexlock.security.auth.AuthMethod
import com.nexlock.security.auth.BiometricCapabilityStatus
import com.nexlock.security.auth.NexLockBiometricManager
import com.nexlock.security.auth.PinManager
import com.nexlock.security.auth.SessionManager
import com.nexlock.security.discovery.AppIconMemoryCache
import com.nexlock.security.monitoring.AppLockEngineRepository
import com.nexlock.security.repository.AuthRepository
import com.nexlock.security.repository.SecuritySettingsRepository
import com.nexlock.security.security.SecureKeyManager
import com.nexlock.security.ui.theme.NexLockTheme
import com.nexlock.security.viewmodel.AuthenticationViewModel

/**
 * Dedicated NEXLOCK Lock Challenge Screen (Section 4).
 *
 * Launched when AppLockMonitoringService detects that a protected package has entered the foreground
 * without a valid temporary unlock session.
 *
 * Security Guarantees:
 * 1. Reuses Phase 2 AuthRepository (PBKDF2-HMAC-SHA256 + AndroidKeyStore AES-256-GCM) and
 *    NexLockBiometricManager (AndroidX BiometricPrompt).
 * 2. Never creates a duplicate PIN store or uses hardcoded bypass credentials.
 * 3. Intercepts Back navigation and exits cleanly to the Android Home Launcher so protected
 *    content remains inaccessible without force-stopping or killing the target application.
 * 4. Excluded from triggering recursive lock challenges via ExcludedSystemPackages.NEXLOCK_PACKAGE.
 */
class AppLockActivity : FragmentActivity() {

    private lateinit var engineRepository: AppLockEngineRepository
    private var targetPackageName: String = ""

    companion object {
        const val EXTRA_TARGET_PACKAGE = "com.nexlock.security.extra.TARGET_PACKAGE"

        fun createLaunchIntent(context: Context, targetPackageName: String): Intent {
            return Intent(context, AppLockActivity::class.java).apply {
                putExtra(EXTRA_TARGET_PACKAGE, targetPackageName)
                addFlags(
                    Intent.FLAG_ACTIVITY_NEW_TASK or
                        Intent.FLAG_ACTIVITY_SINGLE_TOP or
                        Intent.FLAG_ACTIVITY_CLEAR_TOP or
                        Intent.FLAG_ACTIVITY_NO_ANIMATION
                )
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        engineRepository = AppLockEngineRepository.getInstance(applicationContext)
        targetPackageName = intent?.getStringExtra(EXTRA_TARGET_PACKAGE).orEmpty()

        if (targetPackageName.isBlank()) {
            finish()
            return
        }

        // Intercept system Back press so the user cannot dismiss the lock challenge to reveal the target app
        onBackPressedDispatcher.addCallback(
            this,
            object : OnBackPressedCallback(true) {
                override fun handleOnBackPressed() {
                    navigateToHomeLauncherAndFinish()
                }
            }
        )

        val pinManager = PinManager()
        val secureKeyManager = SecureKeyManager()
        val settingsStore = SecuritySettingsRepository(applicationContext)
        val sessionManager = SessionManager()
        val biometricManager = NexLockBiometricManager(applicationContext)
        val authRepository = AuthRepository(
            pinManager = pinManager,
            keyManager = secureKeyManager,
            settingsStore = settingsStore,
            sessionManager = sessionManager
        )

        val authViewModel = ViewModelProvider(
            this,
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return AuthenticationViewModel(
                        authRepository = authRepository,
                        settingsStore = settingsStore,
                        sessionManager = sessionManager,
                        biometricGateway = biometricManager,
                        keyManager = secureKeyManager
                    ) as T
                }
            }
        )[AuthenticationViewModel::class.java]

        val iconCache = AppIconMemoryCache()
        val pm = applicationContext.packageManager
        val appLabel = runCatching {
            val appInfo = pm.getApplicationInfo(targetPackageName, 0)
            pm.getApplicationLabel(appInfo).toString()
        }.getOrDefault(targetPackageName)
        val appDrawable = iconCache.getOrLoadIcon(pm, targetPackageName)

        setContent {
            val authState by authViewModel.authState.collectAsState()
            NexLockTheme {
                AppLockChallengeScreen(
                    targetPackageName = targetPackageName,
                    targetAppName = appLabel,
                    targetAppIcon = appDrawable,
                    authState = authState,
                    onPinSubmit = { pinInput, onComplete ->
                        authViewModel.authenticateWithPin(pinInput) {
                            onComplete()
                            engineRepository.grantPackageAccessAfterAuthentication(
                                packageName = targetPackageName,
                                authMethod = AuthMethod.MASTER_PIN
                            )
                            finish()
                        }
                    },
                    onBiometricPromptRequest = {
                        authViewModel.authenticateWithBiometric(this@AppLockActivity) {
                            engineRepository.grantPackageAccessAfterAuthentication(
                                packageName = targetPackageName,
                                authMethod = AuthMethod.BIOMETRIC_PROMPT
                            )
                            finish()
                        }
                    },
                    onExitToHome = {
                        navigateToHomeLauncherAndFinish()
                    }
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        val updatedPkg = intent.getStringExtra(EXTRA_TARGET_PACKAGE).orEmpty()
        if (updatedPkg.isNotBlank()) {
            targetPackageName = updatedPkg
        }
    }

    private fun navigateToHomeLauncherAndFinish() {
        engineRepository.onChallengeDismissed(targetPackageName)
        val homeIntent = Intent(Intent.ACTION_MAIN).apply {
            addCategory(Intent.CATEGORY_HOME)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        runCatching { startActivity(homeIntent) }
        finish()
    }
}

@Composable
private fun AppLockChallengeScreen(
    targetPackageName: String,
    targetAppName: String,
    targetAppIcon: Drawable?,
    authState: com.nexlock.security.auth.AuthenticationState,
    onPinSubmit: (String, () -> Unit) -> Unit,
    onBiometricPromptRequest: () -> Unit,
    onExitToHome: () -> Unit
) {
    var pinInput by remember { mutableStateOf("") }
    var isVerifying by remember { mutableStateOf(false) }

    // Automatically trigger BiometricPrompt on launch if enabled and hardware is ready
    LaunchedEffect(authState.biometricEnabledInSettings, authState.biometricCapability) {
        if (authState.biometricEnabledInSettings &&
            authState.biometricCapability == BiometricCapabilityStatus.AVAILABLE &&
            !authState.isTemporarilyLockedOut
        ) {
            onBiometricPromptRequest()
        }
    }

    val iconBitmap: ImageBitmap? = remember(targetAppIcon) {
        targetAppIcon?.let {
            runCatching {
                val w = it.intrinsicWidth.coerceIn(96, 192)
                val h = it.intrinsicHeight.coerceIn(96, 192)
                it.toBitmap(width = w, height = h).asImageBitmap()
            }.getOrNull()
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF0B1020))
            .padding(24.dp)
            .semantics { contentDescription = "NEXLOCK Authentication Challenge Screen for $targetAppName" },
        contentAlignment = Alignment.Center
    ) {
        Card(
            shape = RoundedCornerShape(28.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF151D32)),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                // NEXLOCK Badge
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Shield,
                        contentDescription = "NEXLOCK Shield",
                        tint = Color(0xFF5B8CFF),
                        modifier = Modifier.size(20.dp)
                    )
                    Text(
                        text = "NEXLOCK PROTECTION ENGINE",
                        style = MaterialTheme.typography.labelMedium,
                        color = Color(0xFF5B8CFF),
                        fontWeight = FontWeight.Bold
                    )
                }

                // Target Application Icon
                if (iconBitmap != null) {
                    Image(
                        bitmap = iconBitmap,
                        contentDescription = "$targetAppName Icon",
                        modifier = Modifier
                            .size(68.dp)
                            .clip(RoundedCornerShape(18.dp))
                    )
                } else {
                    Box(
                        modifier = Modifier
                            .size(68.dp)
                            .clip(CircleShape)
                            .background(Color(0xFF5B8CFF).copy(alpha = 0.18f)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Android,
                            contentDescription = "$targetAppName Fallback Icon",
                            tint = Color(0xFF5B8CFF),
                            modifier = Modifier.size(36.dp)
                        )
                    }
                }

                // Target Application Name & Protection Notice
                Text(
                    text = targetAppName,
                    style = MaterialTheme.typography.headlineLarge,
                    color = Color(0xFFF5F7FF),
                    textAlign = TextAlign.Center
                )
                Text(
                    text = "This app is protected by NEXLOCK",
                    style = MaterialTheme.typography.bodyLarge,
                    color = Color(0xFFA6B0C3),
                    textAlign = TextAlign.Center
                )
                Text(
                    text = targetPackageName,
                    style = MaterialTheme.typography.labelMedium,
                    color = Color(0xFFA6B0C3).copy(alpha = 0.7f),
                    textAlign = TextAlign.Center
                )

                // Error or Temporary Lockout Message
                if (authState.isTemporarilyLockedOut) {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = Color(0xFF3B1824)),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = "Too many failed attempts. Try again in ${authState.lockoutRemainingSeconds}s.",
                            color = Color(0xFFFF8A8A),
                            style = MaterialTheme.typography.labelMedium,
                            modifier = Modifier.padding(12.dp),
                            textAlign = TextAlign.Center
                        )
                    }
                } else if (authState.errorMessage != null) {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = Color(0xFF3B1824)),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = authState.errorMessage,
                            color = Color(0xFFFF8A8A),
                            style = MaterialTheme.typography.labelMedium,
                            modifier = Modifier.padding(12.dp),
                            textAlign = TextAlign.Center
                        )
                    }
                }

                // PIN Input Field
                OutlinedTextField(
                    value = pinInput,
                    onValueChange = { next ->
                        if (next.length <= 6 && next.all(Char::isDigit)) {
                            pinInput = next
                        }
                    },
                    label = { Text("Enter Master PIN") },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    enabled = !authState.isTemporarilyLockedOut && !isVerifying,
                    modifier = Modifier
                        .fillMaxWidth()
                        .semantics { contentDescription = "Master PIN input field" }
                )

                // Quick Numeric Keypad (0-9) for ergonomic thumb entry
                Column(
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    listOf(
                        listOf("1", "2", "3"),
                        listOf("4", "5", "6"),
                        listOf("7", "8", "9"),
                        listOf("Clear", "0", "⌫")
                    ).forEach { rowKeys ->
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            rowKeys.forEach { key ->
                                OutlinedButton(
                                    onClick = {
                                        when (key) {
                                            "Clear" -> pinInput = ""
                                            "⌫" -> if (pinInput.isNotEmpty()) pinInput = pinInput.dropLast(1)
                                            else -> if (pinInput.length < 6) pinInput += key
                                        }
                                    },
                                    enabled = !authState.isTemporarilyLockedOut && !isVerifying,
                                    modifier = Modifier
                                        .weight(1f)
                                        .height(46.dp)
                                ) {
                                    Text(key, style = MaterialTheme.typography.bodyLarge)
                                }
                            }
                        }
                    }
                }

                if (isVerifying) {
                    CircularProgressIndicator(modifier = Modifier.size(28.dp))
                }

                // Unlock with PIN + Fingerprint Buttons
                Row(
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Button(
                        onClick = {
                            isVerifying = true
                            onPinSubmit(pinInput) {
                                isVerifying = false
                                pinInput = ""
                            }
                            isVerifying = false
                        },
                        enabled = pinInput.length >= 4 && !authState.isTemporarilyLockedOut,
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp)
                    ) {
                        Icon(Icons.Outlined.Lock, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Unlock with PIN")
                    }

                    if (authState.biometricCapability == BiometricCapabilityStatus.AVAILABLE) {
                        OutlinedButton(
                            onClick = onBiometricPromptRequest,
                            enabled = !authState.isTemporarilyLockedOut,
                            modifier = Modifier
                                .weight(1f)
                                .height(48.dp)
                                .semantics { contentDescription = "Authenticate with Fingerprint" }
                        ) {
                            Icon(Icons.Outlined.Fingerprint, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Fingerprint")
                        }
                    }
                }

                // Safe Exit to Home Screen
                TextButton(
                    onClick = onExitToHome,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Outlined.Home, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Cancel & Exit to Home Screen")
                }
            }
        }
    }
}
