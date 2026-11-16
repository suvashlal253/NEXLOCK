package com.nexlock.security.monitoring

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.nexlock.security.MainActivity
import com.nexlock.security.R
import com.nexlock.security.lockengine.AppLockActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Foreground Monitoring Service for NEXLOCK Phase 4 (Sections 2, 5, 8, 10).
 *
 * Architectural & Android Compliance Guarantees:
 * 1. Uses a transparent, user-visible ForegroundService (specialUse subtype: app_lock_protection)
 *    with an ongoing status notification. Never uses hidden AccessibilityServices or
 *    full-screen intent notifications to bypass Android restrictions.
 * 2. Polls UsageStatsManager.queryEvents() with adaptive intervals (400ms active -> 1100ms stable)
 *    and suspends polling completely while the device screen is off.
 * 3. Automatically stops itself when 0 applications are locked, when the user pauses protection,
 *    or when Usage Access / Overlay permissions are revoked.
 */
class AppLockMonitoringService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var monitoringJob: Job? = null
    private lateinit var engineRepository: AppLockEngineRepository
    private lateinit var detector: ForegroundAppDetector
    private var screenStateReceiver: BroadcastReceiver? = null

    companion object {
        const val CHANNEL_ID = "nexlock_protection_monitoring_channel"
        const val NOTIFICATION_ID = 4102
        const val ACTION_START_MONITORING = "com.nexlock.security.action.START_MONITORING"
        const val ACTION_PAUSE_MONITORING = "com.nexlock.security.action.PAUSE_MONITORING"

        fun startMonitoringService(context: Context): Boolean {
            val repo = AppLockEngineRepository.getInstance(context)
            val perms = repo.refreshPermissionHealth()
            if (!perms.canRunMonitoringEngine) {
                repo.updateServiceState(
                    MonitoringServiceState.STOPPED,
                    "Grant Usage Access and Display Over Other Apps permissions before starting monitoring."
                )
                return false
            }

            return try {
                repo.updateServiceState(MonitoringServiceState.STARTING)
                val intent = Intent(context, AppLockMonitoringService::class.java).apply {
                    action = ACTION_START_MONITORING
                }
                ContextCompat.startForegroundService(context, intent)
                true
            } catch (e: Exception) {
                repo.updateServiceState(
                    MonitoringServiceState.FAILED_TO_START,
                    "Android restricted foreground service launch (${e.javaClass.simpleName}). Open NEXLOCK to start monitoring."
                )
                false
            }
        }

        fun stopMonitoringService(context: Context) {
            val repo = AppLockEngineRepository.getInstance(context)
            runCatching {
                context.stopService(Intent(context, AppLockMonitoringService::class.java))
            }
            repo.updateServiceState(MonitoringServiceState.STOPPED)
        }
    }

    override fun onCreate() {
        super.onCreate()
        engineRepository = AppLockEngineRepository.getInstance(applicationContext)
        detector = ForegroundAppDetector(UsageStatsRepository(applicationContext))
        createNotificationChannel()
        registerScreenStateReceiver()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_PAUSE_MONITORING) {
            serviceScope.launch {
                engineRepository.setMonitoringEnabledByUser(false)
                stopForegroundAndTerminate()
            }
            return START_NOT_STICKY
        }

        val perms = engineRepository.refreshPermissionHealth()
        if (!perms.canRunMonitoringEngine) {
            engineRepository.updateServiceState(
                MonitoringServiceState.STOPPED,
                "Required permissions missing; stopping monitoring service."
            )
            stopSelf()
            return START_NOT_STICKY
        }

        val lockedCount = engineRepository.engineStateFlow.value.selectedLockedCount
        val notification = buildMonitoringNotification(lockedCount)

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
            engineRepository.updateServiceState(
                MonitoringServiceState.RUNNING,
                "App Lock Monitoring Service is active."
            )
            startAdaptiveMonitoringLoop()
        } catch (e: Exception) {
            engineRepository.updateServiceState(
                MonitoringServiceState.FAILED_TO_START,
                "Unable to enter foreground service state: ${e.javaClass.simpleName}"
            )
            stopSelf()
            return START_NOT_STICKY
        }

        return START_STICKY
    }

    private fun startAdaptiveMonitoringLoop() {
        if (monitoringJob?.isActive == true) return

        monitoringJob = serviceScope.launch {
            val powerManager = getSystemService(Context.POWER_SERVICE) as? PowerManager

            while (isActive) {
                val perms = engineRepository.refreshPermissionHealth()
                val engineState = engineRepository.engineStateFlow.value

                // Stop service if permissions were revoked, user paused monitoring, or no apps are locked
                if (!perms.canRunMonitoringEngine ||
                    !engineState.isMonitoringEnabledByUser ||
                    engineState.selectedLockedCount <= 0
                ) {
                    stopForegroundAndTerminate()
                    break
                }

                val isInteractive = powerManager?.isInteractive ?: true
                if (!isInteractive) {
                    engineRepository.onScreenInteractiveChanged(false)
                    delay(1_500L)
                    continue
                }

                val transitions = detector.pollNewTransitions()
                val pollInterval = detector.computeAdaptivePollIntervalMillis(isInteractive)

                for (event in transitions) {
                    val decision = engineRepository.engine.onForegroundTransition(event)
                    engineRepository.recordForegroundEvaluation(
                        event = event,
                        decision = decision,
                        adaptivePollMillis = pollInterval
                    )

                    if (decision is LockEnforcementDecision.RequireAuthentication) {
                        launchLockChallengeScreen(decision.packageName)
                    }
                }

                delay(pollInterval.coerceAtLeast(350L))
            }
        }
    }

    private fun launchLockChallengeScreen(targetPackageName: String) {
        try {
            val challengeIntent = AppLockActivity.createLaunchIntent(
                context = applicationContext,
                targetPackageName = targetPackageName
            )
            startActivity(challengeIntent)
        } catch (e: Exception) {
            // If Android suppresses background activity start, clear visibility lock so next poll can retry
            engineRepository.onChallengeDismissed(targetPackageName)
            engineRepository.updateServiceState(
                MonitoringServiceState.RUNNING,
                "Android delayed background lock-screen launch. Verify Display Over Other Apps permission is enabled."
            )
        }
    }

    private fun registerScreenStateReceiver() {
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_USER_PRESENT)
        }
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_SCREEN_OFF -> {
                        engineRepository.onScreenInteractiveChanged(false)
                    }
                    Intent.ACTION_SCREEN_ON,
                    Intent.ACTION_USER_PRESENT -> {
                        engineRepository.onScreenInteractiveChanged(true)
                    }
                }
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(receiver, filter)
        }
        screenStateReceiver = receiver
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "NEXLOCK Protection Engine",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows when NEXLOCK is actively monitoring protected applications."
                setShowBadge(false)
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            manager?.createNotificationChannel(channel)
        }
    }

    private fun buildMonitoringNotification(lockedCount: Int): Notification {
        val openDashboardIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingOpen = PendingIntent.getActivity(
            this,
            100,
            openDashboardIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val pauseIntent = Intent(this, AppLockMonitoringService::class.java).apply {
            action = ACTION_PAUSE_MONITORING
        }
        val pendingPause = PendingIntent.getService(
            this,
            101,
            pauseIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle("NEXLOCK Protection Active")
            .setContentText("Monitoring $lockedCount protected application(s)")
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(pendingOpen)
            .addAction(0, "Pause Protection", pendingPause)
            .build()
    }

    private fun stopForegroundAndTerminate() {
        monitoringJob?.cancel()
        monitoringJob = null
        engineRepository.updateServiceState(MonitoringServiceState.STOPPED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        stopSelf()
    }

    override fun onDestroy() {
        monitoringJob?.cancel()
        screenStateReceiver?.let {
            runCatching { unregisterReceiver(it) }
        }
        screenStateReceiver = null
        engineRepository.updateServiceState(MonitoringServiceState.STOPPED)
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
