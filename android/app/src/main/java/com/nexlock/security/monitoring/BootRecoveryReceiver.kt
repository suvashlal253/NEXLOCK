package com.nexlock.security.monitoring

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Boot Recovery Receiver (Section 10).
 *
 * Restarts AppLockMonitoringService after a device reboot ONLY if:
 * 1. The user explicitly enabled persistent monitoring.
 * 2. At least one application is marked as locked in Room.
 * 3. Usage Access and Overlay permissions are still granted.
 *
 * If Android 14/15 background start restrictions prevent starting the service on boot,
 * NEXLOCK records the stopped state honestly rather than falsely claiming protection is active.
 */
class BootRecoveryReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != Intent.ACTION_MY_PACKAGE_REPLACED
        ) {
            return
        }

        val pendingResult = goAsync()
        val appContext = context.applicationContext
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            try {
                val repo = AppLockEngineRepository.getInstance(appContext)
                if (repo.shouldAutoStartMonitoringOnBoot()) {
                    AppLockMonitoringService.startMonitoringService(appContext)
                } else {
                    repo.updateServiceState(MonitoringServiceState.STOPPED)
                }
            } finally {
                pendingResult.finish()
            }
        }
    }
}
