package com.nexlock.security.discovery

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build

/**
 * Dynamically registered BroadcastReceiver for detecting package installation, update, and removal.
 *
 * Android 8+ (API 26+) Compliance:
 * Package change broadcasts (ACTION_PACKAGE_ADDED, ACTION_PACKAGE_REMOVED, ACTION_PACKAGE_REPLACED)
 * must be registered dynamically in an active Context with dataScheme("package"), combined with an
 * explicit foreground refresh in Activity.onResume() so missed background events are reconciled.
 */
sealed class PackageChangeEvent(open val packageName: String) {
    data class Installed(override val packageName: String) : PackageChangeEvent(packageName)
    data class Updated(override val packageName: String) : PackageChangeEvent(packageName)
    data class Uninstalled(override val packageName: String) : PackageChangeEvent(packageName)
}

class PackageChangeReceiver(
    private val onPackageChanged: (PackageChangeEvent) -> Unit
) : BroadcastReceiver() {

    override fun onReceive(context: Context?, intent: Intent?) {
        val action = intent?.action ?: return
        val pkg = intent.data?.schemeSpecificPart?.takeIf { it.isNotBlank() } ?: return
        val isReplacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)

        when (action) {
            Intent.ACTION_PACKAGE_ADDED -> {
                if (isReplacing) {
                    onPackageChanged(PackageChangeEvent.Updated(pkg))
                } else {
                    onPackageChanged(PackageChangeEvent.Installed(pkg))
                }
            }
            Intent.ACTION_PACKAGE_REPLACED -> {
                onPackageChanged(PackageChangeEvent.Updated(pkg))
            }
            Intent.ACTION_PACKAGE_REMOVED -> {
                // Only treat as full uninstallation if EXTRA_REPLACING is false
                if (!isReplacing) {
                    onPackageChanged(PackageChangeEvent.Uninstalled(pkg))
                }
            }
        }
    }

    companion object {
        fun register(
            context: Context,
            onPackageChanged: (PackageChangeEvent) -> Unit
        ): PackageChangeReceiver {
            val receiver = PackageChangeReceiver(onPackageChanged)
            val filter = IntentFilter().apply {
                addAction(Intent.ACTION_PACKAGE_ADDED)
                addAction(Intent.ACTION_PACKAGE_REMOVED)
                addAction(Intent.ACTION_PACKAGE_REPLACED)
                addDataScheme("package")
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                context.registerReceiver(receiver, filter)
            }
            return receiver
        }
    }
}
