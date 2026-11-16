package com.nexlock.security.discovery

import android.content.pm.ApplicationInfo
import android.graphics.drawable.Drawable
import android.os.Build

/**
 * Automatic application categories required in NEXLOCK Phase 3.
 * Uses Android ApplicationInfo.category metadata and package domain rules (never display name heuristics).
 */
enum class AppCategory(val displayName: String) {
    SOCIAL_MEDIA("Social Media"),
    COMMUNICATION("Communication"),
    ENTERTAINMENT("Entertainment"),
    FINANCE("Finance"),
    SHOPPING("Shopping"),
    PRODUCTIVITY("Productivity"),
    GAMES("Games"),
    PHOTOGRAPHY("Photography"),
    TOOLS("Tools"),
    OTHER("Other");

    companion object {
        fun fromMetadata(
            androidCategory: Int,
            packageName: String
        ): AppCategory {
            val pkg = packageName.lowercase()

            // First inspect known package domain namespaces (immune to localized display names)
            when {
                pkg.startsWith("com.whatsapp") ||
                    pkg.startsWith("org.thoughtcrime.securesms") ||
                    pkg.startsWith("org.telegram") ||
                    pkg.startsWith("com.discord") ||
                    pkg.startsWith("com.google.android.apps.messaging") ->
                    return COMMUNICATION

                pkg.startsWith("com.instagram") ||
                    pkg.startsWith("com.zhiliaoapp.musically") ||
                    pkg.startsWith("com.twitter") ||
                    pkg.startsWith("com.facebook.katana") ||
                    pkg.startsWith("com.linkedin") ||
                    pkg.startsWith("com.reddit") ->
                    return SOCIAL_MEDIA

                pkg.startsWith("com.revolut") ||
                    pkg.startsWith("com.coinbase") ||
                    pkg.startsWith("com.paypal") ||
                    pkg.startsWith("com.chase") ||
                    pkg.startsWith("com.stripe") ||
                    pkg.startsWith("com.google.android.apps.nbu.paisa") ->
                    return FINANCE

                pkg.startsWith("com.amazon") ||
                    pkg.startsWith("com.ebay") ||
                    pkg.startsWith("com.shopify") ||
                    pkg.startsWith("com.alibaba") ->
                    return SHOPPING

                pkg.startsWith("com.google.android.apps.photos") ||
                    pkg.startsWith("com.adobe.lrmobile") ||
                    pkg.startsWith("com.vsco") ||
                    pkg.contains(".camera") ->
                    return PHOTOGRAPHY

                pkg.startsWith("com.netflix") ||
                    pkg.startsWith("com.spotify") ||
                    pkg.startsWith("com.google.android.youtube") ||
                    pkg.startsWith("tv.twitch") ->
                    return ENTERTAINMENT

                pkg.startsWith("com.google.android.gm") ||
                    pkg.startsWith("com.google.android.apps.docs") ||
                    pkg.startsWith("com.slack") ||
                    pkg.startsWith("com.microsoft.office") ||
                    pkg.startsWith("notion.id") ->
                    return PRODUCTIVITY

                pkg.startsWith("com.android.settings") ||
                    pkg.startsWith("com.google.android.calculator") ||
                    pkg.startsWith("com.android.vending") ||
                    pkg.startsWith("com.1password") ||
                    pkg.startsWith("com.bitwarden") ->
                    return TOOLS
            }

            // Second, map official Android ApplicationInfo.category (API 26+)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                return when (androidCategory) {
                    ApplicationInfo.CATEGORY_GAME -> GAMES
                    ApplicationInfo.CATEGORY_SOCIAL -> SOCIAL_MEDIA
                    ApplicationInfo.CATEGORY_VIDEO,
                    ApplicationInfo.CATEGORY_AUDIO -> ENTERTAINMENT
                    ApplicationInfo.CATEGORY_IMAGE -> PHOTOGRAPHY
                    ApplicationInfo.CATEGORY_PRODUCTIVITY -> PRODUCTIVITY
                    ApplicationInfo.CATEGORY_MAPS -> TOOLS
                    else -> OTHER
                }
            }
            return OTHER
        }

        fun fromDisplayName(name: String): AppCategory =
            entries.find { it.displayName.equals(name, ignoreCase = true) } ?: OTHER
    }
}

/**
 * Filter tabs on the Installed Applications screen.
 */
enum class AppFilter(val label: String) {
    ALL("All"),
    LOCKED("Locked"),
    UNLOCKED("Unlocked"),
    SYSTEM_APPS("System Apps")
}

/**
 * Explicit protection state distinction required by Phase 3 Section 5.
 * Never claims the foreground lock engine is active before Phase 4.
 */
enum class ProtectionStatus(val label: String, val detail: String) {
    UNPROTECTED(
        "Unprotected",
        "Not selected for NEXLOCK protection."
    ),
    SELECTED_FOR_PROTECTION(
        "Selected for Protection",
        "Saved in local Room database; Master PIN required before enforcement."
    ),
    PROTECTION_CONFIGURED(
        "Protection Configured",
        "Lock policy persisted in Room & verified with Master Auth (Phase 4 lock engine required for OS interception)."
    ),
    PROTECTION_ENGINE_ACTIVE(
        "Protection Engine Active",
        "Foreground UsageStatsManager & Overlay lock engine actively enforcing (Phase 4)."
    ),
    PROTECTION_TEMPORARILY_UNAVAILABLE(
        "Protection Temporarily Unavailable",
        "Package was uninstalled or hidden under Android package visibility rules."
    )
}

/**
 * Core InstalledApp domain model required by Phase 3 Section 2.
 * Note: Drawable icon is held in memory/cache only and NEVER persisted in Room.
 */
data class InstalledApp(
    val packageName: String,
    val appName: String,
    val icon: Drawable? = null,
    val isSystemApp: Boolean,
    val isLaunchable: Boolean,
    val isLocked: Boolean,
    val isVisible: Boolean = true,
    val category: AppCategory = AppCategory.OTHER,
    val versionName: String = "1.0",
    val isInstalled: Boolean = true,
    val protectionStatus: ProtectionStatus = if (isLocked) {
        ProtectionStatus.PROTECTION_CONFIGURED
    } else {
        ProtectionStatus.UNPROTECTED
    },
    val createdAtMillis: Long = System.currentTimeMillis(),
    val updatedAtMillis: Long = System.currentTimeMillis()
)

/**
 * Complete UI state for AppManagerViewModel.
 */
data class AppManagerUiState(
    val installedApps: List<InstalledApp> = emptyList(),
    val filteredApps: List<InstalledApp> = emptyList(),
    val uninstalledLockedApps: List<InstalledApp> = emptyList(),
    val searchQuery: String = "",
    val selectedFilter: AppFilter = AppFilter.ALL,
    val selectedCategory: AppCategory? = null,
    val isMultiSelectMode: Boolean = false,
    val selectedPackageNames: Set<String> = emptySet(),
    val totalInstalledCount: Int = 0,
    val totalLockedCount: Int = 0,
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val requiresBulkLockConfirmation: Boolean = false,
    val errorMessage: String? = null,
    val statusMessage: String? = null
)
