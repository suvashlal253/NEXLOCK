package com.nexlock.security.model

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

enum class ReLockPolicy(val label: String, val description: String) {
    IMMEDIATELY("Immediately on exit", "Re-locks as soon as the protected app leaves the foreground"),
    SCREEN_OFF("When screen turns off", "Stays unlocked until the device display powers down"),
    AFTER_1_MIN("After 1 minute", "Allows brief app switching for 60 seconds before re-locking"),
    AFTER_5_MIN("After 5 minutes", "Keeps session active for 5 minutes after leaving the app")
}

/**
 * Phase 5 Security Event Severity levels.
 */
enum class SecurityEventSeverity(val label: String) {
    INFO("Info"),
    WARNING("Warning"),
    CRITICAL("Critical");

    companion object {
        fun fromString(raw: String?): SecurityEventSeverity =
            entries.firstOrNull { it.name.equals(raw, ignoreCase = true) } ?: INFO
    }
}

/**
 * Phase 3 LockedAppEntity with unique index on packageName.
 * Never stores Drawable objects in Room.
 */
@Entity(
    tableName = "locked_apps",
    indices = [Index(value = ["packageName"], unique = true)]
)
data class LockedAppEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val packageName: String,
    val appName: String,
    val isLocked: Boolean,
    val category: String,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis()
)

@Entity(tableName = "protected_apps")
data class ProtectedAppEntity(
    @PrimaryKey val packageName: String,
    val appName: String,
    val category: String,
    val isLocked: Boolean = false,
    val allowBiometric: Boolean = true,
    val hideNotificationsPreview: Boolean = false,
    val customReLockPolicy: String? = null,
    val updatedAtEpochMillis: Long = System.currentTimeMillis()
)

/**
 * Phase 5 SecurityEventEntity (Room Schema v3).
 *
 * Security Invariant:
 * - Never stores raw PINs, passwords, cryptographic keys, or biometric templates.
 * - Backward compatible with Phase 1–4 callers via default parameter values.
 */
@Entity(
    tableName = "security_events",
    indices = [
        Index(value = ["eventType"]),
        Index(value = ["timestampMillis"]),
        Index(value = ["severity"])
    ]
)
data class SecurityEventEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val eventType: String,
    val packageName: String? = null,
    val authenticationMethod: String? = null,
    val title: String,
    val detail: String,
    val severity: String = SecurityEventSeverity.INFO.name,
    val metadata: String = "",
    val timestampMillis: Long = System.currentTimeMillis()
) {
    val eventDescription: String get() = detail
}

/**
 * Phase 5 IntruderImageEntity (Room Schema v3).
 *
 * Stores metadata for local AES-256-GCM encrypted intruder selfie captures or camera-unavailable records.
 * Actual image bytes are stored encrypted inside app-private storage (filesDir/intruder_encrypted/)
 * and are NEVER stored as plaintext or uploaded to external servers.
 */
@Entity(
    tableName = "intruder_images",
    indices = [Index(value = ["timestampMillis"])]
)
data class IntruderImageEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestampMillis: Long = System.currentTimeMillis(),
    val targetPackageName: String?,
    val consecutiveFailures: Int,
    val authenticationMethod: String,
    val encryptedFilePath: String?,
    val encryptionIvBase64: String?,
    val byteSize: Long = 0L,
    val captureStatus: String
)

/**
 * Phase 5 VaultItemMetadataEntity (Room Schema v3).
 *
 * Stores non-sensitive metadata for AES-256-GCM encrypted files managed by SecureFileRepository.
 * Never stores file content or encryption keys in Room.
 */
@Entity(tableName = "vault_items_metadata")
data class VaultItemMetadataEntity(
    @PrimaryKey val id: String,
    val displayName: String,
    val mediaType: String,
    val sizeBytes: Long,
    val addedAtMillis: Long,
    val encryptedRelativePath: String = "",
    val encryptionIvBase64: String = "",
    val ciphertextSha256Hex: String = ""
)

data class PermissionStatusItem(
    val id: String,
    val title: String,
    val androidPermission: String,
    val whyRequired: String,
    val limitationNote: String,
    val isGrantedInPreview: Boolean,
    val phaseImplemented: String
)

/**
 * Phase 6 Lock Mode Management (Section 2).
 */
enum class LockMode(
    val id: String,
    val label: String,
    val description: String
) {
    NORMAL(
        id = "NORMAL",
        label = "Normal Protection",
        description = "Applies your configured re-lock timer and active smart schedules."
    ),
    MAX_SECURITY(
        id = "MAX_SECURITY",
        label = "Maximum Security",
        description = "Forces immediate re-lock on app exit, screen-off lock, and strict intruder threshold (3 attempts)."
    ),
    NIGHT(
        id = "NIGHT",
        label = "Night Mode",
        description = "Enforces overnight protection across all locked apps with immediate re-lock and silent notifications."
    ),
    CUSTOM(
        id = "CUSTOM",
        label = "Custom Schedule Rules",
        description = "Enforces protection strictly according to your active Smart Lock Schedules and per-app overrides."
    );

    companion object {
        fun fromId(raw: String?): LockMode =
            entries.firstOrNull { it.id.equals(raw, ignoreCase = true) } ?: NORMAL
    }
}

/**
 * Phase 6 Appearance & Lock Screen Personalization enums (Sections 3 & 4).
 */
enum class ThemePreference(val id: String, val label: String) {
    DARK("DARK", "Dark (Obsidian)"),
    LIGHT("LIGHT", "Light (Clean Daylight)"),
    SYSTEM("SYSTEM", "Follow System");

    companion object {
        fun fromId(raw: String?): ThemePreference =
            entries.firstOrNull { it.id.equals(raw, ignoreCase = true) } ?: DARK
    }
}

enum class AccentColorPreset(val id: String, val label: String, val hexColor: String) {
    NEXLOCK_BLUE("NEXLOCK_BLUE", "Electric Security Blue", "#5B8CFF"),
    VIOLET_PULSE("VIOLET_PULSE", "Quantum Violet", "#9B7BFF"),
    EMERALD_SHIELD("EMERALD_SHIELD", "Emerald Shield", "#2DD4A3"),
    CYBER_AMBER("CYBER_AMBER", "Cyber Amber", "#F59E0B"),
    CRIMSON_GUARD("CRIMSON_GUARD", "Crimson Guard", "#F43F5E");

    companion object {
        fun fromId(raw: String?): AccentColorPreset =
            entries.firstOrNull { it.id.equals(raw, ignoreCase = true) } ?: NEXLOCK_BLUE
    }
}

enum class AppListDensity(val id: String, val label: String) {
    COMFORTABLE("COMFORTABLE", "Comfortable"),
    COMPACT("COMPACT", "Compact");

    companion object {
        fun fromId(raw: String?): AppListDensity =
            entries.firstOrNull { it.id.equals(raw, ignoreCase = true) } ?: COMFORTABLE
    }
}

enum class LockScreenBackgroundStyle(val id: String, val label: String) {
    OBSIDIAN_GRADIENT("OBSIDIAN_GRADIENT", "Obsidian Security Gradient"),
    MIDNIGHT_MESH("MIDNIGHT_MESH", "Midnight Cyber Mesh"),
    MINIMAL_SURFACE("MINIMAL_SURFACE", "Minimal Solid Surface");

    companion object {
        fun fromId(raw: String?): LockScreenBackgroundStyle =
            entries.firstOrNull { it.id.equals(raw, ignoreCase = true) } ?: OBSIDIAN_GRADIENT
    }
}

enum class KeypadStyle(val id: String, val label: String) {
    ROUNDED_MODERN("ROUNDED_MODERN", "Rounded Glass Keypad"),
    COMPACT_GRID("COMPACT_GRID", "Compact Tactile Grid"),
    HIGH_CONTRAST("HIGH_CONTRAST", "High-Contrast Security Pad");

    companion object {
        fun fromId(raw: String?): KeypadStyle =
            entries.firstOrNull { it.id.equals(raw, ignoreCase = true) } ?: ROUNDED_MODERN
    }
}

enum class AppSortOrder(val id: String, val label: String) {
    NAME_ASC("NAME_ASC", "Name (A → Z)"),
    NAME_DESC("NAME_DESC", "Name (Z → A)"),
    LOCKED_FIRST("LOCKED_FIRST", "Locked First");

    companion object {
        fun fromId(raw: String?): AppSortOrder =
            entries.firstOrNull { it.id.equals(raw, ignoreCase = true) } ?: NAME_ASC
    }
}

/**
 * Phase 6 LockScheduleEntity (Room Schema v4).
 *
 * Represents a time-windowed Smart Lock Schedule (e.g., Work Hours, Night Protection, Weekend Protection).
 * Supports overnight schedules where startTime > endTime (crosses midnight).
 *
 * - daysOfWeekCsv: Comma-separated ISO-8601 weekday integers (1=Monday .. 7=Sunday), e.g., "1,2,3,4,5"
 * - targetPackagesCsv: Comma-separated package names, or "*" when applyToAllLockedApps = true
 */
@Entity(
    tableName = "lock_schedules",
    indices = [
        Index(value = ["isEnabled"]),
        Index(value = ["name"])
    ]
)
data class LockScheduleEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val name: String,
    val description: String,
    val startHour: Int,
    val startMinute: Int,
    val endHour: Int,
    val endMinute: Int,
    val daysOfWeekCsv: String,
    val targetPackagesCsv: String = "*",
    val applyToAllLockedApps: Boolean = true,
    val isEnabled: Boolean = true,
    val createdAtMillis: Long = System.currentTimeMillis(),
    val updatedAtMillis: Long = System.currentTimeMillis()
) {
    fun parsedDaysOfWeek(): Set<Int> =
        daysOfWeekCsv.split(",")
            .mapNotNull { it.trim().toIntOrNull() }
            .filter { it in 1..7 }
            .toSet()

    fun parsedTargetPackages(): Set<String> =
        if (applyToAllLockedApps || targetPackagesCsv.trim() == "*") {
            emptySet()
        } else {
            targetPackagesCsv.split(",")
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .toSet()
        }

    val isOvernightSchedule: Boolean
        get() {
            val startTotal = startHour * 60 + startMinute
            val endTotal = endHour * 60 + endMinute
            return startTotal > endTotal
        }
}

