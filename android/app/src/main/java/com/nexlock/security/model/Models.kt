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

@Entity(tableName = "security_events")
data class SecurityEventEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val eventType: String,
    val packageName: String?,
    val title: String,
    val detail: String,
    val timestampMillis: Long = System.currentTimeMillis()
)

@Entity(tableName = "vault_items_metadata")
data class VaultItemMetadataEntity(
    @PrimaryKey val id: String,
    val displayName: String,
    val mediaType: String,
    val sizeBytes: Long,
    val addedAtMillis: Long
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
