package com.nexlock.security.database

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.nexlock.security.model.IntruderImageEntity
import com.nexlock.security.model.LockScheduleEntity
import com.nexlock.security.model.LockedAppEntity
import com.nexlock.security.model.ProtectedAppEntity
import com.nexlock.security.model.SecurityEventEntity
import com.nexlock.security.model.VaultItemMetadataEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface LockedAppsDao {
    @Query("SELECT * FROM locked_apps ORDER BY appName COLLATE NOCASE ASC")
    fun observeAllLockedApps(): Flow<List<LockedAppEntity>>

    @Query("SELECT * FROM locked_apps WHERE isLocked = 1 ORDER BY appName COLLATE NOCASE ASC")
    fun observeLockedApps(): Flow<List<LockedAppEntity>>

    @Query("SELECT COUNT(*) FROM locked_apps WHERE isLocked = 1")
    fun observeLockedCount(): Flow<Int>

    @Query("SELECT * FROM locked_apps")
    suspend fun getAllLockedAppsSnapshot(): List<LockedAppEntity>

    @Query("SELECT * FROM locked_apps WHERE packageName = :packageName LIMIT 1")
    suspend fun getByPackageName(packageName: String): LockedAppEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertLockedApp(entity: LockedAppEntity): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertLockedApps(entities: List<LockedAppEntity>)

    @Query("DELETE FROM locked_apps WHERE packageName = :packageName")
    suspend fun deleteByPackageName(packageName: String)

    @Query("UPDATE locked_apps SET isLocked = 0, updatedAt = :timestampMillis")
    suspend fun unlockAll(timestampMillis: Long = System.currentTimeMillis())
}

@Dao
interface ProtectedAppDao {
    @Query("SELECT * FROM protected_apps ORDER BY appName ASC")
    fun observeAllApps(): Flow<List<ProtectedAppEntity>>

    @Query("SELECT * FROM protected_apps WHERE packageName = :packageName LIMIT 1")
    fun observeApp(packageName: String): Flow<ProtectedAppEntity?>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertApp(app: ProtectedAppEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(apps: List<ProtectedAppEntity>)
}

@Dao
interface SecurityEventDao {
    @Query("SELECT * FROM security_events ORDER BY timestampMillis DESC LIMIT 250")
    fun observeRecentEvents(): Flow<List<SecurityEventEntity>>

    @Query("SELECT * FROM security_events ORDER BY timestampMillis ASC LIMIT 250")
    fun observeEventsOldestFirst(): Flow<List<SecurityEventEntity>>

    @Query("SELECT * FROM security_events WHERE eventType = :eventType ORDER BY timestampMillis DESC")
    fun observeEventsByType(eventType: String): Flow<List<SecurityEventEntity>>

    @Query("SELECT * FROM security_events WHERE timestampMillis BETWEEN :startMillis AND :endMillis ORDER BY timestampMillis DESC")
    suspend fun getEventsInDateRange(startMillis: Long, endMillis: Long): List<SecurityEventEntity>

    @Query("SELECT * FROM security_events ORDER BY timestampMillis DESC")
    suspend fun getAllEventsSnapshot(): List<SecurityEventEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertEvent(event: SecurityEventEntity): Long

    @Query("DELETE FROM security_events WHERE id = :eventId")
    suspend fun deleteEventById(eventId: Long)

    @Query("DELETE FROM security_events")
    suspend fun clearEvents()
}

@Dao
interface IntruderImageDao {
    @Query("SELECT * FROM intruder_images ORDER BY timestampMillis DESC")
    fun observeIntruderImages(): Flow<List<IntruderImageEntity>>

    @Query("SELECT * FROM intruder_images ORDER BY timestampMillis DESC")
    suspend fun getAllIntruderImagesSnapshot(): List<IntruderImageEntity>

    @Query("SELECT COUNT(*) FROM intruder_images")
    fun observeIntruderCount(): Flow<Int>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertIntruderImage(entity: IntruderImageEntity): Long

    @Query("DELETE FROM intruder_images WHERE id = :id")
    suspend fun deleteIntruderImageById(id: Long)

    @Query("DELETE FROM intruder_images")
    suspend fun clearAllIntruderImages()
}

@Dao
interface VaultMetadataDao {
    @Query("SELECT * FROM vault_items_metadata ORDER BY addedAtMillis DESC")
    fun observeVaultItems(): Flow<List<VaultItemMetadataEntity>>

    @Query("SELECT * FROM vault_items_metadata ORDER BY addedAtMillis DESC")
    suspend fun getAllVaultItemsSnapshot(): List<VaultItemMetadataEntity>

    @Query("SELECT * FROM vault_items_metadata WHERE id = :id LIMIT 1")
    suspend fun getVaultItemById(id: String): VaultItemMetadataEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertVaultItem(item: VaultItemMetadataEntity)

    @Query("DELETE FROM vault_items_metadata WHERE id = :id")
    suspend fun deleteVaultItemById(id: String)

    @Query("DELETE FROM vault_items_metadata")
    suspend fun clearAllVaultItems()
}

@Dao
interface LockScheduleDao {
    @Query("SELECT * FROM lock_schedules ORDER BY id ASC")
    fun observeAllSchedules(): Flow<List<LockScheduleEntity>>

    @Query("SELECT * FROM lock_schedules WHERE isEnabled = 1 ORDER BY id ASC")
    fun observeEnabledSchedules(): Flow<List<LockScheduleEntity>>

    @Query("SELECT * FROM lock_schedules ORDER BY id ASC")
    suspend fun getAllSchedulesSnapshot(): List<LockScheduleEntity>

    @Query("SELECT * FROM lock_schedules WHERE id = :id LIMIT 1")
    suspend fun getScheduleById(id: Long): LockScheduleEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertSchedule(schedule: LockScheduleEntity): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertSchedules(schedules: List<LockScheduleEntity>)

    @Query("UPDATE lock_schedules SET isEnabled = :enabled, updatedAtMillis = :updatedAt WHERE id = :id")
    suspend fun setScheduleEnabled(id: Long, enabled: Boolean, updatedAt: Long = System.currentTimeMillis())

    @Query("DELETE FROM lock_schedules WHERE id = :id")
    suspend fun deleteScheduleById(id: Long)

    @Query("DELETE FROM lock_schedules")
    suspend fun clearAllSchedules()
}

@Database(
    entities = [
        LockedAppEntity::class,
        ProtectedAppEntity::class,
        SecurityEventEntity::class,
        IntruderImageEntity::class,
        VaultItemMetadataEntity::class,
        LockScheduleEntity::class
    ],
    version = 4,
    exportSchema = false
)
abstract class NexLockDatabase : RoomDatabase() {
    abstract fun lockedAppsDao(): LockedAppsDao
    abstract fun protectedAppDao(): ProtectedAppDao
    abstract fun securityEventDao(): SecurityEventDao
    abstract fun intruderImageDao(): IntruderImageDao
    abstract fun vaultMetadataDao(): VaultMetadataDao
    abstract fun lockScheduleDao(): LockScheduleDao

    companion object {
        @Volatile
        private var INSTANCE: NexLockDatabase? = null

        /**
         * Non-destructive migration from Phase 1/2 (v1) to Phase 3/4 (v2).
         * Creates locked_apps with unique index on packageName and migrates existing locked selections.
         */
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS `locked_apps` (
                        `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        `packageName` TEXT NOT NULL,
                        `appName` TEXT NOT NULL,
                        `isLocked` INTEGER NOT NULL,
                        `category` TEXT NOT NULL,
                        `createdAt` INTEGER NOT NULL,
                        `updatedAt` INTEGER NOT NULL
                    )
                    """.trimIndent()
                )
                db.execSQL(
                    "CREATE UNIQUE INDEX IF NOT EXISTS `index_locked_apps_packageName` ON `locked_apps` (`packageName`)"
                )
                db.execSQL(
                    """
                    INSERT OR IGNORE INTO `locked_apps` (`packageName`, `appName`, `isLocked`, `category`, `createdAt`, `updatedAt`)
                    SELECT `packageName`, `appName`, `isLocked`, `category`, `updatedAtEpochMillis`, `updatedAtEpochMillis`
                    FROM `protected_apps`
                    """.trimIndent()
                )
            }
        }

        /**
         * Non-destructive migration from Phase 3/4 (v2) to Phase 5 (v3).
         * 1. Adds authenticationMethod, severity, and metadata columns to security_events + indexes.
         * 2. Creates intruder_images table with timestamp index for encrypted selfie metadata.
         * 3. Adds encryptedRelativePath, encryptionIvBase64, and ciphertextSha256Hex to vault_items_metadata.
         */
        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE `security_events` ADD COLUMN `authenticationMethod` TEXT DEFAULT NULL")
                db.execSQL("ALTER TABLE `security_events` ADD COLUMN `severity` TEXT NOT NULL DEFAULT 'INFO'")
                db.execSQL("ALTER TABLE `security_events` ADD COLUMN `metadata` TEXT NOT NULL DEFAULT ''")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_security_events_eventType` ON `security_events` (`eventType`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_security_events_timestampMillis` ON `security_events` (`timestampMillis`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_security_events_severity` ON `security_events` (`severity`)")

                db.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS `intruder_images` (
                        `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        `timestampMillis` INTEGER NOT NULL,
                        `targetPackageName` TEXT,
                        `consecutiveFailures` INTEGER NOT NULL,
                        `authenticationMethod` TEXT NOT NULL,
                        `encryptedFilePath` TEXT,
                        `encryptionIvBase64` TEXT,
                        `byteSize` INTEGER NOT NULL,
                        `captureStatus` TEXT NOT NULL
                    )
                    """.trimIndent()
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_intruder_images_timestampMillis` ON `intruder_images` (`timestampMillis`)"
                )

                db.execSQL("ALTER TABLE `vault_items_metadata` ADD COLUMN `encryptedRelativePath` TEXT NOT NULL DEFAULT ''")
                db.execSQL("ALTER TABLE `vault_items_metadata` ADD COLUMN `encryptionIvBase64` TEXT NOT NULL DEFAULT ''")
                db.execSQL("ALTER TABLE `vault_items_metadata` ADD COLUMN `ciphertextSha256Hex` TEXT NOT NULL DEFAULT ''")
            }
        }

        /**
         * Non-destructive migration from Phase 5 (v3) to Phase 6 (v4).
         * Creates the `lock_schedules` table with indexes on `isEnabled` and `name`.
         */
        val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS `lock_schedules` (
                        `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        `name` TEXT NOT NULL,
                        `description` TEXT NOT NULL,
                        `startHour` INTEGER NOT NULL,
                        `startMinute` INTEGER NOT NULL,
                        `endHour` INTEGER NOT NULL,
                        `endMinute` INTEGER NOT NULL,
                        `daysOfWeekCsv` TEXT NOT NULL,
                        `targetPackagesCsv` TEXT NOT NULL,
                        `applyToAllLockedApps` INTEGER NOT NULL,
                        `isEnabled` INTEGER NOT NULL,
                        `createdAtMillis` INTEGER NOT NULL,
                        `updatedAtMillis` INTEGER NOT NULL
                    )
                    """.trimIndent()
                )
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_lock_schedules_isEnabled` ON `lock_schedules` (`isEnabled`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_lock_schedules_name` ON `lock_schedules` (`name`)")
            }
        }

        fun getInstance(context: Context): NexLockDatabase {
            return INSTANCE ?: synchronized(this) {
                Room.databaseBuilder(
                    context.applicationContext,
                    NexLockDatabase::class.java,
                    "nexlock_phase1.db"
                )
                    .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4)
                    .build()
                    .also { INSTANCE = it }
            }
        }
    }
}

