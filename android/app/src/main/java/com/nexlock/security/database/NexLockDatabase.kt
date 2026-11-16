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
import com.nexlock.security.model.LockedAppEntity
import com.nexlock.security.model.ProtectedAppEntity
import com.nexlock.security.model.SecurityEventEntity
import com.nexlock.security.model.VaultItemMetadataEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface LockedAppsDao {
    @Query("SELECT * FROM locked_apps ORDER BY appName COLLATE NOCASE ASC")
    fun observeAllLockedApps(): Flow<List<LockedAppEntity>>

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
    @Query("SELECT * FROM security_events ORDER BY timestampMillis DESC LIMIT 100")
    fun observeRecentEvents(): Flow<List<SecurityEventEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertEvent(event: SecurityEventEntity)

    @Query("DELETE FROM security_events")
    suspend fun clearEvents()
}

@Dao
interface VaultMetadataDao {
    @Query("SELECT * FROM vault_items_metadata ORDER BY addedAtMillis DESC")
    fun observeVaultItems(): Flow<List<VaultItemMetadataEntity>>
}

@Database(
    entities = [
        LockedAppEntity::class,
        ProtectedAppEntity::class,
        SecurityEventEntity::class,
        VaultItemMetadataEntity::class
    ],
    version = 2,
    exportSchema = false
)
abstract class NexLockDatabase : RoomDatabase() {
    abstract fun lockedAppsDao(): LockedAppsDao
    abstract fun protectedAppDao(): ProtectedAppDao
    abstract fun securityEventDao(): SecurityEventDao
    abstract fun vaultMetadataDao(): VaultMetadataDao

    companion object {
        @Volatile
        private var INSTANCE: NexLockDatabase? = null

        /**
         * Non-destructive migration from Phase 1/2 (v1) to Phase 3 (v2).
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

        fun getInstance(context: Context): NexLockDatabase {
            return INSTANCE ?: synchronized(this) {
                Room.databaseBuilder(
                    context.applicationContext,
                    NexLockDatabase::class.java,
                    "nexlock_phase1.db"
                )
                    .addMigrations(MIGRATION_1_2)
                    .build()
                    .also { INSTANCE = it }
            }
        }
    }
}
