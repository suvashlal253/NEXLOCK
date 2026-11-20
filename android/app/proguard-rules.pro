# NEXLOCK Production ProGuard / R8 Configuration (Phase 6 v2.0.0-production)

# Keep Room Entities, DAOs, and Migration classes
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class * { *; }
-keep @androidx.room.Dao class * { *; }
-keep class com.nexlock.security.database.** { *; }
-keep class com.nexlock.security.model.** { *; }

# Keep Phase 2-6 Security, Auth, Discovery, Backup, and Schedule models
-keep class com.nexlock.security.auth.** { *; }
-keep class com.nexlock.security.discovery.** { *; }
-keep class com.nexlock.security.backup.** { *; }
-keep class com.nexlock.security.schedule.** { *; }
-keep class com.nexlock.security.analytics.** { *; }

# Keep AndroidX Biometric & CameraX reflection entry points
-keep class androidx.biometric.** { *; }
-keep class androidx.camera.** { *; }

# Strip verbose debug/verbose logs in release builds without removing critical error handling
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}

-dontwarn java.lang.invoke.StringConcatFactory

