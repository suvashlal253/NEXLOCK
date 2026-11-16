# NEXLOCK ProGuard / R8 configuration
-keep class com.nexlock.security.model.** { *; }
-keep class com.nexlock.security.discovery.** { *; }
-keep class com.nexlock.security.auth.** { *; }
-dontwarn java.lang.invoke.StringConcatFactory
