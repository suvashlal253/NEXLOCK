package com.nexlock.security.discovery

import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.util.LruCache

/**
 * Thread-safe in-memory LRU cache for application Drawable icons retrieved from PackageManager.
 *
 * Performance & Reliability Guarantees:
 * 1. Prevents repeated IPC calls to PackageManager during LazyColumn scrolling.
 * 2. Preserves intrinsic Drawable aspect ratio without bitmap distortion.
 * 3. Never crashes if an application is uninstalled mid-scroll or has missing resources;
 *    returns null so the Composable renders a clean fallback vector icon.
 */
class AppIconMemoryCache(
    maxEntries: Int = 180
) {
    private val cache = object : LruCache<String, Drawable>(maxEntries) {}

    fun getOrLoadIcon(
        packageName: String,
        packageManager: PackageManager
    ): Drawable? {
        synchronized(cache) {
            cache.get(packageName)?.let { return it }
        }

        val loaded = try {
            packageManager.getApplicationIcon(packageName)
        } catch (_: PackageManager.NameNotFoundException) {
            null
        } catch (_: SecurityException) {
            null
        } catch (_: Exception) {
            null
        }

        if (loaded != null) {
            synchronized(cache) {
                cache.put(packageName, loaded)
            }
        }
        return loaded
    }

    fun evictPackage(packageName: String) {
        synchronized(cache) {
            cache.remove(packageName)
        }
    }

    fun clearAll() {
        synchronized(cache) {
            cache.evictAll()
        }
    }
}
