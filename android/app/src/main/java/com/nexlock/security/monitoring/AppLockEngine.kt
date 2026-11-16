package com.nexlock.security.monitoring

import com.nexlock.security.auth.AuthMethod
import com.nexlock.security.auth.MonotonicClock
import com.nexlock.security.auth.SystemMonotonicClock
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Core NEXLOCK Phase 4 App Lock Enforcement State Machine (Sections 5, 6, 9, 10).
 *
 * Key Invariants:
 * 1. Never locks excluded packages (NEXLOCK itself, System Settings, System UI, Home Launcher,
 *    Permission Controllers, Package Installers, Emergency/Telecom interfaces).
 * 2. Never invalidates a target package's unlock flow simply because AppLockActivity or
 *    Android's BiometricPrompt system UI enters the foreground.
 * 3. Uses a monotonic clock (SystemClock.elapsedRealtime()) for all re-lock timer calculations.
 * 4. Prevents duplicate AppLockActivity launches for the same foreground package.
 * 5. Handles rapid switching between two protected apps (App A <-> App B) by maintaining
 *    independent per-package unlock sessions and background departure timestamps.
 */
class AppLockEngine(
    private val clock: MonotonicClock = SystemMonotonicClock,
    initialReLockOption: ReLockDurationOption = ReLockDurationOption.IMMEDIATELY,
    initialLockOnScreenOff: Boolean = true
) {
    private val unlockedSessions = linkedMapOf<String, PackageUnlockSession>()

    private val _unlockedSessionsFlow = MutableStateFlow<Map<String, PackageUnlockSession>>(emptyMap())
    val unlockedSessionsFlow: StateFlow<Map<String, PackageUnlockSession>> = _unlockedSessionsFlow.asStateFlow()

    var reLockDurationOption: ReLockDurationOption = initialReLockOption
        private set

    var lockOnScreenOff: Boolean = initialLockOnScreenOff
        private set

    var currentForegroundAppPackage: String? = null
        private set

    var activeChallengePackage: String? = null
        private set

    var isChallengeActivityVisible: Boolean = false
        private set

    private var lockedPackageSet: Set<String> = emptySet()
    private var homeLauncherPackages: Set<String> = emptySet()

    @Synchronized
    fun updateLockedPackages(packages: Set<String>) {
        lockedPackageSet = packages
        // Prune sessions for packages that are no longer marked as locked
        val iterator = unlockedSessions.iterator()
        var changed = false
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (entry.key !in lockedPackageSet) {
                iterator.remove()
                changed = true
            }
        }
        if (changed) {
            publishSessionsSnapshot()
        }
    }

    @Synchronized
    fun updateHomeLauncherPackages(packages: Set<String>) {
        homeLauncherPackages = packages
    }

    @Synchronized
    fun setReLockDuration(option: ReLockDurationOption) {
        reLockDurationOption = option
        pruneExpiredSessionsInternal(clock.elapsedRealtimeMillis())
    }

    @Synchronized
    fun setLockOnScreenOffPolicy(enabled: Boolean) {
        lockOnScreenOff = enabled
    }

    /**
     * Evaluates a foreground transition event and determines whether to allow access or
     * trigger the NEXLOCK authentication challenge screen (AppLockActivity).
     */
    @Synchronized
    fun onForegroundTransition(event: ForegroundTransitionEvent): LockEnforcementDecision {
        val nowElapsed = clock.elapsedRealtimeMillis()

        when (event.transitionType) {
            UsageTransitionType.SCREEN_NON_INTERACTIVE,
            UsageTransitionType.KEYGUARD_SHOWN -> {
                onScreenTurnedOffOrDeviceLocked()
                return LockEnforcementDecision.AllowExcluded(
                    packageName = event.packageName,
                    reason = "Screen non-interactive / keyguard transition handled."
                )
            }
            UsageTransitionType.ACTIVITY_PAUSED -> {
                handlePackageBackgrounded(event.packageName, nowElapsed)
                return LockEnforcementDecision.AllowUnprotected(event.packageName)
            }
            UsageTransitionType.SCREEN_INTERACTIVE -> {
                pruneExpiredSessionsInternal(nowElapsed)
                return LockEnforcementDecision.AllowExcluded(
                    packageName = event.packageName,
                    reason = "Screen interactive transition."
                )
            }
            UsageTransitionType.ACTIVITY_RESUMED -> {
                // Proceed to foreground evaluation below
            }
        }

        val targetPackage = event.packageName

        // 1. Check if the foreground package is NEXLOCK itself (e.g., AppLockActivity) or System UI
        // Crucial: Do NOT mark the previously foregrounded app as backgrounded when AppLockActivity
        // or SystemUI (biometric prompt / notification shade) overlays it!
        if (targetPackage == ExcludedSystemPackages.NEXLOCK_PACKAGE ||
            targetPackage == "com.android.systemui" ||
            (targetPackage.contains("biometric", ignoreCase = true) && targetPackage.startsWith("com.android."))
        ) {
            return LockEnforcementDecision.AllowExcluded(
                packageName = targetPackage,
                reason = ExcludedSystemPackages.getExclusionReason(targetPackage, homeLauncherPackages)
                    ?: "NEXLOCK / System UI overlay excluded."
            )
        }

        // 2. If transitioning from a different user/system package, start the re-lock timer
        // for the departed package.
        val previousPkg = currentForegroundAppPackage
        if (previousPkg != null && previousPkg != targetPackage) {
            handlePackageBackgrounded(previousPkg, nowElapsed)
        }
        currentForegroundAppPackage = targetPackage

        // 3. Check if the new foreground package is in the Safe Exclusion Registry
        // (Home Launcher, System Settings, Permission Controller, Emergency Dialer, etc.)
        if (ExcludedSystemPackages.isPackageExcluded(targetPackage, homeLauncherPackages)) {
            return LockEnforcementDecision.AllowExcluded(
                packageName = targetPackage,
                reason = ExcludedSystemPackages.getExclusionReason(targetPackage, homeLauncherPackages)
                    ?: "Excluded recovery/system package."
            )
        }

        // 4. Expire any sessions whose background re-lock timer has elapsed
        pruneExpiredSessionsInternal(nowElapsed)

        // 5. Check whether targetPackage is selected for protection in Room (locked_apps)
        if (targetPackage !in lockedPackageSet) {
            return LockEnforcementDecision.AllowUnprotected(targetPackage)
        }

        // 6. Check whether a valid temporary unlock session exists for targetPackage
        val existingSession = unlockedSessions[targetPackage]
        if (existingSession != null && !isSessionExpiredInternal(existingSession, nowElapsed)) {
            // User returned within the allowed re-lock window; clear backgrounded timestamp
            val refreshed = existingSession.copy(
                lastForegroundElapsedMillis = nowElapsed,
                backgroundedAtElapsedMillis = null
            )
            unlockedSessions[targetPackage] = refreshed
            publishSessionsSnapshot()
            val remainingMillis = reLockDurationOption.durationMillis.takeIf { it > 0L }
            return LockEnforcementDecision.AllowActiveSession(
                packageName = targetPackage,
                remainingMillis = remainingMillis
            )
        }

        // 7. Prevent duplicate lock-screen launches if AppLockActivity is already showing for targetPackage
        if (isChallengeActivityVisible && activeChallengePackage == targetPackage) {
            return LockEnforcementDecision.SuppressDuplicateChallenge(targetPackage)
        }

        // 8. Require authentication challenge via AppLockActivity
        activeChallengePackage = targetPackage
        isChallengeActivityVisible = true
        return LockEnforcementDecision.RequireAuthentication(
            packageName = targetPackage,
            reason = "Protected application entered foreground without an active unlock session."
        )
    }

    /**
     * Called when the user successfully authenticates (via Master PIN or BiometricPrompt)
     * on AppLockActivity for [packageName].
     */
    @Synchronized
    fun grantTemporaryPackageSession(
        packageName: String,
        authMethod: AuthMethod
    ): PackageUnlockSession {
        val nowElapsed = clock.elapsedRealtimeMillis()
        val session = PackageUnlockSession(
            packageName = packageName,
            unlockedAtElapsedMillis = nowElapsed,
            lastForegroundElapsedMillis = nowElapsed,
            backgroundedAtElapsedMillis = null,
            authMethod = authMethod
        )
        unlockedSessions[packageName] = session
        if (activeChallengePackage == packageName) {
            activeChallengePackage = null
            isChallengeActivityVisible = false
        }
        currentForegroundAppPackage = packageName
        publishSessionsSnapshot()
        return session
    }

    /**
     * Called when AppLockActivity is dismissed without unlocking (e.g. user pressed Back / Exit to Home).
     */
    @Synchronized
    fun onChallengeDismissedOrAborted(packageName: String) {
        if (activeChallengePackage == packageName) {
            activeChallengePackage = null
            isChallengeActivityVisible = false
        }
        if (currentForegroundAppPackage == packageName) {
            currentForegroundAppPackage = null
        }
    }

    @Synchronized
    fun isPackageCurrentlyUnlocked(packageName: String): Boolean {
        val nowElapsed = clock.elapsedRealtimeMillis()
        pruneExpiredSessionsInternal(nowElapsed)
        return unlockedSessions.containsKey(packageName)
    }

    /**
     * Handles Screen-Off or Device Keyguard Lock events (Sections 6 & 10).
     */
    @Synchronized
    fun onScreenTurnedOffOrDeviceLocked() {
        val nowElapsed = clock.elapsedRealtimeMillis()
        activeChallengePackage = null
        isChallengeActivityVisible = false
        if (lockOnScreenOff) {
            unlockedSessions.clear()
        } else {
            // Start background re-lock timers for all unlocked packages
            unlockedSessions.replaceAll { _, session ->
                if (session.backgroundedAtElapsedMillis == null) {
                    session.copy(backgroundedAtElapsedMillis = nowElapsed)
                } else {
                    session
                }
            }
            pruneExpiredSessionsInternal(nowElapsed)
        }
        publishSessionsSnapshot()
    }

    @Synchronized
    fun revokeAllPackageSessions() {
        unlockedSessions.clear()
        activeChallengePackage = null
        isChallengeActivityVisible = false
        publishSessionsSnapshot()
    }

    private fun handlePackageBackgrounded(packageName: String, nowElapsed: Long) {
        val session = unlockedSessions[packageName] ?: return
        if (reLockDurationOption == ReLockDurationOption.IMMEDIATELY) {
            unlockedSessions.remove(packageName)
            publishSessionsSnapshot()
        } else if (session.backgroundedAtElapsedMillis == null) {
            unlockedSessions[packageName] = session.copy(backgroundedAtElapsedMillis = nowElapsed)
            publishSessionsSnapshot()
        }
    }

    private fun isSessionExpiredInternal(
        session: PackageUnlockSession,
        nowElapsed: Long
    ): Boolean {
        val departedAt = session.backgroundedAtElapsedMillis ?: return false
        val allowedDuration = reLockDurationOption.durationMillis
        if (allowedDuration <= 0L) return true
        return (nowElapsed - departedAt) >= allowedDuration
    }

    private fun pruneExpiredSessionsInternal(nowElapsed: Long) {
        val iterator = unlockedSessions.iterator()
        var removed = false
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (isSessionExpiredInternal(entry.value, nowElapsed)) {
                iterator.remove()
                removed = true
            }
        }
        if (removed) {
            publishSessionsSnapshot()
        }
    }

    private fun publishSessionsSnapshot() {
        _unlockedSessionsFlow.value = unlockedSessions.toMap()
    }
}
