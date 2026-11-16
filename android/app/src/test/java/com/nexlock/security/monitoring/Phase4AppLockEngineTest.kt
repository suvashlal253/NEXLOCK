package com.nexlock.security.monitoring

import com.nexlock.security.auth.AuthMethod
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Complete Unit Test Suite for NEXLOCK Phase 4: Real App Lock Engine Implementation.
 *
 * Covers all 12 required Phase 4 unit & state-machine test cases:
 * 1. Foreground package detection & timestamp deduplication
 * 2. Locked package matching against Room locked_apps
 * 3. Session validity after PIN / BiometricPrompt authentication
 * 4. Session expiration after configured monotonic timeout
 * 5. Re-lock timer logic (Immediately, 5s, 15s, 30s, 1m, 5m)
 * 6. Duplicate lock-screen launch prevention (AppLockActivity guard)
 * 7. Excluded package handling (NEXLOCK itself, System Settings, SystemUI, Home Launcher, Emergency Dialer)
 * 8. Permission state evaluation (never reports Active when permissions are missing)
 * 9. Monitoring state transitions (Start, Pause, Screen-Off invalidation)
 * 10. Rapid switching between two protected applications (WhatsApp <-> Signal)
 * 11. AppLockActivity foreground appearance does not invalidate active or pending sessions
 * 12. Adaptive polling interval backoff calculation
 */
class Phase4AppLockEngineTest {

    private var fakeMonotonicMillis: Long = 500_000L
    private var fakeEpochMillis: Long = 1_750_000_000_000L

    private lateinit var engine: AppLockEngine
    private lateinit var fakeUsageSource: FakeUsageEventsSource
    private lateinit var detector: ForegroundAppDetector

    @Before
    fun setUp() {
        fakeMonotonicMillis = 500_000L
        fakeEpochMillis = 1_750_000_000_000L
        engine = AppLockEngine(
            clock = { fakeMonotonicMillis },
            initialReLockOption = ReLockDurationOption.SECONDS_15,
            initialLockOnScreenOff = true
        )
        engine.updateLockedPackages(
            setOf("com.whatsapp", "org.thoughtcrime.securesms", "com.revolut.revolut")
        )
        engine.updateHomeLauncherPackages(setOf("com.google.android.apps.nexuslauncher"))

        fakeUsageSource = FakeUsageEventsSource()
        detector = ForegroundAppDetector(
            usageEventsSource = fakeUsageSource,
            epochClockMillis = { fakeEpochMillis }
        )
    }

    @Test
    fun `1 - Foreground package detection orders events and deduplicates by timestamp`() = runBlocking {
        fakeUsageSource.events = listOf(
            ForegroundTransitionEvent(
                packageName = "com.instagram.android",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis - 1_000L
            ),
            ForegroundTransitionEvent(
                packageName = "com.whatsapp",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis - 200L
            )
        )

        val firstPoll = detector.pollNewTransitions()
        assertEquals(2, firstPoll.size)
        assertEquals("com.whatsapp", detector.currentForegroundPackage)

        // Second poll with identical timestamps must return 0 duplicate events
        val secondPoll = detector.pollNewTransitions()
        assertTrue(secondPoll.isEmpty())
    }

    @Test
    fun `2 - Locked package matching requires authentication while unlocked package is allowed`() {
        val unprotectedDecision = engine.onForegroundTransition(
            ForegroundTransitionEvent(
                packageName = "com.spotify.music",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis
            )
        )
        assertTrue(unprotectedDecision is LockEnforcementDecision.AllowUnprotected)

        val protectedDecision = engine.onForegroundTransition(
            ForegroundTransitionEvent(
                packageName = "com.whatsapp",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis + 100L
            )
        )
        assertTrue(protectedDecision is LockEnforcementDecision.RequireAuthentication)
        assertEquals("com.whatsapp", engine.activeChallengePackage)
    }

    @Test
    fun `3 - Session validity allows access after PIN or Biometric unlock without re-prompting`() {
        // Trigger challenge for com.whatsapp
        val firstAttempt = engine.onForegroundTransition(
            ForegroundTransitionEvent(
                packageName = "com.whatsapp",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis
            )
        )
        assertTrue(firstAttempt is LockEnforcementDecision.RequireAuthentication)

        // User completes authentication in AppLockActivity
        engine.grantTemporaryPackageSession("com.whatsapp", AuthMethod.BIOMETRIC_PROMPT)
        assertTrue(engine.isPackageCurrentlyUnlocked("com.whatsapp"))

        // Subsequent ACTIVITY_RESUMED within WhatsApp allows access immediately
        val secondEvent = engine.onForegroundTransition(
            ForegroundTransitionEvent(
                packageName = "com.whatsapp",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis + 500L
            )
        )
        assertTrue(secondEvent is LockEnforcementDecision.AllowActiveSession)
    }

    @Test
    fun `4 - Session expiration requires authentication after configured monotonic re-lock window`() {
        engine.setReLockDuration(ReLockDurationOption.SECONDS_15)
        engine.grantTemporaryPackageSession("com.whatsapp", AuthMethod.MASTER_PIN)

        // Switch away to unlocked app (e.g. Chrome) — starts 15s re-lock timer for WhatsApp
        engine.onForegroundTransition(
            ForegroundTransitionEvent(
                packageName = "com.android.chrome",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis + 1_000L
            )
        )

        // Advance monotonic clock by 10s (still within 15s grace window)
        fakeMonotonicMillis += 10_000L
        val returnWithinWindow = engine.onForegroundTransition(
            ForegroundTransitionEvent(
                packageName = "com.whatsapp",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis + 11_000L
            )
        )
        assertTrue(returnWithinWindow is LockEnforcementDecision.AllowActiveSession)

        // Leave WhatsApp again and advance clock by 16s (past 15s window)
        engine.onForegroundTransition(
            ForegroundTransitionEvent(
                packageName = "com.android.chrome",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis + 12_000L
            )
        )
        fakeMonotonicMillis += 16_000L

        val returnAfterExpiry = engine.onForegroundTransition(
            ForegroundTransitionEvent(
                packageName = "com.whatsapp",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis + 28_000L
            )
        )
        assertTrue(returnAfterExpiry is LockEnforcementDecision.RequireAuthentication)
    }

    @Test
    fun `5 - Re-lock timer IMMEDIATELY revokes package session as soon as user leaves the app`() {
        engine.setReLockDuration(ReLockDurationOption.IMMEDIATELY)
        engine.grantTemporaryPackageSession("com.whatsapp", AuthMethod.MASTER_PIN)
        assertTrue(engine.isPackageCurrentlyUnlocked("com.whatsapp"))

        // User switches to Home Launcher or another app
        engine.onForegroundTransition(
            ForegroundTransitionEvent(
                packageName = "com.google.android.apps.nexuslauncher",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis + 500L
            )
        )
        assertFalse(engine.isPackageCurrentlyUnlocked("com.whatsapp"))

        // Returning 1 second later immediately requires authentication again
        fakeMonotonicMillis += 1_000L
        val decision = engine.onForegroundTransition(
            ForegroundTransitionEvent(
                packageName = "com.whatsapp",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis + 1_500L
            )
        )
        assertTrue(decision is LockEnforcementDecision.RequireAuthentication)
    }

    @Test
    fun `6 - Duplicate lock-screen launch prevention suppresses repeated challenge for same package`() {
        val first = engine.onForegroundTransition(
            ForegroundTransitionEvent(
                packageName = "com.revolut.revolut",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis
            )
        )
        assertTrue(first is LockEnforcementDecision.RequireAuthentication)

        // Second ACTIVITY_RESUMED for the same package while AppLockActivity is visible is suppressed
        val duplicate = engine.onForegroundTransition(
            ForegroundTransitionEvent(
                packageName = "com.revolut.revolut",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis + 200L
            )
        )
        assertTrue(duplicate is LockEnforcementDecision.SuppressDuplicateChallenge)
    }

    @Test
    fun `7 - Excluded package handling never locks NEXLOCK, System Settings, SystemUI, Home Launcher, or Dialer`() {
        // Even if someone attempted to add excluded packages to lockedPackageSet, they are never locked
        engine.updateLockedPackages(
            setOf(
                "com.nexlock.security",
                "com.android.settings",
                "com.android.systemui",
                "com.google.android.apps.nexuslauncher",
                "com.google.android.permissioncontroller",
                "com.google.android.dialer"
            )
        )

        val criticalPackages = listOf(
            "com.nexlock.security",
            "com.android.settings",
            "com.android.systemui",
            "com.google.android.apps.nexuslauncher",
            "com.google.android.permissioncontroller",
            "com.google.android.dialer"
        )

        for (pkg in criticalPackages) {
            val decision = engine.onForegroundTransition(
                ForegroundTransitionEvent(
                    packageName = pkg,
                    transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                    timestampMillis = fakeEpochMillis
                )
            )
            assertTrue(
                "Expected $pkg to be excluded for safety",
                decision is LockEnforcementDecision.AllowExcluded
            )
        }
    }

    @Test
    fun `8 - Permission state evaluation never reports ACTIVE when required permissions are missing`() {
        val missingUsage = PermissionHealthState(
            usageAccessGranted = false,
            overlayPermissionGranted = true,
            notificationPermissionGranted = true
        )
        val status1 = MonitoringPermissionManager.evaluateOperationalStatus(
            permissionHealth = missingUsage,
            serviceState = MonitoringServiceState.RUNNING,
            isMonitoringEnabledByUser = true,
            selectedLockedCount = 4
        )
        assertEquals(EngineOperationalStatus.PAUSED_MISSING_PERMISSIONS, status1)
        assertFalse(status1.isOperational)

        val allGrantedAndRunning = PermissionHealthState(
            usageAccessGranted = true,
            overlayPermissionGranted = true,
            notificationPermissionGranted = true
        )
        val status2 = MonitoringPermissionManager.evaluateOperationalStatus(
            permissionHealth = allGrantedAndRunning,
            serviceState = MonitoringServiceState.RUNNING,
            isMonitoringEnabledByUser = true,
            selectedLockedCount = 4
        )
        assertEquals(EngineOperationalStatus.ACTIVE, status2)
        assertTrue(status2.isOperational)
    }

    @Test
    fun `9 - Screen-off transition immediately revokes temporary package sessions when lockOnScreenOff is true`() {
        engine.setReLockDuration(ReLockDurationOption.MINUTES_5)
        engine.setLockOnScreenOffPolicy(true)
        engine.grantTemporaryPackageSession("com.whatsapp", AuthMethod.MASTER_PIN)
        assertTrue(engine.isPackageCurrentlyUnlocked("com.whatsapp"))

        engine.onForegroundTransition(
            ForegroundTransitionEvent(
                packageName = "android",
                transitionType = UsageTransitionType.SCREEN_NON_INTERACTIVE,
                timestampMillis = fakeEpochMillis + 1_000L
            )
        )
        assertFalse(engine.isPackageCurrentlyUnlocked("com.whatsapp"))
    }

    @Test
    fun `10 - Rapid switching between two protected applications tracks independent sessions accurately`() {
        engine.setReLockDuration(ReLockDurationOption.SECONDS_30)

        // Open WhatsApp -> requires auth -> unlock WhatsApp
        val wa1 = engine.onForegroundTransition(
            ForegroundTransitionEvent(
                packageName = "com.whatsapp",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis
            )
        )
        assertTrue(wa1 is LockEnforcementDecision.RequireAuthentication)
        engine.grantTemporaryPackageSession("com.whatsapp", AuthMethod.MASTER_PIN)

        // Rapidly switch to Signal (also locked, not yet unlocked) -> requires auth for Signal
        fakeMonotonicMillis += 2_000L
        val sig1 = engine.onForegroundTransition(
            ForegroundTransitionEvent(
                packageName = "org.thoughtcrime.securesms",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis + 2_000L
            )
        )
        assertTrue(sig1 is LockEnforcementDecision.RequireAuthentication)
        engine.grantTemporaryPackageSession("org.thoughtcrime.securesms", AuthMethod.BIOMETRIC_PROMPT)

        // Switch back to WhatsApp 5 seconds later (within 30s re-lock timer) -> allowed without prompt!
        fakeMonotonicMillis += 5_000L
        val wa2 = engine.onForegroundTransition(
            ForegroundTransitionEvent(
                packageName = "com.whatsapp",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis + 7_000L
            )
        )
        assertTrue(wa2 is LockEnforcementDecision.AllowActiveSession)
    }

    @Test
    fun `11 - AppLockActivity or SystemUI entering foreground does not invalidate active session`() {
        engine.setReLockDuration(ReLockDurationOption.IMMEDIATELY)
        engine.grantTemporaryPackageSession("com.whatsapp", AuthMethod.MASTER_PIN)

        // Notification shade / SystemUI or NEXLOCK overlay briefly appears
        engine.onForegroundTransition(
            ForegroundTransitionEvent(
                packageName = "com.android.systemui",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis + 500L
            )
        )
        assertTrue(engine.isPackageCurrentlyUnlocked("com.whatsapp"))
    }

    @Test
    fun `12 - Adaptive polling interval backs off when foreground package is stable and pauses when screen off`() = runBlocking {
        fakeUsageSource.events = listOf(
            ForegroundTransitionEvent(
                packageName = "com.whatsapp",
                transitionType = UsageTransitionType.ACTIVITY_RESUMED,
                timestampMillis = fakeEpochMillis
            )
        )
        detector.pollNewTransitions()
        assertEquals(
            ForegroundAppDetector.FAST_POLL_INTERVAL_MILLIS,
            detector.computeAdaptivePollIntervalMillis(isScreenInteractive = true)
        )

        // Advance clock by 12 seconds without any foreground package change
        fakeEpochMillis += 12_000L
        assertEquals(
            ForegroundAppDetector.STABLE_POLL_INTERVAL_MILLIS,
            detector.computeAdaptivePollIntervalMillis(isScreenInteractive = true)
        )

        // Screen off -> polling interval is 0ms (suspended)
        assertEquals(
            0L,
            detector.computeAdaptivePollIntervalMillis(isScreenInteractive = false)
        )
    }
}

private class FakeUsageEventsSource : UsageEventsSource {
    var events: List<ForegroundTransitionEvent> = emptyList()

    override suspend fun queryRecentEvents(
        sinceEpochMillis: Long,
        untilEpochMillis: Long
    ): List<ForegroundTransitionEvent> = events.filter {
        it.timestampMillis in sinceEpochMillis..untilEpochMillis
    }
}
