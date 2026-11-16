package com.nexlock.security.monitoring

import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Abstraction for querying recent foreground/background UsageEvents from the Android OS.
 * Enables deterministic unit tests without requiring a live system UsageStatsManager.
 */
interface UsageEventsSource {
    suspend fun queryRecentEvents(
        sinceEpochMillis: Long,
        untilEpochMillis: Long
    ): List<ForegroundTransitionEvent>
}

class UsageStatsRepository(
    private val context: Context
) : UsageEventsSource {

    override suspend fun queryRecentEvents(
        sinceEpochMillis: Long,
        untilEpochMillis: Long
    ): List<ForegroundTransitionEvent> = withContext(Dispatchers.Default) {
        val usageStatsManager = context.getSystemService(Context.USAGE_STATS_SERVICE)
            as? UsageStatsManager ?: return@withContext emptyList()

        val result = mutableListOf<ForegroundTransitionEvent>()
        try {
            val usageEvents = usageStatsManager.queryEvents(sinceEpochMillis, untilEpochMillis)
                ?: return@withContext emptyList()
            val event = UsageEvents.Event()
            while (usageEvents.hasNextEvent()) {
                usageEvents.getNextEvent(event)
                val pkg = event.packageName ?: continue
                val transitionType = mapAndroidEventType(event.eventType) ?: continue
                result.add(
                    ForegroundTransitionEvent(
                        packageName = pkg,
                        className = event.className,
                        transitionType = transitionType,
                        timestampMillis = event.timeStamp
                    )
                )
            }
        } catch (e: SecurityException) {
            // Usage Access was revoked while polling
            return@withContext emptyList()
        } catch (e: Exception) {
            return@withContext emptyList()
        }
        result
    }

    companion object {
        // UsageEvents.Event constants across API 26–35:
        // 1 = MOVE_TO_FOREGROUND / ACTIVITY_RESUMED
        // 2 = MOVE_TO_BACKGROUND / ACTIVITY_PAUSED
        // 15 = SCREEN_INTERACTIVE
        // 16 = SCREEN_NON_INTERACTIVE
        // 17 = KEYGUARD_SHOWN
        private const val EVENT_ACTIVITY_RESUMED = 1
        private const val EVENT_ACTIVITY_PAUSED = 2
        private const val EVENT_SCREEN_INTERACTIVE = 15
        private const val EVENT_SCREEN_NON_INTERACTIVE = 16
        private const val EVENT_KEYGUARD_SHOWN = 17

        fun mapAndroidEventType(rawEventType: Int): UsageTransitionType? = when (rawEventType) {
            EVENT_ACTIVITY_RESUMED -> UsageTransitionType.ACTIVITY_RESUMED
            EVENT_ACTIVITY_PAUSED -> UsageTransitionType.ACTIVITY_PAUSED
            EVENT_SCREEN_INTERACTIVE -> UsageTransitionType.SCREEN_INTERACTIVE
            EVENT_SCREEN_NON_INTERACTIVE -> UsageTransitionType.SCREEN_NON_INTERACTIVE
            EVENT_KEYGUARD_SHOWN -> UsageTransitionType.KEYGUARD_SHOWN
            else -> null
        }
    }
}

/**
 * Stateful Foreground Application Detector (Section 2).
 *
 * Responsibilities:
 * 1. Deduplicates UsageEvents using [lastProcessedEventTimestampMillis].
 * 2. Processes chronological transitions (ACTIVITY_RESUMED, ACTIVITY_PAUSED, SCREEN_NON_INTERACTIVE).
 * 3. Handles rapid app switching by ordering events strictly by timestamp and returning
 *    all new transitions so re-lock timers are started accurately for departed packages.
 * 4. Computes adaptive polling intervals (400ms active -> 1100ms stable) to save battery.
 */
class ForegroundAppDetector(
    private val usageEventsSource: UsageEventsSource,
    private val epochClockMillis: () -> Long = { System.currentTimeMillis() }
) {
    var lastProcessedEventTimestampMillis: Long = 0L
        private set

    var currentForegroundPackage: String? = null
        private set

    private var lastForegroundChangeEpochMillis: Long = 0L

    companion object {
        const val INITIAL_LOOKBACK_WINDOW_MILLIS = 3_500L
        const val MAX_QUERY_WINDOW_MILLIS = 15_000L
        const val FAST_POLL_INTERVAL_MILLIS = 400L
        const val STABLE_POLL_INTERVAL_MILLIS = 1_100L
        const val STABLE_THRESHOLD_MILLIS = 8_000L
    }

    /**
     * Polls UsageEvents since [lastProcessedEventTimestampMillis] and returns ordered,
     * unprocessed transitions.
     */
    suspend fun pollNewTransitions(): List<ForegroundTransitionEvent> {
        val now = epochClockMillis()
        val queryStart = if (lastProcessedEventTimestampMillis <= 0L) {
            (now - INITIAL_LOOKBACK_WINDOW_MILLIS).coerceAtLeast(0L)
        } else {
            (lastProcessedEventTimestampMillis - 50L).coerceAtLeast(now - MAX_QUERY_WINDOW_MILLIS)
        }

        val rawEvents = usageEventsSource.queryRecentEvents(queryStart, now)
        if (rawEvents.isEmpty()) return emptyList()

        val unseenEvents = rawEvents
            .filter { it.timestampMillis > lastProcessedEventTimestampMillis }
            .sortedBy { it.timestampMillis }

        if (unseenEvents.isEmpty()) return emptyList()

        lastProcessedEventTimestampMillis = unseenEvents.last().timestampMillis
        unseenEvents.forEach { ev ->
            if (ev.transitionType == UsageTransitionType.ACTIVITY_RESUMED) {
                if (currentForegroundPackage != ev.packageName) {
                    currentForegroundPackage = ev.packageName
                    lastForegroundChangeEpochMillis = now
                }
            }
        }
        return unseenEvents
    }

    /**
     * Adaptive polling interval calculation:
     * Uses faster polling (400ms) right after user switches apps, and backs off to 1100ms
     * when the user remains in the same foreground app for >8 seconds.
     */
    fun computeAdaptivePollIntervalMillis(isScreenInteractive: Boolean): Long {
        if (!isScreenInteractive) return 0L
        val now = epochClockMillis()
        val elapsedSinceChange = now - lastForegroundChangeEpochMillis
        return if (elapsedSinceChange in 0L..STABLE_THRESHOLD_MILLIS) {
            FAST_POLL_INTERVAL_MILLIS
        } else {
            STABLE_POLL_INTERVAL_MILLIS
        }
    }

    fun resetState() {
        lastProcessedEventTimestampMillis = 0L
        currentForegroundPackage = null
        lastForegroundChangeEpochMillis = 0L
    }
}
