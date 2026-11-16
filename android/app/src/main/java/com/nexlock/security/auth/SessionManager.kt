package com.nexlock.security.auth

import android.os.SystemClock
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Monotonic Clock abstraction so unit tests can advance elapsed time deterministically
 * while production uses Android's SystemClock.elapsedRealtime().
 */
fun interface MonotonicClock {
    fun elapsedRealtimeMillis(): Long
}

object SystemMonotonicClock : MonotonicClock {
    override fun elapsedRealtimeMillis(): Long = SystemClock.elapsedRealtime()
}

data class SessionSnapshot(
    val isAuthenticated: Boolean = false,
    val lastAuthMethod: AuthMethod? = null,
    val authenticatedAtElapsedMillis: Long? = null,
    val lastInteractionElapsedMillis: Long? = null,
    val timeoutOption: SessionTimeoutOption = SessionTimeoutOption.MINUTE_1
)

/**
 * In-memory Security Session Manager.
 *
 * Critical Security Guarantees:
 * 1. Session state lives strictly in volatile RAM — it is NEVER persisted to disk or DataStore,
 *    so a device reboot or process termination automatically requires fresh authentication.
 * 2. Uses a monotonic clock (SystemClock.elapsedRealtime()) immune to wall-clock tampering.
 * 3. Supports Immediately (0s), 15s, 30s, 1m, and 5m session timeouts.
 * 4. Provides explicit lockNow() / invalidateSession() actions.
 */
class SessionManager(
    private val clock: MonotonicClock = SystemMonotonicClock,
    initialTimeout: SessionTimeoutOption = SessionTimeoutOption.MINUTE_1
) {
    private val _sessionFlow = MutableStateFlow(
        SessionSnapshot(
            isAuthenticated = false,
            timeoutOption = initialTimeout
        )
    )
    val sessionFlow: StateFlow<SessionSnapshot> = _sessionFlow.asStateFlow()

    fun startAuthenticatedSession(method: AuthMethod) {
        val now = clock.elapsedRealtimeMillis()
        _sessionFlow.value = _sessionFlow.value.copy(
            isAuthenticated = true,
            lastAuthMethod = method,
            authenticatedAtElapsedMillis = now,
            lastInteractionElapsedMillis = now
        )
    }

    fun recordUserInteraction() {
        val current = _sessionFlow.value
        if (!current.isAuthenticated) return
        if (evaluateAndExpireIfNecessary()) return
        _sessionFlow.value = current.copy(
            lastInteractionElapsedMillis = clock.elapsedRealtimeMillis()
        )
    }

    fun setSessionTimeoutOption(option: SessionTimeoutOption) {
        _sessionFlow.value = _sessionFlow.value.copy(timeoutOption = option)
        evaluateAndExpireIfNecessary()
    }

    /**
     * Checks whether the current session has exceeded the configured timeout when backgrounded
     * or idle. Returns true if the session expired and was invalidated.
     */
    fun evaluateAndExpireIfNecessary(onBackgroundTransition: Boolean = false): Boolean {
        val current = _sessionFlow.value
        if (!current.isAuthenticated) return true

        val timeoutMillis = current.timeoutOption.durationMillis
        if (onBackgroundTransition && timeoutMillis == 0L) {
            invalidateSession()
            return true
        }

        val anchor = current.lastInteractionElapsedMillis ?: current.authenticatedAtElapsedMillis
        if (anchor == null) {
            invalidateSession()
            return true
        }

        val elapsed = clock.elapsedRealtimeMillis() - anchor
        if (timeoutMillis > 0L && elapsed >= timeoutMillis) {
            invalidateSession()
            return true
        }
        return false
    }

    fun remainingSessionSeconds(): Long {
        val current = _sessionFlow.value
        if (!current.isAuthenticated) return 0L
        val timeoutMillis = current.timeoutOption.durationMillis
        if (timeoutMillis == 0L) return 0L
        val anchor = current.lastInteractionElapsedMillis ?: return 0L
        val remainingMillis = (timeoutMillis - (clock.elapsedRealtimeMillis() - anchor)).coerceAtLeast(0L)
        return (remainingMillis + 999L) / 1000L
    }

    fun invalidateSession() {
        _sessionFlow.value = _sessionFlow.value.copy(
            isAuthenticated = false,
            lastAuthMethod = null,
            authenticatedAtElapsedMillis = null,
            lastInteractionElapsedMillis = null
        )
    }
}
