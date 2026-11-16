package com.nexlock.security.auth

import com.nexlock.security.repository.AuthRepository
import com.nexlock.security.repository.SecuritySettingsStore
import com.nexlock.security.repository.StoredSecuritySettings
import com.nexlock.security.security.DecryptedEnvelopeResult
import com.nexlock.security.security.EncryptedEnvelopeResult
import com.nexlock.security.security.KeyManagerContract
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Complete Unit Test Suite for NEXLOCK Phase 2 Authentication & Security Infrastructure.
 *
 * Covers all 12 required test cases:
 * 1. PIN creation
 * 2. PIN confirmation mismatch detection
 * 3. Correct PIN verification
 * 4. Incorrect PIN verification
 * 5. Weak PIN rejection (0000, 1111, 1234, 654321, 1212, etc.)
 * 6. Failed attempt counter increment & reset on success
 * 7. Temporary lockout enforcement & expiration recovery
 * 8. Session expiration using monotonic clock
 * 9. Session explicit invalidation / lockNow
 * 10. Biometric unavailable fallback handling
 * 11. Biometric user cancellation handling
 * 12. AndroidKeyStore key invalidation detection & recovery
 */
class Phase2AuthenticationTest {

    private lateinit var pinManager: PinManager
    private lateinit var fakeKeyManager: FakeKeyManager
    private lateinit var fakeSettingsStore: InMemorySecuritySettingsStore
    private lateinit var sessionManager: SessionManager
    private lateinit var authRepository: AuthRepository

    private var fakeMonotonicMillis: Long = 1_000_000L
    private var fakeEpochMillis: Long = 1_700_000_000_000L

    @Before
    fun setUp() {
        pinManager = PinManager()
        fakeKeyManager = FakeKeyManager()
        fakeSettingsStore = InMemorySecuritySettingsStore()
        sessionManager = SessionManager(
            clock = { fakeMonotonicMillis },
            initialTimeout = SessionTimeoutOption.MINUTE_1
        )
        authRepository = AuthRepository(
            pinManager = pinManager,
            keyManager = fakeKeyManager,
            settingsStore = fakeSettingsStore,
            sessionManager = sessionManager,
            epochClockMillis = { fakeEpochMillis }
        )
    }

    @Test
    fun `1 - PIN creation derives salted PBKDF2 verifier and encrypts envelope`() = runBlocking {
        val res = authRepository.createOrUpdateMasterPin("739204", "739204")
        assertTrue(res.isSuccess)
        val stored = fakeSettingsStore.getSnapshot()
        assertTrue(stored.isPinConfigured)
        assertEquals(6, stored.pinLength)
        assertTrue(!stored.pinSaltBase64.isNullOrBlank())
        assertTrue(!stored.encryptedVerifierCiphertextBase64.isNullOrBlank())
        assertTrue(sessionManager.sessionFlow.value.isAuthenticated)
    }

    @Test
    fun `2 - PIN confirmation rejects mismatched confirmation input`() = runBlocking {
        val res = authRepository.createOrUpdateMasterPin("739204", "739205")
        assertTrue(res.isFailure)
        assertFalse(fakeSettingsStore.getSnapshot().isPinConfigured)
    }

    @Test
    fun `3 - Correct PIN verification succeeds and establishes session`() = runBlocking {
        authRepository.createOrUpdateMasterPin("8492", "8492")
        sessionManager.invalidateSession()
        assertFalse(sessionManager.sessionFlow.value.isAuthenticated)

        val verify = authRepository.verifyMasterPin("8492")
        assertTrue(verify is AuthenticationResult.Success)
        assertTrue(sessionManager.sessionFlow.value.isAuthenticated)
    }

    @Test
    fun `4 - Incorrect PIN verification fails and denies access`() = runBlocking {
        authRepository.createOrUpdateMasterPin("8492", "8492")
        sessionManager.invalidateSession()

        val verify = authRepository.verifyMasterPin("8499")
        assertTrue(verify is AuthenticationResult.IncorrectPin)
        assertFalse(sessionManager.sessionFlow.value.isAuthenticated)
    }

    @Test
    fun `5 - Weak PIN rejection blocks predictable 4 and 6 digit patterns`() {
        val weakSamples = listOf(
            "0000", "1111", "9999", "1234", "4321", "1212", "1122", "2580",
            "000000", "111111", "123456", "654321", "123123", "112233"
        )
        for (weak in weakSamples) {
            val result = pinManager.validatePinStrength(weak)
            assertTrue("Expected $weak to be rejected as weak", result is PinValidationResult.WeakPattern)
        }

        val strongSamples = listOf("7392", "5819", "739204", "904827")
        for (strong in strongSamples) {
            val result = pinManager.validatePinStrength(strong)
            assertTrue("Expected $strong to be accepted as strong", result is PinValidationResult.Valid)
        }
    }

    @Test
    fun `6 - Failed attempt counter increments and resets after valid PIN`() = runBlocking {
        authRepository.createOrUpdateMasterPin("739204", "739204")
        sessionManager.invalidateSession()

        authRepository.verifyMasterPin("999991")
        authRepository.verifyMasterPin("999992")
        assertEquals(2, fakeSettingsStore.getSnapshot().failedAttempts)

        val ok = authRepository.verifyMasterPin("739204")
        assertTrue(ok is AuthenticationResult.Success)
        assertEquals(0, fakeSettingsStore.getSnapshot().failedAttempts)
    }

    @Test
    fun `7 - Temporary lockout triggers after max failed attempts and recovers after cooldown`() = runBlocking {
        fakeSettingsStore.setMaxFailedAttempts(3)
        authRepository.createOrUpdateMasterPin("739204", "739204")
        sessionManager.invalidateSession()

        authRepository.verifyMasterPin("100001")
        authRepository.verifyMasterPin("100002")
        val third = authRepository.verifyMasterPin("100003")
        assertTrue(third is AuthenticationResult.LockedOut)

        // Even with the right PIN during active lockout, access is denied
        val blockedAttempt = authRepository.verifyMasterPin("739204")
        assertTrue(blockedAttempt is AuthenticationResult.LockedOut)

        // Advance clock by 31 seconds past cooldown
        fakeEpochMillis += 31_000L
        val unlockedAttempt = authRepository.verifyMasterPin("739204")
        assertTrue(unlockedAttempt is AuthenticationResult.Success)
    }

    @Test
    fun `8 - Session expiration invalidates session after configured monotonic timeout`() {
        sessionManager.setSessionTimeoutOption(SessionTimeoutOption.SECONDS_15)
        sessionManager.startAuthenticatedSession(AuthMethod.MASTER_PIN)
        assertTrue(sessionManager.sessionFlow.value.isAuthenticated)

        fakeMonotonicMillis += 10_000L
        assertFalse(sessionManager.evaluateAndExpireIfNecessary())
        assertTrue(sessionManager.sessionFlow.value.isAuthenticated)

        fakeMonotonicMillis += 6_000L
        assertTrue(sessionManager.evaluateAndExpireIfNecessary())
        assertFalse(sessionManager.sessionFlow.value.isAuthenticated)
    }

    @Test
    fun `9 - Session explicit invalidation immediately locks NEXLOCK`() {
        sessionManager.startAuthenticatedSession(AuthMethod.BIOMETRIC_PROMPT)
        assertTrue(sessionManager.sessionFlow.value.isAuthenticated)

        sessionManager.invalidateSession()
        assertFalse(sessionManager.sessionFlow.value.isAuthenticated)
    }

    @Test
    fun `10 - Biometric unavailable reports status and preserves PIN fallback`() = runBlocking {
        val unavailableResult = AuthenticationResult.BiometricFailed(
            reason = BiometricCapabilityStatus.NONE_ENROLLED.description,
            allowPinFallback = true
        )
        val processed = authRepository.onBiometricPromptResult(unavailableResult)
        assertTrue(processed is AuthenticationResult.BiometricFailed)
        assertFalse(sessionManager.sessionFlow.value.isAuthenticated)
    }

    @Test
    fun `11 - Biometric cancellation keeps session locked without incrementing PIN lockout`() = runBlocking {
        val canceled = AuthenticationResult.BiometricCanceled("User tapped Use Master PIN")
        val processed = authRepository.onBiometricPromptResult(canceled)
        assertTrue(processed is AuthenticationResult.BiometricCanceled)
        assertEquals(0, fakeSettingsStore.getSnapshot().failedAttempts)
        assertFalse(sessionManager.sessionFlow.value.isAuthenticated)
    }

    @Test
    fun `12 - AndroidKeyStore key invalidation is detected and recovered safely`() = runBlocking {
        authRepository.createOrUpdateMasterPin("739204", "739204")
        sessionManager.invalidateSession()

        fakeKeyManager.simulateKeyInvalidated = true
        val verifyDuringInvalidation = authRepository.verifyMasterPin("739204")
        assertTrue(verifyDuringInvalidation is AuthenticationResult.KeyInvalidated)

        // Recover key and re-establish PIN
        assertTrue(fakeKeyManager.rotateOrRecoverMasterKey())
        val recreate = authRepository.createOrUpdateMasterPin("739204", "739204")
        assertTrue(recreate.isSuccess)
    }
}

private class FakeKeyManager : KeyManagerContract {
    var simulateKeyInvalidated: Boolean = false

    override fun isKeyHealthy(): Boolean = !simulateKeyInvalidated

    override fun encryptPayload(plaintext: ByteArray): EncryptedEnvelopeResult {
        if (simulateKeyInvalidated) {
            return EncryptedEnvelopeResult.KeyInvalidated("Simulated KeyPermanentlyInvalidatedException")
        }
        return EncryptedEnvelopeResult.Success(
            ivBase64 = "c2ltdWxhdGVkX2l2",
            ciphertextBase64 = java.util.Base64.getEncoder().encodeToString(plaintext)
        )
    }

    override fun decryptPayload(ivBase64: String, ciphertextBase64: String): DecryptedEnvelopeResult {
        if (simulateKeyInvalidated) {
            return DecryptedEnvelopeResult.KeyInvalidated("Simulated KeyPermanentlyInvalidatedException")
        }
        return DecryptedEnvelopeResult.Success(
            java.util.Base64.getDecoder().decode(ciphertextBase64)
        )
    }

    override fun rotateOrRecoverMasterKey(): Boolean {
        simulateKeyInvalidated = false
        return true
    }
}

private class InMemorySecuritySettingsStore : SecuritySettingsStore {
    private val state = MutableStateFlow(StoredSecuritySettings())
    override val settingsFlow: Flow<StoredSecuritySettings> = state

    override suspend fun getSnapshot(): StoredSecuritySettings = state.value

    override suspend fun saveEncryptedPinVerifier(
        saltBase64: String,
        ivBase64: String,
        ciphertextBase64: String,
        iterations: Int,
        pinLength: Int
    ) {
        state.value = state.value.copy(
            isPinConfigured = true,
            pinSaltBase64 = saltBase64,
            encryptedVerifierIvBase64 = ivBase64,
            encryptedVerifierCiphertextBase64 = ciphertextBase64,
            pbkdf2Iterations = iterations,
            pinLength = pinLength,
            failedAttempts = 0,
            lockoutUntilEpochMillis = 0L
        )
    }

    override suspend fun recordFailedAttempt(newCount: Int, lockoutUntilEpochMillis: Long) {
        state.value = state.value.copy(
            failedAttempts = newCount,
            lockoutUntilEpochMillis = lockoutUntilEpochMillis
        )
    }

    override suspend fun resetFailedAttempts() {
        state.value = state.value.copy(failedAttempts = 0, lockoutUntilEpochMillis = 0L)
    }

    override suspend fun setMaxFailedAttempts(maxAttempts: Int) {
        state.value = state.value.copy(maxFailedAttempts = maxAttempts)
    }

    override suspend fun setBiometricEnabled(enabled: Boolean) {
        state.value = state.value.copy(biometricEnabled = enabled)
    }

    override suspend fun setSessionTimeout(option: SessionTimeoutOption) {
        state.value = state.value.copy(sessionTimeoutOption = option)
    }
}
