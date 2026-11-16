package com.nexlock.security.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Manages AES-256-GCM cryptographic keys inside the hardware-backed AndroidKeyStore.
 *
 * Key Responsibilities:
 * 1. Generates and retrieves non-exportable AES-256-GCM keys in AndroidKeyStore.
 * 2. Never hardcodes secrets or stores raw symmetric keys in DataStore.
 * 3. Encrypts and decrypts sensitive security material (such as the PBKDF2 verifier envelope).
 * 4. Detects and recovers safely from KeyPermanentlyInvalidatedException or corrupted key entries.
 */
interface KeyManagerContract {
    fun isKeyHealthy(): Boolean
    fun encryptPayload(plaintext: ByteArray): EncryptedEnvelopeResult
    fun decryptPayload(ivBase64: String, ciphertextBase64: String): DecryptedEnvelopeResult
    fun rotateOrRecoverMasterKey(): Boolean
}

sealed class EncryptedEnvelopeResult {
    data class Success(val ivBase64: String, val ciphertextBase64: String) : EncryptedEnvelopeResult()
    data class KeyInvalidated(val message: String) : EncryptedEnvelopeResult()
    data class Failure(val message: String) : EncryptedEnvelopeResult()
}

sealed class DecryptedEnvelopeResult {
    data class Success(val plaintext: ByteArray) : DecryptedEnvelopeResult()
    data class KeyInvalidated(val message: String) : DecryptedEnvelopeResult()
    data class Failure(val message: String) : DecryptedEnvelopeResult()
}

class SecureKeyManager(
    private val keyAlias: String = DEFAULT_KEY_ALIAS
) : KeyManagerContract {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val DEFAULT_KEY_ALIAS = "nexlock_master_aes256_gcm_v2"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH_BITS = 128
        private const val KEY_SIZE_BITS = 256
    }

    private fun getKeyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    @Synchronized
    private fun getOrCreateSecretKey(): SecretKey {
        val keyStore = getKeyStore()
        val existingEntry = keyStore.getEntry(keyAlias, null) as? KeyStore.SecretKeyEntry
        if (existingEntry != null) {
            return existingEntry.secretKey
        }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )
        val spec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(KEY_SIZE_BITS)
            .setRandomizedEncryptionRequired(true)
            .build()

        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    override fun isKeyHealthy(): Boolean {
        return try {
            val key = getOrCreateSecretKey()
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            true
        } catch (e: KeyPermanentlyInvalidatedException) {
            false
        } catch (e: Exception) {
            false
        }
    }

    override fun encryptPayload(plaintext: ByteArray): EncryptedEnvelopeResult {
        return try {
            val secretKey = getOrCreateSecretKey()
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            val iv = cipher.iv
            val ciphertext = cipher.doFinal(plaintext)
            EncryptedEnvelopeResult.Success(
                ivBase64 = Base64.encodeToString(iv, Base64.NO_WRAP),
                ciphertextBase64 = Base64.encodeToString(ciphertext, Base64.NO_WRAP)
            )
        } catch (e: KeyPermanentlyInvalidatedException) {
            EncryptedEnvelopeResult.KeyInvalidated(
                "AndroidKeyStore key was invalidated by a system lockscreen or biometric enrollment change. Re-verify Master PIN to rotate the key."
            )
        } catch (e: Exception) {
            EncryptedEnvelopeResult.Failure("Keystore encryption failed: ${e.javaClass.simpleName}")
        }
    }

    override fun decryptPayload(ivBase64: String, ciphertextBase64: String): DecryptedEnvelopeResult {
        return try {
            val secretKey = getOrCreateSecretKey()
            val iv = Base64.decode(ivBase64, Base64.NO_WRAP)
            val ciphertext = Base64.decode(ciphertextBase64, Base64.NO_WRAP)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            val decrypted = cipher.doFinal(ciphertext)
            DecryptedEnvelopeResult.Success(decrypted)
        } catch (e: KeyPermanentlyInvalidatedException) {
            DecryptedEnvelopeResult.KeyInvalidated(
                "AndroidKeyStore key was permanently invalidated due to device credential/biometric enrollment changes."
            )
        } catch (e: Exception) {
            DecryptedEnvelopeResult.Failure("Keystore decryption failed: ${e.javaClass.simpleName}")
        }
    }

    /**
     * Recovery behavior when a key is invalidated:
     * Deletes the invalidated alias and provisions a fresh hardware-backed AES-256-GCM key.
     * Note: PIN verification relies on PBKDF2-HMAC-SHA256 derived verifiers, while Keystore
     * provides an additional hardware-bound encryption layer and biometric CryptoObject binding.
     */
    override fun rotateOrRecoverMasterKey(): Boolean {
        return try {
            val keyStore = getKeyStore()
            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias)
            }
            getOrCreateSecretKey()
            true
        } catch (e: Exception) {
            false
        }
    }
}
