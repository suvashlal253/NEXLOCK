package com.nexlock.security.vault

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import android.util.Base64
import com.nexlock.security.database.VaultMetadataDao
import com.nexlock.security.model.VaultItemMetadataEntity
import com.nexlock.security.security.DecryptedEnvelopeResult
import com.nexlock.security.security.EncryptedEnvelopeResult
import com.nexlock.security.security.KeyManagerContract
import com.nexlock.security.security.SecureKeyManager
import java.io.File
import java.security.MessageDigest
import java.util.Arrays
import java.util.UUID
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext

data class EncryptedFileRecord(
    val relativePath: String,
    val ivBase64: String,
    val ciphertextByteSize: Long,
    val ciphertextSha256Hex: String
)

/**
 * Phase 5 & Phase 6 SecureFileRepository:
 *
 * Provides AndroidKeyStore-backed AES-256-GCM authenticated file encryption and decryption
 * for both the Privacy Vault and local Intruder Selfie storage, with Phase 6 Storage Access
 * Framework (`Uri`) stream import and atomic temporary-file write + rename protection.
 *
 * Security Invariants:
 * 1. Uses a dedicated AndroidKeyStore AES-256-GCM key alias ("nexlock_vault_aes256_gcm_v5").
 * 2. Never stores encryption keys in plaintext in Room, DataStore, or disk.
 * 3. Never stores private file content as ordinary database strings; ciphertext is written to
 *    app-private storage (context.filesDir/private_vault_encrypted/ or intruder_encrypted/).
 * 4. Writes ciphertext to an atomic `.tmp` staging file and renames only after full flush so
 *    interrupted imports never leave half-written or corrupted files in the vault.
 * 5. Zeroes plaintext byte arrays in memory after encryption when requested, and verifies round-trip
 *    authenticated GCM tag integrity + SHA-256 ciphertext digest upon decryption.
 */
class SecureFileRepository(
    private val basePrivateDir: File,
    private val vaultMetadataDao: VaultMetadataDao? = null,
    private val keyManager: KeyManagerContract = SecureKeyManager(keyAlias = VAULT_KEY_ALIAS),
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) {
    companion object {
        const val VAULT_KEY_ALIAS = "nexlock_vault_aes256_gcm_v5"
        private const val VAULT_SUBDIR = "private_vault_encrypted"
        private const val INTRUDER_SUBDIR = "intruder_encrypted"
        const val MAX_VAULT_IMPORT_BYTES = 50L * 1024L * 1024L // 50 MB guard against OOM

        fun sha256Hex(bytes: ByteArray): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
            return digest.joinToString("") { "%02x".format(it) }
        }
    }

    private val vaultDir: File
        get() = File(basePrivateDir, VAULT_SUBDIR).apply { if (!exists()) mkdirs() }

    private val intruderDir: File
        get() = File(basePrivateDir, INTRUDER_SUBDIR).apply { if (!exists()) mkdirs() }

    fun observeVaultMetadata(): Flow<List<VaultItemMetadataEntity>>? =
        vaultMetadataDao?.observeVaultItems()

    fun isVaultKeyHealthy(): Boolean = keyManager.isKeyHealthy()

    /**
     * Phase 6 Storage Access Framework (SAF) import helper.
     * Reads a user-selected document/image [Uri] via ContentResolver, extracts its display name
     * and MIME type, and encrypts it into app-private vault storage using AES-256-GCM.
     */
    suspend fun importFromStorageAccessFrameworkUri(
        context: Context,
        sourceUri: Uri,
        fallbackDisplayName: String = "Imported Vault File"
    ): Result<VaultItemMetadataEntity> = withContext(ioDispatcher) {
        val resolver = context.contentResolver
        val mimeType = resolver.getType(sourceUri) ?: "application/octet-stream"
        var resolvedName = fallbackDisplayName

        runCatching {
            resolver.query(sourceUri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)
                ?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        if (nameIdx >= 0 && !cursor.isNull(nameIdx)) {
                            resolvedName = cursor.getString(nameIdx)
                        }
                        val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
                        if (sizeIdx >= 0 && !cursor.isNull(sizeIdx)) {
                            val size = cursor.getLong(sizeIdx)
                            if (size > MAX_VAULT_IMPORT_BYTES) {
                                return@withContext Result.failure(
                                    IllegalArgumentException("Selected file exceeds 50 MB single-file vault import limit.")
                                )
                            }
                        }
                    }
                }
        }

        val plaintextBytes = try {
            val stream = resolver.openInputStream(sourceUri)
                ?: return@withContext Result.failure(IllegalStateException("Unable to open SAF input stream."))
            stream.use { it.readBytes() }
        } catch (e: Exception) {
            return@withContext Result.failure(IllegalStateException("Failed to read SAF stream: ${e.message}"))
        }

        val mediaCategory = when {
            mimeType.startsWith("image/", ignoreCase = true) -> "Photo"
            mimeType.startsWith("video/", ignoreCase = true) -> "Video"
            else -> "Document"
        }

        encryptAndStoreVaultFile(
            displayName = resolvedName,
            mediaType = mediaCategory,
            plaintextBytes = plaintextBytes,
            wipePlaintextBufferAfterEncrypt = true
        )
    }

    /**
     * Encrypts raw file bytes with AES-256-GCM via AndroidKeyStore and writes ciphertext to app-private storage
     * using an atomic `.tmp` staging write followed by rename so interrupted writes never corrupt the vault.
     * Optionally zeroes the caller's plaintext buffer in-place so no unencrypted copy lingers in heap buffers.
     */
    suspend fun encryptAndStoreVaultFile(
        displayName: String,
        mediaType: String,
        plaintextBytes: ByteArray,
        wipePlaintextBufferAfterEncrypt: Boolean = false
    ): Result<VaultItemMetadataEntity> = withContext(ioDispatcher) {
        if (plaintextBytes.isEmpty()) {
            return@withContext Result.failure(IllegalArgumentException("Cannot encrypt an empty file payload."))
        }

        val originalSize = plaintextBytes.size.toLong()
        val encrypted = keyManager.encryptPayload(plaintextBytes)
        if (wipePlaintextBufferAfterEncrypt) {
            Arrays.fill(plaintextBytes, 0.toByte())
        }

        when (encrypted) {
            is EncryptedEnvelopeResult.Success -> {
                val ciphertextBytes = Base64.decode(encrypted.ciphertextBase64, Base64.NO_WRAP)
                val itemId = "vault_${UUID.randomUUID()}"
                val fileName = "$itemId.enc"
                val tempFile = File(vaultDir, "$fileName.tmp")
                val targetFile = File(vaultDir, fileName)

                try {
                    tempFile.writeBytes(ciphertextBytes)
                    if (!tempFile.renameTo(targetFile)) {
                        tempFile.copyTo(targetFile, overwrite = true)
                        tempFile.delete()
                    }
                } catch (e: Exception) {
                    tempFile.delete()
                    return@withContext Result.failure(
                        IllegalStateException("Atomic vault write interrupted: ${e.message}")
                    )
                }

                val metadata = VaultItemMetadataEntity(
                    id = itemId,
                    displayName = displayName.trim().ifEmpty { "Encrypted Vault Item" },
                    mediaType = mediaType,
                    sizeBytes = originalSize,
                    addedAtMillis = System.currentTimeMillis(),
                    encryptedRelativePath = "$VAULT_SUBDIR/$fileName",
                    encryptionIvBase64 = encrypted.ivBase64,
                    ciphertextSha256Hex = sha256Hex(ciphertextBytes)
                )
                vaultMetadataDao?.upsertVaultItem(metadata)
                Result.success(metadata)
            }
            is EncryptedEnvelopeResult.KeyInvalidated -> {
                Result.failure(IllegalStateException(encrypted.message))
            }
            is EncryptedEnvelopeResult.Failure -> {
                Result.failure(IllegalStateException(encrypted.message))
            }
        }
    }

    /**
     * Reads encrypted ciphertext from app-private storage, verifies its SHA-256 integrity and
     * AES-256-GCM authentication tag, and returns the decrypted plaintext bytes in memory.
     */
    suspend fun decryptVaultFile(item: VaultItemMetadataEntity): Result<ByteArray> =
        withContext(ioDispatcher) {
            val targetFile = File(basePrivateDir, item.encryptedRelativePath)
            if (!targetFile.exists() || !targetFile.isFile) {
                return@withContext Result.failure(
                    IllegalStateException("Encrypted vault file not found on disk: ${item.encryptedRelativePath}")
                )
            }

            val ciphertextBytes = targetFile.readBytes()
            if (item.ciphertextSha256Hex.isNotBlank()) {
                val actualHash = sha256Hex(ciphertextBytes)
                if (!actualHash.equals(item.ciphertextSha256Hex, ignoreCase = true)) {
                    return@withContext Result.failure(
                        SecurityException("Vault file integrity check failed: SHA-256 ciphertext mismatch.")
                    )
                }
            }

            val ciphertextBase64 = Base64.encodeToString(ciphertextBytes, Base64.NO_WRAP)
            when (val decrypted = keyManager.decryptPayload(item.encryptionIvBase64, ciphertextBase64)) {
                is DecryptedEnvelopeResult.Success -> Result.success(decrypted.plaintext)
                is DecryptedEnvelopeResult.KeyInvalidated -> Result.failure(IllegalStateException(decrypted.message))
                is DecryptedEnvelopeResult.Failure -> Result.failure(SecurityException(decrypted.message))
            }
        }

    suspend fun deleteVaultFile(item: VaultItemMetadataEntity): Boolean = withContext(ioDispatcher) {
        val targetFile = File(basePrivateDir, item.encryptedRelativePath)
        val deleted = if (targetFile.exists()) {
            // Overwrite with zeros before unlinking
            runCatching {
                val len = targetFile.length().toInt().coerceAtMost(1024 * 1024)
                if (len > 0) {
                    targetFile.writeBytes(ByteArray(len))
                }
            }
            targetFile.delete()
        } else {
            true
        }
        vaultMetadataDao?.deleteVaultItemById(item.id)
        deleted
    }

    /**
     * Encrypts an Intruder Selfie JPEG byte array with AES-256-GCM and stores it inside
     * app-private filesDir/intruder_encrypted/.
     */
    suspend fun encryptIntruderSelfieBytes(
        jpegBytes: ByteArray,
        wipePlaintextAfterEncrypt: Boolean = true
    ): Result<EncryptedFileRecord> = withContext(ioDispatcher) {
        if (jpegBytes.isEmpty()) {
            return@withContext Result.failure(IllegalArgumentException("Empty image byte buffer."))
        }

        val encrypted = keyManager.encryptPayload(jpegBytes)
        if (wipePlaintextAfterEncrypt) {
            Arrays.fill(jpegBytes, 0.toByte())
        }

        when (encrypted) {
            is EncryptedEnvelopeResult.Success -> {
                val ciphertextBytes = Base64.decode(encrypted.ciphertextBase64, Base64.NO_WRAP)
                val fileName = "intruder_${System.currentTimeMillis()}_${UUID.randomUUID().toString().take(8)}.enc"
                val targetFile = File(intruderDir, fileName)
                targetFile.writeBytes(ciphertextBytes)

                Result.success(
                    EncryptedFileRecord(
                        relativePath = "$INTRUDER_SUBDIR/$fileName",
                        ivBase64 = encrypted.ivBase64,
                        ciphertextByteSize = ciphertextBytes.size.toLong(),
                        ciphertextSha256Hex = sha256Hex(ciphertextBytes)
                    )
                )
            }
            is EncryptedEnvelopeResult.KeyInvalidated -> Result.failure(IllegalStateException(encrypted.message))
            is EncryptedEnvelopeResult.Failure -> Result.failure(IllegalStateException(encrypted.message))
        }
    }

    suspend fun decryptIntruderSelfieBytes(
        relativePath: String,
        ivBase64: String
    ): Result<ByteArray> = withContext(ioDispatcher) {
        val targetFile = File(basePrivateDir, relativePath)
        if (!targetFile.exists()) {
            return@withContext Result.failure(IllegalStateException("Encrypted intruder file missing: $relativePath"))
        }
        val ciphertextBase64 = Base64.encodeToString(targetFile.readBytes(), Base64.NO_WRAP)
        when (val dec = keyManager.decryptPayload(ivBase64, ciphertextBase64)) {
            is DecryptedEnvelopeResult.Success -> Result.success(dec.plaintext)
            is DecryptedEnvelopeResult.KeyInvalidated -> Result.failure(IllegalStateException(dec.message))
            is DecryptedEnvelopeResult.Failure -> Result.failure(SecurityException(dec.message))
        }
    }

    suspend fun deleteEncryptedFileAtRelativePath(relativePath: String?): Boolean =
        withContext(ioDispatcher) {
            if (relativePath.isNullOrBlank()) return@withContext true
            val file = File(basePrivateDir, relativePath)
            if (!file.exists()) return@withContext true
            runCatching {
                val len = file.length().toInt().coerceAtMost(512 * 1024)
                if (len > 0) file.writeBytes(ByteArray(len))
            }
            file.delete()
        }
}
