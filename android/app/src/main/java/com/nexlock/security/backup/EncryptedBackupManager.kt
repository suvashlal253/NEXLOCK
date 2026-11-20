package com.nexlock.security.backup

import android.content.Context
import android.net.Uri
import com.nexlock.security.auth.SessionTimeoutOption
import com.nexlock.security.model.AccentColorPreset
import com.nexlock.security.model.AppListDensity
import com.nexlock.security.model.AppSortOrder
import com.nexlock.security.model.KeypadStyle
import com.nexlock.security.model.LockMode
import com.nexlock.security.model.LockScheduleEntity
import com.nexlock.security.model.LockScreenBackgroundStyle
import com.nexlock.security.model.LockedAppEntity
import com.nexlock.security.model.ThemePreference
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import java.util.Base64
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONArray
import org.json.JSONObject

/**
 * Phase 6 BackupMetadata (Section 5).
 */
data class BackupMetadata(
    val formatMagic: String = FORMAT_MAGIC,
    val formatVersion: Int = CURRENT_FORMAT_VERSION,
    val appVersionName: String = "2.0.0-production",
    val exportedAtEpochMillis: Long,
    val kdfAlgorithm: String = "PBKDF2WithHmacSHA256",
    val kdfIterations: Int = PBKDF2_ITERATIONS,
    val cipherAlgorithm: String = "AES/GCM/NoPadding",
    val lockedAppsCount: Int,
    val schedulesCount: Int,
    val plaintextSha256Hex: String,
    val ciphertextSha256Hex: String
) {
    companion object {
        const val FORMAT_MAGIC = "NEXLOCK_ENCRYPTED_BACKUP"
        const val CURRENT_FORMAT_VERSION = 1
        const val PBKDF2_ITERATIONS = 210_000
    }
}

/**
 * Non-secret configuration payload exported into the encrypted backup.
 *
 * SECURITY INVARIANT:
 * - NEVER contains plaintext PINs, PBKDF2 PIN verifiers, PIN salts, AndroidKeyStore private keys,
 *   or biometric enrollment templates.
 */
data class BackupConfigurationPayload(
    val lockedApps: List<LockedAppEntity>,
    val schedules: List<LockScheduleEntity>,
    val lockMode: LockMode,
    val sessionTimeoutOption: SessionTimeoutOption,
    val maxFailedAttempts: Int,
    val themePreference: ThemePreference,
    val accentColorPreset: AccentColorPreset,
    val appListDensity: AppListDensity,
    val appSortOrder: AppSortOrder,
    val showAppIconOnLockScreen: Boolean,
    val showAppNameOnLockScreen: Boolean,
    val lockScreenBackgroundStyle: LockScreenBackgroundStyle,
    val enableLockScreenAnimations: Boolean,
    val keypadStyle: KeypadStyle,
    val languageCode: String
)

sealed class BackupRestoreResult {
    data class Success(
        val metadata: BackupMetadata,
        val payload: BackupConfigurationPayload,
        val requiresMasterPinVerification: Boolean = true
    ) : BackupRestoreResult()

    data class Failure(
        val errorCode: RestoreErrorCode,
        val userMessage: String
    ) : BackupRestoreResult()
}

enum class RestoreErrorCode {
    WEAK_OR_EMPTY_PASSWORD,
    INVALID_FORMAT_OR_MAGIC,
    UNSUPPORTED_VERSION,
    INTEGRITY_HASH_MISMATCH,
    AUTHENTICATION_FAILED_WRONG_PASSWORD_OR_TAMPERED,
    MALFORMED_PAYLOAD_JSON,
    CONFIRMATION_REQUIRED
}

/**
 * Phase 6 BackupEncryptionManager (Section 5).
 *
 * Uses standard Android / Java Cryptography Architecture APIs:
 * - Key Derivation: `PBKDF2WithHmacSHA256` with 210,000 iterations and 128-bit CSPRNG salt -> 256-bit AES key.
 * - Authenticated Encryption: `AES/GCM/NoPadding` with 96-bit CSPRNG nonce and 128-bit authentication tag.
 * - Integrity Verification: SHA-256 digests over both ciphertext and decrypted plaintext JSON, plus AES-GCM AEAD tag.
 */
class BackupEncryptionManager(
    private val secureRandom: SecureRandom = SecureRandom()
) {
    companion object {
        private const val SALT_BYTES = 16
        private const val GCM_IV_BYTES = 12
        private const val GCM_TAG_BITS = 128
        private const val AES_KEY_BITS = 256
        const val MIN_BACKUP_PASSWORD_LENGTH = 8

        private val FORBIDDEN_SECRET_KEYS = setOf(
            "pin",
            "masterPin",
            "rawPin",
            "pinSaltBase64",
            "pin_salt_b64",
            "encryptedVerifierCiphertextBase64",
            "verifier_ciphertext_b64",
            "keystorePrivateKey",
            "biometricTemplate"
        )

        fun sha256Hex(bytes: ByteArray): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
            return digest.joinToString("") { "%02x".format(it) }
        }
    }

    fun validateBackupPassword(password: CharArray): String? {
        if (password.size < MIN_BACKUP_PASSWORD_LENGTH) {
            return "Backup password must be at least $MIN_BACKUP_PASSWORD_LENGTH characters long."
        }
        val allSame = password.all { it == password[0] }
        if (allSame) {
            return "Backup password cannot consist of a single repeated character."
        }
        return null
    }

    private fun deriveAes256Key(password: CharArray, salt: ByteArray, iterations: Int): SecretKeySpec {
        val spec = PBEKeySpec(password, salt, iterations, AES_KEY_BITS)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val encoded = factory.generateSecret(spec).encoded
        spec.clearPassword()
        val keySpec = SecretKeySpec(encoded, "AES")
        Arrays.fill(encoded, 0.toByte())
        return keySpec
    }

    fun serializePayloadToJson(payload: BackupConfigurationPayload): String {
        val root = JSONObject()
        root.put("lockMode", payload.lockMode.id)
        root.put("sessionTimeoutOption", payload.sessionTimeoutOption.id)
        root.put("maxFailedAttempts", payload.maxFailedAttempts.coerceIn(3, 10))
        root.put("themePreference", payload.themePreference.id)
        root.put("accentColorPreset", payload.accentColorPreset.id)
        root.put("appListDensity", payload.appListDensity.id)
        root.put("appSortOrder", payload.appSortOrder.id)
        root.put("showAppIconOnLockScreen", payload.showAppIconOnLockScreen)
        root.put("showAppNameOnLockScreen", payload.showAppNameOnLockScreen)
        root.put("lockScreenBackgroundStyle", payload.lockScreenBackgroundStyle.id)
        root.put("enableLockScreenAnimations", payload.enableLockScreenAnimations)
        root.put("keypadStyle", payload.keypadStyle.id)
        root.put("languageCode", payload.languageCode)

        val appsArray = JSONArray()
        for (app in payload.lockedApps) {
            val obj = JSONObject()
            obj.put("packageName", app.packageName)
            obj.put("appName", app.appName)
            obj.put("isLocked", app.isLocked)
            obj.put("category", app.category)
            obj.put("createdAt", app.createdAt)
            obj.put("updatedAt", app.updatedAt)
            appsArray.put(obj)
        }
        root.put("lockedApps", appsArray)

        val schedulesArray = JSONArray()
        for (sched in payload.schedules) {
            val obj = JSONObject()
            obj.put("id", sched.id)
            obj.put("name", sched.name)
            obj.put("description", sched.description)
            obj.put("startHour", sched.startHour)
            obj.put("startMinute", sched.startMinute)
            obj.put("endHour", sched.endHour)
            obj.put("endMinute", sched.endMinute)
            obj.put("daysOfWeekCsv", sched.daysOfWeekCsv)
            obj.put("targetPackagesCsv", sched.targetPackagesCsv)
            obj.put("applyToAllLockedApps", sched.applyToAllLockedApps)
            obj.put("isEnabled", sched.isEnabled)
            obj.put("createdAtMillis", sched.createdAtMillis)
            obj.put("updatedAtMillis", sched.updatedAtMillis)
            schedulesArray.put(obj)
        }
        root.put("schedules", schedulesArray)
        return root.toString()
    }

    fun deserializePayloadFromJson(jsonString: String): BackupConfigurationPayload {
        val root = JSONObject(jsonString)

        // Defense-in-depth audit: reject any payload attempting to smuggle raw PINs or verifiers
        for (forbidden in FORBIDDEN_SECRET_KEYS) {
            if (root.has(forbidden)) {
                throw SecurityException("Backup payload contains forbidden authentication secret field: $forbidden")
            }
        }

        val appsArray = root.optJSONArray("lockedApps") ?: JSONArray()
        val lockedApps = mutableListOf<LockedAppEntity>()
        for (i in 0 until appsArray.length()) {
            val item = appsArray.getJSONObject(i)
            val pkg = item.getString("packageName").trim()
            if (pkg.isNotEmpty()) {
                lockedApps.add(
                    LockedAppEntity(
                        packageName = pkg,
                        appName = item.optString("appName", pkg),
                        isLocked = item.optBoolean("isLocked", true),
                        category = item.optString("category", "User Apps"),
                        createdAt = item.optLong("createdAt", System.currentTimeMillis()),
                        updatedAt = item.optLong("updatedAt", System.currentTimeMillis())
                    )
                )
            }
        }

        val schedulesArray = root.optJSONArray("schedules") ?: JSONArray()
        val schedules = mutableListOf<LockScheduleEntity>()
        for (i in 0 until schedulesArray.length()) {
            val item = schedulesArray.getJSONObject(i)
            schedules.add(
                LockScheduleEntity(
                    id = item.optLong("id", (i + 1).toLong()),
                    name = item.getString("name"),
                    description = item.optString("description", ""),
                    startHour = item.getInt("startHour").coerceIn(0, 23),
                    startMinute = item.getInt("startMinute").coerceIn(0, 59),
                    endHour = item.getInt("endHour").coerceIn(0, 23),
                    endMinute = item.getInt("endMinute").coerceIn(0, 59),
                    daysOfWeekCsv = item.optString("daysOfWeekCsv", "1,2,3,4,5"),
                    targetPackagesCsv = item.optString("targetPackagesCsv", "*"),
                    applyToAllLockedApps = item.optBoolean("applyToAllLockedApps", true),
                    isEnabled = item.optBoolean("isEnabled", true),
                    createdAtMillis = item.optLong("createdAtMillis", System.currentTimeMillis()),
                    updatedAtMillis = item.optLong("updatedAtMillis", System.currentTimeMillis())
                )
            )
        }

        return BackupConfigurationPayload(
            lockedApps = lockedApps,
            schedules = schedules,
            lockMode = LockMode.fromId(root.optString("lockMode")),
            sessionTimeoutOption = SessionTimeoutOption.fromId(root.optString("sessionTimeoutOption")),
            maxFailedAttempts = root.optInt("maxFailedAttempts", 5).coerceIn(3, 10),
            themePreference = ThemePreference.fromId(root.optString("themePreference")),
            accentColorPreset = AccentColorPreset.fromId(root.optString("accentColorPreset")),
            appListDensity = AppListDensity.fromId(root.optString("appListDensity")),
            appSortOrder = AppSortOrder.fromId(root.optString("appSortOrder")),
            showAppIconOnLockScreen = root.optBoolean("showAppIconOnLockScreen", true),
            showAppNameOnLockScreen = root.optBoolean("showAppNameOnLockScreen", true),
            lockScreenBackgroundStyle = LockScreenBackgroundStyle.fromId(root.optString("lockScreenBackgroundStyle")),
            enableLockScreenAnimations = root.optBoolean("enableLockScreenAnimations", true),
            keypadStyle = KeypadStyle.fromId(root.optString("keypadStyle")),
            languageCode = root.optString("languageCode", "en")
        )
    }

    /**
     * Encrypts [payload] with user-provided [password] and produces a self-contained JSON envelope string
     * ready to be written to an Android Storage Access Framework document stream.
     */
    fun createEncryptedBackupEnvelope(
        payload: BackupConfigurationPayload,
        password: CharArray,
        exportedAtEpochMillis: Long = System.currentTimeMillis()
    ): Result<String> {
        val validationError = validateBackupPassword(password)
        if (validationError != null) {
            return Result.failure(IllegalArgumentException(validationError))
        }

        val plaintextJson = serializePayloadToJson(payload)
        val plaintextBytes = plaintextJson.toByteArray(StandardCharsets.UTF_8)
        val plaintextHash = sha256Hex(plaintextBytes)

        val salt = ByteArray(SALT_BYTES).also { secureRandom.nextBytes(it) }
        val iv = ByteArray(GCM_IV_BYTES).also { secureRandom.nextBytes(it) }
        val secretKey = deriveAes256Key(password, salt, BackupMetadata.PBKDF2_ITERATIONS)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))

        // Bind format magic & version as AEAD Additional Authenticated Data (AAD)
        val aad = "${BackupMetadata.FORMAT_MAGIC}:v${BackupMetadata.CURRENT_FORMAT_VERSION}"
            .toByteArray(StandardCharsets.UTF_8)
        cipher.updateAAD(aad)

        val ciphertextBytes = cipher.doFinal(plaintextBytes)
        val ciphertextHash = sha256Hex(ciphertextBytes)

        val envelope = JSONObject()
        envelope.put("formatMagic", BackupMetadata.FORMAT_MAGIC)
        envelope.put("formatVersion", BackupMetadata.CURRENT_FORMAT_VERSION)
        envelope.put("appVersionName", "2.0.0-production")
        envelope.put("exportedAtEpochMillis", exportedAtEpochMillis)
        envelope.put("kdfAlgorithm", "PBKDF2WithHmacSHA256")
        envelope.put("kdfIterations", BackupMetadata.PBKDF2_ITERATIONS)
        envelope.put("cipherAlgorithm", "AES/GCM/NoPadding")
        envelope.put("lockedAppsCount", payload.lockedApps.count { it.isLocked })
        envelope.put("schedulesCount", payload.schedules.size)
        envelope.put("saltBase64", Base64.getEncoder().encodeToString(salt))
        envelope.put("ivBase64", Base64.getEncoder().encodeToString(iv))
        envelope.put("ciphertextBase64", Base64.getEncoder().encodeToString(ciphertextBytes))
        envelope.put("ciphertextSha256Hex", ciphertextHash)
        envelope.put("plaintextSha256Hex", plaintextHash)

        return Result.success(envelope.toString(2))
    }

    /**
     * Verifies and decrypts an encrypted backup envelope string.
     */
    fun decryptAndVerifyBackupEnvelope(
        envelopeJsonString: String,
        password: CharArray
    ): BackupRestoreResult {
        if (password.isEmpty()) {
            return BackupRestoreResult.Failure(
                RestoreErrorCode.WEAK_OR_EMPTY_PASSWORD,
                "Please enter the backup password used when creating this file."
            )
        }

        val envelope = try {
            JSONObject(envelopeJsonString)
        } catch (_: Exception) {
            return BackupRestoreResult.Failure(
                RestoreErrorCode.INVALID_FORMAT_OR_MAGIC,
                "Selected file is not a valid JSON NEXLOCK backup archive."
            )
        }

        val magic = envelope.optString("formatMagic", "")
        if (magic != BackupMetadata.FORMAT_MAGIC) {
            return BackupRestoreResult.Failure(
                RestoreErrorCode.INVALID_FORMAT_OR_MAGIC,
                "Invalid backup header magic. File is not a NEXLOCK backup."
            )
        }

        val version = envelope.optInt("formatVersion", -1)
        if (version != BackupMetadata.CURRENT_FORMAT_VERSION) {
            return BackupRestoreResult.Failure(
                RestoreErrorCode.UNSUPPORTED_VERSION,
                "Unsupported backup format version ($version). Expected version ${BackupMetadata.CURRENT_FORMAT_VERSION}."
            )
        }

        val iterations = envelope.optInt("kdfIterations", BackupMetadata.PBKDF2_ITERATIONS)
        if (iterations < 100_000 || iterations > 1_000_000) {
            return BackupRestoreResult.Failure(
                RestoreErrorCode.INVALID_FORMAT_OR_MAGIC,
                "Invalid KDF iteration count in backup header."
            )
        }

        val saltBase64 = envelope.optString("saltBase64", "")
        val ivBase64 = envelope.optString("ivBase64", "")
        val ciphertextBase64 = envelope.optString("ciphertextBase64", "")
        val expectedCiphertextHash = envelope.optString("ciphertextSha256Hex", "")
        val expectedPlaintextHash = envelope.optString("plaintextSha256Hex", "")

        if (saltBase64.isBlank() || ivBase64.isBlank() || ciphertextBase64.isBlank() ||
            expectedCiphertextHash.isBlank() || expectedPlaintextHash.isBlank()
        ) {
            return BackupRestoreResult.Failure(
                RestoreErrorCode.INVALID_FORMAT_OR_MAGIC,
                "Backup envelope is missing required cryptographic fields."
            )
        }

        val salt: ByteArray
        val iv: ByteArray
        val ciphertextBytes: ByteArray
        try {
            salt = Base64.getDecoder().decode(saltBase64)
            iv = Base64.getDecoder().decode(ivBase64)
            ciphertextBytes = Base64.getDecoder().decode(ciphertextBase64)
        } catch (_: Exception) {
            return BackupRestoreResult.Failure(
                RestoreErrorCode.INVALID_FORMAT_OR_MAGIC,
                "Corrupted Base64 encoding in backup envelope."
            )
        }

        // 1. Pre-decryption ciphertext SHA-256 integrity verification
        val actualCiphertextHash = sha256Hex(ciphertextBytes)
        if (!actualCiphertextHash.equals(expectedCiphertextHash, ignoreCase = true)) {
            return BackupRestoreResult.Failure(
                RestoreErrorCode.INTEGRITY_HASH_MISMATCH,
                "Backup integrity check failed: Ciphertext SHA-256 digest mismatch (file corrupted or modified)."
            )
        }

        // 2. Authenticated AES-256-GCM decryption
        val plaintextBytes: ByteArray = try {
            val secretKey = deriveAes256Key(password, salt, iterations)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))
            val aad = "${BackupMetadata.FORMAT_MAGIC}:v$version".toByteArray(StandardCharsets.UTF_8)
            cipher.updateAAD(aad)
            cipher.doFinal(ciphertextBytes)
        } catch (_: AEADBadTagException) {
            return BackupRestoreResult.Failure(
                RestoreErrorCode.AUTHENTICATION_FAILED_WRONG_PASSWORD_OR_TAMPERED,
                "Decryption failed: Incorrect backup password or tampered AES-GCM authentication tag."
            )
        } catch (e: Exception) {
            return BackupRestoreResult.Failure(
                RestoreErrorCode.AUTHENTICATION_FAILED_WRONG_PASSWORD_OR_TAMPERED,
                "Decryption error: ${e.message ?: "Unable to decrypt backup payload."}"
            )
        }

        // 3. Post-decryption plaintext SHA-256 verification
        val actualPlaintextHash = sha256Hex(plaintextBytes)
        if (!actualPlaintextHash.equals(expectedPlaintextHash, ignoreCase = true)) {
            return BackupRestoreResult.Failure(
                RestoreErrorCode.INTEGRITY_HASH_MISMATCH,
                "Decrypted payload SHA-256 integrity mismatch."
            )
        }

        // 4. Schema validation & deserialization
        val payload = try {
            val jsonStr = String(plaintextBytes, StandardCharsets.UTF_8)
            deserializePayloadFromJson(jsonStr)
        } catch (e: Exception) {
            return BackupRestoreResult.Failure(
                RestoreErrorCode.MALFORMED_PAYLOAD_JSON,
                "Restored configuration failed schema validation: ${e.message}"
            )
        }

        val metadata = BackupMetadata(
            formatMagic = magic,
            formatVersion = version,
            appVersionName = envelope.optString("appVersionName", "2.0.0-production"),
            exportedAtEpochMillis = envelope.optLong("exportedAtEpochMillis", 0L),
            kdfIterations = iterations,
            lockedAppsCount = payload.lockedApps.count { it.isLocked },
            schedulesCount = payload.schedules.size,
            plaintextSha256Hex = actualPlaintextHash,
            ciphertextSha256Hex = actualCiphertextHash
        )

        return BackupRestoreResult.Success(
            metadata = metadata,
            payload = payload,
            requiresMasterPinVerification = true
        )
    }
}

/**
 * Phase 6 BackupManager & RestoreManager (Section 5).
 *
 * Uses Android's Storage Access Framework (`ContentResolver.openOutputStream` / `openInputStream`)
 * so no broad storage permissions are required on Android 10–14+.
 */
class BackupManager(
    private val encryptionManager: BackupEncryptionManager = BackupEncryptionManager()
) {
    fun exportEncryptedBackupToUri(
        context: Context,
        targetUri: Uri,
        payload: BackupConfigurationPayload,
        password: CharArray
    ): Result<BackupMetadata> {
        val envelopeResult = encryptionManager.createEncryptedBackupEnvelope(payload, password)
        return envelopeResult.fold(
            onSuccess = { envelopeJson ->
                runCatching {
                    val outputStream = context.contentResolver.openOutputStream(targetUri, "wt")
                        ?: throw IllegalStateException("Unable to open Storage Access Framework output stream.")
                    outputStream.use { stream ->
                        stream.write(envelopeJson.toByteArray(StandardCharsets.UTF_8))
                        stream.flush()
                    }
                    val parsed = JSONObject(envelopeJson)
                    BackupMetadata(
                        exportedAtEpochMillis = parsed.getLong("exportedAtEpochMillis"),
                        lockedAppsCount = parsed.getInt("lockedAppsCount"),
                        schedulesCount = parsed.getInt("schedulesCount"),
                        plaintextSha256Hex = parsed.getString("plaintextSha256Hex"),
                        ciphertextSha256Hex = parsed.getString("ciphertextSha256Hex")
                    )
                }
            },
            onFailure = { Result.failure(it) }
        )
    }
}

class RestoreManager(
    private val encryptionManager: BackupEncryptionManager = BackupEncryptionManager()
) {
    fun restoreFromUri(
        context: Context,
        sourceUri: Uri,
        password: CharArray,
        userConfirmedOverwrite: Boolean
    ): BackupRestoreResult {
        if (!userConfirmedOverwrite) {
            return BackupRestoreResult.Failure(
                RestoreErrorCode.CONFIRMATION_REQUIRED,
                "Explicit user confirmation is required before overwriting current protection settings."
            )
        }

        val rawJson = try {
            val inputStream = context.contentResolver.openInputStream(sourceUri)
                ?: return BackupRestoreResult.Failure(
                    RestoreErrorCode.INVALID_FORMAT_OR_MAGIC,
                    "Unable to open backup file stream from Storage Access Framework."
                )
            inputStream.use { stream ->
                stream.readBytes().toString(StandardCharsets.UTF_8)
            }
        } catch (e: Exception) {
            return BackupRestoreResult.Failure(
                RestoreErrorCode.INVALID_FORMAT_OR_MAGIC,
                "Failed to read backup file: ${e.message}"
            )
        }

        return encryptionManager.decryptAndVerifyBackupEnvelope(rawJson, password)
    }
}
