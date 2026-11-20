package com.nexlock.security.intruder

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.ImageProxy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import com.nexlock.security.vault.SecureFileRepository
import java.lang.ref.WeakReference
import java.nio.ByteBuffer
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * Phase 5 IntruderSelfieManager:
 *
 * Implements optional, user-consented front-camera intruder image capture using AndroidX CameraX
 * and encrypts captured bytes immediately with AES-256-GCM via SecureFileRepository.
 *
 * Strict Android Privacy & OS Limitation Compliance:
 * 1. Never activates the camera without explicit user consent (settings.hasExplicitCameraConsent)
 *    AND granted runtime android.permission.CAMERA.
 * 2. Modern Android (API 29+) restricts camera access from background services. Capture is
 *    performed ONLY when a foreground LifecycleOwner (such as AppLockActivity or MainActivity)
 *    is currently in Lifecycle.State.STARTED or RESUMED.
 * 3. If the camera cannot be safely and legally activated in the current state, or if the device
 *    lacks a front camera, returns IntruderCaptureOutcome.Skipped so IntruderDetectionManager
 *    records the failed attempt honestly without crashing or bypassing OS privacy protections.
 * 4. Never records video, never captures during successful authentication, and never uploads images.
 */
class IntruderSelfieManager(
    private val appContext: Context,
    private val secureFileRepository: SecureFileRepository
) : IntruderSelfieCaptureGateway {

    private var foregroundLifecycleRef: WeakReference<LifecycleOwner>? = null

    fun attachForegroundLifecycleOwner(owner: LifecycleOwner) {
        foregroundLifecycleRef = WeakReference(owner)
    }

    fun detachForegroundLifecycleOwner(owner: LifecycleOwner) {
        if (foregroundLifecycleRef?.get() == owner) {
            foregroundLifecycleRef = null
        }
    }

    fun isCameraPermissionGranted(): Boolean {
        return ContextCompat.checkSelfPermission(
            appContext,
            Manifest.permission.CAMERA
        ) == PackageManager.PERMISSION_GRANTED
    }

    fun hasFrontCameraHardware(): Boolean {
        return appContext.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_FRONT)
    }

    override suspend fun captureAndEncryptFrontSelfieIfPermitted(
        settings: IntruderDetectionSettings
    ): IntruderCaptureOutcome {
        if (!settings.intruderSelfieEnabled) {
            return IntruderCaptureOutcome.Skipped("Intruder Selfie feature is disabled in settings.")
        }
        if (!settings.hasExplicitCameraConsent) {
            return IntruderCaptureOutcome.Skipped("Explicit user camera consent has not been granted.")
        }
        if (!isCameraPermissionGranted()) {
            return IntruderCaptureOutcome.Skipped("android.permission.CAMERA is not granted.")
        }
        if (!hasFrontCameraHardware()) {
            return IntruderCaptureOutcome.Skipped("No front-facing camera hardware detected on this device.")
        }

        val lifecycleOwner = foregroundLifecycleRef?.get()
        if (lifecycleOwner == null || !lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
            return IntruderCaptureOutcome.Skipped(
                "Android blocks background camera capture when no foreground Activity lifecycle is active. Recorded intruder event without photo."
            )
        }

        val capturedBytesResult = captureSingleFrontFrameWithCameraX(lifecycleOwner)
        return capturedBytesResult.fold(
            onSuccess = { rawBytes ->
                secureFileRepository.encryptIntruderSelfieBytes(
                    jpegBytes = rawBytes,
                    wipePlaintextAfterEncrypt = true
                ).fold(
                    onSuccess = { encryptedRecord ->
                        IntruderCaptureOutcome.CapturedEncrypted(
                            relativePath = encryptedRecord.relativePath,
                            ivBase64 = encryptedRecord.ivBase64,
                            byteSize = encryptedRecord.ciphertextByteSize
                        )
                    },
                    onFailure = { err ->
                        IntruderCaptureOutcome.Skipped("AES-256-GCM encryption failed: ${err.message}")
                    }
                )
            },
            onFailure = { err ->
                IntruderCaptureOutcome.Skipped("CameraX front capture unavailable: ${err.message}")
            }
        )
    }

    private suspend fun captureSingleFrontFrameWithCameraX(
        lifecycleOwner: LifecycleOwner
    ): Result<ByteArray> = suspendCancellableCoroutine { cont ->
        val cameraProviderFuture = ProcessCameraProvider.getInstance(appContext)
        val mainExecutor = ContextCompat.getMainExecutor(appContext)

        cameraProviderFuture.addListener({
            try {
                val cameraProvider = cameraProviderFuture.get()
                val imageCapture = ImageCapture.Builder()
                    .setCaptureMode(ImageCapture.CAPTURE_MODE_MINIMIZE_LATENCY)
                    .build()

                cameraProvider.unbindAll()
                cameraProvider.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.DEFAULT_FRONT_CAMERA,
                    imageCapture
                )

                imageCapture.takePicture(
                    mainExecutor,
                    object : ImageCapture.OnImageCapturedCallback() {
                        override fun onCaptureSuccess(image: ImageProxy) {
                            val bytes = runCatching {
                                val buffer: ByteBuffer = image.planes[0].buffer
                                val data = ByteArray(buffer.remaining())
                                buffer.get(data)
                                data
                            }
                            image.close()
                            runCatching { cameraProvider.unbindAll() }
                            if (cont.isActive) {
                                cont.resume(bytes)
                            }
                        }

                        override fun onError(exception: ImageCaptureException) {
                            runCatching { cameraProvider.unbindAll() }
                            if (cont.isActive) {
                                cont.resume(Result.failure(exception))
                            }
                        }
                    }
                )
            } catch (e: Exception) {
                if (cont.isActive) {
                    cont.resume(Result.failure(e))
                }
            }
        }, mainExecutor)
    }
}
