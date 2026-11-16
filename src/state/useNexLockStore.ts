import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  INITIAL_DISCOVERED_PACKAGES,
  INITIAL_LOCKED_ROOM_ROWS,
  INITIAL_SECURITY_EVENTS,
  SESSION_TIMEOUT_OPTIONS,
} from '../data/initialData';
import {
  evictCachedPackageIcon,
  mergeDiscoveredAppsWithRoom,
} from '../discovery/appDiscoveryEngine';
import {
  createEncryptedPinEnvelope,
  deriveStandaloneVerifierBase64,
  isKeystoreKeyHealthy,
  PBKDF2_ITERATIONS,
  rotateKeystoreMasterKey,
  setSimulatedKeyInvalidated,
  validatePinStrength,
  verifyEncryptedPinEnvelope,
  verifyStandalonePbkdf2,
} from '../security/cryptoEngine';
import {
  AppFilterTabType,
  BiometricHardwareState,
  InstalledAppRecord,
  LockedAppRoomRow,
  ReLockPolicyId,
  ScreenId,
  SecurityEventEntity,
  SessionTimeoutId,
  ThemeMode,
  UserPreferencesState,
} from '../types/nexlock';

const STORAGE_KEYS = {
  DISCOVERED: 'nexlock_phase3_pm_discovered_v1',
  LOCKED_ROOM: 'nexlock_phase3_room_locked_apps_v1',
  EVENTS: 'nexlock_phase2_room_events_v1',
  PREFS: 'nexlock_phase2_datastore_prefs_v1',
};

const DEFAULT_PREFERENCES: UserPreferencesState = {
  onboardingCompleted: false,
  themeMode: 'dark',
  globalReLockPolicy: 'IMMEDIATELY',
  biometricPreferenceEnabled: true,
  biometricHardwareState: 'AVAILABLE',
  pinLength: 6,
  randomizeKeypad: false,
  hidePinRipple: false,
  draftMasterPinConfigured: false,
  pinConfigured: false,
  pinSaltBase64: null,
  pinVerifierDigestBase64: null,
  pinEncryptedEnvelope: null,
  pbkdf2Iterations: PBKDF2_ITERATIONS,
  failedAttempts: 0,
  maxFailedAttempts: 5,
  lockoutUntilEpochMillis: 0,
  sessionTimeout: 'MINUTE_1',
};

export function useNexLockStore() {
  const [preferences, setPreferences] = useState<UserPreferencesState>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEYS.PREFS);
      return saved ? { ...DEFAULT_PREFERENCES, ...JSON.parse(saved) } : DEFAULT_PREFERENCES;
    } catch {
      return DEFAULT_PREFERENCES;
    }
  });

  // Phase 2 Volatile Session State (Never persisted across process restarts)
  const [isSessionAuthenticated, setIsSessionAuthenticated] = useState<boolean>(false);
  const [lastAuthMethod, setLastAuthMethod] = useState<'MASTER_PIN' | 'BIOMETRIC_PROMPT' | null>(
    null
  );
  const sessionAnchorMonotonicRef = useRef<number | null>(null);
  const [sessionRemainingSeconds, setSessionRemainingSeconds] = useState<number>(0);
  const [lockoutRemainingSeconds, setLockoutRemainingSeconds] = useState<number>(0);
  const [keystoreHealthy, setKeystoreHealthy] = useState<boolean>(() => isKeystoreKeyHealthy());
  const [isCryptoBusy, setIsCryptoBusy] = useState<boolean>(false);

  // Navigation & Filter State
  const [currentScreen, setCurrentScreenState] = useState<ScreenId>('home');
  const [selectedPackageName, setSelectedPackageName] = useState<string>('com.whatsapp');
  const [draftPin, setDraftPin] = useState<string>('');
  const [confirmPinInput, setConfirmPinInput] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('All');
  const [lockFilter, setLockFilter] = useState<AppFilterTabType>('all');

  // Phase 3 Multi-Select & PackageManager Discovery State
  const [isMultiSelectMode, setIsMultiSelectMode] = useState<boolean>(false);
  const [selectedPackageSet, setSelectedPackageSet] = useState<string[]>([]);
  const [requiresBulkLockConfirmation, setRequiresBulkLockConfirmation] = useState<boolean>(false);
  const [isRefreshingPackages, setIsRefreshingPackages] = useState<boolean>(false);
  const [discoveryNotice, setDiscoveryNotice] = useState<string | null>(null);

  const [discoveredPackages, setDiscoveredPackages] = useState<InstalledAppRecord[]>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEYS.DISCOVERED);
      return saved ? JSON.parse(saved) : INITIAL_DISCOVERED_PACKAGES;
    } catch {
      return INITIAL_DISCOVERED_PACKAGES;
    }
  });

  const [lockedRoomRows, setLockedRoomRows] = useState<LockedAppRoomRow[]>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEYS.LOCKED_ROOM);
      return saved ? JSON.parse(saved) : INITIAL_LOCKED_ROOM_ROWS;
    } catch {
      return INITIAL_LOCKED_ROOM_ROWS;
    }
  });

  const [events, setEvents] = useState<SecurityEventEntity[]>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEYS.EVENTS);
      return saved ? JSON.parse(saved) : INITIAL_SECURITY_EVENTS;
    } catch {
      return INITIAL_SECURITY_EVENTS;
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEYS.DISCOVERED, JSON.stringify(discoveredPackages));
    } catch {
      // Ignore storage quota errors
    }
  }, [discoveredPackages]);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEYS.LOCKED_ROOM, JSON.stringify(lockedRoomRows));
    } catch {
      // Ignore storage quota errors
    }
  }, [lockedRoomRows]);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEYS.EVENTS, JSON.stringify(events));
    } catch {
      // Ignore storage quota errors
    }
  }, [events]);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEYS.PREFS, JSON.stringify(preferences));
    } catch {
      // Ignore storage quota errors
    }
  }, [preferences]);

  // Synchronize document.documentElement dark class
  useEffect(() => {
    const root = document.documentElement;
    const applyTheme = (isDark: boolean) => {
      if (isDark) {
        root.classList.add('dark');
      } else {
        root.classList.remove('dark');
      }
    };

    if (preferences.themeMode === 'dark') {
      applyTheme(true);
    } else if (preferences.themeMode === 'light') {
      applyTheme(false);
    } else {
      const media = window.matchMedia('(prefers-color-scheme: dark)');
      applyTheme(media.matches);
      const listener = (e: MediaQueryListEvent) => applyTheme(e.matches);
      media.addEventListener('change', listener);
      return () => media.removeEventListener('change', listener);
    }
  }, [preferences.themeMode]);

  const appendEvent = useCallback(
    (
      eventType: SecurityEventEntity['eventType'],
      title: string,
      detail: string,
      packageName: string | null = null
    ) => {
      const newEvent: SecurityEventEntity = {
        id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        eventType,
        packageName,
        title,
        detail,
        timestampMillis: Date.now(),
      };
      setEvents((prev) => [newEvent, ...prev.slice(0, 99)]);
    },
    []
  );

  // Merge PackageManager discovered packages with Room locked_apps unique rows
  const { mergedApps: apps, uninstalledLockedApps } = useMemo(
    () =>
      mergeDiscoveredAppsWithRoom(
        discoveredPackages,
        lockedRoomRows,
        preferences.pinConfigured
      ),
    [discoveredPackages, lockedRoomRows, preferences.pinConfigured]
  );

  // Monotonic Session & Lockout Cooldown Ticker
  useEffect(() => {
    const interval = setInterval(() => {
      const nowEpoch = Date.now();
      if (preferences.lockoutUntilEpochMillis > nowEpoch) {
        setLockoutRemainingSeconds(
          Math.ceil((preferences.lockoutUntilEpochMillis - nowEpoch) / 1000)
        );
      } else {
        setLockoutRemainingSeconds(0);
      }

      if (isSessionAuthenticated && sessionAnchorMonotonicRef.current !== null) {
        const timeoutOpt =
          SESSION_TIMEOUT_OPTIONS.find((o) => o.id === preferences.sessionTimeout) ||
          SESSION_TIMEOUT_OPTIONS[3];
        if (timeoutOpt.durationMs === 0) {
          setSessionRemainingSeconds(0);
        } else {
          const elapsed = performance.now() - sessionAnchorMonotonicRef.current;
          if (elapsed >= timeoutOpt.durationMs) {
            sessionAnchorMonotonicRef.current = null;
            setIsSessionAuthenticated(false);
            setLastAuthMethod(null);
            setSessionRemainingSeconds(0);
            appendEvent(
              'SESSION_LOCKED',
              'Session Expired Automatically',
              `Monotonic session timeout (${timeoutOpt.label}) reached; re-authentication required.`
            );
          } else {
            setSessionRemainingSeconds(Math.ceil((timeoutOpt.durationMs - elapsed) / 1000));
          }
        }
      } else {
        setSessionRemainingSeconds(0);
      }
    }, 500);

    return () => clearInterval(interval);
  }, [
    isSessionAuthenticated,
    preferences.lockoutUntilEpochMillis,
    preferences.sessionTimeout,
    appendEvent,
  ]);

  const startSession = useCallback((method: 'MASTER_PIN' | 'BIOMETRIC_PROMPT') => {
    sessionAnchorMonotonicRef.current = performance.now();
    setIsSessionAuthenticated(true);
    setLastAuthMethod(method);
  }, []);

  const touchSessionActivity = useCallback(() => {
    if (isSessionAuthenticated && sessionAnchorMonotonicRef.current !== null) {
      sessionAnchorMonotonicRef.current = performance.now();
    }
  }, [isSessionAuthenticated]);

  const lockSessionNow = useCallback(() => {
    sessionAnchorMonotonicRef.current = null;
    setIsSessionAuthenticated(false);
    setLastAuthMethod(null);
    setSessionRemainingSeconds(0);
    appendEvent(
      'SESSION_LOCKED',
      'Session Locked Manually',
      'User invoked explicit session invalidation.'
    );
    setCurrentScreenState('auth_screen');
  }, [appendEvent]);

  const setCurrentScreen = useCallback(
    (target: ScreenId) => {
      touchSessionActivity();
      setCurrentScreenState(target);
    },
    [touchSessionActivity]
  );

  // Phase 2: Create or Update Master PIN
  const createOrUpdateMasterPin = async (
    rawPin: string,
    confirmPin: string
  ): Promise<{ ok: boolean; message: string }> => {
    if (rawPin !== confirmPin) {
      return {
        ok: false,
        message: 'Confirmation PIN does not match the created Master PIN.',
      };
    }

    const strength = validatePinStrength(rawPin, preferences.pinLength);
    if (!strength.valid) {
      return { ok: false, message: strength.reason };
    }

    setIsCryptoBusy(true);
    try {
      const envelope = await createEncryptedPinEnvelope(rawPin, PBKDF2_ITERATIONS);
      const standaloneVerifier = await deriveStandaloneVerifierBase64(
        rawPin,
        envelope.saltBase64,
        PBKDF2_ITERATIONS
      );

      setPreferences((prev) => ({
        ...prev,
        pinConfigured: true,
        draftMasterPinConfigured: true,
        pinLength: envelope.pinLength,
        pinSaltBase64: envelope.saltBase64,
        pinVerifierDigestBase64: standaloneVerifier,
        pinEncryptedEnvelope: envelope,
        pbkdf2Iterations: envelope.iterations,
        failedAttempts: 0,
        lockoutUntilEpochMillis: 0,
      }));

      startSession('MASTER_PIN');
      appendEvent(
        'PIN_CREATED',
        `Master PIN Created (${envelope.pinLength}-Digit PBKDF2-HMAC-SHA256)`,
        `Derived 256-bit verifier with ${envelope.iterations.toLocaleString()} iterations, 128-bit CSPRNG salt, and sealed inside AES-256-GCM Keystore envelope.`
      );
      return {
        ok: true,
        message: 'Master PIN securely derived and sealed in AndroidKeyStore envelope.',
      };
    } catch (err) {
      return {
        ok: false,
        message: err instanceof Error ? err.message : 'Cryptographic derivation failed.',
      };
    } finally {
      setIsCryptoBusy(false);
    }
  };

  // Phase 2: Verify Master PIN
  const verifyMasterPin = async (
    candidatePin: string
  ): Promise<{
    ok: boolean;
    lockedOut?: boolean;
    keyInvalidated?: boolean;
    message: string;
  }> => {
    if (!preferences.pinConfigured || !preferences.pinSaltBase64) {
      return {
        ok: false,
        message: 'No Master PIN is configured yet. Create a Master PIN first.',
      };
    }

    const nowEpoch = Date.now();
    if (preferences.lockoutUntilEpochMillis > nowEpoch) {
      const rem = Math.ceil((preferences.lockoutUntilEpochMillis - nowEpoch) / 1000);
      return {
        ok: false,
        lockedOut: true,
        message: `Temporarily locked due to repeated failed attempts. Try again in ${rem}s.`,
      };
    }

    if (!keystoreHealthy) {
      return {
        ok: false,
        keyInvalidated: true,
        message:
          'AndroidKeyStore key was invalidated (KeyPermanentlyInvalidatedException). Use Keystore Recovery below to rotate the hardware key.',
      };
    }

    setIsCryptoBusy(true);
    try {
      let isMatch = false;

      if (preferences.pinEncryptedEnvelope) {
        const envCheck = await verifyEncryptedPinEnvelope(
          candidatePin,
          preferences.pinEncryptedEnvelope
        );
        if (envCheck.status === 'MATCH') {
          isMatch = true;
        } else if (envCheck.status === 'MISMATCH') {
          isMatch = false;
        } else if (preferences.pinVerifierDigestBase64) {
          isMatch = await verifyStandalonePbkdf2(
            candidatePin,
            preferences.pinSaltBase64,
            preferences.pinVerifierDigestBase64,
            preferences.pbkdf2Iterations
          );
          if (isMatch) {
            const refreshedEnv = await createEncryptedPinEnvelope(
              candidatePin,
              preferences.pbkdf2Iterations
            );
            setPreferences((prev) => ({
              ...prev,
              pinSaltBase64: refreshedEnv.saltBase64,
              pinEncryptedEnvelope: refreshedEnv,
            }));
          }
        }
      } else if (preferences.pinVerifierDigestBase64) {
        isMatch = await verifyStandalonePbkdf2(
          candidatePin,
          preferences.pinSaltBase64,
          preferences.pinVerifierDigestBase64,
          preferences.pbkdf2Iterations
        );
      }

      if (isMatch) {
        setPreferences((prev) => ({
          ...prev,
          failedAttempts: 0,
          lockoutUntilEpochMillis: 0,
        }));
        startSession('MASTER_PIN');
        appendEvent(
          'AUTH_SUCCESS',
          'Master PIN Authentication Succeeded',
          'Verified 256-bit PBKDF2-HMAC-SHA256 digest in constant time and established monotonic session.'
        );
        return {
          ok: true,
          message: 'Master PIN verified. Session authenticated.',
        };
      }

      const nextFailed = preferences.failedAttempts + 1;
      const maxAllowed = Math.max(3, preferences.maxFailedAttempts);

      if (nextFailed >= maxAllowed) {
        const tier = nextFailed - maxAllowed;
        const cooldownMs = tier <= 0 ? 30_000 : tier === 1 ? 60_000 : 300_000;
        const lockoutUntil = Date.now() + cooldownMs;
        const cooldownSec = Math.round(cooldownMs / 1000);

        setPreferences((prev) => ({
          ...prev,
          failedAttempts: nextFailed,
          lockoutUntilEpochMillis: lockoutUntil,
        }));
        setLockoutRemainingSeconds(cooldownSec);

        appendEvent(
          'AUTH_LOCKOUT',
          `Temporary Brute-Force Cooldown Triggered (${cooldownSec}s)`,
          `Failed attempt #${nextFailed} reached threshold (${maxAllowed}). PIN entry paused for ${cooldownSec} seconds.`
        );

        return {
          ok: false,
          lockedOut: true,
          message: `Maximum failed attempts (${maxAllowed}) reached. Temporarily locked for ${cooldownSec}s.`,
        };
      } else {
        const remaining = maxAllowed - nextFailed;
        setPreferences((prev) => ({
          ...prev,
          failedAttempts: nextFailed,
          lockoutUntilEpochMillis: 0,
        }));
        appendEvent(
          'AUTH_FAILED',
          `Incorrect Master PIN Attempt (${nextFailed}/${maxAllowed})`,
          `${remaining} attempt(s) remaining before temporary cooldown.`
        );
        return {
          ok: false,
          message: `Incorrect PIN. ${remaining} attempt(s) remaining before temporary lockout.`,
        };
      }
    } finally {
      setIsCryptoBusy(false);
    }
  };

  // Phase 2: Change Master PIN
  const changeMasterPin = async (
    currentPin: string,
    newPin: string,
    confirmNewPin: string
  ): Promise<{ ok: boolean; message: string }> => {
    const verifyCurrent = await verifyMasterPin(currentPin);
    if (!verifyCurrent.ok) {
      return {
        ok: false,
        message: `Current PIN check failed: ${verifyCurrent.message}`,
      };
    }

    const updateRes = await createOrUpdateMasterPin(newPin, confirmNewPin);
    if (updateRes.ok) {
      appendEvent(
        'PIN_CHANGED',
        'Master PIN Rotated Successfully',
        'Current PIN verified; generated new 128-bit CSPRNG salt and PBKDF2-HMAC-SHA256 verifier.'
      );
    }
    return updateRes;
  };

  const triggerBiometricAuthentication = (
    simulatedOutcome: 'SUCCESS' | 'FAIL_MISMATCH' | 'USER_CANCELED' | 'SENSOR_LOCKOUT'
  ): { ok: boolean; message: string } => {
    if (!preferences.biometricPreferenceEnabled) {
      return {
        ok: false,
        message: 'Biometric authentication is disabled in Security Settings. Use your Master PIN.',
      };
    }

    const hwState = preferences.biometricHardwareState;
    if (hwState === 'NO_HARDWARE') {
      return {
        ok: false,
        message:
          'BIOMETRIC_ERROR_NO_HARDWARE: No fingerprint sensor detected on device. Use Master PIN fallback.',
      };
    }
    if (hwState === 'HARDWARE_UNAVAILABLE') {
      return {
        ok: false,
        message:
          'BIOMETRIC_ERROR_HW_UNAVAILABLE: Biometric sensor is temporarily busy or unavailable. Use Master PIN fallback.',
      };
    }
    if (hwState === 'NONE_ENROLLED') {
      return {
        ok: false,
        message:
          'BIOMETRIC_ERROR_NONE_ENROLLED: No fingerprint enrolled in Android System Settings. Enroll a fingerprint or use Master PIN.',
      };
    }
    if (hwState === 'BIOMETRIC_LOCKOUT' || simulatedOutcome === 'SENSOR_LOCKOUT') {
      appendEvent(
        'AUTH_LOCKOUT',
        'BiometricPrompt Sensor Lockout (ERROR_LOCKOUT)',
        'Android biometric hardware locked after 5 failed sensor reads; Master PIN fallback required.'
      );
      return {
        ok: false,
        message:
          'BiometricPrompt ERROR_LOCKOUT: Too many failed sensor reads. Biometric sensor locked; please authenticate with your Master PIN.',
      };
    }

    if (simulatedOutcome === 'USER_CANCELED') {
      return {
        ok: false,
        message:
          'BiometricPrompt ERROR_USER_CANCELED: Prompt dismissed. Enter your Master PIN to continue.',
      };
    }

    if (simulatedOutcome === 'FAIL_MISMATCH') {
      appendEvent(
        'AUTH_FAILED',
        'BiometricPrompt Fingerprint Not Recognized',
        'onAuthenticationFailed() callback invoked by system sensor; session remains locked.'
      );
      return {
        ok: false,
        message:
          'Fingerprint not recognized by Android BiometricPrompt sensor. Try again or enter Master PIN.',
      };
    }

    setPreferences((prev) => ({
      ...prev,
      failedAttempts: 0,
      lockoutUntilEpochMillis: 0,
    }));
    startSession('BIOMETRIC_PROMPT');
    appendEvent(
      'AUTH_SUCCESS',
      'AndroidX BiometricPrompt Authentication Succeeded',
      'Hardware TEE verified biometric credential and unlocked NEXLOCK session.'
    );
    return {
      ok: true,
      message: 'BiometricPrompt authentication succeeded. Session unlocked.',
    };
  };

  const toggleSimulateKeyInvalidation = async () => {
    if (keystoreHealthy) {
      setSimulatedKeyInvalidated(true);
      setKeystoreHealthy(false);
      appendEvent(
        'KEYSTORE_RECOVERY',
        'Simulated KeyPermanentlyInvalidatedException',
        'AndroidKeyStore AES-256-GCM key marked invalidated.'
      );
    } else {
      const nextVer = await rotateKeystoreMasterKey();
      setKeystoreHealthy(true);
      appendEvent(
        'KEYSTORE_RECOVERY',
        `AndroidKeyStore Master Key Rotated (v${nextVer})`,
        'Provisioned fresh non-exportable AES-256-GCM key in Keystore.'
      );
    }
  };

  // Phase 3: Individual App Lock Management (with unique packageName constraint in locked_apps)
  const toggleAppLock = (packageName: string) => {
    touchSessionActivity();
    const targetApp = apps.find((a) => a.packageName === packageName);
    if (!targetApp) return;

    if (!targetApp.isInstalled || !targetApp.isVisible) {
      setDiscoveryNotice(
        `Cannot enable protection: ${targetApp.appName} is currently uninstalled or restricted.`
      );
      return;
    }

    const nextLocked = !targetApp.isLocked;
    const now = Date.now();

    setLockedRoomRows((prev) => {
      const existing = prev.find((r) => r.packageName === packageName);
      if (nextLocked) {
        const updatedRow: LockedAppRoomRow = {
          id: existing?.id ?? prev.length + 1,
          packageName: targetApp.packageName,
          appName: targetApp.appName,
          isLocked: true,
          category: targetApp.category,
          createdAt: existing?.createdAt ?? now,
          updatedAt: now,
        };
        return [...prev.filter((r) => r.packageName !== packageName), updatedRow];
      } else {
        return prev.filter((r) => r.packageName !== packageName);
      }
    });

    const statusDetail = nextLocked
      ? preferences.pinConfigured
        ? `Protection Configured in Room locked_apps (${packageName}). Active foreground enforcement activates in Phase 4.`
        : `Selected for Protection in Room locked_apps (${packageName}). Create your Master PIN to complete configuration.`
      : `Removed ${packageName} from Room locked_apps table.`;

    setDiscoveryNotice(
      nextLocked
        ? `${targetApp.appName}: ${
            preferences.pinConfigured ? 'Protection Configured' : 'Selected for Protection'
          } (Saved to Room DB; Phase 4 Lock Engine required for OS interception).`
        : `${targetApp.appName} removed from protected list.`
    );

    appendEvent(
      nextLocked ? 'CONFIG_LOCK_ENABLED' : 'CONFIG_LOCK_DISABLED',
      nextLocked
        ? `${targetApp.appName} ${
            preferences.pinConfigured ? 'Protection Configured' : 'Selected for Protection'
          }`
        : `${targetApp.appName} Removed from Protected List`,
      statusDetail,
      packageName
    );
  };

  // Phase 3: Multi-Select & Bulk Lock Management
  const toggleMultiSelectMode = () => {
    setIsMultiSelectMode((prev) => !prev);
    setSelectedPackageSet([]);
  };

  const togglePackageSelection = (packageName: string) => {
    setIsMultiSelectMode(true);
    setSelectedPackageSet((prev) =>
      prev.includes(packageName)
        ? prev.filter((p) => p !== packageName)
        : [...prev, packageName]
    );
  };

  const clearPackageSelection = () => {
    setSelectedPackageSet([]);
  };

  const applyBulkSelectionLock = (targetLocked: boolean) => {
    if (selectedPackageSet.length === 0) return;
    const now = Date.now();
    const targetApps = apps.filter(
      (a) => selectedPackageSet.includes(a.packageName) && a.isInstalled && a.isVisible
    );

    setLockedRoomRows((prev) => {
      if (targetLocked) {
        const nextMap = new Map<string, LockedAppRoomRow>(
          prev.map((r) => [r.packageName, r])
        );
        targetApps.forEach((app, idx) => {
          const existing = nextMap.get(app.packageName);
          nextMap.set(app.packageName, {
            id: existing?.id ?? prev.length + idx + 1,
            packageName: app.packageName,
            appName: app.appName,
            isLocked: true,
            category: app.category,
            createdAt: existing?.createdAt ?? now,
            updatedAt: now,
          });
        });
        return Array.from(nextMap.values());
      } else {
        const removeSet = new Set(targetApps.map((a) => a.packageName));
        return prev.filter((r) => !removeSet.has(r.packageName));
      }
    });

    setDiscoveryNotice(
      targetLocked
        ? `Bulk Lock: Configured ${targetApps.length} selected applications in Room locked_apps.`
        : `Bulk Unlock: Removed ${targetApps.length} selected applications from Room locked_apps.`
    );

    appendEvent(
      'BULK_LOCK_UPDATED',
      targetLocked
        ? `Bulk Locked ${targetApps.length} Selected Applications`
        : `Bulk Unlocked ${targetApps.length} Selected Applications`,
      `Updated ${targetApps.length} rows in Room locked_apps table.`
    );

    setSelectedPackageSet([]);
    setIsMultiSelectMode(false);
  };

  const confirmLockAllEligibleApps = () => {
    setRequiresBulkLockConfirmation(false);
    const eligible = apps.filter((a) => a.isLaunchable && a.isInstalled && a.isVisible);
    const now = Date.now();

    setLockedRoomRows((prev) => {
      const nextMap = new Map<string, LockedAppRoomRow>(
        prev.map((r) => [r.packageName, r])
      );
      eligible.forEach((app, idx) => {
        const existing = nextMap.get(app.packageName);
        nextMap.set(app.packageName, {
          id: existing?.id ?? prev.length + idx + 1,
          packageName: app.packageName,
          appName: app.appName,
          isLocked: true,
          category: app.category,
          createdAt: existing?.createdAt ?? now,
          updatedAt: now,
        });
      });
      return Array.from(nextMap.values());
    });

    setDiscoveryNotice(
      `Locked all ${eligible.length} eligible launchable applications after explicit confirmation.`
    );
    appendEvent(
      'BULK_LOCK_UPDATED',
      `Locked All ${eligible.length} Eligible Applications`,
      'User confirmed bulk lock operation; persisted to Room locked_apps.'
    );
  };

  const unlockAllProtectedApps = () => {
    const count = lockedRoomRows.length;
    setLockedRoomRows([]);
    setDiscoveryNotice(`Unlocked all ${count} previously protected applications.`);
    appendEvent(
      'BULK_LOCK_UPDATED',
      `Unlocked All Applications (${count} Cleared)`,
      'Removed all entries from Room locked_apps table.'
    );
  };

  // Phase 3: Refresh PackageManager Discovery & Simulate Package Change Broadcasts
  const refreshInstalledPackages = () => {
    setIsRefreshingPackages(true);
    setTimeout(() => {
      setDiscoveredPackages((prev) => [...prev]);
      setIsRefreshingPackages(false);
      setDiscoveryNotice(
        `PackageManager scan completed on Dispatchers.IO (${discoveredPackages.length} visible packages verified).`
      );
    }, 280);
  };

  const refreshSinglePackageMetadata = (packageName: string) => {
    evictCachedPackageIcon(packageName);
    setDiscoveredPackages((prev) =>
      prev.map((app) =>
        app.packageName === packageName
          ? { ...app, updatedAtMillis: Date.now() }
          : app
      )
    );
    setDiscoveryNotice(
      `Refreshed PackageManager metadata and Drawable icon cache for ${packageName}.`
    );
  };

  const simulatePackageInstall = () => {
    const candidatePackages: InstalledAppRecord[] = [
      {
        packageName: 'org.telegram.messenger',
        appName: 'Telegram Messenger',
        category: 'Communication',
        androidCategoryCode: 'CATEGORY_SOCIAL',
        versionName: '11.4.2',
        isSystemApp: false,
        isLaunchable: true,
        isLocked: false,
        isVisible: true,
        isInstalled: true,
        hasValidIconResource: true,
        iconDrawableUri: 'drawable://org.telegram.messenger/ic_launcher_adaptive',
        protectionStatus: 'UNPROTECTED',
        allowBiometric: true,
        hideNotificationsPreview: true,
        customReLockPolicy: null,
        createdAtMillis: Date.now(),
        updatedAtMillis: Date.now(),
        accentHex: '#0EA5E9',
      },
      {
        packageName: 'com.1password.android',
        appName: '1Password Vault Manager',
        category: 'Tools',
        androidCategoryCode: 'CATEGORY_PRODUCTIVITY',
        versionName: '8.10.52',
        isSystemApp: false,
        isLaunchable: true,
        isLocked: false,
        isVisible: true,
        isInstalled: true,
        hasValidIconResource: true,
        iconDrawableUri: 'drawable://com.1password.android/ic_launcher_adaptive',
        protectionStatus: 'UNPROTECTED',
        allowBiometric: true,
        hideNotificationsPreview: true,
        customReLockPolicy: 'IMMEDIATELY',
        createdAtMillis: Date.now(),
        updatedAtMillis: Date.now(),
        accentHex: '#3B82F6',
      },
      {
        packageName: 'com.netflix.mediaclient',
        appName: 'Netflix',
        category: 'Entertainment',
        androidCategoryCode: 'CATEGORY_VIDEO',
        versionName: '8.136.0',
        isSystemApp: false,
        isLaunchable: true,
        isLocked: false,
        isVisible: true,
        isInstalled: true,
        hasValidIconResource: true,
        iconDrawableUri: 'drawable://com.netflix.mediaclient/ic_launcher_adaptive',
        protectionStatus: 'UNPROTECTED',
        allowBiometric: true,
        hideNotificationsPreview: false,
        customReLockPolicy: null,
        createdAtMillis: Date.now(),
        updatedAtMillis: Date.now(),
        accentHex: '#E11D48',
      },
    ];

    const existingSet = new Set(discoveredPackages.map((p) => p.packageName));
    const nextPkg = candidatePackages.find((c) => !existingSet.has(c.packageName)) || {
      ...candidatePackages[0],
      packageName: `com.nexlock.custom.app_${discoveredPackages.length + 1}`,
      appName: `New Discovered App ${discoveredPackages.length + 1}`,
    };

    setDiscoveredPackages((prev) =>
      [...prev, nextPkg].sort((a, b) => a.appName.localeCompare(b.appName))
    );
    setDiscoveryNotice(
      `ACTION_PACKAGE_ADDED: Discovered newly installed package ${nextPkg.appName} (${nextPkg.packageName}).`
    );
    appendEvent(
      'PACKAGE_INSTALLED',
      `Package Installed: ${nextPkg.appName}`,
      `PackageChangeReceiver received ACTION_PACKAGE_ADDED for ${nextPkg.packageName} (Category: ${nextPkg.category}).`,
      nextPkg.packageName
    );
  };

  const simulatePackageUninstall = (packageName?: string) => {
    const target =
      discoveredPackages.find((p) => p.packageName === packageName) ||
      discoveredPackages.find((p) => p.isLocked && !p.isSystemApp) ||
      discoveredPackages[0];
    if (!target) return;

    evictCachedPackageIcon(target.packageName);
    setDiscoveredPackages((prev) =>
      prev.filter((p) => p.packageName !== target.packageName)
    );

    const wasProtected = lockedRoomRows.some(
      (r) => r.packageName === target.packageName && r.isLocked
    );

    setDiscoveryNotice(
      wasProtected
        ? `ACTION_PACKAGE_REMOVED: Protected application "${target.appName}" (${target.packageName}) was uninstalled. Marked as Protection Temporarily Unavailable.`
        : `ACTION_PACKAGE_REMOVED: Uninstalled ${target.appName} (${target.packageName}).`
    );

    appendEvent(
      'PACKAGE_UNINSTALLED',
      `Package Uninstalled: ${target.appName}`,
      wasProtected
        ? `Protected package ${target.packageName} was uninstalled from the device. Stale lock policy flagged for review.`
        : `Package ${target.packageName} removed from device.`,
      target.packageName
    );
  };

  const simulatePackageUpdate = (packageName: string) => {
    evictCachedPackageIcon(packageName);
    setDiscoveredPackages((prev) =>
      prev.map((app) => {
        if (app.packageName !== packageName) return app;
        const parts = app.versionName.split('.');
        const lastNum = parseInt(parts[parts.length - 1] || '0', 10);
        const nextVer = [...parts.slice(0, -1), String((isNaN(lastNum) ? 1 : lastNum) + 1)].join(
          '.'
        );
        appendEvent(
          'PACKAGE_UPDATED',
          `Package Updated: ${app.appName} (v${nextVer})`,
          `ACTION_PACKAGE_REPLACED refreshed versionName to ${nextVer} and evicted stale Drawable cache.`,
          app.packageName
        );
        setDiscoveryNotice(
          `ACTION_PACKAGE_REPLACED: Updated ${app.appName} metadata to v${nextVer}.`
        );
        return {
          ...app,
          versionName: nextVer,
          updatedAtMillis: Date.now(),
        };
      })
    );
  };

  const removeStaleUninstalledPackage = (packageName: string, appName: string) => {
    setLockedRoomRows((prev) => prev.filter((r) => r.packageName !== packageName));
    setDiscoveryNotice(`Removed stale lock entry for uninstalled package ${appName}.`);
    appendEvent(
      'CONFIG_LOCK_DISABLED',
      `Cleaned Up Uninstalled Package (${appName})`,
      `Removed stale locked_apps entry for ${packageName}.`,
      packageName
    );
  };

  const updateAppDetails = (
    packageName: string,
    updates: Partial<
      Pick<
        InstalledAppRecord,
        'isLocked' | 'allowBiometric' | 'hideNotificationsPreview' | 'customReLockPolicy'
      >
    >
  ) => {
    touchSessionActivity();
    setDiscoveredPackages((prev) =>
      prev.map((app) => {
        if (app.packageName !== packageName) return app;
        const updated = {
          ...app,
          ...updates,
          updatedAtMillis: Date.now(),
        };
        appendEvent(
          'PREF_UPDATED',
          `Updated Lock Rules for ${app.appName}`,
          `Biometric: ${updated.allowBiometric ? 'Enabled' : 'PIN Only'} · Re-lock: ${
            updated.customReLockPolicy ?? 'Global Default'
          }`,
          app.packageName
        );
        return updated;
      })
    );
  };

  const updatePreferences = (updates: Partial<UserPreferencesState>, logLabel?: string) => {
    touchSessionActivity();
    setPreferences((prev) => {
      const next = { ...prev, ...updates };
      if (logLabel) {
        appendEvent('PREF_UPDATED', logLabel, 'Persisted to Jetpack DataStore.');
      }
      return next;
    });
  };

  const setThemeMode = (themeMode: ThemeMode) => {
    updatePreferences({ themeMode }, `Theme Mode Switched to ${themeMode.toUpperCase()}`);
  };

  const setGlobalReLockPolicy = (globalReLockPolicy: ReLockPolicyId) => {
    updatePreferences(
      { globalReLockPolicy },
      `Global Re-Lock Policy Set to ${globalReLockPolicy}`
    );
  };

  const setSessionTimeout = (sessionTimeout: SessionTimeoutId) => {
    updatePreferences({ sessionTimeout }, `Session Timeout Updated to ${sessionTimeout}`);
  };

  const setBiometricHardwareState = (biometricHardwareState: BiometricHardwareState) => {
    updatePreferences(
      { biometricHardwareState },
      `Biometric Hardware State Set to ${biometricHardwareState}`
    );
  };

  const openAppConfiguration = (packageName: string) => {
    touchSessionActivity();
    setSelectedPackageName(packageName);
    setCurrentScreenState('app_config');
  };

  const clearActivityHistory = () => {
    setEvents([]);
  };

  const resetAllPhase1Data = () => {
    setDiscoveredPackages(INITIAL_DISCOVERED_PACKAGES);
    setLockedRoomRows(INITIAL_LOCKED_ROOM_ROWS);
    setEvents(INITIAL_SECURITY_EVENTS);
    setPreferences(DEFAULT_PREFERENCES);
    setDraftPin('');
    setConfirmPinInput('');
    setSelectedPackageSet([]);
    setIsMultiSelectMode(false);
    setDiscoveryNotice(null);
    sessionAnchorMonotonicRef.current = null;
    setIsSessionAuthenticated(false);
    setLastAuthMethod(null);
    setSimulatedKeyInvalidated(false);
    setKeystoreHealthy(true);
  };

  const selectedApp =
    apps.find((a) => a.packageName === selectedPackageName) ||
    uninstalledLockedApps.find((a) => a.packageName === selectedPackageName) ||
    apps[0];

  return {
    currentScreen,
    setCurrentScreen,
    apps,
    uninstalledLockedApps,
    lockedRoomRows,
    events,
    preferences,
    selectedApp,
    selectedPackageName,
    setSelectedPackageName,
    draftPin,
    setDraftPin,
    confirmPinInput,
    setConfirmPinInput,
    searchQuery,
    setSearchQuery,
    categoryFilter,
    setCategoryFilter,
    lockFilter,
    setLockFilter,
    isMultiSelectMode,
    toggleMultiSelectMode,
    selectedPackageSet,
    togglePackageSelection,
    clearPackageSelection,
    applyBulkSelectionLock,
    requiresBulkLockConfirmation,
    setRequiresBulkLockConfirmation,
    confirmLockAllEligibleApps,
    unlockAllProtectedApps,
    isRefreshingPackages,
    refreshInstalledPackages,
    refreshSinglePackageMetadata,
    simulatePackageInstall,
    simulatePackageUninstall,
    simulatePackageUpdate,
    removeStaleUninstalledPackage,
    discoveryNotice,
    setDiscoveryNotice,
    isSessionAuthenticated,
    lastAuthMethod,
    sessionRemainingSeconds,
    lockoutRemainingSeconds,
    keystoreHealthy,
    isCryptoBusy,
    createOrUpdateMasterPin,
    verifyMasterPin,
    changeMasterPin,
    triggerBiometricAuthentication,
    lockSessionNow,
    touchSessionActivity,
    toggleSimulateKeyInvalidation,
    toggleAppLock,
    updateAppDetails,
    updatePreferences,
    setThemeMode,
    setGlobalReLockPolicy,
    setSessionTimeout,
    setBiometricHardwareState,
    openAppConfiguration,
    clearActivityHistory,
    resetAllPhase1Data,
    appendEvent,
  };
}

export type NexLockStore = ReturnType<typeof useNexLockStore>;
