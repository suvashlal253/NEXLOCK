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
  evaluateEngineOperationalStatus,
  evaluateForegroundTransition,
  EXCLUDED_SYSTEM_PACKAGES,
  getPackageExclusionReason,
  isPackageExcludedFromLocking,
  MonitoringServiceStateType,
  PackageUnlockSessionRecord,
  PermissionHealthSnapshot,
  RELOCK_DURATION_OPTIONS,
  ReLockDurationId,
} from '../monitoring/appLockEngine';
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
  ENGINE_CFG: 'nexlock_phase4_engine_config_v1',
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

  // Phase 4 Real App Lock Engine & Foreground Monitoring State
  const [permissionHealth, setPermissionHealth] = useState<PermissionHealthSnapshot>({
    usageAccessGranted: true,
    overlayPermissionGranted: true,
    notificationPermissionGranted: true,
  });
  const [monitoringServiceState, setMonitoringServiceState] =
    useState<MonitoringServiceStateType>('RUNNING');
  const [isMonitoringEnabledByUser, setIsMonitoringEnabledByUser] = useState<boolean>(true);
  const [reLockDurationOption, setReLockDurationOption] = useState<ReLockDurationId>('SECONDS_15');
  const [lockOnScreenOff, setLockOnScreenOff] = useState<boolean>(true);
  const [isScreenInteractive, setIsScreenInteractive] = useState<boolean>(true);
  const [currentForegroundPackage, setCurrentForegroundPackage] = useState<string | null>(
    'com.nexlock.security'
  );
  const [activeChallengePackage, setActiveChallengePackage] = useState<string | null>(null);
  const [isChallengeActivityVisible, setIsChallengeActivityVisible] = useState<boolean>(false);
  const [unlockedPackageSessions, setUnlockedPackageSessions] = useState<
    Record<string, PackageUnlockSessionRecord>
  >({});
  const [lastMonitoringEventEpochMillis, setLastMonitoringEventEpochMillis] = useState<number>(
    () => Date.now()
  );

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
      return saved
        ? JSON.parse(saved).filter((r: LockedAppRoomRow) => !isPackageExcludedFromLocking(r.packageName))
        : INITIAL_LOCKED_ROOM_ROWS;
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

  // Phase 3 & 4: Individual App Lock Management (with unique packageName constraint & Safe Exclusion check)
  const toggleAppLock = (packageName: string) => {
    touchSessionActivity();
    const targetApp = apps.find((a) => a.packageName === packageName);
    if (!targetApp) return;

    if (isPackageExcludedFromLocking(packageName)) {
      const reason =
        getPackageExclusionReason(packageName) ??
        'Excluded critical Android system/recovery package.';
      setDiscoveryNotice(`Excluded for Safe Recovery: ${targetApp.appName} (${reason})`);
      return;
    }

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

    if (!nextLocked) {
      setUnlockedPackageSessions((prev) => {
        const copy = { ...prev };
        delete copy[packageName];
        return copy;
      });
    }

    const statusDetail = nextLocked
      ? preferences.pinConfigured
        ? `Protection Configured in Room locked_apps (${packageName}). Active foreground enforcement via AppLockMonitoringService.`
        : `Selected for Protection in Room locked_apps (${packageName}). Create your Master PIN to complete configuration.`
      : `Removed ${packageName} from Room locked_apps table.`;

    setDiscoveryNotice(
      nextLocked
        ? `${targetApp.appName}: ${
            preferences.pinConfigured ? 'Protection Configured' : 'Selected for Protection'
          } (Saved to Room DB).`
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

  // Phase 4: Evaluate Operational Status honestly
  const engineOperationalEvaluation = useMemo(
    () =>
      evaluateEngineOperationalStatus({
        permissions: permissionHealth,
        serviceState: monitoringServiceState,
        isMonitoringEnabledByUser,
        selectedLockedCount: lockedRoomRows.length,
      }),
    [permissionHealth, monitoringServiceState, isMonitoringEnabledByUser, lockedRoomRows.length]
  );

  // Phase 4: Toggle Required Android Special Permissions (Usage Access, Overlay, Notifications)
  const togglePermissionState = (
    key: 'usageAccessGranted' | 'overlayPermissionGranted' | 'notificationPermissionGranted'
  ) => {
    setPermissionHealth((prev) => {
      const nextVal = !prev[key];
      const nextPerms = { ...prev, [key]: nextVal };
      if (!nextPerms.usageAccessGranted || !nextPerms.overlayPermissionGranted) {
        setMonitoringServiceState('STOPPED');
        setDiscoveryNotice(
          'Required permission revoked in Android Settings. AppLockMonitoringService paused automatically.'
        );
        appendEvent(
          'PREF_UPDATED',
          `Permission Revoked (${key}) — Engine Paused`,
          'AppLockMonitoringService stopped because Usage Access or Overlay permission is missing.'
        );
      } else if (isMonitoringEnabledByUser && lockedRoomRows.length > 0) {
        setMonitoringServiceState('RUNNING');
        setDiscoveryNotice(
          'All required permissions granted. AppLockMonitoringService is now Running and Operational.'
        );
        appendEvent(
          'PREF_UPDATED',
          `Permission Granted (${key}) — Engine Active`,
          'Usage Access and Overlay permissions verified; AppLockMonitoringService started.'
        );
      }
      return nextPerms;
    });
  };

  const startMonitoringEngine = () => {
    setIsMonitoringEnabledByUser(true);
    if (!permissionHealth.usageAccessGranted || !permissionHealth.overlayPermissionGranted) {
      setMonitoringServiceState('STOPPED');
      setDiscoveryNotice(
        'Cannot start monitoring: Grant Usage Access and Display Over Other Apps permissions first.'
      );
      setCurrentScreenState('permission_setup');
      return;
    }
    setMonitoringServiceState('RUNNING');
    setDiscoveryNotice('AppLockMonitoringService started. Foreground app protection is Active.');
    appendEvent(
      'PREF_UPDATED',
      'AppLockMonitoringService Started',
      'Foreground service running with adaptive UsageStatsManager polling.'
    );
  };

  const pauseMonitoringEngine = () => {
    setIsMonitoringEnabledByUser(false);
    setMonitoringServiceState('STOPPED');
    setUnlockedPackageSessions({});
    setActiveChallengePackage(null);
    setIsChallengeActivityVisible(false);
    setDiscoveryNotice('Protection paused by user. Selected apps are not currently intercepted.');
    appendEvent(
      'PREF_UPDATED',
      'AppLockMonitoringService Paused by User',
      'Foreground monitoring service stopped and temporary package sessions cleared.'
    );
  };

  // Phase 4: Simulate launching an application into the foreground on the Android device
  const simulateForegroundLaunch = (packageName: string) => {
    const nowElapsed = Math.round(performance.now());
    setLastMonitoringEventEpochMillis(Date.now());

    // If engine is not operational, foreground launch is not intercepted
    if (!engineOperationalEvaluation.isOperational) {
      setCurrentForegroundPackage(packageName);
      setDiscoveryNotice(
        `Opened ${packageName} without interception because App Lock Engine is ${engineOperationalEvaluation.badgeLabel}.`
      );
      return;
    }

    const lockedSet = new Set(lockedRoomRows.filter((r) => r.isLocked).map((r) => r.packageName));
    const evalRes = evaluateForegroundTransition({
      targetPackage: packageName,
      previousForegroundPackage: currentForegroundPackage,
      lockedPackages: lockedSet,
      unlockedSessions: unlockedPackageSessions,
      activeChallengePackage,
      isChallengeActivityVisible,
      reLockOption: reLockDurationOption,
      nowElapsedMillis: nowElapsed,
    });

    setCurrentForegroundPackage(evalRes.nextForegroundPackage);
    setActiveChallengePackage(evalRes.nextActiveChallengePackage);
    setIsChallengeActivityVisible(evalRes.nextChallengeVisible);
    setUnlockedPackageSessions(evalRes.nextSessions);

    const appObj = apps.find((a) => a.packageName === packageName);
    const label = appObj?.appName ?? packageName;

    switch (evalRes.decision.type) {
      case 'ALLOW_EXCLUDED':
        setDiscoveryNotice(`Allowed ${label}: ${evalRes.decision.reason}`);
        break;
      case 'ALLOW_UNPROTECTED':
        setDiscoveryNotice(
          `Foreground transition to ${label} (${packageName}) allowed (Unprotected).`
        );
        break;
      case 'ALLOW_ACTIVE_SESSION':
        setDiscoveryNotice(
          `Foreground transition to ${label} allowed via active unlock session (${reLockDurationOption}).`
        );
        break;
      case 'SUPPRESS_DUPLICATE_CHALLENGE':
        setDiscoveryNotice(
          `Duplicate AppLockActivity launch suppressed for ${label} (already challenging).`
        );
        setCurrentScreenState('auth_screen');
        break;
      case 'REQUIRE_AUTHENTICATION':
        setDiscoveryNotice(
          `AppLockMonitoringService detected protected app "${label}" in foreground -> Launched AppLockActivity!`
        );
        appendEvent(
          'AUTH_LOCKOUT',
          `Intercepted Foreground Launch: ${label}`,
          `UsageStatsManager detected ACTIVITY_RESUMED for ${packageName}; launched AppLockActivity authentication challenge.`,
          packageName
        );
        setCurrentScreenState('auth_screen');
        break;
    }
  };

  const grantPackageChallengeUnlock = (
    packageName: string,
    method: 'MASTER_PIN' | 'BIOMETRIC_PROMPT'
  ) => {
    const nowElapsed = Math.round(performance.now());
    setUnlockedPackageSessions((prev) => ({
      ...prev,
      [packageName]: {
        packageName,
        unlockedAtElapsedMillis: nowElapsed,
        lastForegroundElapsedMillis: nowElapsed,
        backgroundedAtElapsedMillis: null,
        authMethod: method,
      },
    }));
    setActiveChallengePackage(null);
    setIsChallengeActivityVisible(false);
    setCurrentForegroundPackage(packageName);
    const appObj = apps.find((a) => a.packageName === packageName);
    const label = appObj?.appName ?? packageName;
    setDiscoveryNotice(
      `Unlocked ${label} via ${method}. Temporary package session active (${reLockDurationOption}).`
    );
    appendEvent(
      'AUTH_SUCCESS',
      `Unlocked Protected App: ${label} (${method})`,
      `Granted temporary package access session (${reLockDurationOption}).`,
      packageName
    );
  };

  const dismissChallengeToHomeLauncher = () => {
    const challenged = activeChallengePackage;
    setActiveChallengePackage(null);
    setIsChallengeActivityVisible(false);
    setCurrentForegroundPackage('com.google.android.apps.nexuslauncher');
    setDiscoveryNotice(
      challenged
        ? `Canceled authentication for ${challenged}. Navigated safely to Android Home Launcher.`
        : 'Exited to Android Home Launcher.'
    );
    setCurrentScreenState('home');
  };

  const simulateScreenOff = () => {
    setIsScreenInteractive(false);
    setActiveChallengePackage(null);
    setIsChallengeActivityVisible(false);
    if (lockOnScreenOff) {
      setUnlockedPackageSessions({});
      setDiscoveryNotice(
        'ACTION_SCREEN_OFF received: All temporary package unlock sessions revoked immediately.'
      );
      appendEvent(
        'SESSION_LOCKED',
        'Screen Turned Off — Protected Apps Re-Locked',
        'BroadcastReceiver handled Intent.ACTION_SCREEN_OFF and cleared temporary package unlock sessions.'
      );
    } else {
      const nowElapsed = Math.round(performance.now());
      setUnlockedPackageSessions((prev) => {
        const next: Record<string, PackageUnlockSessionRecord> = {};
        for (const [pkg, sess] of Object.entries(prev)) {
          next[pkg] = {
            ...sess,
            backgroundedAtElapsedMillis: sess.backgroundedAtElapsedMillis ?? nowElapsed,
          };
        }
        return next;
      });
      setDiscoveryNotice(
        'ACTION_SCREEN_OFF received: Started background re-lock timers for unlocked apps.'
      );
    }
  };

  const simulateScreenOn = () => {
    setIsScreenInteractive(true);
    setDiscoveryNotice(
      'ACTION_SCREEN_ON / ACTION_USER_PRESENT received: Resumed adaptive UsageStatsManager polling.'
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
      (a) =>
        selectedPackageSet.includes(a.packageName) &&
        a.isInstalled &&
        a.isVisible &&
        !isPackageExcludedFromLocking(a.packageName)
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
    const eligible = apps.filter(
      (a) =>
        a.isLaunchable &&
        a.isInstalled &&
        a.isVisible &&
        !a.isSystemApp &&
        !isPackageExcludedFromLocking(a.packageName)
    );
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
      `Locked all ${eligible.length} eligible user-installed applications after explicit confirmation.`
    );
    appendEvent(
      'BULK_LOCK_UPDATED',
      `Locked All ${eligible.length} Eligible Applications`,
      'User confirmed bulk lock operation; persisted to Room locked_apps (critical system/recovery apps excluded).'
    );
  };

  const unlockAllProtectedApps = () => {
    const count = lockedRoomRows.length;
    setLockedRoomRows([]);
    setUnlockedPackageSessions({});
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
    setPermissionHealth({
      usageAccessGranted: true,
      overlayPermissionGranted: true,
      notificationPermissionGranted: true,
    });
    setMonitoringServiceState('RUNNING');
    setIsMonitoringEnabledByUser(true);
    setReLockDurationOption('SECONDS_15');
    setLockOnScreenOff(true);
    setIsScreenInteractive(true);
    setActiveChallengePackage(null);
    setIsChallengeActivityVisible(false);
    setUnlockedPackageSessions({});
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
    // Phase 4 Engine State & Actions
    permissionHealth,
    togglePermissionState,
    monitoringServiceState,
    isMonitoringEnabledByUser,
    engineOperationalEvaluation,
    reLockDurationOption,
    setReLockDurationOption,
    lockOnScreenOff,
    setLockOnScreenOff,
    isScreenInteractive,
    currentForegroundPackage,
    activeChallengePackage,
    isChallengeActivityVisible,
    unlockedPackageSessions,
    lastMonitoringEventEpochMillis,
    startMonitoringEngine,
    pauseMonitoringEngine,
    simulateForegroundLaunch,
    grantPackageChallengeUnlock,
    dismissChallengeToHomeLauncher,
    simulateScreenOff,
    simulateScreenOn,
    excludedSystemPackages: EXCLUDED_SYSTEM_PACKAGES,
    reLockDurationOptions: RELOCK_DURATION_OPTIONS,
    // Phase 2 Auth State & Actions
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
