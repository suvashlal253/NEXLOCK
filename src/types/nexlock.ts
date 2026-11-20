import { EncryptedPinEnvelope } from '../security/cryptoEngine';

export type ScreenId =
  | 'splash'
  | 'onboarding'
  | 'create_pin'
  | 'confirm_pin'
  | 'change_pin'
  | 'biometric_setup'
  | 'permission_setup'
  | 'home'
  | 'apps'
  | 'app_config'
  | 'auth_screen'
  | 'vault'
  | 'security_activity'
  | 'security_settings'
  | 'theme_settings'
  | 'about';

export type BottomNavTab = 'home' | 'apps' | 'vault' | 'security_activity' | 'security_settings';

export type ThemeMode = 'dark' | 'light' | 'system';

export type ReLockPolicyId = 'IMMEDIATELY' | 'SCREEN_OFF' | 'AFTER_1_MIN' | 'AFTER_5_MIN';

export type SessionTimeoutId =
  | 'IMMEDIATELY'
  | 'SECONDS_15'
  | 'SECONDS_30'
  | 'MINUTE_1'
  | 'MINUTES_5';

export type BiometricHardwareState =
  | 'AVAILABLE'
  | 'NONE_ENROLLED'
  | 'NO_HARDWARE'
  | 'HARDWARE_UNAVAILABLE'
  | 'BIOMETRIC_LOCKOUT';

/**
 * 10 automatic categories required by NEXLOCK Phase 3 Section 3.
 */
export type AppCategoryType =
  | 'Social Media'
  | 'Communication'
  | 'Entertainment'
  | 'Finance'
  | 'Shopping'
  | 'Productivity'
  | 'Games'
  | 'Photography'
  | 'Tools'
  | 'Other';

/**
 * 4 filter tabs required by NEXLOCK Phase 3 Section 4.C.
 */
export type AppFilterTabType = 'all' | 'locked' | 'unlocked' | 'system';

/**
 * Explicit protection state distinction required by NEXLOCK Phase 3 Section 5.
 */
export type ProtectionStatusType =
  | 'UNPROTECTED'
  | 'SELECTED_FOR_PROTECTION'
  | 'PROTECTION_CONFIGURED'
  | 'PROTECTION_ENGINE_ACTIVE'
  | 'PROTECTION_TEMPORARILY_UNAVAILABLE';

/**
 * Room locked_apps entity row (unique index on packageName, never stores Drawable).
 */
export interface LockedAppRoomRow {
  id: number;
  packageName: string;
  appName: string;
  isLocked: boolean;
  category: AppCategoryType;
  createdAt: number;
  updatedAt: number;
}

/**
 * InstalledApp domain model combining PackageManager metadata and Room lock state.
 */
export interface InstalledAppRecord {
  packageName: string;
  appName: string;
  category: AppCategoryType;
  androidCategoryCode: string;
  versionName: string;
  isSystemApp: boolean;
  isLaunchable: boolean;
  isLocked: boolean;
  isVisible: boolean;
  isInstalled: boolean;
  hasValidIconResource: boolean;
  iconDrawableUri: string | null;
  protectionStatus: ProtectionStatusType;
  allowBiometric: boolean;
  hideNotificationsPreview: boolean;
  customReLockPolicy: ReLockPolicyId | null;
  createdAtMillis: number;
  updatedAtMillis: number;
  accentHex: string;
}

export type ProtectedAppEntity = InstalledAppRecord;

export interface SessionTimeoutOption {
  id: SessionTimeoutId;
  label: string;
  shortLabel: string;
  durationMs: number;
  description: string;
}

export interface ReLockPolicyOption {
  id: ReLockPolicyId;
  label: string;
  shortLabel: string;
  description: string;
}

export type SecurityEventSeverity = 'INFO' | 'WARNING' | 'CRITICAL';

export interface SecurityEventEntity {
  id: string;
  eventType:
    | 'PHASE1_INIT'
    | 'PHASE2_AUTH'
    | 'PHASE3_DISCOVERY'
    | 'CONFIG_LOCK_ENABLED'
    | 'CONFIG_LOCK_DISABLED'
    | 'BULK_LOCK_UPDATED'
    | 'PACKAGE_INSTALLED'
    | 'PACKAGE_UPDATED'
    | 'PACKAGE_UNINSTALLED'
    | 'PREF_UPDATED'
    | 'PIN_CREATED'
    | 'PIN_CHANGED'
    | 'AUTH_SUCCESS'
    | 'UNLOCK_SUCCESS'
    | 'AUTH_FAILED'
    | 'FAILED_PIN'
    | 'FAILED_BIOMETRIC'
    | 'AUTH_LOCKOUT'
    | 'INTRUDER_DETECTED'
    | 'INTRUDER_THRESHOLD_REACHED'
    | 'INTRUDER_IMAGE_CAPTURED'
    | 'INTRUDER_SELFIE_CAPTURED'
    | 'INTRUDER_IMAGES_DELETED'
    | 'QUICK_LOCK_EXECUTED'
    | 'QUICK_LOCK_TRIGGERED'
    | 'PERMISSION_REVOKED'
    | 'VAULT_FILE_ENCRYPTED'
    | 'VAULT_FILE_IMPORTED'
    | 'VAULT_FILE_DELETED'
    | 'SENSITIVE_SETTING_CHANGED'
    | 'LOGS_CLEARED'
    | 'SESSION_LOCKED'
    | 'SESSION_EXPIRED'
    | 'KEYSTORE_RECOVERY'
    | 'ONBOARDING_COMPLETED';
  packageName: string | null;
  authenticationMethod?: 'MASTER_PIN' | 'BIOMETRIC_PROMPT' | null;
  severity?: SecurityEventSeverity;
  metadata?: string;
  title: string;
  detail: string;
  timestampMillis: number;
}

export interface UserPreferencesState {
  onboardingCompleted: boolean;
  themeMode: ThemeMode;
  globalReLockPolicy: ReLockPolicyId;
  biometricPreferenceEnabled: boolean;
  biometricHardwareState: BiometricHardwareState;
  pinLength: 4 | 6;
  randomizeKeypad: boolean;
  hidePinRipple: boolean;
  draftMasterPinConfigured: boolean;
  pinConfigured: boolean;
  pinSaltBase64: string | null;
  pinVerifierDigestBase64: string | null;
  pinEncryptedEnvelope: EncryptedPinEnvelope | null;
  pbkdf2Iterations: number;
  failedAttempts: number;
  maxFailedAttempts: number;
  lockoutUntilEpochMillis: number;
  sessionTimeout: SessionTimeoutId;
}

export interface PermissionExplanation {
  id: string;
  title: string;
  androidConstant: string;
  whyNeeded: string;
  osLimitationNote: string;
  targetPhase: string;
  statusLabel: string;
}

export interface ScreenDefinition {
  id: ScreenId;
  number: number;
  title: string;
  group: 'Setup & Onboarding' | 'Core Protection' | 'Vault & Audit' | 'Configuration';
  bottomTab?: BottomNavTab;
  summary: string;
}
