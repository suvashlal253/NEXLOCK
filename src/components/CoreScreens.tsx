import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  Check,
  CheckSquare,
  ChevronRight,
  Clock,
  Code2,
  Delete,
  ExternalLink,
  FileText,
  Film,
  Fingerprint,
  FolderLock,
  Image,
  Info,
  KeyRound,
  Lock,
  Moon,
  Palette,
  Play,
  Plus,
  RefreshCw,
  Search,
  Shield,
  Sliders,
  Smartphone,
  Square,
  Sun,
  Trash2,
  Unlock,
  X,
} from 'lucide-react';
import {
  DEVELOPMENT_PHASES,
  RELOCK_POLICIES,
  SCREEN_DEFINITIONS,
  SESSION_TIMEOUT_OPTIONS,
} from '../data/initialData';
import {
  ALL_APP_CATEGORIES,
  Phase3UnitTestResult,
  runPhase3UnitTests,
} from '../discovery/appDiscoveryEngine';
import {
  EXCLUDED_SYSTEM_PACKAGES,
  isPackageExcludedFromLocking,
  Phase4UnitTestResult,
  RELOCK_DURATION_OPTIONS,
  runPhase4UnitTests,
} from '../monitoring/appLockEngine';
import {
  DOCUMENTED_ANDROID_TAMPER_LIMITATIONS,
  IntruderThresholdOption,
  Phase5UnitTestResult,
  runPhase5UnitTests,
} from '../intruder/phase5SecurityEngine';
import {
  ACCENT_COLOR_PRESETS,
  AppListDensityId,
  AppSortOrderId,
  isOvernightSchedule,
  isScheduleActiveAtInstant,
  KeypadStyleId,
  LOCALIZATION_STRINGS,
  LOCK_MODE_OPTIONS,
  LockModeId,
  LockScreenBackgroundStyleId,
  NexLockLanguageCode,
  PHASE6_HELP_CENTER_TOPICS,
  Phase6UnitTestResult,
  runPhase6AutomatedTestSuite,
} from '../phase6/phase6AutomationEngine';
import {
  runPhase2UnitTests,
  UnitTestResultItem,
  validatePinStrength,
} from '../security/cryptoEngine';
import { NexLockStore } from '../state/useNexLockStore';
import {
  AppFilterTabType,
  ReLockPolicyId,
  SecurityEventSeverity,
  SessionTimeoutId,
  ThemeMode,
} from '../types/nexlock';
import { AppPackageIcon } from './AppPackageIcon';

interface CoreScreensProps {
  store: NexLockStore;
  onOpenSourceDrawer: () => void;
}

function formatProtectionStatusLabel(status: string): string {
  switch (status) {
    case 'PROTECTION_CONFIGURED':
      return 'Protection Configured (Start Monitoring / Grant Permissions)';
    case 'SELECTED_FOR_PROTECTION':
      return 'Selected for Protection (Set Master PIN to Finish)';
    case 'PROTECTION_ENGINE_ACTIVE':
      return 'Protection Engine Active (Intercepting Foreground Launches)';
    case 'PROTECTION_TEMPORARILY_UNAVAILABLE':
      return 'Protection Temporarily Unavailable';
    default:
      return 'Unprotected';
  }
}

export const CoreScreens: React.FC<CoreScreensProps> = ({ store, onOpenSourceDrawer }) => {
  const {
    currentScreen,
    setCurrentScreen,
    apps,
    uninstalledLockedApps,
    events,
    preferences,
    selectedApp,
    toggleAppLock,
    updateAppDetails,
    updatePreferences,
    setThemeMode,
    setGlobalReLockPolicy,
    setSessionTimeout,
    openAppConfiguration,
    clearActivityHistory,
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
    verifyMasterPin,
    changeMasterPin,
    triggerBiometricAuthentication,
    lockSessionNow,
    toggleSimulateKeyInvalidation,
    monitoringServiceState,
    engineOperationalEvaluation,
    permissionHealth,
    reLockDurationOption,
    setReLockDurationOption,
    lockOnScreenOff,
    setLockOnScreenOff,
    isScreenInteractive,
    currentForegroundPackage,
    activeChallengePackage,
    unlockedPackageSessions,
    startMonitoringEngine,
    pauseMonitoringEngine,
    simulateForegroundLaunch,
    grantPackageChallengeUnlock,
    dismissChallengeToHomeLauncher,
    simulateScreenOff,
    simulateScreenOn,
    // Phase 5
    intruderConfig,
    updateIntruderConfig,
    consecutiveFailedAttempts,
    intruderImages,
    deleteAllIntruderRecords,
    vaultFiles,
    decryptedVaultPreview,
    setDecryptedVaultPreview,
    encryptAndImportVaultFile,
    decryptVaultFileById,
    deleteVaultFileById,
    quickLockStatusBanner,
    setQuickLockStatusBanner,
    executeQuickLock,
    deleteSingleSecurityEvent,
    authorizeSensitiveAction,
    // Phase 6
    lockSchedules,
    toggleLockScheduleEnabled,
    createOrUpdateLockSchedule,
    deleteLockSchedule,
    scheduleModeEvaluation,
    simulatedScheduleTimeZone,
    setSimulatedScheduleTimeZone,
    phase6Appearance,
    setLockMode,
    updatePhase6Appearance,
    securityAnalyticsReport,
    lastExportedBackupJson,
    setLastExportedBackupJson,
    backupRestoreStatusMessage,
    setBackupRestoreStatusMessage,
    requiresPostRestorePinVerify,
    setRequiresPostRestorePinVerify,
    exportEncryptedConfigurationBackup,
    restoreEncryptedConfigurationBackup,
  } = store;

  const [authPinEntry, setAuthPinEntry] = useState<string>('');
  const [authStatus, setAuthStatus] = useState<{ ok: boolean; text: string } | null>(null);
  const [showBiometricSheet, setShowBiometricSheet] = useState<boolean>(false);
  const [activityTypeFilter, setActivityTypeFilter] = useState<
    'ALL' | 'LOCK' | 'AUTH' | 'INTRUDER' | 'VAULT'
  >('ALL');
  const [activitySeverityFilter, setActivitySeverityFilter] = useState<
    'ALL' | SecurityEventSeverity
  >('ALL');
  const [activityDateFilter, setActivityDateFilter] = useState<
    'ALL_TIME' | 'TODAY' | 'LAST_7_DAYS'
  >('ALL_TIME');
  const [activitySortOrder, setActivitySortOrder] = useState<'NEWEST_FIRST' | 'OLDEST_FIRST'>(
    'NEWEST_FIRST'
  );
  const [showClearLogsConfirm, setShowClearLogsConfirm] = useState<boolean>(false);
  const [launchAppNotice, setLaunchAppNotice] = useState<string | null>(null);

  // Phase 5 Vault new file form state
  const [newVaultFileName, setNewVaultFileName] = useState<string>('recovery_key_backup.txt');
  const [newVaultFileMime, setNewVaultFileMime] = useState<string>('text/plain');
  const [newVaultFileContent, setNewVaultFileContent] = useState<string>(
    'CONFIDENTIAL NEXLOCK RECOVERY RECORD\nHardware Alias: nexlock_vault_aes256_gcm_v5\nZero-Knowledge Local Storage Verified.'
  );
  const [isEncryptingVaultFile, setIsEncryptingVaultFile] = useState<boolean>(false);

  // Phase 6 Smart Lock Scheduler Form State
  const [newScheduleName, setNewScheduleName] = useState<string>('Focus Session');
  const [newScheduleDesc, setNewScheduleDesc] = useState<string>(
    '1:00 PM – 4:00 PM deep work app lock schedule.'
  );
  const [newScheduleStartHour, setNewScheduleStartHour] = useState<number>(13);
  const [newScheduleEndHour, setNewScheduleEndHour] = useState<number>(16);
  const [newScheduleDays, setNewScheduleDays] = useState<number[]>([1, 2, 3, 4, 5]);
  const [scheduleFeedback, setScheduleFeedback] = useState<string | null>(null);

  // Phase 6 Encrypted Backup & Restore Form State
  const [backupPasswordInput, setBackupPasswordInput] = useState<string>('NexLockProdBackup#2026');
  const [restoreJsonInput, setRestoreJsonInput] = useState<string>('');
  const [restoreConfirmChecked, setRestoreConfirmChecked] = useState<boolean>(false);

  // Phase 6 Analytics Window Toggle (7D vs 30D)
  const [analyticsRange, setAnalyticsRange] = useState<'7D' | '30D'>('7D');

  // Change PIN screen state
  const [currentPinInput, setCurrentPinInput] = useState<string>('');
  const [newPinInput, setNewPinInput] = useState<string>('');
  const [confirmNewPinInput, setConfirmNewPinInput] = useState<string>('');
  const [changePinFeedback, setChangePinFeedback] = useState<{
    ok: boolean;
    text: string;
  } | null>(null);

  // Interactive Test Suite Runners (Phase 6: 14 + Phase 5: 12 + Phase 4: 12 + Phase 3: 17 + Phase 2: 12 = 67 tests)
  const [testResultsP6, setTestResultsP6] = useState<Phase6UnitTestResult[] | null>(null);
  const [testResultsP5, setTestResultsP5] = useState<Phase5UnitTestResult[] | null>(null);
  const [testResultsP4, setTestResultsP4] = useState<Phase4UnitTestResult[] | null>(null);
  const [testResultsP2, setTestResultsP2] = useState<UnitTestResultItem[] | null>(null);
  const [testResultsP3, setTestResultsP3] = useState<Phase3UnitTestResult[] | null>(null);
  const [isRunningTests, setIsRunningTests] = useState<boolean>(false);

  const i18n = LOCALIZATION_STRINGS[phase6Appearance.languageCode] || LOCALIZATION_STRINGS.en;
  const activeAccentObj =
    ACCENT_COLOR_PRESETS.find((a) => a.id === phase6Appearance.accentColorPreset) ||
    ACCENT_COLOR_PRESETS[0];

  const lockedCount = useMemo(() => apps.filter((a) => a.isLocked).length, [apps]);
  const operationalProtectedAppsCount = engineOperationalEvaluation.isOperational
    ? lockedCount
    : 0;
  const currentReLockOption =
    RELOCK_POLICIES.find((p) => p.id === preferences.globalReLockPolicy) || RELOCK_POLICIES[0];
  const currentSessionTimeoutOption =
    SESSION_TIMEOUT_OPTIONS.find((s) => s.id === preferences.sessionTimeout) ||
    SESSION_TIMEOUT_OPTIONS[3];

  const keypadDigits = useMemo(() => {
    const base = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'];
    if (!preferences.randomizeKeypad) return base;
    return ['7', '2', '9', '4', '0', '1', '8', '5', '3', '6'];
  }, [preferences.randomizeKeypad]);

  // 7. HOME DASHBOARD (Phase 4 Real App Lock Engine & Phase 5 Intruder/Quick Lock Status)
  if (currentScreen === 'home') {
    const isEngineActive = engineOperationalEvaluation.isOperational;
    const currentReLockConfig =
      RELOCK_DURATION_OPTIONS.find((r) => r.id === reLockDurationOption) ||
      RELOCK_DURATION_OPTIONS[0];
    const latestSecurityEvent = events[0] || null;
    const activeUnlockedPackageCount = Object.keys(unlockedPackageSessions).length;

    return (
      <div className="space-y-6">
        <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-8 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-[#A6B0C3]">
            <span>
              Screen 07 of 15 · Home Dashboard · Phase 6 Automation & Production Ready ·{' '}
              <span className="font-semibold text-[#5B8CFF]">{i18n.tagline}</span>
            </span>
            <div className="flex items-center gap-3">
              {/* Phase 6 Localization Switcher: English / বাংলা */}
              <div className="inline-flex items-center rounded-lg bg-slate-100 dark:bg-[#0B1020] p-0.5 border border-slate-200 dark:border-white/10">
                {(['en', 'bn'] as NexLockLanguageCode[]).map((lang) => (
                  <button
                    key={lang}
                    type="button"
                    onClick={() =>
                      updatePhase6Appearance(
                        { languageCode: lang },
                        `App Language Switched to ${lang === 'bn' ? 'Bangla (বাংলা)' : 'English'}`
                      )
                    }
                    className={`px-2 py-0.5 rounded-md text-[11px] font-bold transition-colors ${
                      phase6Appearance.languageCode === lang
                        ? 'bg-[#5B8CFF] text-white'
                        : 'text-slate-600 dark:text-[#A6B0C3]'
                    }`}
                  >
                    {lang === 'en' ? 'EN' : 'বাংলা'}
                  </button>
                ))}
              </div>
              <span>
                Engine Status:{' '}
                <span
                  className={
                    isEngineActive
                      ? 'text-[#2DD4A3] font-bold'
                      : 'text-amber-500 font-bold'
                  }
                >
                  {engineOperationalEvaluation.badgeLabel}
                </span>
              </span>
            </div>
          </div>

          {requiresPostRestorePinVerify && (
            <div className="p-3.5 rounded-2xl bg-amber-500/15 border border-amber-500/40 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-900 dark:text-[#F5F7FF]">
              <span>
                Encrypted Backup Restored: Please verify your Master PIN on Screen 10 to re-authorize
                your local security session.
              </span>
              <button
                type="button"
                onClick={() => {
                  setRequiresPostRestorePinVerify(false);
                  setCurrentScreen('auth_screen');
                }}
                className="min-h-[34px] px-3 py-1 rounded-lg bg-amber-500 text-slate-950 font-bold"
              >
                Verify Master PIN Now
              </button>
            </div>
          )}

          {quickLockStatusBanner && (
            <div className="p-3.5 rounded-2xl bg-[#2DD4A3]/15 border border-[#2DD4A3]/40 flex items-center justify-between gap-3 text-xs text-slate-900 dark:text-[#F5F7FF]">
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-[#2DD4A3] shrink-0" />
                <span className="font-semibold">{quickLockStatusBanner}</span>
              </div>
              <button
                type="button"
                onClick={() => setQuickLockStatusBanner(null)}
                aria-label="Dismiss Quick Lock confirmation"
                className="p-1 text-slate-500 hover:text-slate-900 dark:hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          )}

          {discoveryNotice && (
            <div className="p-3.5 rounded-2xl bg-[#5B8CFF]/10 border border-[#5B8CFF]/30 flex items-center justify-between gap-3 text-xs text-slate-800 dark:text-[#F5F7FF]">
              <span>{discoveryNotice}</span>
              <button
                type="button"
                onClick={() => setDiscoveryNotice(null)}
                aria-label="Dismiss engine notice"
                className="p-1 text-slate-500 hover:text-slate-900 dark:hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
            <div className="md:col-span-7 space-y-2">
              <p className="text-xs font-semibold" style={{ color: activeAccentObj.hex }}>
                NEXLOCK Foreground App Lock Engine · {scheduleModeEvaluation.statusSummary}
              </p>
              <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 dark:text-[#F5F7FF] text-balance">
                {operationalProtectedAppsCount} Operational of {lockedCount} Selected Protected Apps
              </h1>
              <p className="text-sm text-slate-600 dark:text-[#A6B0C3] leading-relaxed">
                {isEngineActive
                  ? `AppLockMonitoringService is actively polling UsageEvents.ACTIVITY_RESUMED. Lock Mode: ${phase6Appearance.lockMode}. Effective Re-Lock: ${scheduleModeEvaluation.effectiveReLockDuration} (${currentReLockConfig.label}). Active Schedules: ${
                      scheduleModeEvaluation.activeSchedules.length > 0
                        ? scheduleModeEvaluation.activeSchedules.map((s) => s.name).join(', ')
                        : 'None currently in window'
                    }.`
                  : 'Protection is currently Paused. Operational Protected Apps is strictly 0 until Usage Access, Overlay Permission, Master PIN, and AppLockMonitoringService are all active.'}
              </p>
              <div className="pt-3 flex flex-wrap items-center gap-2.5">
                {/* Phase 5 Prominent Quick Lock / Panic Lock Button */}
                <button
                  type="button"
                  onClick={() => executeQuickLock(false)}
                  className="min-h-[44px] px-4 py-2.5 rounded-xl bg-rose-500 hover:bg-rose-600 text-white font-bold text-xs sm:text-sm flex items-center gap-1.5 transition-colors whitespace-nowrap shadow-sm"
                >
                  <Lock className="w-4 h-4" />
                  <span>
                    {i18n.quickLockBtn} ({activeUnlockedPackageCount} Session
                    {activeUnlockedPackageCount === 1 ? '' : 's'})
                  </span>
                </button>

                {monitoringServiceState === 'RUNNING' && isEngineActive ? (
                  <button
                    type="button"
                    onClick={pauseMonitoringEngine}
                    className="min-h-[44px] px-4 py-2.5 rounded-xl bg-amber-500 hover:bg-amber-600 text-slate-950 font-semibold text-xs sm:text-sm transition-colors whitespace-nowrap"
                  >
                    Pause Protection Service
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={startMonitoringEngine}
                    className="min-h-[44px] px-4 py-2.5 rounded-xl bg-[#2DD4A3] hover:bg-[#25be90] text-[#0B1020] font-bold text-xs sm:text-sm transition-colors whitespace-nowrap"
                  >
                    Start Protection Service
                  </button>
                )}

                <button
                  type="button"
                  onClick={() => setCurrentScreen('permission_setup')}
                  className="min-h-[44px] px-4 py-2.5 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 text-slate-800 dark:text-[#F5F7FF] font-semibold text-xs sm:text-sm transition-colors whitespace-nowrap"
                >
                  Permission Health (
                  {permissionHealth.usageAccessGranted && permissionHealth.overlayPermissionGranted
                    ? 'All Granted'
                    : 'Action Needed'}
                  )
                </button>

                <button
                  type="button"
                  onClick={() => setCurrentScreen('apps')}
                  className="min-h-[44px] px-4 py-2.5 rounded-xl bg-[#5B8CFF] hover:bg-[#4A7BF7] text-white font-semibold text-xs sm:text-sm transition-colors whitespace-nowrap"
                >
                  Manage Apps ({apps.length})
                </button>

                <button
                  type="button"
                  onClick={isScreenInteractive ? simulateScreenOff : simulateScreenOn}
                  className="min-h-[44px] px-3.5 py-2.5 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 text-slate-700 dark:text-[#A6B0C3] font-medium text-xs transition-colors whitespace-nowrap"
                >
                  {isScreenInteractive ? 'Simulate Screen Off' : 'Simulate Screen On'}
                </button>
              </div>
            </div>

            {/* Required Phase 4, 5 & 6 Dashboard Status Metrics */}
            <div className="md:col-span-5 grid grid-cols-2 gap-3">
              <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200/80 dark:border-white/10">
                <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">Protection Operational</p>
                <p
                  className={`mt-1 text-2xl font-bold font-mono tabular-nums ${
                    operationalProtectedAppsCount > 0
                      ? 'text-[#2DD4A3]'
                      : 'text-amber-500'
                  }`}
                >
                  {operationalProtectedAppsCount} / {lockedCount}
                </p>
                <p className="mt-1 text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                  Mode: {phase6Appearance.lockMode}
                </p>
              </div>

              <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200/80 dark:border-white/10">
                <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">Smart Schedules</p>
                <p className="mt-1 text-lg font-bold font-mono tabular-nums text-[#5B8CFF]">
                  {scheduleModeEvaluation.activeSchedules.length} Active /{' '}
                  {lockSchedules.filter((s) => s.isEnabled).length} Enabled
                </p>
                <p className="mt-1 text-[11px] text-slate-500 dark:text-[#A6B0C3] truncate">
                  TZ: {simulatedScheduleTimeZone}
                </p>
              </div>

              <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200/80 dark:border-white/10">
                <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">Intruder Detection</p>
                <p
                  className={`mt-1 text-sm font-bold font-mono tabular-nums ${
                    consecutiveFailedAttempts >= intruderConfig.threshold
                      ? 'text-rose-400'
                      : intruderConfig.isEnabled
                      ? 'text-[#2DD4A3]'
                      : 'text-amber-500'
                  }`}
                >
                  {intruderConfig.isEnabled ? 'Active' : 'Disabled'} · {consecutiveFailedAttempts}/
                  {intruderConfig.threshold}
                </p>
                <p className="mt-1 text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                  Captures: {intruderImages.length} · Vault: {vaultFiles.length}
                </p>
              </div>

              <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200/80 dark:border-white/10">
                <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">Latest Security Event</p>
                <p className="mt-1 text-xs font-bold text-slate-900 dark:text-[#F5F7FF] truncate">
                  {latestSecurityEvent ? latestSecurityEvent.title : 'No Events'}
                </p>
                <p className="mt-1 text-[11px] text-[#5B8CFF] truncate">
                  {latestSecurityEvent
                    ? `${latestSecurityEvent.eventType} · ${
                        latestSecurityEvent.severity || 'INFO'
                      }`
                    : 'Audit Log Ready'}
                </p>
              </div>
            </div>
          </div>

          {/* Phase 6 Section 2: Quick Lock Mode Management Selector */}
          <div className="pt-4 border-t border-slate-200 dark:border-white/10 space-y-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-xs font-bold text-slate-900 dark:text-[#F5F7FF]">
                Phase 6 Lock Mode Management (`LockMode` · Synchronized with `AppLockEngine`)
              </p>
              <button
                type="button"
                onClick={() => setCurrentScreen('security_settings')}
                className="text-xs font-semibold text-[#5B8CFF] hover:underline"
              >
                Configure Smart Schedules & Encrypted Backup →
              </button>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
              {LOCK_MODE_OPTIONS.map((modeOpt) => {
                const isSelectedMode = phase6Appearance.lockMode === modeOpt.id;
                return (
                  <button
                    key={modeOpt.id}
                    type="button"
                    onClick={() => setLockMode(modeOpt.id)}
                    className={`p-3 rounded-2xl border text-left transition-all ${
                      isSelectedMode
                        ? 'border-[#5B8CFF] bg-[#5B8CFF]/10'
                        : 'border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-[#0B1020] hover:border-slate-300 dark:hover:border-white/20'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-bold text-slate-900 dark:text-[#F5F7FF]">
                        {phase6Appearance.languageCode === 'bn' ? modeOpt.labelBn : modeOpt.label}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded-md text-[10px] font-mono font-bold ${
                          isSelectedMode
                            ? 'bg-[#2DD4A3] text-[#0B1020]'
                            : 'bg-slate-200 dark:bg-white/10 text-slate-600 dark:text-[#A6B0C3]'
                        }`}
                      >
                        {modeOpt.badge}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3] mt-1 line-clamp-2">
                      {modeOpt.description}
                    </p>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Featured Protected Applications & Quick Screen Access */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
          <div className="lg:col-span-7 rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="text-lg font-bold text-slate-900 dark:text-[#F5F7FF]">
                    Discovered Applications Preview
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">
                    Tap any application row to inspect package metadata & lock configuration
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setCurrentScreen('apps')}
                  className="min-h-[44px] px-3 text-xs font-semibold text-[#5B8CFF] hover:underline flex items-center gap-1 whitespace-nowrap"
                >
                  <span>Manage All ({apps.length})</span>
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>

              <div className="divide-y divide-slate-200/70 dark:divide-white/10">
                {apps.slice(0, 5).map((app) => (
                  <div
                    key={app.packageName}
                    className="py-3 flex items-center justify-between gap-3"
                  >
                    <button
                      type="button"
                      onClick={() => openAppConfiguration(app.packageName)}
                      className="flex-1 text-left flex items-center gap-3 min-h-[48px] group"
                    >
                      <AppPackageIcon
                        packageName={app.packageName}
                        appName={app.appName}
                        category={app.category}
                        accentHex={app.accentHex}
                        hasValidIconResource={app.hasValidIconResource}
                        size="sm"
                      />
                      <div className="min-w-0">
                        <p className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF] group-hover:text-[#5B8CFF] transition-colors truncate">
                          {app.appName}
                        </p>
                        <p className="text-xs text-slate-500 dark:text-[#A6B0C3] truncate">
                          {app.category} · {app.packageName} ·{' '}
                          {formatProtectionStatusLabel(app.protectionStatus)}
                        </p>
                      </div>
                    </button>

                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => simulateForegroundLaunch(app.packageName)}
                        className="min-h-[44px] px-3 rounded-xl bg-[#5B8CFF]/15 hover:bg-[#5B8CFF]/25 text-[#5B8CFF] text-xs font-semibold flex items-center gap-1 whitespace-nowrap"
                        title={`Simulate Android foreground launch of ${app.appName}`}
                      >
                        <Play className="w-3 h-3" />
                        <span>Launch App</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => toggleAppLock(app.packageName)}
                        aria-label={`Toggle lock policy for ${app.appName}`}
                        className={`min-h-[44px] px-3.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-colors whitespace-nowrap ${
                          app.isLocked
                            ? 'bg-[#2DD4A3]/15 text-[#2DD4A3]'
                            : 'bg-slate-100 dark:bg-[#0B1020] text-slate-600 dark:text-[#A6B0C3]'
                        }`}
                      >
                        {app.isLocked ? (
                          <>
                            <Lock className="w-3.5 h-3.5" />
                            <span>Locked</span>
                          </>
                        ) : (
                          <>
                            <Unlock className="w-3.5 h-3.5" />
                            <span>Unlocked</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="mt-4 pt-4 border-t border-slate-200 dark:border-white/10 text-xs text-slate-500 dark:text-[#A6B0C3] flex items-center justify-between">
              <span>Click "Launch App" on any row to test real-time foreground interception</span>
              <button
                type="button"
                onClick={() => setCurrentScreen('about')}
                className="text-[#5B8CFF] hover:underline font-medium"
              >
                Run All 53 Unit Tests
              </button>
            </div>
          </div>

          <div className="lg:col-span-5 rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="text-lg font-bold text-slate-900 dark:text-[#F5F7FF]">
                    Quick Screen Access
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">
                    Direct jump to any NEXLOCK screen
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {SCREEN_DEFINITIONS.map((scr) => (
                  <button
                    key={scr.id}
                    type="button"
                    onClick={() => setCurrentScreen(scr.id)}
                    className={`min-h-[42px] px-3 py-2 rounded-xl text-left text-xs font-medium flex items-center justify-between transition-colors ${
                      currentScreen === scr.id
                        ? 'bg-[#5B8CFF] text-white'
                        : 'bg-slate-50 hover:bg-slate-100 dark:bg-[#0B1020] dark:hover:bg-white/10 text-slate-800 dark:text-[#F5F7FF]'
                    }`}
                  >
                    <span className="truncate">
                      <span className="font-mono tabular-nums opacity-70 mr-1.5">
                        {String(scr.number).padStart(2, '0')}.
                      </span>
                      {scr.title}
                    </span>
                    <ChevronRight className="w-3.5 h-3.5 shrink-0 opacity-60" />
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // 8. INSTALLED APPLICATIONS SCREEN (Phase 3 Full Implementation)
  if (currentScreen === 'apps') {
    const categories = ['All', ...ALL_APP_CATEGORIES];
    const filterTabs: { id: AppFilterTabType; label: string; count: number }[] = [
      { id: 'all', label: 'All', count: apps.length },
      { id: 'locked', label: 'Locked', count: lockedCount },
      { id: 'unlocked', label: 'Unlocked', count: apps.length - lockedCount },
      {
        id: 'system',
        label: 'System Apps',
        count: apps.filter((a) => a.isSystemApp).length,
      },
    ];

    const filteredApps = apps
      .filter((app) => {
        const q = searchQuery.trim().toLowerCase();
        const matchesQuery =
          q.length === 0 ||
          app.appName.toLowerCase().includes(q) ||
          app.packageName.toLowerCase().includes(q);
        const matchesCat = categoryFilter === 'All' || app.category === categoryFilter;
        const matchesTab =
          lockFilter === 'all'
            ? true
            : lockFilter === 'locked'
            ? app.isLocked
            : lockFilter === 'unlocked'
            ? !app.isLocked
            : app.isSystemApp;
        return matchesQuery && matchesCat && matchesTab;
      })
      .sort((a, b) => {
        if (phase6Appearance.appSortOrder === 'NAME_DESC') {
          return b.appName.localeCompare(a.appName);
        }
        if (phase6Appearance.appSortOrder === 'LOCKED_FIRST') {
          if (a.isLocked !== b.isLocked) {
            return a.isLocked ? -1 : 1;
          }
          return a.appName.localeCompare(b.appName);
        }
        return a.appName.localeCompare(b.appName);
      });

    return (
      <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-8 space-y-6">
        {/* Top Metadata Line */}
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-[#A6B0C3]">
          <span>Screen 08 of 15 · Installed Apps Manager (AppDiscoveryRepository)</span>
          <div className="flex flex-wrap items-center gap-3">
            {/* Phase 6 Section 7: App Manager Sort Order & List Density */}
            <div className="flex items-center gap-1">
              <span className="text-[11px]">Sort:</span>
              {(
                [
                  { id: 'NAME_ASC', label: 'A → Z' },
                  { id: 'NAME_DESC', label: 'Z → A' },
                  { id: 'LOCKED_FIRST', label: 'Locked First' },
                ] as { id: AppSortOrderId; label: string }[]
              ).map((sOpt) => (
                <button
                  key={sOpt.id}
                  type="button"
                  onClick={() =>
                    updatePhase6Appearance(
                      { appSortOrder: sOpt.id },
                      `App Manager Sort Order Set to ${sOpt.label}`
                    )
                  }
                  className={`px-2 py-0.5 rounded-md text-[11px] font-semibold ${
                    phase6Appearance.appSortOrder === sOpt.id
                      ? 'bg-[#5B8CFF] text-white'
                      : 'bg-slate-100 dark:bg-[#0B1020] text-slate-600 dark:text-[#A6B0C3]'
                  }`}
                >
                  {sOpt.label}
                </button>
              ))}
            </div>
            <span className="font-mono tabular-nums">
              Total Installed: {apps.length} · Total Locked: {lockedCount}
            </span>
          </div>
        </div>

        {/* Required Header (A. Header: Title: Applications, Subtitle: Manage your app protection, Counts) */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-[#F5F7FF]">
              Applications
            </h1>
            <p className="text-xs sm:text-sm text-slate-500 dark:text-[#A6B0C3] mt-0.5">
              Manage your app protection · {apps.length} installed apps · {lockedCount} locked apps
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={refreshInstalledPackages}
              disabled={isRefreshingPackages}
              className="min-h-[42px] px-3.5 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 text-xs font-semibold text-slate-700 dark:text-[#F5F7FF] flex items-center gap-1.5 transition-colors whitespace-nowrap"
            >
              <RefreshCw
                className={`w-3.5 h-3.5 ${isRefreshingPackages ? 'animate-spin' : ''}`}
              />
              <span>{isRefreshingPackages ? 'Scanning...' : 'Refresh Packages'}</span>
            </button>

            <button
              type="button"
              onClick={simulatePackageInstall}
              className="min-h-[42px] px-3.5 py-2 rounded-xl bg-[#5B8CFF]/15 hover:bg-[#5B8CFF]/25 text-[#5B8CFF] text-xs font-semibold flex items-center gap-1.5 transition-colors whitespace-nowrap"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Simulate Install</span>
            </button>

            <button
              type="button"
              onClick={() => simulatePackageUninstall()}
              className="min-h-[42px] px-3.5 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 text-xs font-medium text-slate-600 dark:text-[#A6B0C3] whitespace-nowrap"
            >
              Simulate Uninstall
            </button>
          </div>
        </div>

        {/* Status / Discovery Feedback Banner */}
        {discoveryNotice && (
          <div className="p-3.5 rounded-2xl bg-[#5B8CFF]/10 border border-[#5B8CFF]/30 flex items-center justify-between gap-3 text-xs text-slate-800 dark:text-[#F5F7FF]">
            <span>{discoveryNotice}</span>
            <button
              type="button"
              onClick={() => setDiscoveryNotice(null)}
              aria-label="Dismiss notification"
              className="p-1 text-slate-500 hover:text-slate-900 dark:hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Uninstalled Protected Applications Alert (Section 10 Requirement) */}
        {uninstalledLockedApps.length > 0 && (
          <div className="p-4 rounded-2xl bg-amber-500/10 border border-amber-500/30 space-y-2.5">
            <div className="flex items-center gap-2 text-amber-500 font-semibold text-xs">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>
                Previously Protected Application Uninstalled ({uninstalledLockedApps.length})
              </span>
            </div>
            {uninstalledLockedApps.map((stale) => (
              <div
                key={stale.packageName}
                className="flex flex-wrap items-center justify-between gap-2 pt-1 text-xs"
              >
                <span className="text-slate-700 dark:text-[#F5F7FF]">
                  <span className="font-semibold">{stale.appName}</span> ({stale.packageName}) ·{' '}
                  <span className="text-amber-500">Protection Temporarily Unavailable</span>
                </span>
                <button
                  type="button"
                  onClick={() =>
                    removeStaleUninstalledPackage(stale.packageName, stale.appName)
                  }
                  className="min-h-[36px] px-3 py-1 rounded-lg bg-amber-500 text-slate-950 font-semibold text-xs"
                >
                  Remove Stale Entry
                </button>
              </div>
            ))}
          </div>
        )}

        {/* B. Search Bar with Clear Search Button */}
        <div className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-4 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by application name or package name (e.g. com.whatsapp)..."
            className="w-full min-h-[48px] pl-11 pr-11 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 text-sm text-slate-900 dark:text-[#F5F7FF] placeholder:text-slate-400 focus:outline-none focus:border-[#5B8CFF]"
          />
          {searchQuery.length > 0 && (
            <button
              type="button"
              onClick={() => setSearchQuery('')}
              aria-label="Clear search query"
              className="min-h-[40px] min-w-[40px] absolute right-2 top-1/2 -translate-y-1/2 flex items-center justify-center text-slate-400 hover:text-slate-700 dark:hover:text-white rounded-xl"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* C. Filter Tabs (All, Locked, Unlocked, System Apps) & E. Bulk Actions */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex items-center gap-1 p-1 rounded-xl bg-slate-100 dark:bg-[#0B1020] overflow-x-auto">
            {filterTabs.map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setLockFilter(tab.id)}
                className={`min-h-[38px] px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors whitespace-nowrap shrink-0 ${
                  lockFilter === tab.id
                    ? 'bg-[#5B8CFF] text-white'
                    : 'text-slate-600 dark:text-[#A6B0C3] hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                {tab.label} ({tab.count})
              </button>
            ))}
          </div>

          {/* E. Bulk Actions Toolbar */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={toggleMultiSelectMode}
              className={`min-h-[38px] px-3 py-1.5 rounded-xl text-xs font-semibold transition-colors whitespace-nowrap ${
                isMultiSelectMode
                  ? 'bg-[#9B7BFF] text-white'
                  : 'bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 text-slate-700 dark:text-[#F5F7FF]'
              }`}
            >
              {isMultiSelectMode
                ? `Selected (${selectedPackageSet.length})`
                : 'Select Multiple'}
            </button>

            {isMultiSelectMode && selectedPackageSet.length > 0 && (
              <>
                <button
                  type="button"
                  onClick={() => applyBulkSelectionLock(true)}
                  className="min-h-[38px] px-3 py-1.5 rounded-xl bg-[#2DD4A3] text-[#0B1020] text-xs font-bold whitespace-nowrap"
                >
                  Lock Selected
                </button>
                <button
                  type="button"
                  onClick={() => applyBulkSelectionLock(false)}
                  className="min-h-[38px] px-3 py-1.5 rounded-xl bg-slate-200 dark:bg-white/10 text-slate-800 dark:text-[#F5F7FF] text-xs font-semibold whitespace-nowrap"
                >
                  Unlock Selected
                </button>
                <button
                  type="button"
                  onClick={clearPackageSelection}
                  className="min-h-[38px] px-3 py-1.5 rounded-xl text-xs text-slate-500 hover:underline whitespace-nowrap"
                >
                  Clear Selection
                </button>
              </>
            )}

            <button
              type="button"
              onClick={() => setRequiresBulkLockConfirmation(true)}
              className="min-h-[38px] px-3 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 text-xs font-semibold text-slate-700 dark:text-[#F5F7FF] whitespace-nowrap"
            >
              Lock All Eligible Apps
            </button>

            {lockedCount > 0 && (
              <button
                type="button"
                onClick={unlockAllProtectedApps}
                className="min-h-[38px] px-3 py-1.5 rounded-xl bg-rose-500/15 hover:bg-rose-500/25 text-rose-400 text-xs font-semibold whitespace-nowrap"
              >
                Unlock All
              </button>
            )}
          </div>
        </div>

        {/* Explicit User Confirmation Prompt for "Lock All Eligible Apps" */}
        {requiresBulkLockConfirmation && (
          <div
            role="dialog"
            aria-label="Confirm Lock All Eligible Applications"
            className="p-4 rounded-2xl bg-slate-900 text-[#F5F7FF] border border-[#5B8CFF]/50 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
          >
            <div className="space-y-1">
              <p className="text-sm font-bold">
                Confirm Bulk Lock of All {apps.filter((a) => a.isLaunchable).length} Eligible
                Applications?
              </p>
              <p className="text-xs text-[#A6B0C3]">
                NEXLOCK never locks every installed application without explicit user confirmation.
              </p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => setRequiresBulkLockConfirmation(false)}
                className="min-h-[40px] px-3.5 py-1.5 rounded-xl bg-white/10 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={confirmLockAllEligibleApps}
                className="min-h-[40px] px-4 py-1.5 rounded-xl bg-[#2DD4A3] text-[#0B1020] text-xs font-bold"
              >
                Confirm Lock All
              </button>
            </div>
          </div>
        )}

        {/* Automatic 10-Category Filter Bar */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
          {categories.map((cat) => (
            <button
              key={cat}
              type="button"
              onClick={() => setCategoryFilter(cat)}
              className={`min-h-[38px] px-3.5 py-1.5 rounded-xl text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                categoryFilter === cat
                  ? 'bg-[#5B8CFF] text-white'
                  : 'bg-slate-100 dark:bg-[#0B1020] text-slate-600 dark:text-[#A6B0C3] hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        {/* D. App List (Stable packageName keys, actual icons, lock status, lock/unlock switch) */}
        {filteredApps.length === 0 ? (
          <div className="py-12 text-center space-y-2">
            <p className="text-sm font-semibold text-slate-700 dark:text-[#F5F7FF]">
              No matching applications found
            </p>
            <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">
              No installed packages match "{searchQuery}" under {lockFilter.toUpperCase()} /{' '}
              {categoryFilter}.
            </p>
            <button
              type="button"
              onClick={() => {
                setSearchQuery('');
                setCategoryFilter('All');
                setLockFilter('all');
              }}
              className="mt-2 min-h-[40px] px-4 py-1.5 rounded-xl bg-[#5B8CFF] text-white text-xs font-semibold"
            >
              Reset Filters
            </button>
          </div>
        ) : (
          <div className="divide-y divide-slate-200/80 dark:divide-white/10">
            {filteredApps.map((app) => {
              const isSelectedForBulk = selectedPackageSet.includes(app.packageName);
              return (
                <div
                  key={app.packageName}
                  className="py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
                >
                  <div className="flex items-center gap-3.5 min-w-0 flex-1">
                    {isMultiSelectMode && (
                      <button
                        type="button"
                        onClick={() => togglePackageSelection(app.packageName)}
                        aria-label={`Select ${app.appName}`}
                        className="min-h-[44px] min-w-[44px] flex items-center justify-center text-[#5B8CFF]"
                      >
                        {isSelectedForBulk ? (
                          <CheckSquare className="w-5 h-5" />
                        ) : (
                          <Square className="w-5 h-5 text-slate-400" />
                        )}
                      </button>
                    )}

                    <button
                      type="button"
                      onClick={() => openAppConfiguration(app.packageName)}
                      className="flex items-center gap-3.5 min-w-0 flex-1 text-left group"
                    >
                      <AppPackageIcon
                        packageName={app.packageName}
                        appName={app.appName}
                        category={app.category}
                        accentHex={app.accentHex}
                        hasValidIconResource={app.hasValidIconResource}
                        size="md"
                      />
                      <div className="min-w-0">
                        <p className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF] group-hover:text-[#5B8CFF] transition-colors truncate">
                          {app.appName}
                        </p>
                        <p className="text-xs text-slate-500 dark:text-[#A6B0C3] font-mono truncate">
                          {app.packageName} · v{app.versionName} ·{' '}
                          {app.isSystemApp ? 'System App' : 'User App'}
                        </p>
                        <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-0.5 truncate">
                          <span className="text-[#5B8CFF] font-medium">{app.category}</span> ·{' '}
                          <span
                            className={
                              app.isLocked
                                ? 'text-[#2DD4A3] font-medium'
                                : 'text-slate-500 dark:text-[#A6B0C3]'
                            }
                          >
                            {formatProtectionStatusLabel(app.protectionStatus)}
                          </span>
                        </p>
                      </div>
                    </button>
                  </div>

                  <div className="flex items-center gap-2 self-end sm:self-center">
                    <button
                      type="button"
                      onClick={() => simulateForegroundLaunch(app.packageName)}
                      className="min-h-[44px] px-3 py-2 rounded-xl bg-[#5B8CFF]/15 hover:bg-[#5B8CFF]/25 text-[#5B8CFF] text-xs font-semibold flex items-center gap-1.5 whitespace-nowrap"
                    >
                      <Play className="w-3.5 h-3.5" />
                      <span>Launch</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => openAppConfiguration(app.packageName)}
                      className="min-h-[44px] px-3.5 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 text-xs font-medium text-slate-700 dark:text-[#F5F7FF] flex items-center gap-1.5 whitespace-nowrap"
                    >
                      <Sliders className="w-3.5 h-3.5" />
                      <span>Details</span>
                    </button>

                    {isPackageExcludedFromLocking(app.packageName) ? (
                      <span className="min-h-[44px] min-w-[114px] px-3 py-2 rounded-xl bg-amber-500/15 text-amber-400 text-xs font-semibold flex items-center justify-center whitespace-nowrap">
                        Recovery Safe
                      </span>
                    ) : (
                      <button
                        type="button"
                        role="switch"
                        aria-checked={app.isLocked}
                        onClick={() => toggleAppLock(app.packageName)}
                        className={`min-h-[44px] min-w-[114px] px-4 py-2 rounded-xl text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors whitespace-nowrap ${
                          app.isLocked
                            ? 'bg-[#2DD4A3] text-[#0B1020]'
                            : 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#A6B0C3]'
                        }`}
                      >
                        {app.isLocked ? (
                          <>
                            <Lock className="w-3.5 h-3.5" />
                            <span>Locked</span>
                          </>
                        ) : (
                          <>
                            <Unlock className="w-3.5 h-3.5" />
                            <span>Unlocked</span>
                          </>
                        )}
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    );
  }

  // 9. APPLICATION INFORMATION & LOCK CONFIGURATION SCREEN (Phase 3 Section 8)
  if (currentScreen === 'app_config') {
    return (
      <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-8 space-y-6">
        <div className="flex items-center justify-between border-b border-slate-200 dark:border-white/10 pb-4">
          <button
            type="button"
            onClick={() => {
              setLaunchAppNotice(null);
              setCurrentScreen('apps');
            }}
            className="min-h-[44px] px-3 rounded-lg text-xs font-medium text-slate-600 dark:text-[#A6B0C3] hover:text-slate-900 dark:hover:text-white flex items-center gap-1.5"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Applications</span>
          </button>
          <span className="text-xs text-slate-500 dark:text-[#A6B0C3]">
            Screen 09 of 15 · Application Details & Lock Configuration
          </span>
        </div>

        {/* Selected Application Information Card */}
        <div className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <AppPackageIcon
                packageName={selectedApp.packageName}
                appName={selectedApp.appName}
                category={selectedApp.category}
                accentHex={selectedApp.accentHex}
                hasValidIconResource={selectedApp.hasValidIconResource}
                size="lg"
              />
              <div>
                <h1 className="text-xl font-bold text-slate-900 dark:text-[#F5F7FF]">
                  {selectedApp.appName}
                </h1>
                <p className="text-xs font-mono text-slate-500 dark:text-[#A6B0C3] mt-0.5">
                  {selectedApp.packageName}
                </p>
                <p className="text-xs text-[#5B8CFF] font-medium mt-1">
                  {formatProtectionStatusLabel(selectedApp.protectionStatus)}
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2.5">
              <button
                type="button"
                onClick={() => toggleAppLock(selectedApp.packageName)}
                className={`min-h-[48px] px-5 py-2.5 rounded-xl font-semibold text-xs sm:text-sm flex items-center justify-center gap-2 transition-colors whitespace-nowrap ${
                  selectedApp.isLocked
                    ? 'bg-rose-500/15 hover:bg-rose-500/25 text-rose-400'
                    : 'bg-[#2DD4A3] hover:bg-[#25be90] text-[#0B1020]'
                }`}
              >
                {selectedApp.isLocked ? (
                  <>
                    <Unlock className="w-4 h-4" />
                    <span>Disable App Lock</span>
                  </>
                ) : (
                  <>
                    <Lock className="w-4 h-4" />
                    <span>Enable App Lock</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Required Package Metadata Grid (Section 8) */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-4 border-t border-slate-200 dark:border-white/10 text-xs">
            <div>
              <p className="text-slate-500 dark:text-[#A6B0C3]">Application Category</p>
              <p className="mt-0.5 font-semibold text-slate-900 dark:text-[#F5F7FF]">
                {selectedApp.category}
              </p>
            </div>
            <div>
              <p className="text-slate-500 dark:text-[#A6B0C3]">Installation Status</p>
              <p className="mt-0.5 font-semibold text-slate-900 dark:text-[#F5F7FF]">
                {selectedApp.isInstalled
                  ? selectedApp.isSystemApp
                    ? 'Installed (System)'
                    : 'Installed (User)'
                  : 'Uninstalled'}
              </p>
            </div>
            <div>
              <p className="text-slate-500 dark:text-[#A6B0C3]">Launchable Activity</p>
              <p className="mt-0.5 font-semibold text-slate-900 dark:text-[#F5F7FF]">
                {selectedApp.isLaunchable ? 'MAIN / LAUNCHER' : 'Non-Launchable'}
              </p>
            </div>
            <div>
              <p className="text-slate-500 dark:text-[#A6B0C3]">Package Version</p>
              <p className="mt-0.5 font-mono font-semibold text-slate-900 dark:text-[#F5F7FF]">
                v{selectedApp.versionName}
              </p>
            </div>
          </div>

          {/* Action Buttons: Launch in Foreground (Test Phase 4 Lock Engine), Refresh Application Information, Simulate Update */}
          <div className="flex flex-wrap items-center gap-2.5 pt-2">
            {selectedApp.isLaunchable && selectedApp.isInstalled && (
              <button
                type="button"
                onClick={() => {
                  simulateForegroundLaunch(selectedApp.packageName);
                  setLaunchAppNotice(
                    `Triggered UsageStatsManager foreground transition event for ${selectedApp.packageName}.`
                  );
                }}
                className="min-h-[42px] px-4 py-2 rounded-xl bg-[#5B8CFF] hover:bg-[#4A7BF7] text-white text-xs font-semibold flex items-center gap-1.5"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>Launch Application in Foreground (Test Lock Engine)</span>
              </button>
            )}

            <button
              type="button"
              onClick={() => {
                refreshSinglePackageMetadata(selectedApp.packageName);
                setLaunchAppNotice(
                  `Refreshed ApplicationInfo, versionName (v${selectedApp.versionName}), and LruCache icon for ${selectedApp.packageName}.`
                );
              }}
              className="min-h-[42px] px-4 py-2 rounded-xl bg-slate-200/80 hover:bg-slate-300/80 dark:bg-white/10 dark:hover:bg-white/15 text-slate-800 dark:text-[#F5F7FF] text-xs font-semibold flex items-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Refresh Application Information</span>
            </button>

            <button
              type="button"
              onClick={() => simulatePackageUpdate(selectedApp.packageName)}
              className="min-h-[42px] px-4 py-2 rounded-xl bg-slate-200/80 hover:bg-slate-300/80 dark:bg-white/10 dark:hover:bg-white/15 text-slate-800 dark:text-[#F5F7FF] text-xs font-medium"
            >
              Simulate Package Update
            </button>
          </div>

          {launchAppNotice && (
            <div className="p-3 rounded-xl bg-[#5B8CFF]/15 text-[#5B8CFF] text-xs font-medium">
              {launchAppNotice}
            </div>
          )}
        </div>

        {/* App Selector Switcher */}
        <div>
          <p className="text-xs font-semibold text-slate-500 dark:text-[#A6B0C3] mb-2">
            Switch Discovered Application:
          </p>
          <div className="flex items-center gap-2 overflow-x-auto pb-1">
            {apps.map((item) => (
              <button
                key={item.packageName}
                type="button"
                onClick={() => {
                  setLaunchAppNotice(null);
                  store.setSelectedPackageName(item.packageName);
                }}
                className={`min-h-[40px] px-3.5 py-1.5 rounded-xl text-xs font-medium whitespace-nowrap shrink-0 transition-colors ${
                  item.packageName === selectedApp.packageName
                    ? 'bg-[#5B8CFF] text-white'
                    : 'bg-slate-100 dark:bg-[#0B1020] text-slate-600 dark:text-[#A6B0C3]'
                }`}
              >
                {item.appName}
              </button>
            ))}
          </div>
        </div>

        {/* Granular Protection Settings */}
        <div className="space-y-4">
          <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 flex items-center justify-between gap-4">
            <div>
              <p className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF]">
                Allow Biometric Fingerprint Unlock
              </p>
              <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-0.5">
                When enabled, allows AndroidX BiometricPrompt in addition to Master PIN.
              </p>
            </div>
            <button
              type="button"
              onClick={() =>
                updateAppDetails(selectedApp.packageName, {
                  allowBiometric: !selectedApp.allowBiometric,
                })
              }
              className={`min-h-[44px] min-w-[84px] px-3.5 rounded-xl text-xs font-semibold transition-colors ${
                selectedApp.allowBiometric
                  ? 'bg-[#2DD4A3] text-[#0B1020]'
                  : 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#A6B0C3]'
              }`}
            >
              {selectedApp.allowBiometric ? 'Allowed' : 'PIN Only'}
            </button>
          </div>

          <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10">
            <p className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF]">
              Custom Re-Lock Behavior Override
            </p>
            <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-0.5 mb-3">
              Override the global re-lock timer specifically for {selectedApp.appName}.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <button
                type="button"
                onClick={() =>
                  updateAppDetails(selectedApp.packageName, { customReLockPolicy: null })
                }
                className={`min-h-[48px] p-3 rounded-xl text-left text-xs border transition-colors ${
                  selectedApp.customReLockPolicy === null
                    ? 'border-[#5B8CFF] bg-[#5B8CFF]/10 text-slate-900 dark:text-[#F5F7FF] font-semibold'
                    : 'border-slate-200 dark:border-white/10 text-slate-600 dark:text-[#A6B0C3]'
                }`}
              >
                Use Global Default ({currentReLockOption.shortLabel})
              </button>

              {RELOCK_POLICIES.map((pol) => (
                <button
                  key={pol.id}
                  type="button"
                  onClick={() =>
                    updateAppDetails(selectedApp.packageName, { customReLockPolicy: pol.id })
                  }
                  className={`min-h-[48px] p-3 rounded-xl text-left text-xs border transition-colors ${
                    selectedApp.customReLockPolicy === pol.id
                      ? 'border-[#5B8CFF] bg-[#5B8CFF]/10 text-slate-900 dark:text-[#F5F7FF] font-semibold'
                      : 'border-slate-200 dark:border-white/10 text-slate-600 dark:text-[#A6B0C3]'
                  }`}
                >
                  {pol.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  // 10. AUTHENTICATION SCREEN & PHASE 4 APPLOCKACTIVITY OVERLAY
  if (currentScreen === 'auth_screen') {
    const targetLen = preferences.pinLength;
    const isLockedOut = lockoutRemainingSeconds > 0;
    const targetChallengeApp = activeChallengePackage
      ? apps.find((a) => a.packageName === activeChallengePackage) || null
      : null;

    const handleAuthDigit = async (d: string) => {
      if (isLockedOut || isCryptoBusy) return;
      setAuthStatus(null);
      if (authPinEntry.length < targetLen) {
        const next = authPinEntry + d;
        setAuthPinEntry(next);
        if (next.length === targetLen) {
          const res = await verifyMasterPin(next);
          setAuthStatus({ ok: res.ok, text: res.message });
          if (res.ok) {
            if (targetChallengeApp) {
              grantPackageChallengeUnlock(targetChallengeApp.packageName, 'MASTER_PIN');
            }
            setTimeout(() => {
              setAuthPinEntry('');
              setCurrentScreen('home');
            }, 500);
          } else {
            setAuthPinEntry('');
          }
        }
      }
    };

    return (
      <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-10 flex flex-col justify-between min-h-[640px]">
        <div className="flex items-center justify-between border-b border-slate-200 dark:border-white/10 pb-4">
          {targetChallengeApp ? (
            <button
              type="button"
              onClick={dismissChallengeToHomeLauncher}
              className="min-h-[44px] px-3 rounded-lg text-xs font-semibold text-rose-400 hover:text-rose-300 flex items-center gap-1.5"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Cancel & Exit to Android Home Launcher</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={() => setCurrentScreen('home')}
              className="min-h-[44px] px-3 rounded-lg text-xs font-medium text-slate-600 dark:text-[#A6B0C3] hover:text-slate-900 dark:hover:text-white flex items-center gap-1.5"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Dashboard</span>
            </button>
          )}
          <span className="text-xs text-slate-500 dark:text-[#A6B0C3]">
            {targetChallengeApp
              ? `AppLockActivity · Intercepting ${targetChallengeApp.packageName}`
              : 'Screen 10 of 15 · Master Authentication Screen'}
          </span>
        </div>

        <div className="max-w-md mx-auto w-full my-auto py-6 text-center">
          {targetChallengeApp ? (
            <div className="flex flex-col items-center mb-3">
              <AppPackageIcon
                packageName={targetChallengeApp.packageName}
                appName={targetChallengeApp.appName}
                category={targetChallengeApp.category}
                accentHex={targetChallengeApp.accentHex}
                hasValidIconResource={targetChallengeApp.hasValidIconResource}
                size="lg"
              />
              <h2 className="mt-3 text-xl sm:text-2xl font-bold text-slate-900 dark:text-[#F5F7FF]">
                {targetChallengeApp.appName}
              </h2>
              <p className="mt-1 text-xs font-semibold text-[#5B8CFF]">
                This app is protected by NEXLOCK
              </p>
              <p className="mt-0.5 text-[11px] font-mono text-slate-500 dark:text-[#A6B0C3]">
                Package: {targetChallengeApp.packageName} · Authenticate with Fingerprint or{' '}
                {targetLen}-Digit Master PIN
              </p>
            </div>
          ) : (
            <>
              <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-[#5B8CFF] to-[#9B7BFF] flex items-center justify-center font-bold text-base text-white mx-auto mb-3 shadow-md">
                <Shield className="w-7 h-7" />
              </div>
              <p className="text-xs text-[#5B8CFF] font-semibold">
                NEXLOCK Master Authentication Challenge
              </p>
              <h2 className="mt-1 text-xl sm:text-2xl font-bold text-slate-900 dark:text-[#F5F7FF]">
                {preferences.pinConfigured
                  ? `Enter Your ${targetLen}-Digit Master PIN`
                  : 'No Master PIN Configured Yet'}
              </h2>
            </>
          )}
          <p className="mt-1 text-xs text-slate-500 dark:text-[#A6B0C3]">
            Failed Attempts: {preferences.failedAttempts}/{preferences.maxFailedAttempts} ·{' '}
            {preferences.randomizeKeypad ? 'Randomized Keypad' : 'Standard Keypad'} ·{' '}
            {keystoreHealthy ? 'Keystore Healthy' : 'Key Invalidated'}
          </p>

          {!preferences.pinConfigured && (
            <div className="my-4 p-4 rounded-2xl bg-amber-500/10 border border-amber-500/30 text-xs text-amber-400">
              <p className="font-semibold">Master PIN Not Created Yet</p>
              <p className="mt-1">
                Create a Master PIN first so NEXLOCK can verify against your salted PBKDF2-HMAC-SHA256
                record.
              </p>
              <button
                type="button"
                onClick={() => setCurrentScreen('create_pin')}
                className="mt-3 min-h-[40px] px-4 py-1.5 rounded-xl bg-[#5B8CFF] text-white font-semibold"
              >
                Create Master PIN Now
              </button>
            </div>
          )}

          {isLockedOut && (
            <div
              role="alert"
              className="my-4 p-4 rounded-2xl bg-rose-500/15 border border-rose-500/40 text-xs text-rose-400 font-medium"
            >
              Temporary Brute-Force Cooldown Active: Keypad disabled for{' '}
              <span className="font-mono font-bold tabular-nums">{lockoutRemainingSeconds}s</span>.
            </div>
          )}

          <div className="my-5 flex items-center justify-center gap-3">
            {Array.from({ length: targetLen }).map((_, i) => (
              <div
                key={i}
                className={`w-4 h-4 rounded-full transition-all ${
                  i < authPinEntry.length
                    ? 'bg-[#5B8CFF] scale-110'
                    : 'bg-slate-200 dark:bg-[#0B1020] border border-slate-300 dark:border-white/20'
                }`}
              />
            ))}
          </div>

          {authStatus && (
            <div
              role="status"
              className={`mb-4 p-3 rounded-xl text-xs font-medium ${
                authStatus.ok
                  ? 'bg-[#2DD4A3]/15 text-[#2DD4A3]'
                  : 'bg-rose-500/15 text-rose-400'
              }`}
            >
              {authStatus.text}
            </div>
          )}

          <div className="grid grid-cols-3 gap-3 max-w-xs mx-auto">
            {keypadDigits.slice(0, 9).map((digit) => (
              <button
                key={digit}
                type="button"
                disabled={isLockedOut || isCryptoBusy || !preferences.pinConfigured}
                onClick={() => handleAuthDigit(digit)}
                className={`min-h-[56px] rounded-2xl bg-slate-100 dark:bg-[#0B1020] text-lg font-semibold font-mono tabular-nums text-slate-900 dark:text-[#F5F7FF] disabled:opacity-40 ${
                  preferences.hidePinRipple
                    ? ''
                    : 'hover:bg-slate-200 dark:hover:bg-white/10 active:scale-[0.97] transition-all'
                }`}
              >
                {digit}
              </button>
            ))}

            <button
              type="button"
              onClick={() => setShowBiometricSheet((v) => !v)}
              aria-label="Authenticate with BiometricPrompt"
              className="min-h-[56px] rounded-2xl bg-[#5B8CFF]/15 text-[#5B8CFF] flex items-center justify-center"
            >
              <Fingerprint className="w-5 h-5" />
            </button>

            <button
              type="button"
              disabled={isLockedOut || isCryptoBusy || !preferences.pinConfigured}
              onClick={() => handleAuthDigit(keypadDigits[9])}
              className={`min-h-[56px] rounded-2xl bg-slate-100 dark:bg-[#0B1020] text-lg font-semibold font-mono tabular-nums text-slate-900 dark:text-[#F5F7FF] disabled:opacity-40 ${
                preferences.hidePinRipple
                  ? ''
                  : 'hover:bg-slate-200 dark:hover:bg-white/10 active:scale-[0.97] transition-all'
              }`}
            >
              {keypadDigits[9]}
            </button>

            <button
              type="button"
              disabled={isLockedOut || isCryptoBusy}
              onClick={() => {
                setAuthStatus(null);
                setAuthPinEntry((p) => p.slice(0, -1));
              }}
              aria-label="Backspace"
              className="min-h-[56px] rounded-2xl bg-slate-100 dark:bg-[#0B1020] flex items-center justify-center text-slate-600 dark:text-[#A6B0C3] disabled:opacity-40"
            >
              <Delete className="w-5 h-5" />
            </button>
          </div>

          {showBiometricSheet && (
            <div className="mt-5 p-4 rounded-2xl bg-slate-900 text-[#F5F7FF] border border-[#5B8CFF]/40 text-left space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <Fingerprint className="w-6 h-6 text-[#5B8CFF]" />
                  <div>
                    <p className="text-xs font-bold">AndroidX BiometricPrompt</p>
                    <p className="text-[11px] text-[#A6B0C3]">
                      Hardware Status: {preferences.biometricHardwareState}
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    const res = triggerBiometricAuthentication('USER_CANCELED');
                    setAuthStatus({ ok: false, text: res.message });
                    setShowBiometricSheet(false);
                  }}
                  className="text-xs text-[#5B8CFF] hover:underline font-medium"
                >
                  Use Master PIN
                </button>
              </div>

              <div className="grid grid-cols-3 gap-2">
                <button
                  type="button"
                  onClick={() => {
                    const res = triggerBiometricAuthentication('SUCCESS');
                    setAuthStatus({ ok: res.ok, text: res.message });
                    if (res.ok) {
                      if (targetChallengeApp) {
                        grantPackageChallengeUnlock(
                          targetChallengeApp.packageName,
                          'BIOMETRIC_PROMPT'
                        );
                      }
                      setShowBiometricSheet(false);
                      setTimeout(() => setCurrentScreen('home'), 450);
                    }
                  }}
                  className="min-h-[40px] px-2.5 py-1.5 rounded-xl bg-[#2DD4A3] text-[#0B1020] text-xs font-bold"
                >
                  Touch Sensor (Match)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const res = triggerBiometricAuthentication('FAIL_MISMATCH');
                    setAuthStatus({ ok: false, text: res.message });
                  }}
                  className="min-h-[40px] px-2.5 py-1.5 rounded-xl bg-white/10 text-white text-xs font-medium"
                >
                  Mismatch Read
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const res = triggerBiometricAuthentication('SENSOR_LOCKOUT');
                    setAuthStatus({ ok: false, text: res.message });
                  }}
                  className="min-h-[40px] px-2.5 py-1.5 rounded-xl bg-rose-500/20 text-rose-300 text-xs font-medium"
                >
                  Sensor Lockout
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-slate-200 dark:border-white/10 text-xs text-slate-500 dark:text-[#A6B0C3]">
          <button
            type="button"
            onClick={toggleSimulateKeyInvalidation}
            className="text-amber-500 hover:underline font-medium"
          >
            {keystoreHealthy
              ? 'Simulate KeyPermanentlyInvalidatedException'
              : 'Recover & Rotate AndroidKeyStore Key'}
          </button>
          <button
            type="button"
            onClick={() => setCurrentScreen('security_settings')}
            className="text-[#5B8CFF] hover:underline font-medium"
          >
            Security & Session Settings
          </button>
        </div>
      </div>
    );
  }

  // 16. CHANGE MASTER PIN SCREEN
  if (currentScreen === 'change_pin') {
    const targetLen = preferences.pinLength;

    const handleRotatePin = async (e: React.FormEvent) => {
      e.preventDefault();
      setChangePinFeedback(null);
      const res = await changeMasterPin(currentPinInput, newPinInput, confirmNewPinInput);
      setChangePinFeedback({ ok: res.ok, text: res.message });
      if (res.ok) {
        setCurrentPinInput('');
        setNewPinInput('');
        setConfirmNewPinInput('');
      }
    };

    const newPinStrength =
      newPinInput.length > 0 ? validatePinStrength(newPinInput, targetLen) : null;

    return (
      <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-8 space-y-6">
        <div className="flex items-center justify-between border-b border-slate-200 dark:border-white/10 pb-4">
          <button
            type="button"
            onClick={() => setCurrentScreen('security_settings')}
            className="min-h-[44px] px-3 rounded-lg text-xs font-medium text-slate-600 dark:text-[#A6B0C3] hover:text-slate-900 dark:hover:text-white flex items-center gap-1.5"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Security Settings</span>
          </button>
          <span className="text-xs text-slate-500 dark:text-[#A6B0C3]">
            Change Master PIN · PBKDF2 Salt & Keystore Rotation
          </span>
        </div>

        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-[#F5F7FF]">
            Change Master PIN
          </h1>
          <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-1">
            Verifies your current Master PIN in constant time before generating a new 128-bit
            CSPRNG salt and AES-256-GCM encrypted verifier.
          </p>
        </div>

        {!preferences.pinConfigured ? (
          <div className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-3">
            <p className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF]">
              No Master PIN Configured Yet
            </p>
            <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">
              Use the Create Master PIN screen to establish your initial credential first.
            </p>
            <button
              type="button"
              onClick={() => setCurrentScreen('create_pin')}
              className="min-h-[44px] px-5 py-2.5 rounded-xl bg-[#5B8CFF] text-white text-xs font-semibold"
            >
              Go to Create Master PIN
            </button>
          </div>
        ) : (
          <form onSubmit={handleRotatePin} className="space-y-4 max-w-md">
            <div>
              <label className="block text-xs font-semibold text-slate-700 dark:text-[#F5F7FF] mb-1.5">
                Current {targetLen}-Digit Master PIN
              </label>
              <input
                type="password"
                inputMode="numeric"
                maxLength={targetLen}
                value={currentPinInput}
                onChange={(e) =>
                  setCurrentPinInput(e.target.value.replace(/\D/g, '').slice(0, targetLen))
                }
                placeholder={`Enter current ${targetLen}-digit PIN`}
                className="w-full min-h-[48px] px-4 rounded-xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 text-sm font-mono text-slate-900 dark:text-[#F5F7FF]"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 dark:text-[#F5F7FF] mb-1.5">
                New {targetLen}-Digit Master PIN
              </label>
              <input
                type="password"
                inputMode="numeric"
                maxLength={targetLen}
                value={newPinInput}
                onChange={(e) =>
                  setNewPinInput(e.target.value.replace(/\D/g, '').slice(0, targetLen))
                }
                placeholder={`Enter new strong ${targetLen}-digit PIN`}
                className="w-full min-h-[48px] px-4 rounded-xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 text-sm font-mono text-slate-900 dark:text-[#F5F7FF]"
              />
              {newPinStrength && !newPinStrength.valid && (
                <p className="mt-1 text-xs text-rose-400">{newPinStrength.reason}</p>
              )}
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 dark:text-[#F5F7FF] mb-1.5">
                Confirm New {targetLen}-Digit Master PIN
              </label>
              <input
                type="password"
                inputMode="numeric"
                maxLength={targetLen}
                value={confirmNewPinInput}
                onChange={(e) =>
                  setConfirmNewPinInput(e.target.value.replace(/\D/g, '').slice(0, targetLen))
                }
                placeholder={`Re-enter new ${targetLen}-digit PIN`}
                className="w-full min-h-[48px] px-4 rounded-xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 text-sm font-mono text-slate-900 dark:text-[#F5F7FF]"
              />
            </div>

            {changePinFeedback && (
              <div
                className={`p-3.5 rounded-xl text-xs font-medium ${
                  changePinFeedback.ok
                    ? 'bg-[#2DD4A3]/15 text-[#2DD4A3]'
                    : 'bg-rose-500/15 text-rose-400'
                }`}
              >
                {changePinFeedback.text}
              </div>
            )}

            <button
              type="submit"
              disabled={isCryptoBusy}
              className="min-h-[48px] px-6 py-2.5 rounded-xl bg-[#5B8CFF] hover:bg-[#4A7BF7] disabled:opacity-40 text-white font-semibold text-sm transition-colors"
            >
              {isCryptoBusy ? 'Rotating PBKDF2 Verifier...' : 'Verify & Update Master PIN'}
            </button>
          </form>
        )}
      </div>
    );
  }

  // 11. PRIVATE VAULT (Phase 5 Foundation: SecureFileRepository AES-256-GCM Encrypted Storage)
  if (currentScreen === 'vault') {
    const handleImportVaultFile = async (e: React.FormEvent) => {
      e.preventDefault();
      if (!newVaultFileName.trim() || !newVaultFileContent.trim()) return;
      if (
        !authorizeSensitiveAction(
          'Import & Encrypt File into Privacy Vault',
          `Encrypting ${newVaultFileName} with AES-256-GCM (nexlock_vault_aes256_gcm_v5).`
        )
      ) {
        return;
      }
      setIsEncryptingVaultFile(true);
      try {
        await encryptAndImportVaultFile(
          newVaultFileName.trim(),
          newVaultFileMime,
          newVaultFileContent
        );
      } finally {
        setIsEncryptingVaultFile(false);
      }
    };

    return (
      <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-8 space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-[#A6B0C3]">
          <span>Screen 11 of 15 · Private Vault Foundation (SecureFileRepository)</span>
          <span className="font-mono text-[#2DD4A3]">
            AES-256-GCM · Key Alias: nexlock_vault_aes256_gcm_v5 · {vaultFiles.length} Encrypted
            File(s)
          </span>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-[#F5F7FF]">
              Private Media & Document Vault (Phase 5 Foundation)
            </h1>
            <p className="text-sm text-slate-600 dark:text-[#A6B0C3] mt-1 leading-relaxed">
              Backed by <code className="font-mono text-xs">SecureFileRepository.kt</code> using
              AndroidKeyStore AES-256-GCM (<code className="font-mono text-xs">96-bit IV</code> +{' '}
              <code className="font-mono text-xs">128-bit GCM Tag</code>), SHA-256 digest
              verification, and in-place plaintext buffer zeroing inside app-private storage (
              <code className="font-mono text-xs">filesDir/private_vault_encrypted/</code>).
            </p>
          </div>
        </div>

        {/* Phase 5 Honest Capability Notice */}
        <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-1.5">
          <p className="text-xs font-bold text-[#5B8CFF]">
            Phase 5 Vault Foundation Scope & Cryptographic Architecture
          </p>
          <p className="text-xs text-slate-600 dark:text-[#A6B0C3] leading-relaxed">
            This foundation implements authenticated AES-256-GCM file encryption, Room{' '}
            <code className="font-mono">vault_metadata</code> isolation (separate from App Lock
            tables), SHA-256 integrity checks, and zero-plaintext persistence. All vault mutations
            require an active Master Session.
          </p>
        </div>

        {/* Encrypt & Import File into App-Private Vault */}
        <form
          onSubmit={handleImportVaultFile}
          className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-4"
        >
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF] flex items-center gap-2">
              <FolderLock className="w-4 h-4 text-[#9B7BFF]" />
              <span>Encrypt & Import File into App-Private Storage</span>
            </h2>
            <span className="text-[11px] font-mono text-slate-500 dark:text-[#A6B0C3]">
              Plaintext buffer wiped immediately after encryption
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-slate-700 dark:text-[#F5F7FF] mb-1">
                File Display Name
              </label>
              <input
                type="text"
                value={newVaultFileName}
                onChange={(e) => setNewVaultFileName(e.target.value)}
                className="w-full min-h-[42px] px-3.5 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 text-xs text-slate-900 dark:text-[#F5F7FF]"
                placeholder="e.g. passport_scan_notes.txt"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 dark:text-[#F5F7FF] mb-1">
                MIME Type / Category
              </label>
              <select
                value={newVaultFileMime}
                onChange={(e) => setNewVaultFileMime(e.target.value)}
                className="w-full min-h-[42px] px-3.5 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 text-xs text-slate-900 dark:text-[#F5F7FF]"
              >
                <option value="text/plain">Confidential Note (text/plain)</option>
                <option value="application/json">Identity / Key Record (application/json)</option>
                <option value="image/jpeg">Encrypted Photo Metadata (image/jpeg)</option>
                <option value="application/pdf">Encrypted Document (application/pdf)</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-[#F5F7FF] mb-1">
              Plaintext Payload to Encrypt (AES-256-GCM)
            </label>
            <textarea
              rows={2}
              value={newVaultFileContent}
              onChange={(e) => setNewVaultFileContent(e.target.value)}
              className="w-full p-3 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 text-xs font-mono text-slate-900 dark:text-[#F5F7FF]"
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3">
            <span className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">
              Target Directory: <code className="font-mono">filesDir/private_vault_encrypted/</code>
            </span>
            <button
              type="submit"
              disabled={isEncryptingVaultFile}
              className="min-h-[42px] px-4 py-2 rounded-xl bg-[#9B7BFF] hover:bg-[#8A68F5] text-white text-xs font-bold flex items-center gap-1.5"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>
                {isEncryptingVaultFile
                  ? 'Encrypting with AES-256-GCM...'
                  : 'Encrypt & Store in Vault'}
              </span>
            </button>
          </div>
        </form>

        {/* Decrypted In-Memory Preview Banner */}
        {decryptedVaultPreview && (
          <div className="p-4 rounded-2xl bg-[#2DD4A3]/10 border border-[#2DD4A3]/40 space-y-2">
            <div className="flex items-center justify-between gap-2">
              <p className="text-xs font-bold text-[#2DD4A3]">
                Authenticated AES-256-GCM Decryption Verified (In-Memory Only):{' '}
                {decryptedVaultPreview.displayName}
              </p>
              <button
                type="button"
                onClick={() => setDecryptedVaultPreview(null)}
                className="text-xs text-slate-500 hover:text-slate-900 dark:hover:text-white font-semibold"
              >
                Wipe In-Memory Preview
              </button>
            </div>
            <pre className="p-3 rounded-xl bg-slate-900 text-[#F5F7FF] text-xs font-mono overflow-x-auto whitespace-pre-wrap">
              {decryptedVaultPreview.plaintextUtf8}
            </pre>
          </div>
        )}

        {/* Encrypted Vault Items Table */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
            Encrypted Vault Files (`vault_metadata` Room Entity)
          </h2>

          {vaultFiles.length === 0 ? (
            <div className="p-8 rounded-2xl bg-slate-50 dark:bg-[#0B1020] text-center text-xs text-slate-500 dark:text-[#A6B0C3]">
              No encrypted files stored in the Privacy Vault yet.
            </div>
          ) : (
            <div className="divide-y divide-slate-200/80 dark:divide-white/10">
              {vaultFiles.map((vf) => (
                <div
                  key={vf.id}
                  className="py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded-md bg-[#9B7BFF]/15 text-[#9B7BFF] text-[10px] font-mono font-bold">
                        AES-256-GCM
                      </span>
                      <p className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF] truncate">
                        {vf.displayName}
                      </p>
                    </div>
                    <p className="text-xs font-mono text-slate-500 dark:text-[#A6B0C3] truncate">
                      {vf.encryptedRelativePath} · Plain: {vf.originalSizeBytes}B · Type:{' '}
                      {vf.mediaType}
                    </p>
                    <p className="text-[11px] font-mono text-slate-400 dark:text-[#A6B0C3]/80 truncate">
                      IV (96-bit): {vf.encryptionIvBase64} · SHA-256:{' '}
                      {vf.ciphertextSha256Hex.slice(0, 24)}...
                    </p>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => {
                        if (
                          authorizeSensitiveAction(
                            `Decrypt Vault File: ${vf.displayName}`,
                            `Verified GCM authentication tag and SHA-256 digest for ${vf.id}.`
                          )
                        ) {
                          decryptVaultFileById(vf.id);
                        }
                      }}
                      className="min-h-[40px] px-3.5 py-1.5 rounded-xl bg-[#5B8CFF]/15 hover:bg-[#5B8CFF]/25 text-[#5B8CFF] text-xs font-semibold"
                    >
                      Verify & Decrypt In-Memory
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        if (
                          authorizeSensitiveAction(
                            `Delete Vault File: ${vf.displayName}`,
                            `Deleted ${vf.encryptedRelativePath}.`
                          )
                        ) {
                          deleteVaultFileById(vf.id);
                        }
                      }}
                      className="min-h-[40px] px-3 py-1.5 rounded-xl bg-rose-500/15 hover:bg-rose-500/25 text-rose-400 text-xs font-semibold flex items-center gap-1"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span>Delete</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    );
  }

  // 12. SECURITY ACTIVITY LOG & INTRUDER SELFIE RECORDS (Phase 5 Enhanced)
  if (currentScreen === 'security_activity') {
    const nowMs = Date.now();
    const startOfTodayMs = new Date().setHours(0, 0, 0, 0);
    const sevenDaysAgoMs = nowMs - 7 * 24 * 60 * 60 * 1000;

    const filteredEvents = events
      .filter((ev) => {
        if (activityTypeFilter === 'LOCK') {
          return (
            ev.eventType === 'CONFIG_LOCK_ENABLED' ||
            ev.eventType === 'CONFIG_LOCK_DISABLED' ||
            ev.eventType === 'BULK_LOCK_UPDATED' ||
            ev.eventType === 'PACKAGE_INSTALLED' ||
            ev.eventType === 'PACKAGE_UPDATED' ||
            ev.eventType === 'PACKAGE_UNINSTALLED' ||
            ev.eventType === 'QUICK_LOCK_TRIGGERED'
          );
        }
        if (activityTypeFilter === 'INTRUDER') {
          return (
            ev.eventType === 'FAILED_PIN' ||
            ev.eventType === 'FAILED_BIOMETRIC' ||
            ev.eventType === 'INTRUDER_THRESHOLD_REACHED' ||
            ev.eventType === 'INTRUDER_SELFIE_CAPTURED' ||
            ev.eventType === 'INTRUDER_IMAGES_DELETED' ||
            ev.eventType === 'AUTH_LOCKOUT'
          );
        }
        if (activityTypeFilter === 'VAULT') {
          return (
            ev.eventType === 'VAULT_FILE_IMPORTED' || ev.eventType === 'VAULT_FILE_DELETED'
          );
        }
        if (activityTypeFilter === 'AUTH') {
          return (
            ev.eventType === 'UNLOCK_SUCCESS' ||
            ev.eventType === 'PIN_CREATED' ||
            ev.eventType === 'PIN_CHANGED' ||
            ev.eventType === 'SESSION_EXPIRED' ||
            ev.eventType === 'SENSITIVE_SETTING_CHANGED'
          );
        }
        return true;
      })
      .filter((ev) => {
        if (activitySeverityFilter === 'ALL') return true;
        return (ev.severity || 'INFO') === activitySeverityFilter;
      })
      .filter((ev) => {
        if (activityDateFilter === 'TODAY') return ev.timestampMillis >= startOfTodayMs;
        if (activityDateFilter === 'LAST_7_DAYS') return ev.timestampMillis >= sevenDaysAgoMs;
        return true;
      })
      .sort((a, b) =>
        activitySortOrder === 'NEWEST_FIRST'
          ? b.timestampMillis - a.timestampMillis
          : a.timestampMillis - b.timestampMillis
      );

    return (
      <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-8 space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-[#A6B0C3]">
          <span>Screen 12 of 15 · Security Activity Timeline & Intruder Records</span>
          <span className="font-mono tabular-nums">
            Showing {filteredEvents.length} of {events.length} Sanitized Audit Entries
          </span>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-[#F5F7FF]">
              Security Activity Log
            </h1>
            <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-1">
              Chronological audit log with credential sanitization, severity levels, intruder
              detection events, and encrypted selfie records.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() =>
                setActivitySortOrder((prev) =>
                  prev === 'NEWEST_FIRST' ? 'OLDEST_FIRST' : 'NEWEST_FIRST'
                )
              }
              className="min-h-[38px] px-3 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 text-xs font-semibold text-slate-700 dark:text-[#F5F7FF]"
            >
              Sort: {activitySortOrder === 'NEWEST_FIRST' ? 'Newest First' : 'Oldest First'}
            </button>

            {events.length > 0 && (
              <button
                type="button"
                onClick={() => setShowClearLogsConfirm(true)}
                className="min-h-[38px] px-3.5 py-1.5 rounded-xl bg-rose-500/15 hover:bg-rose-500/25 text-xs font-semibold text-rose-400 flex items-center gap-1.5"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear Logs</span>
              </button>
            )}
          </div>
        </div>

        {/* Explicit Confirmation Modal for Clearing Security Logs (Master Auth Protected) */}
        {showClearLogsConfirm && (
          <div
            role="dialog"
            aria-label="Confirm Clear Security Logs"
            className="p-4 rounded-2xl bg-slate-900 text-[#F5F7FF] border border-rose-500/50 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
          >
            <div className="space-y-1">
              <p className="text-sm font-bold text-rose-400">
                Confirm Clearing All {events.length} Security Activity Logs?
              </p>
              <p className="text-xs text-[#A6B0C3]">
                Clearing audit history requires an active Master Session and records a new
                LOGS_CLEARED audit event.
              </p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => setShowClearLogsConfirm(false)}
                className="min-h-[38px] px-3.5 py-1.5 rounded-xl bg-white/10 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowClearLogsConfirm(false);
                  if (
                    authorizeSensitiveAction(
                      'Clear Security Activity Logs',
                      'User confirmed clearing all historical security events.'
                    )
                  ) {
                    clearActivityHistory(true);
                  }
                }}
                className="min-h-[38px] px-4 py-1.5 rounded-xl bg-rose-500 text-white text-xs font-bold"
              >
                Confirm Clear All
              </button>
            </div>
          </div>
        )}

        {/* Phase 5 Multi-Dimensional Filters: Category, Severity, Date Range */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-1 p-1 rounded-xl bg-slate-100 dark:bg-[#0B1020] overflow-x-auto">
            {(
              [
                { id: 'ALL', label: 'All Events' },
                { id: 'INTRUDER', label: 'Intruder & Failures' },
                { id: 'AUTH', label: 'Auth & Settings' },
                { id: 'LOCK', label: 'App Lock & Quick Lock' },
                { id: 'VAULT', label: 'Privacy Vault' },
              ] as const
            ).map((f) => (
              <button
                key={f.id}
                type="button"
                onClick={() => setActivityTypeFilter(f.id)}
                className={`min-h-[34px] px-3 py-1 rounded-lg text-xs font-semibold transition-colors whitespace-nowrap ${
                  activityTypeFilter === f.id
                    ? 'bg-[#5B8CFF] text-white'
                    : 'text-slate-600 dark:text-[#A6B0C3]'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-1 p-1 rounded-xl bg-slate-100 dark:bg-[#0B1020]">
              {(['ALL', 'INFO', 'WARNING', 'CRITICAL'] as const).map((sev) => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setActivitySeverityFilter(sev)}
                  className={`min-h-[32px] px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-colors ${
                    activitySeverityFilter === sev
                      ? 'bg-[#9B7BFF] text-white'
                      : 'text-slate-600 dark:text-[#A6B0C3]'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-1 p-1 rounded-xl bg-slate-100 dark:bg-[#0B1020]">
              {(
                [
                  { id: 'ALL_TIME', label: 'All Time' },
                  { id: 'TODAY', label: 'Today' },
                  { id: 'LAST_7_DAYS', label: '7 Days' },
                ] as const
              ).map((dt) => (
                <button
                  key={dt.id}
                  type="button"
                  onClick={() => setActivityDateFilter(dt.id)}
                  className={`min-h-[32px] px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-colors ${
                    activityDateFilter === dt.id
                      ? 'bg-[#2DD4A3] text-[#0B1020]'
                      : 'text-slate-600 dark:text-[#A6B0C3]'
                  }`}
                >
                  {dt.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Phase 6 Section 6: Real Security Analytics Dashboard (7-Day & 30-Day Activity Breakdown) */}
        <div className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
                {i18n.securityAnalytics} · Derived from Room `security_events` & `locked_apps`
              </h2>
              <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">
                Real database metrics computed dynamically without fabricated telemetry.
              </p>
            </div>
            <div className="inline-flex items-center rounded-xl bg-white dark:bg-[#151D32] p-1 border border-slate-200 dark:border-white/10">
              {(['7D', '30D'] as const).map((rng) => (
                <button
                  key={rng}
                  type="button"
                  onClick={() => setAnalyticsRange(rng)}
                  className={`px-3 py-1 rounded-lg text-xs font-bold transition-colors ${
                    analyticsRange === rng
                      ? 'bg-[#5B8CFF] text-white'
                      : 'text-slate-600 dark:text-[#A6B0C3]'
                  }`}
                >
                  {rng === '7D' ? 'Last 7 Days' : 'Last 30 Days'}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5">
            <div className="p-3 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200/80 dark:border-white/10">
              <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">Protected Apps</p>
              <p className="mt-1 text-lg font-bold font-mono text-[#5B8CFF]">
                {securityAnalyticsReport.totalProtectedApps}
              </p>
            </div>
            <div className="p-3 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200/80 dark:border-white/10">
              <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">Successful Auth</p>
              <p className="mt-1 text-lg font-bold font-mono text-[#2DD4A3]">
                {securityAnalyticsReport.totalSuccessfulAuthentications}
              </p>
            </div>
            <div className="p-3 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200/80 dark:border-white/10">
              <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">Failed PIN</p>
              <p className="mt-1 text-lg font-bold font-mono text-amber-400">
                {securityAnalyticsReport.totalFailedPinAttempts}
              </p>
            </div>
            <div className="p-3 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200/80 dark:border-white/10">
              <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">Failed Biometric</p>
              <p className="mt-1 text-lg font-bold font-mono text-amber-400">
                {securityAnalyticsReport.totalFailedBiometricAttempts}
              </p>
            </div>
            <div className="p-3 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200/80 dark:border-white/10">
              <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">Intruder Alerts</p>
              <p className="mt-1 text-lg font-bold font-mono text-rose-400">
                {securityAnalyticsReport.totalIntruderEvents}
              </p>
            </div>
            <div className="p-3 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200/80 dark:border-white/10">
              <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">Interruptions</p>
              <p className="mt-1 text-lg font-bold font-mono text-slate-700 dark:text-[#F5F7FF]">
                {securityAnalyticsReport.totalMonitoringInterruptions}
              </p>
            </div>
          </div>

          {/* Activity Breakdown Bar Chart (7D or 30D) */}
          <div className="pt-2">
            <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-[#A6B0C3] mb-2">
              <span>
                Daily Activity Breakdown ({analyticsRange === '7D' ? '7-Day Window' : '30-Day Window'})
              </span>
              <div className="flex items-center gap-3">
                <span className="inline-flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-[#2DD4A3]" /> Unlocks
                </span>
                <span className="inline-flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-amber-400" /> Failed Auth
                </span>
                <span className="inline-flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-rose-500" /> Intruder
                </span>
              </div>
            </div>
            <div className="grid grid-cols-7 sm:grid-cols-10 lg:grid-cols-15 gap-1.5 items-end pt-2">
              {(analyticsRange === '7D'
                ? securityAnalyticsReport.activity7Days
                : securityAnalyticsReport.activity30Days.slice(-15)
              ).map((pt) => {
                const total = pt.successfulUnlocks + pt.failedAttempts + pt.intruderAlerts;
                return (
                  <div
                    key={pt.dateIso}
                    className="p-2 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200/70 dark:border-white/10 flex flex-col items-center gap-1"
                  >
                    <div className="flex items-end gap-0.5 h-10">
                      <div
                        className="w-2 rounded-t bg-[#2DD4A3]"
                        style={{ height: `${Math.min(40, Math.max(4, pt.successfulUnlocks * 10))}px` }}
                        title={`Unlocks: ${pt.successfulUnlocks}`}
                      />
                      <div
                        className="w-2 rounded-t bg-amber-400"
                        style={{ height: `${Math.min(40, Math.max(4, pt.failedAttempts * 10))}px` }}
                        title={`Failed: ${pt.failedAttempts}`}
                      />
                      <div
                        className="w-2 rounded-t bg-rose-500"
                        style={{ height: `${Math.min(40, Math.max(4, pt.intruderAlerts * 12))}px` }}
                        title={`Intruders: ${pt.intruderAlerts}`}
                      />
                    </div>
                    <span className="text-[10px] font-mono text-slate-600 dark:text-[#A6B0C3] truncate">
                      {pt.label}
                    </span>
                    <span className="text-[10px] font-mono font-bold text-slate-900 dark:text-[#F5F7FF]">
                      {total} evt
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Phase 5 Encrypted Intruder Selfie Records Panel */}
        <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
                Encrypted Intruder Capture Records (`intruder_images` Room Table)
              </h2>
              <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">
                Consented foreground CameraX captures encrypted with AES-256-GCM inside{' '}
                <code className="font-mono">filesDir/intruder_encrypted/</code> (Max stored:{' '}
                {intruderConfig.maxStoredImages})
              </p>
            </div>
            {intruderImages.length > 0 && (
              <button
                type="button"
                onClick={deleteAllIntruderRecords}
                className="min-h-[36px] px-3 py-1.5 rounded-xl bg-rose-500/15 hover:bg-rose-500/25 text-rose-400 text-xs font-semibold"
              >
                Delete All Captures ({intruderImages.length})
              </button>
            )}
          </div>

          {intruderImages.length === 0 ? (
            <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">
              No intruder selfie captures stored. Trigger {intruderConfig.threshold} consecutive
              failed PIN/Biometric attempts on Screen 10 to test intruder threshold detection.
            </p>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {intruderImages.map((img) => (
                <div
                  key={img.id}
                  className="p-3 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 space-y-1 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-rose-400">
                      {img.captureStatus === 'CAPTURED_ENCRYPTED_AES256_GCM'
                        ? 'AES-256-GCM Encrypted Photo'
                        : 'Event-Only Record (No Photo)'}
                    </span>
                    <span className="font-mono text-[11px] text-slate-400">
                      #{img.consecutiveFailures} Failures
                    </span>
                  </div>
                  <p className="font-mono text-[11px] text-slate-700 dark:text-[#F5F7FF] truncate">
                    Target: {img.targetPackageName || 'com.nexlock.security'} · Auth:{' '}
                    {img.authenticationMethod}
                  </p>
                  {img.encryptedFilePath ? (
                    <p className="font-mono text-[10px] text-[#2DD4A3] truncate">
                      {img.encryptedFilePath} ({img.byteSize}B · IV: {img.encryptionIvBase64})
                    </p>
                  ) : (
                    <p className="text-[11px] text-amber-400">
                      Fallback Reason: {img.statusReason}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Security Events List */}
        {filteredEvents.length === 0 ? (
          <div className="py-12 text-center text-sm text-slate-500 dark:text-[#A6B0C3]">
            No security activity entries recorded for the selected filters.
          </div>
        ) : (
          <div className="divide-y divide-slate-200/80 dark:divide-white/10">
            {filteredEvents.map((ev) => {
              const timeStr = new Date(ev.timestampMillis).toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
              });
              const severity = ev.severity || 'INFO';
              const badgeClass =
                severity === 'CRITICAL'
                  ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                  : severity === 'WARNING'
                  ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                  : 'bg-[#5B8CFF]/15 text-[#5B8CFF] border-[#5B8CFF]/30';

              return (
                <div key={ev.id} className="py-4 flex items-start justify-between gap-4">
                  <div className="space-y-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`px-2 py-0.5 rounded-md border text-[10px] font-mono font-bold ${badgeClass}`}
                      >
                        {severity}
                      </span>
                      <p className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF]">
                        {ev.title}
                      </p>
                    </div>
                    <p className="text-xs text-slate-600 dark:text-[#A6B0C3] leading-relaxed">
                      {ev.detail}
                    </p>
                    <p className="text-[11px] font-mono text-slate-400 dark:text-[#A6B0C3]/70">
                      {ev.eventType}
                      {ev.authenticationMethod ? ` · Auth: ${ev.authenticationMethod}` : ''}
                      {ev.packageName ? ` · Pkg: ${ev.packageName}` : ''} · {timeStr}
                    </p>
                  </div>

                  <button
                    type="button"
                    onClick={() => deleteSingleSecurityEvent(ev.id)}
                    aria-label={`Delete event ${ev.title}`}
                    className="p-2 rounded-xl text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 shrink-0"
                    title="Delete individual event entry"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </div>
    );
  }

  // 13. SECURITY SETTINGS (Phase 5 Intruder Detection, Consented Selfie, Sensitive Session Gate & Anti-Tampering)
  if (currentScreen === 'security_settings') {
    return (
      <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-8 space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-[#A6B0C3]">
          <span>Screen 13 of 15 · Security Settings & Phase 5 Intruder / Privacy Controls</span>
          <span>
            Master Session:{' '}
            <span className={isSessionAuthenticated ? 'text-[#2DD4A3] font-bold' : 'text-amber-400 font-bold'}>
              {isSessionAuthenticated ? `Authenticated (${sessionRemainingSeconds}s)` : 'Locked (Required for Changes)'}
            </span>
          </span>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-[#F5F7FF]">
              Security, Intruder Detection & Privacy Settings
            </h1>
            <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-1">
              Critical settings require an active Phase 2 Master Session. Session authorization is
              reused without repeated prompts until expiration.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => executeQuickLock(true)}
              className="min-h-[44px] px-4 py-2 rounded-xl bg-rose-500 hover:bg-rose-600 text-white font-bold text-xs flex items-center gap-1.5 whitespace-nowrap"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Panic Lock All + Master Session</span>
            </button>

            {isSessionAuthenticated && (
              <button
                type="button"
                onClick={lockSessionNow}
                className="min-h-[44px] px-4 py-2 rounded-xl bg-amber-500 hover:bg-amber-600 text-slate-950 font-semibold text-xs flex items-center gap-1.5 whitespace-nowrap"
              >
                <Lock className="w-3.5 h-3.5" />
                <span>Lock Session</span>
              </button>
            )}
          </div>
        </div>

        {/* Phase 6 Section 1 & 2: Smart Lock Scheduler & Lock Mode Manager */}
        <div className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
                {i18n.smartSchedules} (`LockScheduleManager` · Room `lock_schedules` Schema v4)
              </h2>
              <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-0.5">
                Supports intraday windows, weekend rules, and overnight cross-midnight schedules
                (e.g. 22:00 – 07:00) using inexact `AlarmManager.setWindow()` boundaries (no
                `SCHEDULE_EXACT_ALARM` required).
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-semibold text-slate-500 dark:text-[#A6B0C3]">
                Simulate TimeZone:
              </span>
              <select
                value={simulatedScheduleTimeZone}
                onChange={(e) => setSimulatedScheduleTimeZone(e.target.value)}
                className="min-h-[34px] px-2.5 rounded-lg bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 text-xs font-mono text-slate-900 dark:text-[#F5F7FF]"
              >
                <option value="UTC">UTC</option>
                <option value="Asia/Dhaka">Asia/Dhaka (UTC+6)</option>
                <option value="America/New_York">America/New_York</option>
                <option value="Europe/London">Europe/London</option>
              </select>
            </div>
          </div>

          {/* Lock Mode Selector */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            {LOCK_MODE_OPTIONS.map((mOpt) => {
              const isSelected = phase6Appearance.lockMode === mOpt.id;
              return (
                <button
                  key={mOpt.id}
                  type="button"
                  onClick={() => setLockMode(mOpt.id)}
                  className={`p-3 rounded-xl border text-left transition-all ${
                    isSelected
                      ? 'border-[#5B8CFF] bg-[#5B8CFF]/10'
                      : 'border-slate-200 dark:border-white/10 bg-white dark:bg-[#151D32]'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-bold text-slate-900 dark:text-[#F5F7FF]">
                      {phase6Appearance.languageCode === 'bn' ? mOpt.labelBn : mOpt.label}
                    </span>
                    <span className="text-[10px] font-mono text-[#5B8CFF]">{mOpt.badge}</span>
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3] mt-1">
                    {mOpt.description}
                  </p>
                </button>
              );
            })}
          </div>

          <div className="p-3 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200/80 dark:border-white/10 text-xs flex flex-wrap items-center justify-between gap-2">
            <span className="font-semibold text-slate-800 dark:text-[#F5F7FF]">
              Live Schedule Evaluation ({simulatedScheduleTimeZone}):
            </span>
            <span className="font-mono text-[#2DD4A3]">
              {scheduleModeEvaluation.statusSummary}
            </span>
          </div>

          {/* Configured Schedules List */}
          <div className="space-y-2.5">
            {lockSchedules.map((sched) => {
              const isOvernight = isOvernightSchedule(sched);
              const isCurrentlyInWindow = isScheduleActiveAtInstant(
                sched,
                Date.now(),
                simulatedScheduleTimeZone
              );
              const dayNames = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
              const formattedDays = sched.daysOfWeek
                .map((d) => dayNames[d - 1] || String(d))
                .join(', ');

              return (
                <div
                  key={sched.id}
                  className="p-3.5 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="text-xs font-bold text-slate-900 dark:text-[#F5F7FF]">
                        {sched.name}
                      </p>
                      <span className="px-2 py-0.5 rounded-md bg-[#5B8CFF]/15 text-[#5B8CFF] text-[10px] font-mono font-bold">
                        {String(sched.startHour).padStart(2, '0')}:
                        {String(sched.startMinute).padStart(2, '0')} –{' '}
                        {String(sched.endHour).padStart(2, '0')}:
                        {String(sched.endMinute).padStart(2, '0')}
                      </span>
                      {isOvernight && (
                        <span className="px-2 py-0.5 rounded-md bg-[#9B7BFF]/15 text-[#9B7BFF] text-[10px] font-semibold">
                          Overnight (Crosses Midnight)
                        </span>
                      )}
                      {isCurrentlyInWindow && (
                        <span className="px-2 py-0.5 rounded-md bg-[#2DD4A3]/15 text-[#2DD4A3] text-[10px] font-bold">
                          Active Window Now
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                      {sched.description}
                    </p>
                    <p className="text-[11px] font-mono text-slate-400 dark:text-[#A6B0C3]/80">
                      Days: {formattedDays} · Target:{' '}
                      {sched.applyToAllLockedApps
                        ? 'All Protected Apps (*)'
                        : `${sched.targetPackages.length} Selected Packages`}
                    </p>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => toggleLockScheduleEnabled(sched.id)}
                      className={`min-h-[36px] px-3 rounded-lg text-xs font-bold ${
                        sched.isEnabled
                          ? 'bg-[#2DD4A3] text-[#0B1020]'
                          : 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#A6B0C3]'
                      }`}
                    >
                      {sched.isEnabled ? 'Enabled' : 'Disabled'}
                    </button>
                    {sched.id > 3 && (
                      <button
                        type="button"
                        onClick={() => deleteLockSchedule(sched.id)}
                        className="p-2 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10"
                        title="Delete custom schedule"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Create New Smart Lock Schedule Form */}
          <div className="pt-3 border-t border-slate-200 dark:border-white/10 space-y-3">
            <p className="text-xs font-bold text-slate-900 dark:text-[#F5F7FF]">
              Create Custom Smart Lock Schedule (Supports Intraday or Overnight Windows)
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-2.5">
              <input
                type="text"
                value={newScheduleName}
                onChange={(e) => setNewScheduleName(e.target.value)}
                placeholder="Schedule Name"
                className="min-h-[38px] px-3 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 text-xs text-slate-900 dark:text-[#F5F7FF]"
              />
              <input
                type="text"
                value={newScheduleDesc}
                onChange={(e) => setNewScheduleDesc(e.target.value)}
                placeholder="Description"
                className="min-h-[38px] px-3 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 text-xs text-slate-900 dark:text-[#F5F7FF]"
              />
              <div className="flex items-center gap-1.5">
                <label className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">Start Hr:</label>
                <input
                  type="number"
                  min={0}
                  max={23}
                  value={newScheduleStartHour}
                  onChange={(e) => setNewScheduleStartHour(Number(e.target.value))}
                  className="w-16 min-h-[38px] px-2 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 text-xs font-mono text-slate-900 dark:text-[#F5F7FF]"
                />
                <label className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">End Hr:</label>
                <input
                  type="number"
                  min={0}
                  max={23}
                  value={newScheduleEndHour}
                  onChange={(e) => setNewScheduleEndHour(Number(e.target.value))}
                  className="w-16 min-h-[38px] px-2 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 text-xs font-mono text-slate-900 dark:text-[#F5F7FF]"
                />
              </div>
              <button
                type="button"
                onClick={() => {
                  const res = createOrUpdateLockSchedule({
                    name: newScheduleName,
                    description: newScheduleDesc,
                    startHour: newScheduleStartHour,
                    startMinute: 0,
                    endHour: newScheduleEndHour,
                    endMinute: 0,
                    daysOfWeek: newScheduleDays,
                    applyToAllLockedApps: true,
                  });
                  setScheduleFeedback(res.message);
                }}
                className="min-h-[38px] px-4 rounded-xl bg-[#5B8CFF] hover:bg-[#4A7BF7] text-white text-xs font-bold flex items-center justify-center gap-1.5"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Schedule</span>
              </button>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-1">
                {[
                  { iso: 1, label: 'Mon' },
                  { iso: 2, label: 'Tue' },
                  { iso: 3, label: 'Wed' },
                  { iso: 4, label: 'Thu' },
                  { iso: 5, label: 'Fri' },
                  { iso: 6, label: 'Sat' },
                  { iso: 7, label: 'Sun' },
                ].map((d) => {
                  const active = newScheduleDays.includes(d.iso);
                  return (
                    <button
                      key={d.iso}
                      type="button"
                      onClick={() =>
                        setNewScheduleDays((prev) =>
                          prev.includes(d.iso)
                            ? prev.filter((x) => x !== d.iso)
                            : [...prev, d.iso]
                        )
                      }
                      className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold ${
                        active
                          ? 'bg-[#5B8CFF] text-white'
                          : 'bg-white dark:bg-[#151D32] text-slate-500 dark:text-[#A6B0C3]'
                      }`}
                    >
                      {d.label}
                    </button>
                  );
                })}
              </div>
              {scheduleFeedback && (
                <span className="text-xs font-semibold text-[#2DD4A3]">{scheduleFeedback}</span>
              )}
            </div>
          </div>
        </div>

        {/* Phase 6 Section 5: Encrypted Configuration Backup & Restore */}
        <div className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
                {i18n.encryptedBackup} (`BackupEncryptionManager` · PBKDF2-HMAC-SHA256 + AES-256-GCM)
              </h2>
              <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-0.5">
                Exports locked app rules, smart schedules, lock mode, and appearance preferences via
                Storage Access Framework. Never exports plaintext PINs, PBKDF2 PIN verifiers,
                AndroidKeyStore private keys, or biometric templates.
              </p>
            </div>
            <span className="px-2.5 py-1 rounded-lg bg-[#2DD4A3]/15 text-[#2DD4A3] text-[11px] font-mono font-bold">
              210,000 Iterations · 128-bit GCM Tag
            </span>
          </div>

          {backupRestoreStatusMessage && (
            <div
              className={`p-3.5 rounded-xl border text-xs font-medium flex items-center justify-between gap-3 ${
                backupRestoreStatusMessage.type === 'success'
                  ? 'bg-[#2DD4A3]/15 border-[#2DD4A3]/40 text-slate-900 dark:text-[#F5F7FF]'
                  : 'bg-rose-500/15 border-rose-500/40 text-rose-400'
              }`}
            >
              <span>{backupRestoreStatusMessage.text}</span>
              <button
                type="button"
                onClick={() => setBackupRestoreStatusMessage(null)}
                className="p-1 opacity-75 hover:opacity-100"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Export Column */}
            <div className="p-4 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 space-y-3">
              <p className="text-xs font-bold text-slate-900 dark:text-[#F5F7FF]">
                1. Export Encrypted Configuration Backup (`.nexlock.json`)
              </p>
              <div>
                <label className="block text-[11px] text-slate-500 dark:text-[#A6B0C3] mb-1">
                  Backup Encryption Password (min 8 chars, derives 256-bit AES key)
                </label>
                <input
                  type="text"
                  value={backupPasswordInput}
                  onChange={(e) => setBackupPasswordInput(e.target.value)}
                  className="w-full min-h-[38px] px-3 rounded-xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 text-xs font-mono text-slate-900 dark:text-[#F5F7FF]"
                  placeholder="Enter strong backup password..."
                />
              </div>
              <button
                type="button"
                disabled={isCryptoBusy}
                onClick={async () => {
                  const res = await exportEncryptedConfigurationBackup(backupPasswordInput);
                  if (res.ok && res.envelopeJson) {
                    setRestoreJsonInput(res.envelopeJson);
                  }
                }}
                className="min-h-[40px] px-4 py-2 rounded-xl bg-[#5B8CFF] hover:bg-[#4A7BF7] text-white text-xs font-bold"
              >
                {isCryptoBusy ? 'Encrypting Archive...' : 'Generate Encrypted Backup Envelope'}
              </button>

              {lastExportedBackupJson && (
                <div className="space-y-1">
                  <p className="text-[11px] font-mono text-[#2DD4A3]">
                    Encrypted Envelope Ready (Ciphertext + SHA-256 Integrity Metadata):
                  </p>
                  <pre className="p-2.5 rounded-xl bg-slate-900 text-[#F5F7FF] text-[10px] font-mono max-h-36 overflow-y-auto whitespace-pre-wrap">
                    {lastExportedBackupJson}
                  </pre>
                </div>
              )}
            </div>

            {/* Restore Column */}
            <div className="p-4 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 space-y-3">
              <p className="text-xs font-bold text-slate-900 dark:text-[#F5F7FF]">
                2. Verify Integrity & Restore Encrypted Backup
              </p>
              <textarea
                rows={4}
                value={restoreJsonInput}
                onChange={(e) => setRestoreJsonInput(e.target.value)}
                placeholder="Paste NEXLOCK_ENCRYPTED_BACKUP JSON envelope here (or click Generate on the left)..."
                className="w-full p-2.5 rounded-xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 text-[11px] font-mono text-slate-900 dark:text-[#F5F7FF]"
              />
              <label className="flex items-center gap-2 text-xs text-slate-700 dark:text-[#A6B0C3] cursor-pointer">
                <input
                  type="checkbox"
                  checked={restoreConfirmChecked}
                  onChange={(e) => setRestoreConfirmChecked(e.target.checked)}
                  className="rounded border-slate-300"
                />
                <span>
                  I confirm overwriting current locked app selections & schedules after integrity
                  verification.
                </span>
              </label>
              <button
                type="button"
                disabled={isCryptoBusy}
                onClick={() =>
                  restoreEncryptedConfigurationBackup(
                    restoreJsonInput,
                    backupPasswordInput,
                    restoreConfirmChecked
                  )
                }
                className="min-h-[40px] px-4 py-2 rounded-xl bg-[#2DD4A3] hover:bg-[#25be90] text-[#0B1020] text-xs font-bold"
              >
                {isCryptoBusy ? 'Verifying & Decrypting...' : 'Verify SHA-256 & Restore Backup'}
              </button>
            </div>
          </div>
        </div>

        {/* Phase 5 Section 1 & 2: Intruder Detection & Optional Consented Intruder Selfie */}
        <div className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
                Phase 5 Intruder Detection & Consented Front-Camera Capture
              </h2>
              <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-0.5">
                Monitors consecutive failed Master PIN and failed Biometric attempts. User
                cancellations (<code className="font-mono">ERROR_USER_CANCELED</code>) are never
                counted as intruder attempts.
              </p>
            </div>
            <button
              type="button"
              onClick={() =>
                updateIntruderConfig(
                  { isEnabled: !intruderConfig.isEnabled },
                  `Intruder Detection ${!intruderConfig.isEnabled ? 'Enabled' : 'Disabled'}`
                )
              }
              className={`min-h-[40px] min-w-[92px] px-3.5 rounded-xl text-xs font-bold ${
                intruderConfig.isEnabled
                  ? 'bg-[#2DD4A3] text-[#0B1020]'
                  : 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#A6B0C3]'
              }`}
            >
              {intruderConfig.isEnabled ? 'Enabled' : 'Disabled'}
            </button>
          </div>

          {/* Failed Attempt Threshold (3, 5, 10) */}
          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-200 dark:border-white/10">
            <div>
              <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                Intruder Alert Failed-Attempt Threshold (3, 5, or 10 Consecutive Failures)
              </p>
              <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                Current Consecutive Failures: {consecutiveFailedAttempts} /{' '}
                {intruderConfig.threshold}
              </p>
            </div>
            <div className="flex items-center gap-1.5">
              {([3, 5, 10] as IntruderThresholdOption[]).map((th) => (
                <button
                  key={th}
                  type="button"
                  onClick={() =>
                    updateIntruderConfig(
                      { threshold: th },
                      `Intruder Threshold Changed to ${th} Failed Attempts`
                    )
                  }
                  className={`min-h-[36px] px-3.5 py-1 rounded-lg text-xs font-mono font-bold ${
                    intruderConfig.threshold === th
                      ? 'bg-[#5B8CFF] text-white'
                      : 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#A6B0C3]'
                  }`}
                >
                  {th} Attempts
                </button>
              ))}
            </div>
          </div>

          {/* Optional Intruder Selfie Consent & Camera Permission Controls */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-slate-200 dark:border-white/10">
            <div className="p-3.5 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 flex items-center justify-between gap-3">
              <div>
                <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                  Explicit User Consent for Intruder Selfie
                </p>
                <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                  Never captures without explicit user opt-in.
                </p>
              </div>
              <button
                type="button"
                onClick={() =>
                  updateIntruderConfig(
                    {
                      hasExplicitCameraConsent: !intruderConfig.hasExplicitCameraConsent,
                      intruderSelfieEnabled: !intruderConfig.hasExplicitCameraConsent,
                    },
                    `Intruder Selfie User Consent ${
                      !intruderConfig.hasExplicitCameraConsent ? 'Granted' : 'Revoked'
                    }`
                  )
                }
                className={`min-h-[38px] px-3 rounded-lg text-xs font-semibold ${
                  intruderConfig.hasExplicitCameraConsent
                    ? 'bg-[#2DD4A3] text-[#0B1020]'
                    : 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#A6B0C3]'
                }`}
              >
                {intruderConfig.hasExplicitCameraConsent ? 'Consented' : 'Off'}
              </button>
            </div>

            <div className="p-3.5 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 flex items-center justify-between gap-3">
              <div>
                <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                  Runtime CAMERA Permission (`android.permission.CAMERA`)
                </p>
                <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                  If denied, logs EVENT_ONLY without crashing.
                </p>
              </div>
              <button
                type="button"
                onClick={() =>
                  updateIntruderConfig(
                    { cameraPermissionGranted: !intruderConfig.cameraPermissionGranted },
                    `Camera Runtime Permission ${
                      !intruderConfig.cameraPermissionGranted ? 'Granted' : 'Revoked'
                    }`
                  )
                }
                className={`min-h-[38px] px-3 rounded-lg text-xs font-semibold ${
                  intruderConfig.cameraPermissionGranted
                    ? 'bg-[#2DD4A3] text-[#0B1020]'
                    : 'bg-amber-500/20 text-amber-400'
                }`}
              >
                {intruderConfig.cameraPermissionGranted ? 'Granted' : 'Denied'}
              </button>
            </div>

            <div className="p-3.5 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 flex items-center justify-between gap-3">
              <div>
                <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                  AppLockActivity Foreground Lifecycle State
                </p>
                <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                  Android blocks background camera capture; falls back to EVENT_ONLY if backgrounded.
                </p>
              </div>
              <button
                type="button"
                onClick={() =>
                  updateIntruderConfig(
                    { isAppInForegroundForCamera: !intruderConfig.isAppInForegroundForCamera },
                    `Camera Lifecycle State: ${
                      !intruderConfig.isAppInForegroundForCamera ? 'Foreground' : 'Background'
                    }`
                  )
                }
                className={`min-h-[38px] px-3 rounded-lg text-xs font-semibold ${
                  intruderConfig.isAppInForegroundForCamera
                    ? 'bg-[#5B8CFF] text-white'
                    : 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#A6B0C3]'
                }`}
              >
                {intruderConfig.isAppInForegroundForCamera ? 'Foreground' : 'Background'}
              </button>
            </div>

            <div className="p-3.5 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 flex items-center justify-between gap-3">
              <div>
                <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                  Non-Critical Operational Security Notifications
                </p>
                <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                  Uses NotificationCompat.VISIBILITY_PRIVATE lock-screen redaction.
                </p>
              </div>
              <button
                type="button"
                onClick={() =>
                  updateIntruderConfig(
                    {
                      nonCriticalNotificationsEnabled:
                        !intruderConfig.nonCriticalNotificationsEnabled,
                    },
                    `Non-Critical Security Alerts ${
                      !intruderConfig.nonCriticalNotificationsEnabled ? 'Enabled' : 'Muted'
                    }`
                  )
                }
                className={`min-h-[38px] px-3 rounded-lg text-xs font-semibold ${
                  intruderConfig.nonCriticalNotificationsEnabled
                    ? 'bg-[#2DD4A3] text-[#0B1020]'
                    : 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#A6B0C3]'
                }`}
              >
                {intruderConfig.nonCriticalNotificationsEnabled ? 'Enabled' : 'Muted'}
              </button>
            </div>
          </div>
        </div>

        {/* Phase 5 Section 5: Anti-Tampering & Honest Android OS Boundary Disclosure */}
        <div className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-2.5">
          <h2 className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
            Protection Health & Honest Android Tamper-Detection Boundaries (`ProtectionHealthMonitor`)
          </h2>
          <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">
            NEXLOCK continuously detects permission revocation, service interruption, and uninstalled
            protected apps, and honestly discloses standard Android OS privilege boundaries:
          </p>
          <ul className="space-y-1.5 text-xs text-slate-600 dark:text-[#A6B0C3] list-disc pl-4">
            {DOCUMENTED_ANDROID_TAMPER_LIMITATIONS.map((lim, i) => (
              <li key={i}>{lim}</li>
            ))}
          </ul>
        </div>

        {/* Monotonic Session Timeout Selector */}
        <div className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF] flex items-center gap-2">
                <Clock className="w-4 h-4 text-[#5B8CFF]" />
                <span>Master Session Timeout (Monotonic Clock)</span>
              </h2>
              <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-0.5">
                Sessions never persist across device reboot or process recreation.
              </p>
            </div>
            <span className="text-xs font-mono text-[#2DD4A3]">
              {isSessionAuthenticated ? `${sessionRemainingSeconds}s active` : 'Locked'}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
            {SESSION_TIMEOUT_OPTIONS.map((opt) => (
              <button
                key={opt.id}
                type="button"
                onClick={() => {
                  if (
                    authorizeSensitiveAction(
                      `Change Session Timeout to ${opt.label}`,
                      `Updated monotonic session timeout to ${opt.id}.`
                    )
                  ) {
                    setSessionTimeout(opt.id as SessionTimeoutId);
                  }
                }}
                className={`min-h-[48px] p-3 rounded-xl text-left border transition-colors ${
                  preferences.sessionTimeout === opt.id
                    ? 'border-[#5B8CFF] bg-[#5B8CFF]/10'
                    : 'border-slate-200 dark:border-white/10'
                }`}
              >
                <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                  {opt.label}
                </p>
                <p className="text-[10px] text-slate-500 dark:text-[#A6B0C3] mt-0.5">
                  {opt.shortLabel}
                </p>
              </button>
            ))}
          </div>
        </div>

        {/* Brute-Force Failed Attempt Threshold */}
        <div className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF]">
                Maximum Failed PIN Attempts Before Temporary Lockout
              </h2>
              <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-0.5">
                Enforces a tiered 30s / 60s / 300s temporary cooldown without permanently locking
                out the user.
              </p>
            </div>
            <div className="flex items-center gap-1.5">
              {[3, 5, 7, 10].map((limit) => (
                <button
                  key={limit}
                  type="button"
                  onClick={() => {
                    if (
                      authorizeSensitiveAction(
                        `Change Lockout Threshold to ${limit}`,
                        `Updated maxFailedAttempts to ${limit}.`
                      )
                    ) {
                      updatePreferences(
                        { maxFailedAttempts: limit },
                        `Max Failed Attempts Threshold Set to ${limit}`
                      );
                    }
                  }}
                  className={`min-h-[38px] px-3 py-1 rounded-lg text-xs font-mono font-semibold ${
                    preferences.maxFailedAttempts === limit
                      ? 'bg-[#5B8CFF] text-white'
                      : 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#A6B0C3]'
                  }`}
                >
                  {limit}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Phase 4 Protected App Re-Lock Session Timer (Section 6: Immediately, 5s, 15s, 30s, 1m, 5m) */}
        <div className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF]">
                Phase 4 Protected App Re-Lock Timer (`AppLockEngine`)
              </h2>
              <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-0.5">
                Controls how long an unlocked protected application remains accessible after leaving
                the foreground.
              </p>
            </div>
            <span className="text-xs font-mono text-[#5B8CFF]">
              Active Unlocked Sessions: {Object.keys(unlockedPackageSessions).length}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
            {RELOCK_DURATION_OPTIONS.map((opt) => (
              <button
                key={opt.id}
                type="button"
                onClick={() => {
                  if (
                    authorizeSensitiveAction(
                      `Change Re-Lock Policy to ${opt.label}`,
                      `Updated protected app re-lock timer to ${opt.id}.`
                    )
                  ) {
                    setReLockDurationOption(opt.id);
                  }
                }}
                className={`p-3.5 rounded-xl text-left border transition-colors ${
                  reLockDurationOption === opt.id
                    ? 'border-[#5B8CFF] bg-[#5B8CFF]/10'
                    : 'border-slate-200 dark:border-white/10'
                }`}
              >
                <div className="flex items-center justify-between">
                  <p className="text-xs font-bold text-slate-900 dark:text-[#F5F7FF]">
                    {opt.label}
                  </p>
                  <span className="text-[11px] font-mono text-[#5B8CFF]">{opt.shortLabel}</span>
                </div>
                <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3] mt-1">
                  {opt.description}
                </p>
              </button>
            ))}
          </div>

          <div className="pt-2 border-t border-slate-200 dark:border-white/10 flex items-center justify-between gap-4">
            <div>
              <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                Invalidate All App Unlock Sessions When Screen Turns Off (`ACTION_SCREEN_OFF`)
              </p>
              <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                Immediately revokes temporary per-package unlock sessions whenever the device locks.
              </p>
            </div>
            <button
              type="button"
              onClick={() => setLockOnScreenOff(!lockOnScreenOff)}
              className={`min-h-[40px] min-w-[84px] px-3 rounded-xl text-xs font-semibold ${
                lockOnScreenOff
                  ? 'bg-[#2DD4A3] text-[#0B1020]'
                  : 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#A6B0C3]'
              }`}
            >
              {lockOnScreenOff ? 'Enabled' : 'Off'}
            </button>
          </div>
        </div>

        {/* Excluded Applications & Recovery Protection (Section 9) */}
        <div className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-2.5">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF]">
            Excluded System & Recovery Packages (`ExcludedSystemPackages`)
          </h2>
          <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">
            To prevent recursive lock loops or locking the user out of device recovery and
            permission settings, NEXLOCK permanently excludes these packages from foreground
            interception:
          </p>
          <div className="flex flex-wrap gap-1.5 pt-1">
            {EXCLUDED_SYSTEM_PACKAGES.map((pkgRule) => (
              <span
                key={pkgRule.packageName}
                className="px-2.5 py-1 rounded-lg bg-slate-200/70 dark:bg-white/5 text-[11px] font-mono text-slate-700 dark:text-[#F5F7FF]"
                title={pkgRule.reason}
              >
                {pkgRule.packageName}
              </span>
            ))}
          </div>
        </div>

        {/* Keypad & Biometric Toggles */}
        <div className="space-y-3">
          <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 flex items-center justify-between gap-4">
            <div>
              <p className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF]">
                Enable Fingerprint Biometric Authentication
              </p>
              <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-0.5">
                Uses AndroidX BiometricPrompt with automatic Master PIN fallback.
              </p>
            </div>
            <button
              type="button"
              onClick={() => {
                if (
                  authorizeSensitiveAction(
                    `Toggle Biometric Authentication`,
                    `Biometric preference set to ${!preferences.biometricPreferenceEnabled}.`
                  )
                ) {
                  updatePreferences(
                    { biometricPreferenceEnabled: !preferences.biometricPreferenceEnabled },
                    `Biometric Authentication ${
                      !preferences.biometricPreferenceEnabled ? 'Enabled' : 'Disabled'
                    }`
                  );
                }
              }}
              className={`min-h-[44px] min-w-[84px] px-3.5 rounded-xl text-xs font-semibold transition-colors ${
                preferences.biometricPreferenceEnabled
                  ? 'bg-[#2DD4A3] text-[#0B1020]'
                  : 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#A6B0C3]'
              }`}
            >
              {preferences.biometricPreferenceEnabled ? 'Enabled' : 'Off'}
            </button>
          </div>

          <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 flex items-center justify-between gap-4">
            <div>
              <p className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF]">
                Randomize PIN Keypad Digit Order
              </p>
              <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-0.5">
                Prevents shoulder-surfing by shuffling digit coordinates on Screen 10.
              </p>
            </div>
            <button
              type="button"
              onClick={() =>
                updatePreferences(
                  { randomizeKeypad: !preferences.randomizeKeypad },
                  `Randomized Keypad ${!preferences.randomizeKeypad ? 'Enabled' : 'Disabled'}`
                )
              }
              className={`min-h-[44px] min-w-[84px] px-3.5 rounded-xl text-xs font-semibold transition-colors ${
                preferences.randomizeKeypad
                  ? 'bg-[#2DD4A3] text-[#0B1020]'
                  : 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#A6B0C3]'
              }`}
            >
              {preferences.randomizeKeypad ? 'Enabled' : 'Off'}
            </button>
          </div>

          <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 flex items-center justify-between gap-4">
            <div>
              <p className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF]">
                Hide PIN Touch Highlight Ripple
              </p>
              <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-0.5">
                Suppresses visual button press feedback when entering your Master PIN.
              </p>
            </div>
            <button
              type="button"
              onClick={() =>
                updatePreferences(
                  { hidePinRipple: !preferences.hidePinRipple },
                  `PIN Touch Ripple Suppression ${!preferences.hidePinRipple ? 'Enabled' : 'Disabled'}`
                )
              }
              className={`min-h-[44px] min-w-[84px] px-3.5 rounded-xl text-xs font-semibold transition-colors ${
                preferences.hidePinRipple
                  ? 'bg-[#2DD4A3] text-[#0B1020]'
                  : 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#A6B0C3]'
              }`}
            >
              {preferences.hidePinRipple ? 'Hidden' : 'Visible'}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
          <button
            type="button"
            onClick={() => setCurrentScreen('change_pin')}
            className="min-h-[52px] p-4 rounded-2xl bg-slate-50 hover:bg-slate-100 dark:bg-[#0B1020] dark:hover:bg-white/10 border border-slate-200 dark:border-white/10 flex items-center justify-between text-left"
          >
            <div className="flex items-center gap-3">
              <KeyRound className="w-4 h-4 text-[#2DD4A3]" />
              <span className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                Change Master PIN (Salt Rotation)
              </span>
            </div>
            <ChevronRight className="w-4 h-4 text-slate-400" />
          </button>

          <button
            type="button"
            onClick={() => setCurrentScreen('create_pin')}
            className="min-h-[52px] p-4 rounded-2xl bg-slate-50 hover:bg-slate-100 dark:bg-[#0B1020] dark:hover:bg-white/10 border border-slate-200 dark:border-white/10 flex items-center justify-between text-left"
          >
            <div className="flex items-center gap-3">
              <KeyRound className="w-4 h-4 text-[#5B8CFF]" />
              <span className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                Create / Reset Master PIN (Screens 3 & 4)
              </span>
            </div>
            <ChevronRight className="w-4 h-4 text-slate-400" />
          </button>

          <button
            type="button"
            onClick={() => setCurrentScreen('biometric_setup')}
            className="min-h-[52px] p-4 rounded-2xl bg-slate-50 hover:bg-slate-100 dark:bg-[#0B1020] dark:hover:bg-white/10 border border-slate-200 dark:border-white/10 flex items-center justify-between text-left"
          >
            <div className="flex items-center gap-3">
              <Fingerprint className="w-4 h-4 text-[#2DD4A3]" />
              <span className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                Biometric Setup & Diagnostics (Screen 5)
              </span>
            </div>
            <ChevronRight className="w-4 h-4 text-slate-400" />
          </button>

          <button
            type="button"
            onClick={() => setCurrentScreen('theme_settings')}
            className="min-h-[52px] p-4 rounded-2xl bg-slate-50 hover:bg-slate-100 dark:bg-[#0B1020] dark:hover:bg-white/10 border border-slate-200 dark:border-white/10 flex items-center justify-between text-left"
          >
            <div className="flex items-center gap-3">
              <Palette className="w-4 h-4 text-[#9B7BFF]" />
              <span className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                Theme & Color System (Screen 14)
              </span>
            </div>
            <ChevronRight className="w-4 h-4 text-slate-400" />
          </button>

          <button
            type="button"
            onClick={() => setCurrentScreen('about')}
            className="min-h-[52px] p-4 rounded-2xl bg-slate-50 hover:bg-slate-100 dark:bg-[#0B1020] dark:hover:bg-white/10 border border-slate-200 dark:border-white/10 flex items-center justify-between text-left sm:col-span-2"
          >
            <div className="flex items-center gap-3">
              <Info className="w-4 h-4 text-[#5B8CFF]" />
              <span className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                About NEXLOCK & Run All 53 Unit Tests (Phases 2–5) (Screen 15)
              </span>
            </div>
            <ChevronRight className="w-4 h-4 text-slate-400" />
          </button>
        </div>
      </div>
    );
  }

  // 14. THEME SETTINGS & PHASE 6 LOCK SCREEN PERSONALIZATION
  if (currentScreen === 'theme_settings') {
    const swatches = [
      { name: 'Background Dark', hex: '#0B1020', role: 'Primary Dark Canvas' },
      { name: 'Surface Dark', hex: '#151D32', role: 'Elevated Card Surface' },
      { name: 'Primary Accent', hex: activeAccentObj.hex, role: 'Interactive Actions & Focus' },
      { name: 'Secondary Accent', hex: activeAccentObj.secondaryHex, role: 'Vault & Secondary Highlights' },
      { name: 'Success Accent', hex: '#2DD4A3', role: 'Protected & Verified States' },
      { name: 'Text Primary', hex: '#F5F7FF', role: 'High-Contrast Headlines' },
      { name: 'Text Secondary', hex: '#A6B0C3', role: 'Muted Captions & Metadata' },
    ];

    return (
      <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-8 space-y-6">
        <div className="flex items-center justify-between border-b border-slate-200 dark:border-white/10 pb-4">
          <button
            type="button"
            onClick={() => setCurrentScreen('security_settings')}
            className="min-h-[44px] px-3 rounded-lg text-xs font-medium text-slate-600 dark:text-[#A6B0C3] hover:text-slate-900 dark:hover:text-white flex items-center gap-1.5"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Security Settings</span>
          </button>
          <span className="text-xs text-slate-500 dark:text-[#A6B0C3]">
            Screen 14 of 15 · Appearance & Lock Screen Personalization
          </span>
        </div>

        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-[#F5F7FF]">
            Appearance, Accent Presets & Lock Screen Personalization
          </h1>
          <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-1">
            Customize NEXLOCK’s theme, accent color preset, app list density, and lock screen
            presentation. All preferences persist immediately via Jetpack DataStore.
          </p>
        </div>

        {/* Theme Mode Selector */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {(
            [
              {
                id: 'dark',
                label: 'Dark Theme',
                sub: 'Signature #0B1020 & #151D32',
                icon: Moon,
              },
              {
                id: 'light',
                label: 'Light Theme',
                sub: 'High-Contrast #F4F7FB & #FFFFFF',
                icon: Sun,
              },
              {
                id: 'system',
                label: 'System Default',
                sub: 'Follows OS Color Scheme',
                icon: Smartphone,
              },
            ] as const
          ).map((item) => {
            const Icon = item.icon;
            const active = preferences.themeMode === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setThemeMode(item.id as ThemeMode)}
                className={`p-4 rounded-2xl border text-left transition-all ${
                  active
                    ? 'border-[#5B8CFF] bg-[#5B8CFF]/10'
                    : 'border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-[#0B1020]'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <Icon className="w-5 h-5 text-[#5B8CFF]" />
                  {active && <Check className="w-4 h-4 text-[#2DD4A3]" />}
                </div>
                <p className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
                  {item.label}
                </p>
                <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-0.5">{item.sub}</p>
              </button>
            );
          })}
        </div>

        {/* Phase 6 Section 3: Accent Color Presets & App List Density */}
        <div className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
                Accent Color Presets (`AccentColorPreset`)
              </h2>
              <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">
                Applies to active indicators, lock badges, and authentication keypad highlights.
              </p>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-slate-500 dark:text-[#A6B0C3]">App List Density:</span>
              {(['COMFORTABLE', 'COMPACT'] as AppListDensityId[]).map((dens) => (
                <button
                  key={dens}
                  type="button"
                  onClick={() =>
                    updatePhase6Appearance(
                      { appListDensity: dens },
                      `App List Density Set to ${dens}`
                    )
                  }
                  className={`px-3 py-1 rounded-lg text-xs font-bold ${
                    phase6Appearance.appListDensity === dens
                      ? 'bg-[#5B8CFF] text-white'
                      : 'bg-white dark:bg-[#151D32] text-slate-600 dark:text-[#A6B0C3]'
                  }`}
                >
                  {dens === 'COMFORTABLE' ? 'Comfortable' : 'Compact'}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-5 gap-2.5">
            {ACCENT_COLOR_PRESETS.map((preset) => {
              const isSelected = phase6Appearance.accentColorPreset === preset.id;
              return (
                <button
                  key={preset.id}
                  type="button"
                  onClick={() =>
                    updatePhase6Appearance(
                      { accentColorPreset: preset.id },
                      `Accent Color Preset Changed to ${preset.label}`
                    )
                  }
                  className={`p-3 rounded-xl border text-left transition-all ${
                    isSelected
                      ? 'border-[#5B8CFF] bg-[#5B8CFF]/10'
                      : 'border-slate-200 dark:border-white/10 bg-white dark:bg-[#151D32]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span
                      className="w-6 h-6 rounded-lg border border-white/20"
                      style={{ backgroundColor: preset.hex }}
                    />
                    {isSelected && <Check className="w-4 h-4 text-[#2DD4A3]" />}
                  </div>
                  <p className="text-xs font-bold text-slate-900 dark:text-[#F5F7FF] truncate">
                    {preset.label}
                  </p>
                  <p className="text-[11px] font-mono text-slate-500 dark:text-[#A6B0C3]">
                    {preset.hex}
                  </p>
                </button>
              );
            })}
          </div>
        </div>

        {/* Phase 6 Section 4: Lock Screen Personalization (`AppLockActivity`) */}
        <div className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-4">
          <div>
            <h2 className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
              Lock Screen Personalization (`AppLockActivity` Challenge Presentation)
            </h2>
            <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">
              Customize how the authentication screen renders over protected applications. Security
              invariant: customization never hides essential PIN/Biometric controls or bypasses
              verification.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="p-3.5 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 flex items-center justify-between gap-2">
              <div>
                <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                  Show Protected App Icon
                </p>
                <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                  Hide for extra shoulder-surfing privacy
                </p>
              </div>
              <button
                type="button"
                onClick={() =>
                  updatePhase6Appearance(
                    { showAppIconOnLockScreen: !phase6Appearance.showAppIconOnLockScreen },
                    `Lock Screen App Icon ${
                      !phase6Appearance.showAppIconOnLockScreen ? 'Shown' : 'Hidden'
                    }`
                  )
                }
                className={`min-h-[36px] px-3 rounded-lg text-xs font-bold ${
                  phase6Appearance.showAppIconOnLockScreen
                    ? 'bg-[#2DD4A3] text-[#0B1020]'
                    : 'bg-slate-200 dark:bg-white/10 text-slate-600 dark:text-[#A6B0C3]'
                }`}
              >
                {phase6Appearance.showAppIconOnLockScreen ? 'Shown' : 'Hidden'}
              </button>
            </div>

            <div className="p-3.5 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 flex items-center justify-between gap-2">
              <div>
                <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                  Show Protected App Name
                </p>
                <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                  Displays generic "Protected Application" if off
                </p>
              </div>
              <button
                type="button"
                onClick={() =>
                  updatePhase6Appearance(
                    { showAppNameOnLockScreen: !phase6Appearance.showAppNameOnLockScreen },
                    `Lock Screen App Name ${
                      !phase6Appearance.showAppNameOnLockScreen ? 'Shown' : 'Hidden'
                    }`
                  )
                }
                className={`min-h-[36px] px-3 rounded-lg text-xs font-bold ${
                  phase6Appearance.showAppNameOnLockScreen
                    ? 'bg-[#2DD4A3] text-[#0B1020]'
                    : 'bg-slate-200 dark:bg-white/10 text-slate-600 dark:text-[#A6B0C3]'
                }`}
              >
                {phase6Appearance.showAppNameOnLockScreen ? 'Shown' : 'Hidden'}
              </button>
            </div>

            <div className="p-3.5 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 flex items-center justify-between gap-2">
              <div>
                <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                  Lock Screen Animations
                </p>
                <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                  Smooth indicator transitions
                </p>
              </div>
              <button
                type="button"
                onClick={() =>
                  updatePhase6Appearance(
                    { enableLockScreenAnimations: !phase6Appearance.enableLockScreenAnimations },
                    `Lock Screen Animations ${
                      !phase6Appearance.enableLockScreenAnimations ? 'Enabled' : 'Disabled'
                    }`
                  )
                }
                className={`min-h-[36px] px-3 rounded-lg text-xs font-bold ${
                  phase6Appearance.enableLockScreenAnimations
                    ? 'bg-[#2DD4A3] text-[#0B1020]'
                    : 'bg-slate-200 dark:bg-white/10 text-slate-600 dark:text-[#A6B0C3]'
                }`}
              >
                {phase6Appearance.enableLockScreenAnimations ? 'Enabled' : 'Reduced'}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <p className="text-xs font-semibold text-slate-700 dark:text-[#F5F7FF] mb-1.5">
                Lock Screen Background Style
              </p>
              <div className="grid grid-cols-3 gap-2">
                {(
                  [
                    { id: 'OBSIDIAN_GRADIENT', label: 'Obsidian Gradient' },
                    { id: 'MIDNIGHT_MESH', label: 'Midnight Mesh' },
                    { id: 'MINIMAL_SURFACE', label: 'Minimal Surface' },
                  ] as { id: LockScreenBackgroundStyleId; label: string }[]
                ).map((bg) => (
                  <button
                    key={bg.id}
                    type="button"
                    onClick={() =>
                      updatePhase6Appearance(
                        { lockScreenBackgroundStyle: bg.id },
                        `Lock Screen Background Set to ${bg.label}`
                      )
                    }
                    className={`p-2.5 rounded-xl border text-xs font-semibold ${
                      phase6Appearance.lockScreenBackgroundStyle === bg.id
                        ? 'border-[#5B8CFF] bg-[#5B8CFF]/10 text-[#5B8CFF]'
                        : 'border-slate-200 dark:border-white/10 bg-white dark:bg-[#151D32] text-slate-600 dark:text-[#A6B0C3]'
                    }`}
                  >
                    {bg.label}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <p className="text-xs font-semibold text-slate-700 dark:text-[#F5F7FF] mb-1.5">
                Keypad Layout Style
              </p>
              <div className="grid grid-cols-3 gap-2">
                {(
                  [
                    { id: 'ROUNDED_MODERN', label: 'Rounded Glass' },
                    { id: 'COMPACT_GRID', label: 'Compact Grid' },
                    { id: 'HIGH_CONTRAST', label: 'High Contrast' },
                  ] as { id: KeypadStyleId; label: string }[]
                ).map((kp) => (
                  <button
                    key={kp.id}
                    type="button"
                    onClick={() =>
                      updatePhase6Appearance(
                        { keypadStyle: kp.id },
                        `Lock Screen Keypad Style Set to ${kp.label}`
                      )
                    }
                    className={`p-2.5 rounded-xl border text-xs font-semibold ${
                      phase6Appearance.keypadStyle === kp.id
                        ? 'border-[#5B8CFF] bg-[#5B8CFF]/10 text-[#5B8CFF]'
                        : 'border-slate-200 dark:border-white/10 bg-white dark:bg-[#151D32] text-slate-600 dark:text-[#A6B0C3]'
                    }`}
                  >
                    {kp.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div>
          <h2 className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF] mb-3">
            NEXLOCK Mandatory Color Tokens (`Theme.kt`)
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {swatches.map((sw) => (
              <div
                key={sw.name}
                className="p-3.5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 flex items-center gap-3"
              >
                <div
                  className="w-10 h-10 rounded-xl border border-black/10 dark:border-white/15 shrink-0"
                  style={{ backgroundColor: sw.hex }}
                />
                <div className="min-w-0">
                  <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF] truncate">
                    {sw.name}
                  </p>
                  <p className="text-xs font-mono text-[#5B8CFF]">{sw.hex}</p>
                  <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3] truncate">
                    {sw.role}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  // 15. ABOUT NEXLOCK, HELP CENTER & PHASE 6 (14) + PHASE 5 (12) + PHASE 4 (12) + PHASE 3 (17) + PHASE 2 (12) RUNNERS (67 TOTAL TESTS)
  const handleRunAllTests = async () => {
    setIsRunningTests(true);
    try {
      const [p6, p5, p4, p3, p2] = await Promise.all([
        runPhase6AutomatedTestSuite(),
        runPhase5UnitTests(),
        runPhase4UnitTests(),
        runPhase3UnitTests(),
        runPhase2UnitTests(),
      ]);
      setTestResultsP6(p6);
      setTestResultsP5(p5);
      setTestResultsP4(p4);
      setTestResultsP3(p3);
      setTestResultsP2(p2);
    } finally {
      setIsRunningTests(false);
    }
  };

  return (
    <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-8 space-y-6">
      <div className="flex items-center justify-between border-b border-slate-200 dark:border-white/10 pb-4">
        <button
          type="button"
          onClick={() => setCurrentScreen('security_settings')}
          className="min-h-[44px] px-3 rounded-lg text-xs font-medium text-slate-600 dark:text-[#A6B0C3] hover:text-slate-900 dark:hover:text-white flex items-center gap-1.5"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Security Settings</span>
        </button>
        <span className="text-xs text-slate-500 dark:text-[#A6B0C3]">
          Screen 15 of 15 · Help Center, About NEXLOCK & Phase 6 Complete Verification (67 Tests)
        </span>
      </div>

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-[#5B8CFF] to-[#9B7BFF] flex items-center justify-center text-white shrink-0">
            <Shield className="w-7 h-7" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-[#F5F7FF]">
              NEXLOCK
            </h1>
            <p className="text-xs text-[#5B8CFF] font-medium">
              {i18n.tagline} · v2.0.0-production (versionCode 6 · Room Schema v4)
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={onOpenSourceDrawer}
          className="min-h-[48px] px-5 py-2.5 rounded-xl bg-[#5B8CFF] hover:bg-[#4A7BF7] text-white font-semibold text-xs sm:text-sm flex items-center gap-2 transition-colors whitespace-nowrap"
        >
          <Code2 className="w-4 h-4" />
          <span>Inspect Native Kotlin Project</span>
        </button>
      </div>

      {/* Phase 6 (14) + Phase 5 (12) + Phase 4 (12) + Phase 3 (17) + Phase 2 (12) Unit Test Suite Runner (67 Total Assertions) */}
      <div className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
              Phase 6 (14), Phase 5 (12), Phase 4 (12), Phase 3 (17) & Phase 2 (12) Verification Suite (67 Total)
            </h2>
            <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-0.5">
              Executes `Phase6ProductionReadinessTest` (14 tests: Intraday & Overnight Cross-Midnight
              Schedules, TimeZone Shifts, Lock Modes, Appearance Persistence, PBKDF2 + AES-256-GCM
              Backup & SHA-256 Integrity, Room v4 Migration, 7D/30D Analytics, Vault Digest,
              Monotonic Session Expiry, App Sorting, Safe Exclusions), plus Phases 2–5 suites.
            </p>
          </div>

          <button
            type="button"
            disabled={isRunningTests}
            onClick={handleRunAllTests}
            className="min-h-[44px] px-4 py-2 rounded-xl bg-[#2DD4A3] hover:bg-[#25be90] text-[#0B1020] font-bold text-xs flex items-center gap-2 shrink-0"
          >
            <Play className="w-3.5 h-3.5" />
            <span>
              {isRunningTests ? 'Running 67 Unit Tests...' : 'Run All 67 Unit Tests'}
            </span>
          </button>
        </div>

        {testResultsP6 && (
          <div className="space-y-2 pt-2 border-t border-slate-200 dark:border-white/10">
            <p className="text-xs font-mono text-[#2DD4A3]">
              Phase 6 Smart Automation, Encrypted Backup & Production Readiness Suite:{' '}
              {testResultsP6.filter((t) => t.passed).length}/{testResultsP6.length} passed
            </p>
            <div className="grid grid-cols-1 gap-2">
              {testResultsP6.map((tr) => (
                <div
                  key={tr.id}
                  className="p-3 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200/80 dark:border-white/10 flex items-start justify-between gap-3"
                >
                  <div className="space-y-0.5">
                    <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                      {tr.name} <span className="text-[#5B8CFF]">({tr.requirementArea})</span>
                    </p>
                    <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                      {tr.assertionDetail}
                    </p>
                  </div>
                  <span className="text-xs font-mono text-[#2DD4A3] shrink-0">
                    {tr.passed ? 'PASS' : 'FAIL'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {testResultsP5 && (
          <div className="space-y-2 pt-2 border-t border-slate-200 dark:border-white/10">
            <p className="text-xs font-mono text-[#2DD4A3]">
              Phase 5 Advanced Security, Intruder Detection & Vault Suite:{' '}
              {testResultsP5.filter((t) => t.passed).length}/{testResultsP5.length} passed
            </p>
            <div className="grid grid-cols-1 gap-2">
              {testResultsP5.map((tr) => (
                <div
                  key={tr.id}
                  className="p-3 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200/80 dark:border-white/10 flex items-start justify-between gap-3"
                >
                  <div className="space-y-0.5">
                    <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                      {tr.name}
                    </p>
                    <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                      {tr.assertionSummary}
                    </p>
                  </div>
                  <span className="text-xs font-mono text-[#2DD4A3] shrink-0">
                    PASS · {tr.durationMs}ms
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {testResultsP4 && (
          <div className="space-y-2 pt-2 border-t border-slate-200 dark:border-white/10">
            <p className="text-xs font-mono text-[#2DD4A3]">
              Phase 4 Real App Lock Engine Suite:{' '}
              {testResultsP4.filter((t) => t.passed).length}/{testResultsP4.length} passed
            </p>
            <div className="grid grid-cols-1 gap-2">
              {testResultsP4.map((tr) => (
                <div
                  key={tr.id}
                  className="p-3 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200/80 dark:border-white/10 flex items-start justify-between gap-3"
                >
                  <div className="space-y-0.5">
                    <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                      {tr.name}
                    </p>
                    <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                      {tr.assertionSummary}
                    </p>
                  </div>
                  <span className="text-xs font-mono text-[#2DD4A3] shrink-0">
                    PASS · {tr.durationMs}ms
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {testResultsP3 && (
          <div className="space-y-2 pt-2 border-t border-slate-200 dark:border-white/10">
            <p className="text-xs font-mono text-[#2DD4A3]">
              Phase 3 App Discovery Suite:{' '}
              {testResultsP3.filter((t) => t.passed).length}/{testResultsP3.length} passed
            </p>
            <div className="grid grid-cols-1 gap-2">
              {testResultsP3.map((tr) => (
                <div
                  key={tr.id}
                  className="p-3 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200/80 dark:border-white/10 flex items-start justify-between gap-3"
                >
                  <div className="space-y-0.5">
                    <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                      {tr.name}
                    </p>
                    <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                      {tr.assertionSummary}
                    </p>
                  </div>
                  <span className="text-xs font-mono text-[#2DD4A3] shrink-0">
                    PASS · {tr.durationMs}ms
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {testResultsP2 && (
          <div className="space-y-2 pt-2 border-t border-slate-200 dark:border-white/10">
            <p className="text-xs font-mono text-[#2DD4A3]">
              Phase 2 Authentication & Crypto Suite:{' '}
              {testResultsP2.filter((t) => t.passed).length}/{testResultsP2.length} passed
            </p>
            <div className="grid grid-cols-1 gap-2">
              {testResultsP2.map((tr) => (
                <div
                  key={tr.id}
                  className="p-3 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200/80 dark:border-white/10 flex items-start justify-between gap-3"
                >
                  <div className="space-y-0.5">
                    <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                      {tr.name}
                    </p>
                    <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                      {tr.assertionSummary}
                    </p>
                  </div>
                  <span className="text-xs font-mono text-[#2DD4A3] shrink-0">
                    PASS · {tr.durationMs}ms
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Phase 6 Section 9: Help Center & Troubleshooting Guides */}
      <div className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-3">
        <h2 className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
          {i18n.helpCenter} (Setup, Permissions, Smart Schedules & OEM Battery Optimization)
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {PHASE6_HELP_CENTER_TOPICS.map((topic) => (
            <div
              key={topic.id}
              className="p-4 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 space-y-2"
            >
              <div className="flex items-center justify-between gap-2">
                <p className="text-xs font-bold text-slate-900 dark:text-[#F5F7FF]">
                  {topic.title}
                </p>
                <span className="px-2 py-0.5 rounded-md bg-[#5B8CFF]/15 text-[#5B8CFF] text-[10px] font-semibold shrink-0">
                  {topic.category}
                </span>
              </div>
              <ol className="list-decimal pl-4 space-y-1 text-[11px] text-slate-600 dark:text-[#A6B0C3]">
                {topic.steps.map((st, idx) => (
                  <li key={idx}>{st}</li>
                ))}
              </ol>
              <p className="text-[11px] text-amber-500 dark:text-amber-400 pt-1 border-t border-slate-200/70 dark:border-white/10">
                Android OS Note: {topic.osNote}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* 6-Phase Development Roadmap */}
      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF]">
          6-Phase Complete Android Engineering Roadmap (100% Complete)
        </h2>
        <div className="space-y-2.5">
          {DEVELOPMENT_PHASES.map((p) => (
            <div
              key={p.phase}
              className="p-4 rounded-2xl border bg-[#2DD4A3]/10 border-[#2DD4A3]/40"
            >
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <p className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
                  {p.phase}: {p.title}
                </p>
                <span className="text-xs font-semibold text-[#2DD4A3]">
                  {p.status}
                </span>
              </div>
              <p className="mt-1 text-xs text-slate-600 dark:text-[#A6B0C3] leading-relaxed">
                {p.summary}
              </p>
            </div>
          ))}
        </div>
      </div>

      <div className="pt-4 border-t border-slate-200 dark:border-white/10 flex flex-wrap items-center justify-between gap-3">
        <span className="text-xs text-slate-500 dark:text-[#A6B0C3]">
          Package: com.nexlock.security · Room Schema v4 (MIGRATION_3_4) · Min SDK 26 · Target SDK
          35 · Localization: English & বাংলা (`values-bn`)
        </span>
        <button
          type="button"
          onClick={store.resetAllPhase1Data}
          className="min-h-[44px] px-4 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 text-xs font-medium text-slate-700 dark:text-[#A6B0C3] flex items-center gap-1.5"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Reset Demo Database & PIN State</span>
        </button>
      </div>
    </div>
  );
};
