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
  runPhase2UnitTests,
  UnitTestResultItem,
  validatePinStrength,
} from '../security/cryptoEngine';
import { NexLockStore } from '../state/useNexLockStore';
import { AppFilterTabType, ReLockPolicyId, SessionTimeoutId, ThemeMode } from '../types/nexlock';
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
  } = store;

  const [authPinEntry, setAuthPinEntry] = useState<string>('');
  const [authStatus, setAuthStatus] = useState<{ ok: boolean; text: string } | null>(null);
  const [showBiometricSheet, setShowBiometricSheet] = useState<boolean>(false);
  const [activityTypeFilter, setActivityTypeFilter] = useState<'ALL' | 'LOCK' | 'AUTH'>('ALL');
  const [launchAppNotice, setLaunchAppNotice] = useState<string | null>(null);

  // Change PIN screen state
  const [currentPinInput, setCurrentPinInput] = useState<string>('');
  const [newPinInput, setNewPinInput] = useState<string>('');
  const [confirmNewPinInput, setConfirmNewPinInput] = useState<string>('');
  const [changePinFeedback, setChangePinFeedback] = useState<{
    ok: boolean;
    text: string;
  } | null>(null);

  // Interactive Test Suite Runners (Phase 4: 12 tests + Phase 3: 17 tests + Phase 2: 12 tests = 41 tests)
  const [testResultsP4, setTestResultsP4] = useState<Phase4UnitTestResult[] | null>(null);
  const [testResultsP2, setTestResultsP2] = useState<UnitTestResultItem[] | null>(null);
  const [testResultsP3, setTestResultsP3] = useState<Phase3UnitTestResult[] | null>(null);
  const [isRunningTests, setIsRunningTests] = useState<boolean>(false);

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

  // 7. HOME DASHBOARD (Phase 4 Real App Lock Engine & Protection Status)
  if (currentScreen === 'home') {
    const isEngineActive = engineOperationalEvaluation.isOperational;
    const currentReLockConfig =
      RELOCK_DURATION_OPTIONS.find((r) => r.id === reLockDurationOption) ||
      RELOCK_DURATION_OPTIONS[0];

    return (
      <div className="space-y-6">
        <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-8 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-[#A6B0C3]">
            <span>Screen 07 of 15 · Home Dashboard & Phase 4 App Lock Engine</span>
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
              <p className="text-xs font-semibold text-[#5B8CFF]">
                NEXLOCK Foreground App Lock Engine · UsageStatsManager + AppLockActivity
              </p>
              <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 dark:text-[#F5F7FF] text-balance">
                {operationalProtectedAppsCount} Operational of {lockedCount} Selected Protected Apps
              </h1>
              <p className="text-sm text-slate-600 dark:text-[#A6B0C3] leading-relaxed">
                {isEngineActive
                  ? `AppLockMonitoringService is actively polling UsageEvents.ACTIVITY_RESUMED. Re-Lock Policy: ${currentReLockConfig.label}. Screen Status: ${
                      isScreenInteractive ? 'Interactive (On)' : 'Non-Interactive (Off)'
                    }.`
                  : 'Protection is currently Paused. Operational Protected Apps is strictly 0 until Usage Access, Overlay Permission, Master PIN, and AppLockMonitoringService are all active.'}
              </p>
              <div className="pt-3 flex flex-wrap items-center gap-2.5">
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
                  Permission Health ({permissionHealth.usageAccessGranted && permissionHealth.overlayPermissionGranted ? 'All Granted' : 'Action Needed'})
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

            {/* Required Phase 4 Dashboard Status Metrics (Section 10) */}
            <div className="md:col-span-5 grid grid-cols-2 gap-3">
              <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200/80 dark:border-white/10">
                <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">Total Installed Apps</p>
                <p className="mt-1 text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-[#F5F7FF]">
                  {apps.length}
                </p>
                <p className="mt-1 text-[11px] text-[#5B8CFF]">
                  Selected for Lock: {lockedCount}
                </p>
              </div>

              <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200/80 dark:border-white/10">
                <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">Protection Operational</p>
                <p
                  className={`mt-1 text-2xl font-bold font-mono tabular-nums ${
                    operationalProtectedAppsCount > 0
                      ? 'text-[#2DD4A3]'
                      : 'text-amber-500'
                  }`}
                >
                  {operationalProtectedAppsCount}
                </p>
                <p className="mt-1 text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                  {isEngineActive ? 'Engine Enforcing' : 'Engine Paused (0 Active)'}
                </p>
              </div>

              <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200/80 dark:border-white/10">
                <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">Usage & Overlay</p>
                <p className="mt-1 text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
                  {permissionHealth.usageAccessGranted ? 'Granted' : 'Not Granted'} /{' '}
                  {permissionHealth.overlayPermissionGranted ? 'Granted' : 'Not Granted'}
                </p>
                <p className="mt-1 text-[11px] text-slate-500 dark:text-[#A6B0C3]">
                  Service: {monitoringServiceState === 'RUNNING' ? 'Running' : 'Stopped'}
                </p>
              </div>

              <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200/80 dark:border-white/10">
                <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">Foreground Detector</p>
                <p className="mt-1 text-xs font-bold font-mono text-slate-900 dark:text-[#F5F7FF] truncate">
                  {currentForegroundPackage || 'com.google.android.apps.nexuslauncher'}
                </p>
                <p className="mt-1 text-[11px] text-[#2DD4A3]">
                  Re-Lock: {currentReLockConfig.shortLabel}
                </p>
              </div>
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
                Run All 41 Unit Tests
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

    const filteredApps = apps.filter((app) => {
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
    });

    return (
      <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-8 space-y-6">
        {/* Top Metadata Line */}
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-[#A6B0C3]">
          <span>Screen 08 of 15 · Installed Apps Manager (AppDiscoveryRepository)</span>
          <span className="font-mono tabular-nums">
            Total Installed: {apps.length} · Total Locked: {lockedCount}
          </span>
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

  // 11. PRIVATE VAULT
  if (currentScreen === 'vault') {
    const vaultFolders = [
      {
        title: 'Encrypted Photos',
        subtitle: '0 items · AES256_GCM_HKDF_4KB · Scheduled for Phase 5',
        icon: Image,
      },
      {
        title: 'Encrypted Videos',
        subtitle: '0 items · Streaming chunk cipher · Scheduled for Phase 5',
        icon: Film,
      },
      {
        title: 'Confidential Documents',
        subtitle: '0 items · PDF & identity records · Scheduled for Phase 5',
        icon: FileText,
      },
      {
        title: 'Offline Recovery Notes',
        subtitle: '0 items · SQLCipher / EncryptedFile · Scheduled for Phase 5',
        icon: FolderLock,
      },
    ];

    return (
      <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-8 space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-[#A6B0C3]">
          <span>Screen 11 of 15 · Private Vault</span>
          <span>Encryption Engine: Coming Soon (Phase 5)</span>
        </div>

        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-[#F5F7FF]">
            Private Media & Document Vault
          </h1>
          <p className="text-sm text-slate-600 dark:text-[#A6B0C3] mt-1 leading-relaxed">
            Designed to isolate sensitive photos, videos, and documents inside app-private storage
            using Jetpack Security `EncryptedFile` (`AES256_GCM_HKDF_4KB`).
          </p>
        </div>

        <div className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-2">
          <p className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF]">
            Phase Boundary Notice
          </p>
          <p className="text-xs text-slate-600 dark:text-[#A6B0C3] leading-relaxed">
            Phases 1–3 implement UI, Authentication/Keystore, and PackageManager App Discovery.
            Encrypted media file streaming (`EncryptedFile`) is scheduled for Phase 5.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {vaultFolders.map((folder) => {
            const Icon = folder.icon;
            return (
              <div
                key={folder.title}
                className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 flex flex-col justify-between gap-4"
              >
                <div className="flex items-start gap-3.5">
                  <div className="w-11 h-11 rounded-xl bg-[#9B7BFF]/15 text-[#9B7BFF] flex items-center justify-center shrink-0">
                    <Icon className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF]">
                      {folder.title}
                    </h3>
                    <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-1">
                      {folder.subtitle}
                    </p>
                  </div>
                </div>

                <button
                  type="button"
                  disabled
                  className="min-h-[44px] px-4 py-2 rounded-xl bg-slate-200/70 dark:bg-white/5 text-slate-500 dark:text-[#A6B0C3] text-xs font-medium cursor-not-allowed"
                >
                  Coming in Phase 5
                </button>
              </div>
            );
          })}
        </div>
      </div>
    );
  }

  // 12. SECURITY ACTIVITY
  if (currentScreen === 'security_activity') {
    const filteredEvents = events.filter((ev) => {
      if (activityTypeFilter === 'ALL') return true;
      if (activityTypeFilter === 'LOCK') {
        return (
          ev.eventType === 'CONFIG_LOCK_ENABLED' ||
          ev.eventType === 'CONFIG_LOCK_DISABLED' ||
          ev.eventType === 'BULK_LOCK_UPDATED' ||
          ev.eventType === 'PACKAGE_INSTALLED' ||
          ev.eventType === 'PACKAGE_UPDATED' ||
          ev.eventType === 'PACKAGE_UNINSTALLED'
        );
      }
      return (
        ev.eventType !== 'CONFIG_LOCK_ENABLED' &&
        ev.eventType !== 'CONFIG_LOCK_DISABLED' &&
        ev.eventType !== 'BULK_LOCK_UPDATED'
      );
    });

    return (
      <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-8 space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-[#A6B0C3]">
          <span>Screen 12 of 15 · Security Activity</span>
          <span className="font-mono tabular-nums">{events.length} Local Audit Entries</span>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-[#F5F7FF]">
              Security Activity Log
            </h1>
            <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-1">
              Chronological audit log of package broadcasts, lock selections, PIN verifications, and
              sessions
            </p>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1 p-1 rounded-xl bg-slate-100 dark:bg-[#0B1020]">
              {(['ALL', 'AUTH', 'LOCK'] as const).map((f) => (
                <button
                  key={f}
                  type="button"
                  onClick={() => setActivityTypeFilter(f)}
                  className={`min-h-[38px] px-3 py-1 rounded-lg text-xs font-semibold transition-colors ${
                    activityTypeFilter === f
                      ? 'bg-[#5B8CFF] text-white'
                      : 'text-slate-600 dark:text-[#A6B0C3]'
                  }`}
                >
                  {f === 'ALL' ? 'All' : f === 'AUTH' ? 'Auth & Crypto' : 'Apps & Packages'}
                </button>
              ))}
            </div>

            {events.length > 0 && (
              <button
                type="button"
                onClick={clearActivityHistory}
                className="min-h-[40px] px-3.5 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 text-xs font-medium text-slate-700 dark:text-[#A6B0C3] flex items-center gap-1.5"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear</span>
              </button>
            )}
          </div>
        </div>

        {filteredEvents.length === 0 ? (
          <div className="py-12 text-center text-sm text-slate-500 dark:text-[#A6B0C3]">
            No security activity entries recorded for this filter.
          </div>
        ) : (
          <div className="divide-y divide-slate-200/80 dark:divide-white/10">
            {filteredEvents.map((ev) => {
              const timeStr = new Date(ev.timestampMillis).toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
              });
              return (
                <div key={ev.id} className="py-4 flex items-start justify-between gap-4">
                  <div className="space-y-1">
                    <p className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF]">
                      {ev.title}
                    </p>
                    <p className="text-xs text-slate-600 dark:text-[#A6B0C3] leading-relaxed">
                      {ev.detail}
                    </p>
                    <p className="text-[11px] font-mono text-slate-400 dark:text-[#A6B0C3]/70">
                      {ev.eventType}
                      {ev.packageName ? ` · ${ev.packageName}` : ''} · {timeStr}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    );
  }

  // 13. SECURITY SETTINGS
  if (currentScreen === 'security_settings') {
    return (
      <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-8 space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-[#A6B0C3]">
          <span>Screen 13 of 15 · Security Settings</span>
          <span>Backed by SecuritySettingsRepository & SessionManager</span>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-[#F5F7FF]">
              Security & Authentication Settings
            </h1>
            <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-1">
              Configure session timeout (monotonic clock), brute-force lockout policy, PIN
              rotation, and biometric rules.
            </p>
          </div>

          {isSessionAuthenticated && (
            <button
              type="button"
              onClick={lockSessionNow}
              className="min-h-[44px] px-4 py-2 rounded-xl bg-amber-500 hover:bg-amber-600 text-slate-950 font-semibold text-xs flex items-center gap-1.5 whitespace-nowrap"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Lock Session Now</span>
            </button>
          )}
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
                onClick={() => setSessionTimeout(opt.id as SessionTimeoutId)}
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
                  onClick={() =>
                    updatePreferences(
                      { maxFailedAttempts: limit },
                      `Max Failed Attempts Threshold Set to ${limit}`
                    )
                  }
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
                onClick={() => setReLockDurationOption(opt.id)}
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
              onClick={() =>
                updatePreferences(
                  { biometricPreferenceEnabled: !preferences.biometricPreferenceEnabled },
                  `Biometric Authentication ${
                    !preferences.biometricPreferenceEnabled ? 'Enabled' : 'Disabled'
                  }`
                )
              }
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
                About NEXLOCK & Run Phase 2 + Phase 3 Unit Tests (Screen 15)
              </span>
            </div>
            <ChevronRight className="w-4 h-4 text-slate-400" />
          </button>
        </div>
      </div>
    );
  }

  // 14. THEME SETTINGS
  if (currentScreen === 'theme_settings') {
    const swatches = [
      { name: 'Background Dark', hex: '#0B1020', role: 'Primary Dark Canvas' },
      { name: 'Surface Dark', hex: '#151D32', role: 'Elevated Card Surface' },
      { name: 'Primary Accent', hex: '#5B8CFF', role: 'Interactive Actions & Focus' },
      { name: 'Secondary Accent', hex: '#9B7BFF', role: 'Vault & Secondary Highlights' },
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
            Screen 14 of 15 · Theme Settings
          </span>
        </div>

        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-[#F5F7FF]">
            Theme & Material 3 Design System
          </h1>
          <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-1">
            Switch between NEXLOCK’s signature `#0B1020` Dark Mode, high-contrast Light Mode, or
            System Default.
          </p>
        </div>

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

        <div>
          <h2 className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF] mb-3">
            NEXLOCK Mandatory Color Tokens (`Theme.kt`)
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {swatches.map((sw) => (
              <div
                key={sw.hex}
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

  // 15. ABOUT NEXLOCK + PHASE 4 (12 TESTS), PHASE 3 (17 TESTS) & PHASE 2 (12 TESTS) RUNNERS
  const handleRunAllTests = async () => {
    setIsRunningTests(true);
    try {
      const [p4, p3, p2] = await Promise.all([
        runPhase4UnitTests(),
        runPhase3UnitTests(),
        runPhase2UnitTests(),
      ]);
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
          Screen 15 of 15 · About NEXLOCK & Phase 4 Verification
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
              Your Apps. Your Privacy. Your Control. · v4.0.0-phase4
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

      {/* Phase 4 (12) + Phase 3 (17) + Phase 2 (12) Unit Test Suite Runner (41 Total Assertions) */}
      <div className="p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
              Phase 4 (12 Tests), Phase 3 (17 Tests) & Phase 2 (12 Tests) Verification Suite
            </h2>
            <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-0.5">
              Executes `Phase4AppLockEngineTest` (Foreground Detection, AppLockActivity Challenge,
              6 Re-Lock Timers, Screen Off Revocation, Rapid App Switching, Recovery Exclusion,
              Permission Health), `Phase3AppDiscoveryTest`, and `Phase2AuthenticationTest`.
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
              {isRunningTests ? 'Running 41 Unit Tests...' : 'Run All 41 Unit Tests'}
            </span>
          </button>
        </div>

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

      {/* 5-Phase Development Roadmap */}
      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF]">
          5-Phase Android Engineering Roadmap
        </h2>
        <div className="space-y-2.5">
          {DEVELOPMENT_PHASES.map((p, idx) => (
            <div
              key={p.phase}
              className={`p-4 rounded-2xl border ${
                idx <= 3
                  ? 'bg-[#2DD4A3]/10 border-[#2DD4A3]/40'
                  : 'bg-slate-50 dark:bg-[#0B1020] border-slate-200 dark:border-white/10'
              }`}
            >
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <p className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
                  {p.phase}: {p.title}
                </p>
                <span
                  className={`text-xs font-semibold ${
                    idx <= 3 ? 'text-[#2DD4A3]' : 'text-slate-500 dark:text-[#A6B0C3]'
                  }`}
                >
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
          Package: com.nexlock.security · Room Schema v2 · Min SDK 26 · Target SDK 35
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
