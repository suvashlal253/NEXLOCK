/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  Activity,
  FolderLock,
  Home,
  LayoutGrid,
  Settings,
} from 'lucide-react';
import { CoreScreens } from './components/CoreScreens';
import { KotlinSourceDrawer } from './components/KotlinSourceDrawer';
import { OnboardingScreens } from './components/OnboardingScreens';
import { SCREEN_DEFINITIONS } from './data/initialData';
import { useNexLockStore } from './state/useNexLockStore';
import { BottomNavTab, ScreenId } from './types/nexlock';

const BOTTOM_NAV_ITEMS: {
  id: BottomNavTab;
  label: string;
  targetScreen: ScreenId;
  icon: React.ComponentType<{ className?: string }>;
}[] = [
  { id: 'home', label: 'Home', targetScreen: 'home', icon: Home },
  { id: 'apps', label: 'Apps', targetScreen: 'apps', icon: LayoutGrid },
  { id: 'vault', label: 'Vault', targetScreen: 'vault', icon: FolderLock },
  { id: 'security_activity', label: 'Security', targetScreen: 'security_activity', icon: Activity },
  { id: 'security_settings', label: 'Settings', targetScreen: 'security_settings', icon: Settings },
];

const ONBOARDING_SCREEN_IDS: ScreenId[] = [
  'splash',
  'onboarding',
  'create_pin',
  'confirm_pin',
  'biometric_setup',
  'permission_setup',
];

export default function App() {
  const store = useNexLockStore();
  const [sourceDrawerOpen, setSourceDrawerOpen] = useState<boolean>(false);

  const activeScreenDef =
    SCREEN_DEFINITIONS.find((s) => s.id === store.currentScreen) || SCREEN_DEFINITIONS[6];

  const isOnboardingScreen = ONBOARDING_SCREEN_IDS.includes(store.currentScreen);

  const lockedAppsCount = store.apps.filter((a) => a.isLocked).length;

  return (
    <div className="min-h-screen flex flex-col bg-[#F4F7FB] dark:bg-[#0B1020] text-slate-900 dark:text-[#F5F7FF] pb-20 lg:pb-12">
      {/* Top Bar Contract: 3 zones separated by gap-8 */}
      <header className="flex items-center justify-between gap-8 px-4 sm:px-8 h-14 border-b border-slate-200 dark:border-white/10 bg-white/90 dark:bg-[#0B1020]/90 backdrop-blur-md sticky top-0 z-30">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            store.setCurrentScreen('home');
          }}
          className="text-lg font-bold tracking-tight text-slate-900 dark:text-[#F5F7FF] whitespace-nowrap shrink-0"
        >
          NEXLOCK
        </a>

        {/* Zone 2: 5 concise single-line text navigation links */}
        <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-600 dark:text-[#A6B0C3]">
          {BOTTOM_NAV_ITEMS.map((item) => {
            const isActive = activeScreenDef.bottomTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => store.setCurrentScreen(item.targetScreen)}
                className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
                  isActive
                    ? 'text-slate-900 dark:text-[#F5F7FF] border-[#5B8CFF]'
                    : 'border-transparent hover:text-slate-900 dark:hover:text-[#F5F7FF]'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={() => setSourceDrawerOpen(true)}
            className="px-4 py-2 text-xs font-semibold text-white bg-[#5B8CFF] hover:bg-[#4A7BF7] rounded-lg transition-colors whitespace-nowrap shrink-0"
          >
            Kotlin Source
          </button>
        </div>
      </header>

      {/* Main Responsive Multi-Column Workspace */}
      <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-6">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* Primary Active Screen Viewport */}
          <section className="lg:col-span-8 space-y-4">
            {isOnboardingScreen ? (
              <OnboardingScreens store={store} />
            ) : (
              <CoreScreens
                store={store}
                onOpenSourceDrawer={() => setSourceDrawerOpen(true)}
              />
            )}
          </section>

          {/* Companion 15-Screen Navigator & Architecture State Panel */}
          <aside className="lg:col-span-4 space-y-6">
            <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-5 space-y-4">
              <div className="flex items-baseline justify-between">
                <h2 className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
                  All 15 Required Screens
                </h2>
                <span className="text-xs text-slate-500 dark:text-[#A6B0C3] font-mono tabular-nums">
                  #{String(activeScreenDef.number).padStart(2, '0')} Active
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">
                Switch directly between any onboarding, configuration, vault, or authentication
                screen in the NEXLOCK Phase 1 navigation graph.
              </p>

              <div className="space-y-4">
                {(
                  [
                    'Setup & Onboarding',
                    'Core Protection',
                    'Vault & Audit',
                    'Configuration',
                  ] as const
                ).map((groupName) => {
                  const groupScreens = SCREEN_DEFINITIONS.filter((s) => s.group === groupName);
                  return (
                    <div key={groupName} className="space-y-1.5">
                      <p className="text-[11px] font-semibold text-slate-400 dark:text-[#A6B0C3]/80">
                        {groupName}
                      </p>
                      <div className="grid grid-cols-1 gap-1">
                        {groupScreens.map((scr) => {
                          const isCurrent = store.currentScreen === scr.id;
                          return (
                            <button
                              key={scr.id}
                              type="button"
                              onClick={() => store.setCurrentScreen(scr.id)}
                              className={`min-h-[40px] px-3 py-2 rounded-xl text-left text-xs font-medium flex items-center justify-between transition-colors ${
                                isCurrent
                                  ? 'bg-[#5B8CFF] text-white font-semibold'
                                  : 'bg-slate-50 hover:bg-slate-100 dark:bg-[#0B1020] dark:hover:bg-white/10 text-slate-700 dark:text-[#F5F7FF]'
                              }`}
                            >
                              <span className="truncate">
                                <span className="font-mono tabular-nums opacity-75 mr-2">
                                  {String(scr.number).padStart(2, '0')}.
                                </span>
                                {scr.title}
                              </span>
                              <span className="text-[11px] opacity-75 ml-2 shrink-0">
                                {isCurrent ? 'Viewing' : 'Open'}
                              </span>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Phase 2 Cryptographic, Session & Room State Summary */}
            <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
                  Phase 2 Auth & Local Persistence
                </h3>
                {store.isSessionAuthenticated && (
                  <button
                    type="button"
                    onClick={store.lockSessionNow}
                    className="text-xs font-semibold text-amber-500 hover:underline"
                  >
                    Lock Now
                  </button>
                )}
              </div>
              <div className="text-xs text-slate-600 dark:text-[#A6B0C3] space-y-1.5 font-mono tabular-nums">
                <p>
                  Session:{' '}
                  {store.isSessionAuthenticated
                    ? `UNLOCKED (${store.sessionRemainingSeconds}s)`
                    : 'LOCKED'}
                </p>
                <p>
                  Master PIN:{' '}
                  {store.preferences.pinConfigured
                    ? `${store.preferences.pinLength}-Digit PBKDF2 (${store.preferences.pbkdf2Iterations.toLocaleString()})`
                    : 'Not Configured'}
                </p>
                {store.preferences.pinSaltBase64 && (
                  <p className="truncate">
                    CSPRNG Salt: {store.preferences.pinSaltBase64}
                  </p>
                )}
                <p>
                  Keystore AES-256-GCM:{' '}
                  {store.keystoreHealthy ? 'HEALTHY' : 'KEY_INVALIDATED'}
                </p>
                <p>
                  Failed Attempts: {store.preferences.failedAttempts}/
                  {store.preferences.maxFailedAttempts}
                </p>
                <p>
                  Room protected_apps: {lockedAppsCount}/{store.apps.length} locked
                </p>
                <p>Room security_events: {store.events.length} rows</p>
              </div>
            </div>
          </aside>
        </div>
      </main>

      {/* Fixed Bottom Navigation Bar for Mobile Viewports (5 Required Destinations) */}
      <nav
        aria-label="Primary Bottom Navigation"
        className="lg:hidden fixed bottom-0 left-0 right-0 z-30 h-14 bg-white/95 dark:bg-[#151D32]/95 backdrop-blur-md border-t border-slate-200 dark:border-white/10 grid grid-cols-5 items-center px-2"
      >
        {BOTTOM_NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isSelected = activeScreenDef.bottomTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => store.setCurrentScreen(item.targetScreen)}
              className={`min-h-[44px] flex flex-col items-center justify-center rounded-xl transition-colors ${
                isSelected
                  ? 'text-[#5B8CFF]'
                  : 'text-slate-500 dark:text-[#A6B0C3] hover:text-slate-900 dark:hover:text-[#F5F7FF]'
              }`}
            >
              <Icon className="w-5 h-5" />
              <span className="text-[10px] font-semibold tracking-tight mt-0.5 whitespace-nowrap">
                {item.label}
              </span>
            </button>
          );
        })}
      </nav>

      {/* Native Android Kotlin Project Source Drawer */}
      <KotlinSourceDrawer
        isOpen={sourceDrawerOpen}
        onClose={() => setSourceDrawerOpen(false)}
      />
    </div>
  );
}
