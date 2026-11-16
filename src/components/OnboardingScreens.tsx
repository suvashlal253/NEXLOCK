import React, { useState } from 'react';
import {
  ArrowLeft,
  ArrowRight,
  Check,
  Delete,
  Fingerprint,
  KeyRound,
  Lock,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
} from 'lucide-react';
import { DOCUMENTED_PERMISSIONS } from '../data/initialData';
import { validatePinStrength } from '../security/cryptoEngine';
import { NexLockStore } from '../state/useNexLockStore';
import { BiometricHardwareState } from '../types/nexlock';

export const OnboardingScreens: React.FC<{ store: NexLockStore }> = ({ store }) => {
  const {
    currentScreen,
    setCurrentScreen,
    preferences,
    updatePreferences,
    createOrUpdateMasterPin,
    triggerBiometricAuthentication,
    setBiometricHardwareState,
    isCryptoBusy,
  } = store;

  const [onboardingStep, setOnboardingStep] = useState<number>(0);
  const [pinError, setPinError] = useState<string>('');
  const [confirmMessage, setConfirmMessage] = useState<{ ok: boolean; text: string } | null>(
    null
  );
  const [biometricFeedback, setBiometricFeedback] = useState<{
    ok: boolean;
    text: string;
  } | null>(null);

  // 1. SPLASH SCREEN (First-Launch vs Returning-User Routing)
  if (currentScreen === 'splash') {
    const isReturningUser = preferences.pinConfigured;

    return (
      <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-8 sm:p-12 flex flex-col items-center text-center justify-between min-h-[600px]">
        <div className="w-full flex items-center justify-between text-xs text-slate-500 dark:text-[#A6B0C3]">
          <span>Screen 01 of 15 · Splash Screen</span>
          <span className="font-mono tabular-nums">v2.0.0-phase2</span>
        </div>

        <div className="my-auto py-8 max-w-md flex flex-col items-center">
          <div className="w-20 h-20 rounded-3xl bg-gradient-to-br from-[#5B8CFF] to-[#9B7BFF] flex items-center justify-center shadow-lg shadow-[#5B8CFF]/25 mb-6">
            <Shield className="w-10 h-10 text-white" />
          </div>

          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-slate-900 dark:text-[#F5F7FF]">
            NEXLOCK
          </h1>
          <p className="mt-2 text-base font-medium text-[#5B8CFF]">
            Your Apps. Your Privacy. Your Control.
          </p>
          <p className="mt-4 text-sm text-slate-600 dark:text-[#A6B0C3] leading-relaxed">
            {isReturningUser
              ? 'Returning user detected. Master PIN verifier is sealed in AndroidKeyStore. Authenticate to unlock your session.'
              : 'First launch detected. Complete the Welcome flow to create your salted PBKDF2-HMAC-SHA256 Master PIN and configure BiometricPrompt.'}
          </p>

          <div className="mt-8 w-full pt-6 border-t border-slate-200/80 dark:border-white/10 text-xs text-slate-500 dark:text-[#A6B0C3] flex flex-wrap items-center justify-center gap-2">
            <span>PBKDF2-HMAC-SHA256 (210k)</span>
            <span aria-hidden="true">·</span>
            <span>AES-256-GCM Keystore</span>
            <span aria-hidden="true">·</span>
            <span>{isReturningUser ? 'PIN Configured' : 'First Launch'}</span>
          </div>
        </div>

        <div className="w-full max-w-md flex flex-col sm:flex-row gap-3">
          {isReturningUser ? (
            <>
              <button
                type="button"
                onClick={() => setCurrentScreen('auth_screen')}
                className="flex-1 min-h-[48px] px-5 py-3 rounded-xl bg-[#5B8CFF] hover:bg-[#4A7BF7] text-white font-semibold text-sm flex items-center justify-center gap-2 transition-colors whitespace-nowrap"
              >
                <Lock className="w-4 h-4" />
                <span>Proceed to Master Authentication</span>
              </button>
              <button
                type="button"
                onClick={() => setCurrentScreen('onboarding')}
                className="min-h-[48px] px-5 py-3 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 text-slate-800 dark:text-[#F5F7FF] font-medium text-sm transition-colors whitespace-nowrap"
              >
                Re-run Setup
              </button>
            </>
          ) : (
            <>
              <button
                type="button"
                onClick={() => setCurrentScreen('onboarding')}
                className="flex-1 min-h-[48px] px-5 py-3 rounded-xl bg-[#5B8CFF] hover:bg-[#4A7BF7] text-white font-semibold text-sm flex items-center justify-center gap-2 transition-colors whitespace-nowrap"
              >
                <span>Start First-Launch Setup</span>
                <ArrowRight className="w-4 h-4" />
              </button>
              <button
                type="button"
                onClick={() => setCurrentScreen('create_pin')}
                className="min-h-[48px] px-5 py-3 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 text-slate-800 dark:text-[#F5F7FF] font-medium text-sm transition-colors whitespace-nowrap"
              >
                Create Master PIN
              </button>
            </>
          )}
        </div>
      </div>
    );
  }

  // 2. ONBOARDING SCREEN
  if (currentScreen === 'onboarding') {
    const slides = [
      {
        step: '01. Granular App Lock Policies',
        title: 'Choose Which Applications Require Authentication',
        description:
          'Configure per-application lock policies, custom re-lock timers, and notification privacy rules stored locally in the NEXLOCK Room database.',
        note: 'Phase 2 adds real cryptographic Master PIN & Biometric authentication protecting NEXLOCK itself.',
        icon: Smartphone,
      },
      {
        step: '02. Hardware-Backed Keystore & Biometrics',
        title: 'Zero Plaintext Credentials on Your Device',
        description:
          'Your Master PIN is derived via PBKDF2-HMAC-SHA256 (210,000 iterations, 128-bit CSPRNG salt) and sealed inside an AES-256-GCM AndroidKeyStore envelope.',
        note: 'Weak PINs (such as 0000, 1111, 1234, or 654321) are automatically rejected during creation.',
        icon: Fingerprint,
      },
      {
        step: '03. Monotonic Session & Brute-Force Protection',
        title: 'Automatic Session Expiry & Temporary Cooldowns',
        description:
          'Authenticated sessions are tracked in volatile memory using a monotonic clock and never persist across device reboots.',
        note: 'Repeated incorrect PIN attempts trigger a temporary 30s/60s/300s cooldown without permanently locking you out.',
        icon: ShieldCheck,
      },
    ];

    const currentSlide = slides[onboardingStep];
    const SlideIcon = currentSlide.icon;

    return (
      <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-10 flex flex-col justify-between min-h-[600px]">
        <div className="flex items-center justify-between border-b border-slate-200 dark:border-white/10 pb-4">
          <button
            type="button"
            onClick={() => setCurrentScreen('splash')}
            className="min-h-[44px] px-3 rounded-lg text-xs font-medium text-slate-600 dark:text-[#A6B0C3] hover:text-slate-900 dark:hover:text-white flex items-center gap-1.5"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Splash</span>
          </button>
          <span className="text-xs text-slate-500 dark:text-[#A6B0C3]">
            Screen 02 of 15 · Welcome & Onboarding ({onboardingStep + 1}/3)
          </span>
          <button
            type="button"
            onClick={() => setCurrentScreen('create_pin')}
            className="min-h-[44px] px-3 rounded-lg text-xs font-medium text-[#5B8CFF] hover:underline"
          >
            Create PIN
          </button>
        </div>

        <div className="my-auto py-8 max-w-xl mx-auto w-full">
          <div className="w-14 h-14 rounded-2xl bg-[#5B8CFF]/15 text-[#5B8CFF] flex items-center justify-center mb-6">
            <SlideIcon className="w-7 h-7" />
          </div>

          <p className="text-xs font-semibold text-[#5B8CFF] tracking-wide">
            {currentSlide.step}
          </p>
          <h2 className="mt-2 text-2xl sm:text-3xl font-bold text-slate-900 dark:text-[#F5F7FF] text-balance">
            {currentSlide.title}
          </h2>
          <p className="mt-4 text-sm sm:text-base text-slate-600 dark:text-[#A6B0C3] leading-relaxed">
            {currentSlide.description}
          </p>

          <div className="mt-6 p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200/80 dark:border-white/10 text-xs text-slate-600 dark:text-[#A6B0C3] leading-relaxed">
            <span className="font-semibold text-slate-900 dark:text-[#F5F7FF]">
              Phase 2 Security Guarantee:{' '}
            </span>
            {currentSlide.note}
          </div>

          <div className="mt-6 flex items-center gap-2">
            {slides.map((_, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => setOnboardingStep(idx)}
                aria-label={`Slide ${idx + 1}`}
                className={`h-2 rounded-full transition-all ${
                  onboardingStep === idx
                    ? 'w-8 bg-[#5B8CFF]'
                    : 'w-2.5 bg-slate-300 dark:bg-white/20'
                }`}
              />
            ))}
          </div>
        </div>

        <div className="flex items-center justify-between gap-3 pt-4 border-t border-slate-200 dark:border-white/10">
          <button
            type="button"
            disabled={onboardingStep === 0}
            onClick={() => setOnboardingStep((s) => Math.max(0, s - 1))}
            className="min-h-[48px] px-5 py-2.5 rounded-xl bg-slate-100 dark:bg-[#0B1020] text-slate-700 dark:text-[#A6B0C3] font-medium text-sm disabled:opacity-40 transition-opacity"
          >
            Previous
          </button>

          {onboardingStep < slides.length - 1 ? (
            <button
              type="button"
              onClick={() => setOnboardingStep((s) => s + 1)}
              className="min-h-[48px] px-6 py-2.5 rounded-xl bg-[#5B8CFF] hover:bg-[#4A7BF7] text-white font-semibold text-sm flex items-center gap-2 transition-colors"
            >
              <span>Next Pillar</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          ) : (
            <button
              type="button"
              onClick={() => setCurrentScreen('create_pin')}
              className="min-h-[48px] px-6 py-2.5 rounded-xl bg-[#5B8CFF] hover:bg-[#4A7BF7] text-white font-semibold text-sm flex items-center gap-2 transition-colors"
            >
              <span>Continue to Create Master PIN</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>
    );
  }

  // 3. CREATE MASTER PIN (Real Weak-Pattern Rejection & 4/6-Digit Validation)
  if (currentScreen === 'create_pin') {
    const targetLen = preferences.pinLength;
    const handleDigit = (digit: string) => {
      setPinError('');
      if (store.draftPin.length < targetLen) {
        const nextPin = store.draftPin + digit;
        store.setDraftPin(nextPin);
        if (nextPin.length === targetLen) {
          const check = validatePinStrength(nextPin, targetLen);
          if (!check.valid) {
            setPinError(check.reason);
          }
        }
      }
    };
    const handleBackspace = () => {
      setPinError('');
      store.setDraftPin(store.draftPin.slice(0, -1));
    };

    const strengthStatus =
      store.draftPin.length === targetLen
        ? validatePinStrength(store.draftPin, targetLen)
        : null;

    return (
      <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-10 flex flex-col justify-between min-h-[600px]">
        <div className="flex items-center justify-between border-b border-slate-200 dark:border-white/10 pb-4">
          <button
            type="button"
            onClick={() => setCurrentScreen('onboarding')}
            className="min-h-[44px] px-3 rounded-lg text-xs font-medium text-slate-600 dark:text-[#A6B0C3] hover:text-slate-900 dark:hover:text-white flex items-center gap-1.5"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Welcome</span>
          </button>
          <span className="text-xs text-slate-500 dark:text-[#A6B0C3]">
            Screen 03 of 15 · Create Master PIN
          </span>
          <div className="flex items-center gap-1 bg-slate-100 dark:bg-[#0B1020] p-1 rounded-lg">
            {([4, 6] as const).map((len) => (
              <button
                key={len}
                type="button"
                onClick={() => {
                  setPinError('');
                  store.setDraftPin('');
                  updatePreferences({ pinLength: len });
                }}
                className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                  preferences.pinLength === len
                    ? 'bg-[#5B8CFF] text-white'
                    : 'text-slate-600 dark:text-[#A6B0C3]'
                }`}
              >
                {len}-Digit
              </button>
            ))}
          </div>
        </div>

        <div className="max-w-md mx-auto w-full my-auto py-6 text-center">
          <div className="w-12 h-12 rounded-2xl bg-[#5B8CFF]/15 text-[#5B8CFF] flex items-center justify-center mx-auto mb-3">
            <KeyRound className="w-6 h-6" />
          </div>
          <h2 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-[#F5F7FF]">
            Create Your {targetLen}-Digit Master PIN
          </h2>
          <p className="mt-1.5 text-xs text-slate-500 dark:text-[#A6B0C3]">
            Rejects predictable patterns (0000, 1111, 1234, 654321, 1212, 1122) · Derives 256-bit
            PBKDF2-HMAC-SHA256 verifier
          </p>

          {/* PIN Dots */}
          <div className="my-6 flex items-center justify-center gap-3">
            {Array.from({ length: targetLen }).map((_, i) => {
              const filled = i < store.draftPin.length;
              const isWeak = strengthStatus && !strengthStatus.valid;
              const isStrong = strengthStatus && strengthStatus.valid;
              return (
                <div
                  key={i}
                  className={`w-4 h-4 rounded-full transition-all ${
                    isWeak
                      ? 'bg-rose-500'
                      : isStrong
                      ? 'bg-[#2DD4A3] scale-110'
                      : filled
                      ? 'bg-[#5B8CFF] scale-110'
                      : 'bg-slate-200 dark:bg-[#0B1020] border border-slate-300 dark:border-white/20'
                  }`}
                />
              );
            })}
          </div>

          {pinError && (
            <div
              role="alert"
              className="mb-4 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-400 font-medium"
            >
              {pinError}
            </div>
          )}

          {strengthStatus?.valid && !pinError && (
            <div className="mb-4 p-2.5 rounded-xl bg-[#2DD4A3]/15 text-[#2DD4A3] text-xs font-medium">
              Strong PIN combination accepted. Proceed to Confirm Master PIN.
            </div>
          )}

          {/* Numeric Keypad */}
          <div className="grid grid-cols-3 gap-3 max-w-xs mx-auto">
            {['1', '2', '3', '4', '5', '6', '7', '8', '9'].map((digit) => (
              <button
                key={digit}
                type="button"
                onClick={() => handleDigit(digit)}
                className="min-h-[56px] rounded-2xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 text-lg font-semibold font-mono tabular-nums text-slate-900 dark:text-[#F5F7FF] active:scale-[0.98] transition-all"
              >
                {digit}
              </button>
            ))}
            <button
              type="button"
              onClick={() => {
                setPinError('');
                store.setDraftPin('');
              }}
              className="min-h-[56px] rounded-2xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 text-xs font-medium text-slate-600 dark:text-[#A6B0C3]"
            >
              Clear
            </button>
            <button
              type="button"
              onClick={() => handleDigit('0')}
              className="min-h-[56px] rounded-2xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 text-lg font-semibold font-mono tabular-nums text-slate-900 dark:text-[#F5F7FF] active:scale-[0.98] transition-all"
            >
              0
            </button>
            <button
              type="button"
              onClick={handleBackspace}
              aria-label="Backspace"
              className="min-h-[56px] rounded-2xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 flex items-center justify-center text-slate-700 dark:text-[#A6B0C3]"
            >
              <Delete className="w-5 h-5" />
            </button>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-slate-200 dark:border-white/10">
          <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-[#A6B0C3]">
            <span>Test weak rejection:</span>
            <button
              type="button"
              onClick={() => {
                const weakSample = targetLen === 4 ? '1234' : '123456';
                store.setDraftPin(weakSample);
                const res = validatePinStrength(weakSample, targetLen);
                if (!res.valid) setPinError(res.reason);
              }}
              className="text-rose-400 hover:underline font-mono"
            >
              Try "{targetLen === 4 ? '1234' : '123456'}"
            </button>
            <span>·</span>
            <button
              type="button"
              onClick={() => {
                const strongSample = targetLen === 4 ? '7392' : '739204';
                setPinError('');
                store.setDraftPin(strongSample);
              }}
              className="text-[#2DD4A3] hover:underline font-mono"
            >
              Try "{targetLen === 4 ? '7392' : '739204'}"
            </button>
          </div>

          <button
            type="button"
            onClick={() => {
              const validation = validatePinStrength(store.draftPin, targetLen);
              if (!validation.valid) {
                setPinError(validation.reason);
                return;
              }
              store.setConfirmPinInput('');
              setConfirmMessage(null);
              setCurrentScreen('confirm_pin');
            }}
            className="min-h-[48px] px-6 py-2.5 rounded-xl bg-[#5B8CFF] hover:bg-[#4A7BF7] text-white font-semibold text-sm flex items-center gap-2 transition-colors whitespace-nowrap"
          >
            <span>Continue to Confirm</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    );
  }

  // 4. CONFIRM MASTER PIN (Derives Real PBKDF2-HMAC-SHA256 + AES-256-GCM Envelope)
  if (currentScreen === 'confirm_pin') {
    const targetLen = preferences.pinLength;
    const expectedPin = store.draftPin;
    const isMatch =
      store.confirmPinInput.length === targetLen && store.confirmPinInput === expectedPin;
    const isMismatch =
      store.confirmPinInput.length === targetLen && store.confirmPinInput !== expectedPin;

    const handleDigit = (digit: string) => {
      setConfirmMessage(null);
      if (store.confirmPinInput.length < targetLen) {
        store.setConfirmPinInput(store.confirmPinInput + digit);
      }
    };

    const handleFinalizePin = async () => {
      const res = await createOrUpdateMasterPin(store.draftPin, store.confirmPinInput);
      setConfirmMessage({ ok: res.ok, text: res.message });
      if (res.ok) {
        setTimeout(() => {
          setCurrentScreen('biometric_setup');
        }, 450);
      }
    };

    return (
      <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-10 flex flex-col justify-between min-h-[600px]">
        <div className="flex items-center justify-between border-b border-slate-200 dark:border-white/10 pb-4">
          <button
            type="button"
            onClick={() => setCurrentScreen('create_pin')}
            className="min-h-[44px] px-3 rounded-lg text-xs font-medium text-slate-600 dark:text-[#A6B0C3] hover:text-slate-900 dark:hover:text-white flex items-center gap-1.5"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Back to Create PIN</span>
          </button>
          <span className="text-xs text-slate-500 dark:text-[#A6B0C3]">
            Screen 04 of 15 · Confirm Master PIN
          </span>
        </div>

        <div className="max-w-md mx-auto w-full my-auto py-6 text-center">
          <div className="w-12 h-12 rounded-2xl bg-[#9B7BFF]/15 text-[#9B7BFF] flex items-center justify-center mx-auto mb-3">
            <Lock className="w-6 h-6" />
          </div>
          <h2 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-[#F5F7FF]">
            Confirm Your {targetLen}-Digit Master PIN
          </h2>
          <p className="mt-1.5 text-xs text-slate-500 dark:text-[#A6B0C3]">
            Re-enter your {targetLen}-digit PIN to run PBKDF2-HMAC-SHA256 (210,000 iterations) and
            seal the verifier in AndroidKeyStore
          </p>

          <div className="my-6 flex items-center justify-center gap-3">
            {Array.from({ length: targetLen }).map((_, i) => {
              const filled = i < store.confirmPinInput.length;
              return (
                <div
                  key={i}
                  className={`w-4 h-4 rounded-full transition-all ${
                    isMatch
                      ? 'bg-[#2DD4A3] scale-110'
                      : isMismatch
                      ? 'bg-rose-500'
                      : filled
                      ? 'bg-[#5B8CFF] scale-110'
                      : 'bg-slate-200 dark:bg-[#0B1020] border border-slate-300 dark:border-white/20'
                  }`}
                />
              );
            })}
          </div>

          {isMismatch && (
            <p role="alert" className="text-xs text-rose-400 mb-3 font-medium">
              Confirmation PIN does not match your initial entry. Tap Clear and try again.
            </p>
          )}

          {confirmMessage && (
            <div
              className={`mb-4 p-3 rounded-xl text-xs font-medium ${
                confirmMessage.ok
                  ? 'bg-[#2DD4A3]/15 text-[#2DD4A3]'
                  : 'bg-rose-500/15 text-rose-400'
              }`}
            >
              {confirmMessage.text}
            </div>
          )}

          <div className="grid grid-cols-3 gap-3 max-w-xs mx-auto">
            {['1', '2', '3', '4', '5', '6', '7', '8', '9'].map((digit) => (
              <button
                key={digit}
                type="button"
                onClick={() => handleDigit(digit)}
                className="min-h-[56px] rounded-2xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 text-lg font-semibold font-mono tabular-nums text-slate-900 dark:text-[#F5F7FF]"
              >
                {digit}
              </button>
            ))}
            <button
              type="button"
              onClick={() => {
                setConfirmMessage(null);
                store.setConfirmPinInput('');
              }}
              className="min-h-[56px] rounded-2xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 text-xs font-medium text-slate-600 dark:text-[#A6B0C3]"
            >
              Clear
            </button>
            <button
              type="button"
              onClick={() => handleDigit('0')}
              className="min-h-[56px] rounded-2xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 text-lg font-semibold font-mono tabular-nums text-slate-900 dark:text-[#F5F7FF]"
            >
              0
            </button>
            <button
              type="button"
              onClick={() => store.setConfirmPinInput(store.confirmPinInput.slice(0, -1))}
              aria-label="Backspace"
              className="min-h-[56px] rounded-2xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 flex items-center justify-center text-slate-700 dark:text-[#A6B0C3]"
            >
              <Delete className="w-5 h-5" />
            </button>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-slate-200 dark:border-white/10">
          {expectedPin ? (
            <button
              type="button"
              onClick={() => store.setConfirmPinInput(expectedPin)}
              className="min-h-[44px] px-3 text-xs text-slate-500 dark:text-[#A6B0C3] hover:text-slate-900 dark:hover:text-white"
            >
              Fill matching confirmation digits
            </button>
          ) : (
            <span className="text-xs text-amber-500">
              No draft PIN entered on Screen 3 yet.
            </span>
          )}

          <button
            type="button"
            disabled={isCryptoBusy || !isMatch}
            onClick={handleFinalizePin}
            className="min-h-[48px] px-6 py-2.5 rounded-xl bg-[#5B8CFF] hover:bg-[#4A7BF7] disabled:opacity-40 text-white font-semibold text-sm flex items-center gap-2 transition-all whitespace-nowrap"
          >
            <span>{isCryptoBusy ? 'Deriving PBKDF2 Key...' : 'Seal PIN & Continue'}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    );
  }

  // 5. BIOMETRIC SETUP (AndroidX BiometricManager & BiometricPrompt Integration)
  if (currentScreen === 'biometric_setup') {
    const hardwareOptions: { id: BiometricHardwareState; label: string }[] = [
      { id: 'AVAILABLE', label: 'BIOMETRIC_SUCCESS (Enrolled & Ready)' },
      { id: 'NONE_ENROLLED', label: 'BIOMETRIC_ERROR_NONE_ENROLLED' },
      { id: 'NO_HARDWARE', label: 'BIOMETRIC_ERROR_NO_HARDWARE' },
      { id: 'HARDWARE_UNAVAILABLE', label: 'BIOMETRIC_ERROR_HW_UNAVAILABLE' },
      { id: 'BIOMETRIC_LOCKOUT', label: 'ERROR_LOCKOUT (Sensor Cooldown)' },
    ];

    return (
      <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-10 flex flex-col justify-between min-h-[600px]">
        <div className="flex items-center justify-between border-b border-slate-200 dark:border-white/10 pb-4">
          <button
            type="button"
            onClick={() => setCurrentScreen('confirm_pin')}
            className="min-h-[44px] px-3 rounded-lg text-xs font-medium text-slate-600 dark:text-[#A6B0C3] hover:text-slate-900 dark:hover:text-white flex items-center gap-1.5"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Confirm PIN</span>
          </button>
          <span className="text-xs text-slate-500 dark:text-[#A6B0C3]">
            Screen 05 of 15 · Biometric Setup (Phase 2 Active)
          </span>
        </div>

        <div className="max-w-xl mx-auto w-full my-auto py-6 space-y-5">
          <div className="flex items-start gap-4">
            <div className="w-14 h-14 rounded-2xl bg-[#2DD4A3]/15 text-[#2DD4A3] flex items-center justify-center shrink-0">
              <Fingerprint className="w-7 h-7" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-slate-900 dark:text-[#F5F7FF]">
                AndroidX BiometricPrompt Setup
              </h2>
              <p className="mt-1 text-xs sm:text-sm text-slate-600 dark:text-[#A6B0C3] leading-relaxed">
                Checks `BiometricManager.canAuthenticate(BIOMETRIC_STRONG)` and binds authentication
                to Android’s Trusted Execution Environment (TEE) with automatic Master PIN fallback.
              </p>
            </div>
          </div>

          <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 flex items-center justify-between gap-4">
            <div>
              <p className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF]">
                Enable Fingerprint Biometric Authentication
              </p>
              <p className="text-xs text-slate-500 dark:text-[#A6B0C3] mt-0.5">
                Persisted in `SecuritySettingsRepository` (`biometric_enabled`).
              </p>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={preferences.biometricPreferenceEnabled}
              onClick={() =>
                updatePreferences(
                  { biometricPreferenceEnabled: !preferences.biometricPreferenceEnabled },
                  `BiometricPrompt Authentication ${
                    !preferences.biometricPreferenceEnabled ? 'Enabled' : 'Disabled'
                  }`
                )
              }
              className={`min-h-[44px] min-w-[84px] px-3.5 rounded-xl font-semibold text-xs transition-colors ${
                preferences.biometricPreferenceEnabled
                  ? 'bg-[#2DD4A3] text-[#0B1020]'
                  : 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#A6B0C3]'
              }`}
            >
              {preferences.biometricPreferenceEnabled ? 'Enabled' : 'Disabled'}
            </button>
          </div>

          {/* Hardware / Enrollment Diagnostic State Selector */}
          <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-2.5">
            <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
              Device BiometricManager Hardware & Enrollment State:
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {hardwareOptions.map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => {
                    setBiometricFeedback(null);
                    setBiometricHardwareState(opt.id);
                  }}
                  className={`min-h-[40px] px-3 py-2 rounded-xl text-left text-xs font-mono border transition-colors ${
                    preferences.biometricHardwareState === opt.id
                      ? 'border-[#5B8CFF] bg-[#5B8CFF]/10 text-slate-900 dark:text-[#F5F7FF] font-semibold'
                      : 'border-slate-200 dark:border-white/10 text-slate-600 dark:text-[#A6B0C3]'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {/* Test BiometricPrompt Callbacks */}
          <div className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-3">
            <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
              Verify BiometricPrompt Callback Handling:
            </p>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => {
                  const res = triggerBiometricAuthentication('SUCCESS');
                  setBiometricFeedback({ ok: res.ok, text: res.message });
                }}
                className="min-h-[40px] px-3.5 py-1.5 rounded-xl bg-[#2DD4A3]/15 text-[#2DD4A3] text-xs font-semibold"
              >
                Verify Enrollment (Success)
              </button>
              <button
                type="button"
                onClick={() => {
                  const res = triggerBiometricAuthentication('FAIL_MISMATCH');
                  setBiometricFeedback({ ok: res.ok, text: res.message });
                }}
                className="min-h-[40px] px-3.5 py-1.5 rounded-xl bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#F5F7FF] text-xs font-medium"
              >
                Test Unrecognized Fingerprint
              </button>
              <button
                type="button"
                onClick={() => {
                  const res = triggerBiometricAuthentication('USER_CANCELED');
                  setBiometricFeedback({ ok: res.ok, text: res.message });
                }}
                className="min-h-[40px] px-3.5 py-1.5 rounded-xl bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#F5F7FF] text-xs font-medium"
              >
                Test User Cancel (PIN Fallback)
              </button>
            </div>

            {biometricFeedback && (
              <div
                className={`p-3 rounded-xl text-xs font-medium ${
                  biometricFeedback.ok
                    ? 'bg-[#2DD4A3]/15 text-[#2DD4A3]'
                    : 'bg-amber-500/15 text-amber-400'
                }`}
              >
                {biometricFeedback.text}
              </div>
            )}
          </div>
        </div>

        <div className="flex items-center justify-between gap-3 pt-4 border-t border-slate-200 dark:border-white/10">
          <button
            type="button"
            onClick={() => setCurrentScreen('permission_setup')}
            className="min-h-[48px] px-4 py-2.5 text-xs font-medium text-slate-600 dark:text-[#A6B0C3] hover:text-slate-900 dark:hover:text-white"
          >
            Skip Biometric Setup
          </button>
          <button
            type="button"
            onClick={() => setCurrentScreen('permission_setup')}
            className="min-h-[48px] px-6 py-2.5 rounded-xl bg-[#5B8CFF] hover:bg-[#4A7BF7] text-white font-semibold text-sm flex items-center gap-2 transition-colors"
          >
            <span>Continue to Permission Setup</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    );
  }

  // 6. PERMISSION SETUP & PHASE 4 PERMISSION HEALTH MATRIX
  return (
    <div className="rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 p-6 sm:p-10 flex flex-col justify-between min-h-[600px]">
      <div className="flex items-center justify-between border-b border-slate-200 dark:border-white/10 pb-4">
        <button
          type="button"
          onClick={() => setCurrentScreen('biometric_setup')}
          className="min-h-[44px] px-3 rounded-lg text-xs font-medium text-slate-600 dark:text-[#A6B0C3] hover:text-slate-900 dark:hover:text-white flex items-center gap-1.5"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Biometric Setup</span>
        </button>
        <span className="text-xs text-slate-500 dark:text-[#A6B0C3]">
          Screen 06 of 15 · Permission Health & Setup (Phase 4 Active)
        </span>
      </div>

      <div className="my-6 space-y-5">
        <div>
          <h2 className="text-2xl font-bold text-slate-900 dark:text-[#F5F7FF]">
            Permission Health & Android Onboarding
          </h2>
          <p className="mt-1.5 text-sm text-slate-600 dark:text-[#A6B0C3]">
            NEXLOCK checks `AppOpsManager.OPSTR_GET_USAGE_STATS` and `Settings.canDrawOverlays()` on
            every `onResume()` return from Android Settings. The App Lock Engine never reports
            Active when required permissions are missing.
          </p>
        </div>

        {/* Live Permission Health Matrix (Section 3.D) */}
        <div className="p-4 sm:p-5 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 dark:border-white/10 pb-3">
            <h3 className="text-sm font-bold text-slate-900 dark:text-[#F5F7FF]">
              Live Permission & Engine Health Status
            </h3>
            <span
              className={`text-xs font-semibold ${
                store.engineOperationalEvaluation.isOperational
                  ? 'text-[#2DD4A3]'
                  : 'text-amber-400'
              }`}
            >
              App Lock Engine: {store.engineOperationalEvaluation.isOperational ? 'Active' : 'Paused'}{' '}
              ({store.engineOperationalEvaluation.badgeLabel})
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {/* Usage Access */}
            <div className="p-3.5 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 flex items-center justify-between gap-3">
              <div>
                <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                  Usage Access (`PACKAGE_USAGE_STATS`)
                </p>
                <p
                  className={`text-xs font-mono mt-0.5 ${
                    store.permissionHealth.usageAccessGranted ? 'text-[#2DD4A3]' : 'text-rose-400'
                  }`}
                >
                  {store.permissionHealth.usageAccessGranted ? 'Granted' : 'Not Granted'}
                </p>
              </div>
              <button
                type="button"
                onClick={() => store.togglePermissionState('usageAccessGranted')}
                className={`min-h-[40px] px-3 py-1.5 rounded-xl text-xs font-semibold transition-colors ${
                  store.permissionHealth.usageAccessGranted
                    ? 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#F5F7FF]'
                    : 'bg-[#5B8CFF] text-white'
                }`}
              >
                {store.permissionHealth.usageAccessGranted ? 'Revoke (Test)' : 'Grant in Settings'}
              </button>
            </div>

            {/* Overlay Permission */}
            <div className="p-3.5 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 flex items-center justify-between gap-3">
              <div>
                <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                  Overlay Permission (`SYSTEM_ALERT_WINDOW`)
                </p>
                <p
                  className={`text-xs font-mono mt-0.5 ${
                    store.permissionHealth.overlayPermissionGranted
                      ? 'text-[#2DD4A3]'
                      : 'text-rose-400'
                  }`}
                >
                  {store.permissionHealth.overlayPermissionGranted ? 'Granted' : 'Not Granted'}
                </p>
              </div>
              <button
                type="button"
                onClick={() => store.togglePermissionState('overlayPermissionGranted')}
                className={`min-h-[40px] px-3 py-1.5 rounded-xl text-xs font-semibold transition-colors ${
                  store.permissionHealth.overlayPermissionGranted
                    ? 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#F5F7FF]'
                    : 'bg-[#5B8CFF] text-white'
                }`}
              >
                {store.permissionHealth.overlayPermissionGranted
                  ? 'Revoke (Test)'
                  : 'Grant in Settings'}
              </button>
            </div>

            {/* Notification Permission */}
            <div className="p-3.5 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 flex items-center justify-between gap-3">
              <div>
                <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                  Notification Permission (`POST_NOTIFICATIONS`)
                </p>
                <p
                  className={`text-xs font-mono mt-0.5 ${
                    store.permissionHealth.notificationPermissionGranted
                      ? 'text-[#2DD4A3]'
                      : 'text-amber-400'
                  }`}
                >
                  {store.permissionHealth.notificationPermissionGranted ? 'Granted' : 'Not Granted'}
                </p>
              </div>
              <button
                type="button"
                onClick={() => store.togglePermissionState('notificationPermissionGranted')}
                className="min-h-[40px] px-3 py-1.5 rounded-xl bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#F5F7FF] text-xs font-semibold"
              >
                {store.permissionHealth.notificationPermissionGranted ? 'Disable' : 'Enable'}
              </button>
            </div>

            {/* Monitoring Service Status */}
            <div className="p-3.5 rounded-xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 flex items-center justify-between gap-3">
              <div>
                <p className="text-xs font-semibold text-slate-900 dark:text-[#F5F7FF]">
                  Monitoring Service (`AppLockMonitoringService`)
                </p>
                <p
                  className={`text-xs font-mono mt-0.5 ${
                    store.monitoringServiceState === 'RUNNING' ? 'text-[#2DD4A3]' : 'text-amber-400'
                  }`}
                >
                  {store.monitoringServiceState === 'RUNNING' ? 'Running' : 'Stopped'}
                </p>
              </div>
              <button
                type="button"
                onClick={() =>
                  store.monitoringServiceState === 'RUNNING'
                    ? store.pauseMonitoringEngine()
                    : store.startMonitoringEngine()
                }
                className={`min-h-[40px] px-3 py-1.5 rounded-xl text-xs font-semibold transition-colors ${
                  store.monitoringServiceState === 'RUNNING'
                    ? 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-[#F5F7FF]'
                    : 'bg-[#2DD4A3] text-[#0B1020]'
                }`}
              >
                {store.monitoringServiceState === 'RUNNING' ? 'Stop Service' : 'Start Service'}
              </button>
            </div>
          </div>
        </div>

        <div className="space-y-3">
          {DOCUMENTED_PERMISSIONS.map((perm) => (
            <div
              key={perm.id}
              className="p-4 rounded-2xl bg-slate-50 dark:bg-[#0B1020] border border-slate-200 dark:border-white/10"
            >
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <h3 className="text-sm font-semibold text-slate-900 dark:text-[#F5F7FF]">
                  {perm.title}
                </h3>
                <span className="text-xs text-[#5B8CFF] font-medium">
                  {perm.targetPhase} · {perm.statusLabel}
                </span>
              </div>
              <p className="mt-1 text-xs font-mono text-slate-500 dark:text-[#A6B0C3]">
                {perm.androidConstant}
              </p>
              <p className="mt-2 text-xs text-slate-700 dark:text-[#F5F7FF]/90 leading-relaxed">
                <span className="font-semibold">Why Needed: </span>
                {perm.whyNeeded}
              </p>
              <p className="mt-1.5 text-xs text-slate-500 dark:text-[#A6B0C3] leading-relaxed">
                <span className="font-semibold">Android Boundary Note: </span>
                {perm.osLimitationNote}
              </p>
            </div>
          ))}
        </div>

        <div className="p-4 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-start gap-3">
          <ShieldAlert className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
          <p className="text-xs text-slate-700 dark:text-[#F5F7FF] leading-relaxed">
            <span className="font-semibold">Honest Android Limitation Disclosure: </span>
            `UsageStatsManager` is a polling-based Android system API and is not a zero-frame kernel
            hook. A brief visibility window may occur before `AppLockActivity` appears, and
            aggressive OEM battery savers may delay background polling.
          </p>
        </div>
      </div>

      <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-200 dark:border-white/10">
        <button
          type="button"
          onClick={() => {
            updatePreferences(
              { onboardingCompleted: true },
              'Onboarding & Permission Health Verification Completed'
            );
            setCurrentScreen('home');
          }}
          className="min-h-[48px] px-6 py-2.5 rounded-xl bg-[#2DD4A3] hover:bg-[#25be90] text-[#0B1020] font-bold text-sm flex items-center gap-2 transition-colors"
        >
          <Check className="w-4 h-4" />
          <span>Recheck Permissions & Enter Home Dashboard</span>
        </button>
      </div>
    </div>
  );
};
