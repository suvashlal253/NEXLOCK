import React, { useState } from 'react';
import { Check, Copy, FileCode2, X } from 'lucide-react';
import { KOTLIN_SOURCE_FILES } from '../data/kotlinProjectFiles';

interface KotlinSourceDrawerProps {
  isOpen: boolean;
  onClose: () => void;
}

export const KotlinSourceDrawer: React.FC<KotlinSourceDrawerProps> = ({ isOpen, onClose }) => {
  const [selectedIndex, setSelectedIndex] = useState<number>(0);
  const [copied, setCopied] = useState<boolean>(false);

  if (!isOpen) return null;

  const currentFile = KOTLIN_SOURCE_FILES[selectedIndex] || KOTLIN_SOURCE_FILES[0];

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(currentFile.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // Fallback ignored
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6"
      role="dialog"
      aria-modal="true"
      aria-label="Native Android Kotlin Project Source Inspector"
    >
      <div className="w-full max-w-5xl max-h-[88vh] rounded-3xl bg-white dark:bg-[#151D32] border border-slate-200 dark:border-white/10 flex flex-col overflow-hidden shadow-2xl">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-200 dark:border-white/10 flex items-center justify-between gap-4">
          <div>
            <h2 className="text-base sm:text-lg font-bold text-slate-900 dark:text-[#F5F7FF]">
              NEXLOCK Native Android Project Source (`/android`)
            </h2>
            <p className="text-xs text-slate-500 dark:text-[#A6B0C3]">
              Kotlin · Jetpack Compose · Material 3 · Room · DataStore · Navigation Compose
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close source inspector"
            className="min-h-[44px] min-w-[44px] rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-[#0B1020] dark:hover:bg-white/10 flex items-center justify-center text-slate-700 dark:text-[#F5F7FF]"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* File Selector + Code Viewer */}
        <div className="flex-1 grid grid-cols-1 md:grid-cols-12 min-h-0 overflow-hidden">
          <div className="md:col-span-4 border-b md:border-b-0 md:border-r border-slate-200 dark:border-white/10 p-3 overflow-y-auto space-y-1.5 bg-slate-50/60 dark:bg-[#0B1020]/50">
            {KOTLIN_SOURCE_FILES.map((file, idx) => (
              <button
                key={file.path}
                type="button"
                onClick={() => setSelectedIndex(idx)}
                className={`w-full p-3 rounded-xl text-left transition-colors flex items-start gap-2.5 ${
                  selectedIndex === idx
                    ? 'bg-[#5B8CFF] text-white'
                    : 'hover:bg-slate-200/60 dark:hover:bg-white/5 text-slate-700 dark:text-[#F5F7FF]'
                }`}
              >
                <FileCode2 className="w-4 h-4 shrink-0 mt-0.5" />
                <div className="min-w-0">
                  <p className="text-xs font-semibold truncate">
                    {file.path.split('/').pop()}
                  </p>
                  <p
                    className={`text-[11px] truncate ${
                      selectedIndex === idx ? 'text-white/80' : 'text-slate-500 dark:text-[#A6B0C3]'
                    }`}
                  >
                    {file.moduleGroup}
                  </p>
                </div>
              </button>
            ))}
          </div>

          <div className="md:col-span-8 flex flex-col min-h-0 overflow-hidden">
            <div className="px-5 py-3 border-b border-slate-200 dark:border-white/10 flex flex-wrap items-center justify-between gap-2 bg-slate-50 dark:bg-[#0B1020]">
              <div className="min-w-0">
                <p className="text-xs font-mono font-semibold text-slate-900 dark:text-[#F5F7FF] truncate">
                  {currentFile.path}
                </p>
                <p className="text-[11px] text-slate-500 dark:text-[#A6B0C3] truncate">
                  {currentFile.description}
                </p>
              </div>
              <button
                type="button"
                onClick={handleCopy}
                className="min-h-[40px] px-3.5 py-1.5 rounded-xl bg-[#5B8CFF] hover:bg-[#4A7BF7] text-white text-xs font-semibold flex items-center gap-1.5 shrink-0"
              >
                {copied ? (
                  <>
                    <Check className="w-3.5 h-3.5" />
                    <span>Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy File</span>
                  </>
                )}
              </button>
            </div>

            <pre className="flex-1 p-5 overflow-auto bg-[#0B1020] text-[#F5F7FF] text-xs font-mono leading-relaxed">
              <code>{currentFile.code}</code>
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
