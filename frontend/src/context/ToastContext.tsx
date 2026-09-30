import React, { createContext, useCallback, useContext, useRef, useState } from 'react';
import { CheckCircle2, XCircle, AlertTriangle, Info, X } from 'lucide-react';

// ─── Types ────────────────────────────────────────────────────────────────────

export type ToastVariant = 'success' | 'error' | 'warning' | 'info';

export interface Toast {
  id: string;
  message: string;
  variant: ToastVariant;
}

interface ToastContextType {
  showToast: (message: string, variant?: ToastVariant) => void;
}

// ─── Context ──────────────────────────────────────────────────────────────────

const ToastContext = createContext<ToastContextType | undefined>(undefined);

// ─── Variant Config ───────────────────────────────────────────────────────────

const VARIANT_CONFIG: Record<
  ToastVariant,
  { icon: React.ReactNode; bg: string; border: string; text: string; progress: string }
> = {
  success: {
    icon: <CheckCircle2 className="w-5 h-5" style={{ color: '#34d399', flexShrink: 0 }} />,
    bg: 'rgba(6, 78, 59, 0.55)',
    border: 'rgba(52, 211, 153, 0.3)',
    text: '#a7f3d0',
    progress: '#34d399',
  },
  error: {
    icon: <XCircle className="w-5 h-5" style={{ color: '#f87171', flexShrink: 0 }} />,
    bg: 'rgba(127, 29, 29, 0.55)',
    border: 'rgba(248, 113, 113, 0.3)',
    text: '#fca5a5',
    progress: '#f87171',
  },
  warning: {
    icon: <AlertTriangle className="w-5 h-5" style={{ color: '#fbbf24', flexShrink: 0 }} />,
    bg: 'rgba(78, 50, 0, 0.55)',
    border: 'rgba(251, 191, 36, 0.3)',
    text: '#fde68a',
    progress: '#fbbf24',
  },
  info: {
    icon: <Info className="w-5 h-5" style={{ color: '#38bdf8', flexShrink: 0 }} />,
    bg: 'rgba(7, 89, 133, 0.55)',
    border: 'rgba(56, 189, 248, 0.3)',
    text: '#bae6fd',
    progress: '#38bdf8',
  },
};

const AUTO_DISMISS_MS = 4000;

// ─── Toast Item ───────────────────────────────────────────────────────────────

const ToastItem: React.FC<{ toast: Toast; onDismiss: (id: string) => void }> = ({
  toast,
  onDismiss,
}) => {
  const cfg = VARIANT_CONFIG[toast.variant];

  return (
    <>
      <style>{`
        @keyframes toast-slide-in {
          from { opacity: 0; transform: translateX(110%); }
          to   { opacity: 1; transform: translateX(0); }
        }
        @keyframes toast-progress {
          from { width: 100%; }
          to   { width: 0%; }
        }
        .toast-item {
          animation: toast-slide-in 0.38s cubic-bezier(0.16, 1, 0.3, 1) forwards;
          position: relative;
          display: flex;
          align-items: flex-start;
          gap: 10px;
          padding: 14px 16px;
          border-radius: 12px;
          border: 1px solid;
          backdrop-filter: blur(16px);
          -webkit-backdrop-filter: blur(16px);
          box-shadow: 0 8px 32px rgba(0,0,0,0.4);
          min-width: 300px;
          max-width: 440px;
          overflow: hidden;
          cursor: pointer;
          transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        .toast-item:hover {
          transform: translateX(-4px);
          box-shadow: 0 12px 40px rgba(0,0,0,0.5);
        }
        .toast-progress-bar {
          position: absolute;
          bottom: 0;
          left: 0;
          height: 3px;
          border-radius: 0 0 12px 12px;
          animation: toast-progress ${AUTO_DISMISS_MS}ms linear forwards;
        }
        .toast-close-btn {
          background: none;
          border: none;
          cursor: pointer;
          padding: 2px;
          border-radius: 4px;
          opacity: 0.6;
          transition: opacity 0.2s;
          flex-shrink: 0;
          display: flex;
          align-items: center;
          color: inherit;
        }
        .toast-close-btn:hover { opacity: 1; }
      `}</style>
      <div
        className="toast-item"
        style={{ background: cfg.bg, borderColor: cfg.border }}
        onClick={() => onDismiss(toast.id)}
        role="alert"
        aria-live="assertive"
      >
        {cfg.icon}
        <span style={{ flex: 1, fontSize: '0.875rem', fontWeight: 500, color: cfg.text, lineHeight: 1.5 }}>
          {toast.message}
        </span>
        <button className="toast-close-btn" style={{ color: cfg.text }} aria-label="Dismiss">
          <X className="w-4 h-4" />
        </button>
        <div className="toast-progress-bar" style={{ background: cfg.progress }} />
      </div>
    </>
  );
};

// ─── Provider ─────────────────────────────────────────────────────────────────

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const timerMap = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
    const timer = timerMap.current.get(id);
    if (timer) {
      clearTimeout(timer);
      timerMap.current.delete(id);
    }
  }, []);

  const showToast = useCallback(
    (message: string, variant: ToastVariant = 'info') => {
      const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      setToasts((prev) => [...prev, { id, message, variant }]);

      const timer = setTimeout(() => dismiss(id), AUTO_DISMISS_MS);
      timerMap.current.set(id, timer);
    },
    [dismiss],
  );

  return (
    <ToastContext.Provider value={{ showToast }}>
      {children}
      {/* Toast Container */}
      <div
        style={{
          position: 'fixed',
          bottom: '24px',
          right: '24px',
          zIndex: 9999,
          display: 'flex',
          flexDirection: 'column',
          gap: '12px',
          alignItems: 'flex-end',
          pointerEvents: 'none',
        }}
        aria-label="Notifications"
      >
        {toasts.map((t) => (
          <div key={t.id} style={{ pointerEvents: 'auto' }}>
            <ToastItem toast={t} onDismiss={dismiss} />
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
};

// ─── Hook ─────────────────────────────────────────────────────────────────────

export const useToast = (): ToastContextType => {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return ctx;
};
