import { createContext, useCallback, useContext, useState, type ReactNode } from 'react';
import * as ToastPrimitive from '@radix-ui/react-toast';
import { cn } from '../../lib/utils';
import { X, CheckCircle, AlertTriangle, Info, AlertCircle } from 'lucide-react';

type ToastVariant = 'success' | 'error' | 'warning' | 'info';

interface ToastData {
  id: string;
  title: string;
  description?: string;
  variant: ToastVariant;
}

interface ToastContextValue {
  toast: (data: Omit<ToastData, 'id'>) => void;
}

const ToastContext = createContext<ToastContextValue>({ toast: () => {} });

export function useToast() {
  return useContext(ToastContext);
}

const icons: Record<ToastVariant, typeof CheckCircle> = {
  success: CheckCircle,
  error: AlertCircle,
  warning: AlertTriangle,
  info: Info,
};

const variantStyles: Record<ToastVariant, string> = {
  success: 'border-emerald-500/30 bg-emerald-500/10',
  error:   'border-red-500/30 bg-red-500/10',
  warning: 'border-yellow-500/30 bg-yellow-500/10',
  info:    'border-pf-500/30 bg-pf-500/10',
};

const iconStyles: Record<ToastVariant, string> = {
  success: 'text-emerald-400',
  error:   'text-red-400',
  warning: 'text-yellow-400',
  info:    'text-pf-400',
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastData[]>([]);

  const toast = useCallback((data: Omit<ToastData, 'id'>) => {
    const id = crypto.randomUUID();
    setToasts((prev) => [...prev, { ...data, id }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4000);
  }, []);

  return (
    <ToastContext.Provider value={{ toast }}>
      <ToastPrimitive.Provider swipeDirection="right">
        {children}
        {toasts.map((t) => {
          const Icon = icons[t.variant];
          return (
            <ToastPrimitive.Root
              key={t.id}
              className={cn(
                'rounded-lg border p-3 shadow-lg',
                'data-[state=open]:animate-slide-in',
                'data-[state=closed]:animate-out data-[state=closed]:fade-out-80',
                variantStyles[t.variant]
              )}
            >
              <div className="flex items-start gap-2.5">
                <Icon size={16} className={cn('mt-0.5 shrink-0', iconStyles[t.variant])} />
                <div className="flex-1 min-w-0">
                  <ToastPrimitive.Title className="text-xs font-medium text-text-primary">
                    {t.title}
                  </ToastPrimitive.Title>
                  {t.description && (
                    <ToastPrimitive.Description className="text-[11px] text-text-muted mt-0.5">
                      {t.description}
                    </ToastPrimitive.Description>
                  )}
                </div>
                <ToastPrimitive.Close className="text-text-muted hover:text-text-primary">
                  <X size={12} />
                </ToastPrimitive.Close>
              </div>
            </ToastPrimitive.Root>
          );
        })}
        <ToastPrimitive.Viewport className="fixed bottom-12 right-4 z-[100] flex flex-col gap-2 w-80" />
      </ToastPrimitive.Provider>
    </ToastContext.Provider>
  );
}