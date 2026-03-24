import { forwardRef, type InputHTMLAttributes } from 'react';
import { clsx } from 'clsx';

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  hint?: string;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, hint, className, ...props }, ref) => (
    <div className="space-y-1">
      {label && (
        <label className="block text-xs font-medium text-text-secondary">{label}</label>
      )}
      <input
        ref={ref}
        className={clsx(
          'w-full px-3 py-1.5 rounded-md text-sm',
          'bg-surface-0 border text-text-primary placeholder:text-text-muted',
          'transition-colors duration-150 focus-ring',
          error ? 'border-red-500' : 'border-border hover:border-pf-500/40',
          className
        )}
        {...props}
      />
      {error && <p className="text-xs text-red-400">{error}</p>}
      {hint && !error && <p className="text-xs text-text-muted">{hint}</p>}
    </div>
  )
);