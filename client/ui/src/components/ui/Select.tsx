import { forwardRef, type SelectHTMLAttributes } from 'react';
import { clsx } from 'clsx';

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  options: { value: string; label: string }[];
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  ({ label, options, className, ...props }, ref) => (
    <div className="space-y-1">
      {label && (
        <label className="block text-xs font-medium text-text-secondary">{label}</label>
      )}
      <select
        ref={ref}
        className={clsx(
          'w-full px-3 py-1.5 rounded-md text-sm',
          'bg-surface-0 border border-border text-text-primary',
          'transition-colors duration-150 focus-ring',
          'hover:border-pf-500/40',
          className
        )}
        {...props}
      >
        {options.map((opt) => (
          <option key={opt.value} value={opt.value}>{opt.label}</option>
        ))}
      </select>
    </div>
  )
);