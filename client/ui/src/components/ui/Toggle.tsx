import { clsx } from 'clsx';

interface ToggleProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label?: string;
  disabled?: boolean;
}

export function Toggle({ checked, onChange, label, disabled }: ToggleProps) {
  return (
    <label className={clsx('inline-flex items-center gap-2 cursor-pointer', disabled && 'opacity-50')}>
      <button
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={clsx(
          'relative w-8 h-[18px] rounded-full transition-colors duration-200',
          checked ? 'bg-pf-600' : 'bg-surface-3'
        )}
      >
        <span
          className={clsx(
            'absolute top-0.5 left-0.5 w-3.5 h-3.5 rounded-full bg-white',
            'transition-transform duration-200',
            checked && 'translate-x-3.5'
          )}
        />
      </button>
      {label && <span className="text-xs text-text-secondary">{label}</span>}
    </label>
  );
}