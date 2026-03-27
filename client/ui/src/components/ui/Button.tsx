import { forwardRef, type ButtonHTMLAttributes } from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '../../lib/utils';

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 rounded-md text-sm font-medium transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-pf-500/50 focus-visible:ring-offset-1 focus-visible:ring-offset-surface-0 disabled:opacity-50 disabled:pointer-events-none',
  {
    variants: {
      variant: {
        primary:   'bg-pf-600 text-white hover:bg-pf-700 active:bg-pf-800 shadow-sm',
        secondary: 'bg-surface-2 text-text-primary hover:bg-surface-3 border border-border',
        ghost:     'text-text-secondary hover:bg-surface-2 hover:text-text-primary',
        danger:    'bg-red-600 text-white hover:bg-red-700 active:bg-red-800',
        outline:   'border border-pf-500/40 text-pf-400 hover:bg-pf-600/10',
      },
      size: {
        xs: 'h-6 px-2 text-[11px] gap-1',
        sm: 'h-7 px-2.5 text-xs gap-1.5',
        md: 'h-8 px-3.5 text-sm gap-2',
        lg: 'h-9 px-5 text-sm gap-2',
        icon: 'h-7 w-7',
      },
    },
    defaultVariants: {
      variant: 'primary',
      size: 'md',
    },
  }
);

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, loading, children, disabled, type, ...props }, ref) => (
    <button
      ref={ref}
      type={type ?? 'button'}
      disabled={disabled || loading}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    >
      {loading && (
        <svg className="animate-spin h-3.5 w-3.5" viewBox="0 0 24 24" fill="none">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      )}
      {children}
    </button>
  )
);
Button.displayName = 'Button';

export { buttonVariants };
