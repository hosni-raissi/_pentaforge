import { clsx } from 'clsx';
import type { ReactNode } from 'react';
import type { SeverityLevel, ProjectStatus, AgentState } from '../../types';

type BadgeVariant = SeverityLevel | ProjectStatus | AgentState | 'default';

const variantStyles: Record<string, string> = {
  critical:  'bg-red-500/15 text-red-400 border-red-500/20',
  high:      'bg-orange-500/15 text-orange-400 border-orange-500/20',
  medium:    'bg-yellow-500/15 text-yellow-400 border-yellow-500/20',
  low:       'bg-blue-500/15 text-blue-400 border-blue-500/20',
  info:      'bg-slate-500/15 text-slate-400 border-slate-500/20',
  running:   'bg-pf-500/15 text-pf-400 border-pf-500/20',
  idle:      'bg-slate-500/15 text-slate-400 border-slate-500/20',
  paused:    'bg-yellow-500/15 text-yellow-400 border-yellow-500/20',
  completed: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20',
  error:     'bg-red-500/15 text-red-400 border-red-500/20',
  success:   'bg-emerald-500/15 text-emerald-400 border-emerald-500/20',
  waiting:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/20',
  default:   'bg-surface-3 text-text-secondary border-border',
};

interface BadgeProps {
  variant?: BadgeVariant;
  children: ReactNode;
  dot?: boolean;
  className?: string;
}

export function Badge({ variant = 'default', children, dot, className }: BadgeProps) {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full',
        'text-sm font-medium border',
        variantStyles[variant] ?? variantStyles.default,
        className
      )}
    >
      {dot && (
        <span className={clsx(
          'w-1.5 h-1.5 rounded-full',
          variant === 'running' ? 'bg-pf-400 animate-pulse' : 'bg-current'
        )} />
      )}
      {children}
    </span>
  );
}
