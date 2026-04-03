import { useState, type ReactNode } from 'react';
import { cn } from '../../lib/utils';

interface TooltipProps {
  content: string;
  children: ReactNode;
  side?: 'top' | 'bottom';
}

export function Tooltip({ content, children, side = 'top' }: TooltipProps) {
  const [show, setShow] = useState(false);

  return (
    <div className="relative inline-flex" onMouseEnter={() => setShow(true)} onMouseLeave={() => setShow(false)}>
      {children}
      {show && (
        <div
          className={cn(
            'absolute z-50 px-2 py-1 rounded text-sm font-medium',
            'bg-surface-3 text-text-primary border border-border shadow-lg',
            'whitespace-nowrap pointer-events-none animate-slide-in',
            side === 'top' ? 'bottom-full mb-1.5 left-1/2 -translate-x-1/2' : 'top-full mt-1.5 left-1/2 -translate-x-1/2'
          )}
        >
          {content}
        </div>
      )}
    </div>
  );
}