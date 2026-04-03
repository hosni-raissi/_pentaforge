import { Card, CardHeader, CardTitle } from '../ui/Card';
import type { PhaseInfo } from '../../types';
import { clsx } from 'clsx';

interface ScanProgressProps {
  phases: PhaseInfo[];
  progress: number;
}

export function ScanProgress({ phases, progress }: ScanProgressProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Scan Progress</CardTitle>
        <span className="text-sm text-pf-400 font-mono">{progress}%</span>
      </CardHeader>

      {/* Overall bar */}
      <div className="h-1.5 bg-surface-2 rounded-full overflow-hidden mb-4">
        <div
          className="h-full bg-pf-600 rounded-full transition-all duration-500"
          style={{ width: `${progress}%` }}
        />
      </div>

      {/* Phase timeline */}
      <div className="space-y-2">
        {phases.map((phase, i) => (
          <div key={phase.name} className="flex items-center gap-3">
            {/* Step dot */}
            <div className={clsx(
              'w-2 h-2 rounded-full shrink-0',
              phase.status === 'completed' ? 'bg-emerald-400' :
              phase.status === 'active' ? 'bg-pf-400 animate-pulse' :
              'bg-surface-3'
            )} />

            {/* Phase name */}
            <span className={clsx(
              'text-sm flex-1',
              phase.status === 'active' ? 'text-text-primary font-medium' : 'text-text-muted'
            )}>
              {phase.name}
            </span>

            {/* Progress */}
            <div className="w-16 h-1 bg-surface-2 rounded-full overflow-hidden">
              <div
                className={clsx(
                  'h-full rounded-full transition-all duration-300',
                  phase.status === 'completed' ? 'bg-emerald-500' : 'bg-pf-600'
                )}
                style={{ width: `${phase.progress}%` }}
              />
            </div>

            <span className="text-sm text-text-muted w-8 text-right font-mono">
              {phase.progress}%
            </span>
          </div>
        ))}
      </div>
    </Card>
  );
}