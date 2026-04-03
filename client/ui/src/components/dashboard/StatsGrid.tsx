import { Card } from '../ui/Card';
import { Bug, Shield, AlertTriangle, CheckCircle } from 'lucide-react';
import type { Finding } from '../../types';

interface StatsGridProps {
  findings: Finding[];
}

export function StatsGrid({ findings }: StatsGridProps) {
  const critical = findings.filter((f) => f.severity === 'critical').length;
  const high     = findings.filter((f) => f.severity === 'high').length;
  const verified = findings.filter((f) => f.status === 'verified').length;
  const total    = findings.length;

  const stats = [
    { label: 'Total Findings',  value: total,    icon: Bug,              color: 'text-pf-400' },
    { label: 'Critical',        value: critical,  icon: AlertTriangle,    color: 'text-red-400' },
    { label: 'High',            value: high,      icon: Shield,           color: 'text-orange-400' },
    { label: 'Verified',        value: verified,  icon: CheckCircle,      color: 'text-emerald-400' },
  ];

  return (
    <div className="grid grid-cols-4 gap-3">
      {stats.map(({ label, value, icon: Icon, color }) => (
        <Card key={label} className="flex items-center gap-3">
          <div className={`p-2 rounded-lg bg-surface-2 ${color}`}>
            <Icon size={18} />
          </div>
          <div>
            <p className="text-2xl font-bold text-text-primary">{value}</p>
            <p className="text-sm text-text-muted">{label}</p>
          </div>
        </Card>
      ))}
    </div>
  );
}