import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { Card, CardHeader, CardTitle } from '../ui/Card';
import type { Finding } from '../../types';

interface SeverityChartProps {
  findings: Finding[];
}

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#3b82f6',
  info:     '#64748b',
};

export function SeverityChart({ findings }: SeverityChartProps) {
  const data = Object.entries(
    findings.reduce<Record<string, number>>((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    }, {})
  ).map(([name, value]) => ({ name, value }));

  if (data.length === 0) {
    return (
      <Card>
        <CardHeader><CardTitle>Severity Distribution</CardTitle></CardHeader>
        <div className="flex items-center justify-center h-40 text-xs text-text-muted">
          No findings yet
        </div>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader><CardTitle>Severity Distribution</CardTitle></CardHeader>
      <div className="h-44">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={35}
              outerRadius={60}
              paddingAngle={3}
              dataKey="value"
              strokeWidth={0}
            >
              {data.map((entry) => (
                <Cell
                  key={entry.name}
                  fill={SEVERITY_COLORS[entry.name as keyof typeof SEVERITY_COLORS] ?? '#64748b'}
                />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: 'var(--surface-2)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                fontSize: '11px',
                color: 'var(--text-primary)',
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
      {/* Legend */}
      <div className="flex flex-wrap gap-3 mt-2">
        {data.map((d) => (
          <div key={d.name} className="flex items-center gap-1.5">
            <div
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: SEVERITY_COLORS[d.name as keyof typeof SEVERITY_COLORS] }}
            />
            <span className="text-xs text-text-muted capitalize">{d.name}: {d.value}</span>
          </div>
        ))}
      </div>
    </Card>
  );
}