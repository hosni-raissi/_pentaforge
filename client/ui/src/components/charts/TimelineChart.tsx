import { AreaChart, Area, XAxis, YAxis, ResponsiveContainer, Tooltip } from 'recharts';
import { Card, CardHeader, CardTitle } from '../ui/Card';

interface TimelineChartProps {
  data: { time: string; findings: number; scanned: number }[];
}

export function TimelineChart({ data }: TimelineChartProps) {
  return (
    <Card>
      <CardHeader><CardTitle>Scan Timeline</CardTitle></CardHeader>
      <div className="h-40">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <defs>
              <linearGradient id="findingsGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.3} />
                <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis
              dataKey="time"
              tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
              axisLine={false}
              tickLine={false}
              width={30}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: 'var(--surface-2)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                fontSize: '11px',
                color: 'var(--text-primary)',
              }}
            />
            <Area
              type="monotone"
              dataKey="findings"
              stroke="#3b82f6"
              strokeWidth={2}
              fill="url(#findingsGrad)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}