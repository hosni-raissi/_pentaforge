import { Card, CardHeader, CardTitle } from '../ui/Card';
import { Badge } from '../ui/Badge';
import type { Finding } from '../../types';
import { format } from 'date-fns';

interface FindingsTableProps {
  findings: Finding[];
  limit?: number;
}

export function FindingsTable({ findings, limit = 10 }: FindingsTableProps) {
  function formatFindingTime(value: string): string {
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      return '--:--';
    }
    return format(parsed, 'HH:mm');
  }

  const sorted = [...findings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
  });
  const displayed = sorted.slice(0, limit);

  return (
    <Card className="p-0">
      <CardHeader className="px-4 pt-4">
        <CardTitle>Recent Findings</CardTitle>
        <span className="text-[11px] text-text-muted">{findings.length} total</span>
      </CardHeader>

      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border text-text-muted">
              <th className="text-left px-4 py-2 font-medium">Severity</th>
              <th className="text-left px-4 py-2 font-medium">Title</th>
              <th className="text-left px-4 py-2 font-medium">Target</th>
              <th className="text-left px-4 py-2 font-medium">Status</th>
              <th className="text-left px-4 py-2 font-medium">Time</th>
            </tr>
          </thead>
          <tbody>
            {displayed.map((f) => (
              <tr key={f.id} className="border-b border-border/50 hover:bg-surface-2 transition-colors">
                <td className="px-4 py-2"><Badge variant={f.severity}>{f.severity}</Badge></td>
                <td className="px-4 py-2 text-text-primary font-medium max-w-[200px] truncate">{f.title}</td>
                <td className="px-4 py-2 text-text-muted font-mono">{f.target}</td>
                <td className="px-4 py-2"><Badge variant={f.status === 'verified' ? 'completed' : 'default'}>{f.status}</Badge></td>
                <td className="px-4 py-2 text-text-muted">{formatFindingTime(f.timestamp)}</td>
              </tr>
            ))}
            {displayed.length === 0 && (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-text-muted">No findings yet</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
