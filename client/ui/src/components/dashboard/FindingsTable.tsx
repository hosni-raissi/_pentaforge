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

  const visibleFindings = findings.filter((finding) => finding.status !== 'false_positive');

  const sorted = [...visibleFindings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
  });
  const displayed = sorted.slice(0, limit);

  function proofBadgeClass(value?: Finding["proofQuality"]): string {
    if (value === "strong") {
      return "border-emerald-500/40 bg-emerald-500/15 text-emerald-900 dark:text-emerald-200";
    }
    if (value === "moderate") {
      return "border-orange-500/40 bg-orange-500/15 text-orange-900 dark:text-orange-200";
    }
    if (value === "weak") {
      return "border-slate-500/40 bg-slate-500/15 text-slate-900 dark:text-slate-200";
    }
    return "";
  }

  function usesOobProof(finding: Finding): boolean {
    const methods = Array.isArray(finding.verificationMethods)
      ? finding.verificationMethods
      : (Array.isArray(finding.evidence?.verification_methods) ? finding.evidence.verification_methods : []);
    return (
      methods.some((item) => typeof item === 'string' && item.trim().toLowerCase() === 'oob_callback')
      || finding.evidence?.oob_confirmed === true
    );
  }

  return (
    <Card className="p-0">
      <CardHeader className="px-4 pt-4">
        <CardTitle>Recent Findings</CardTitle>
        <span className="text-xs text-text-muted">{visibleFindings.length} active</span>
      </CardHeader>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
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
                <td className="px-4 py-2">
                  <div className="flex flex-wrap gap-1">
                    <Badge variant={f.status === 'verified' ? 'completed' : 'default'}>{f.status}</Badge>
                    {(f.evidenceStatus ?? f.evidence?.evidence_status) ? (
                      <Badge
                        variant="default"
                        className={proofBadgeClass(f.proofQuality ?? f.evidence?.proof_quality)}
                      >
                        {String(f.evidenceStatus ?? f.evidence?.evidence_status).replace(/_/g, ' ')}
                      </Badge>
                    ) : null}
                    {usesOobProof(f) ? (
                      <Badge
                        variant="default"
                        className="border border-sky-500/40 bg-sky-500/15 text-sky-200"
                      >
                        OOB
                      </Badge>
                    ) : null}
                  </div>
                </td>
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
