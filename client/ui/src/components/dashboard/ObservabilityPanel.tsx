import { useEffect, useRef } from "react";
import { ActivitySquare, AlertTriangle, Clock3, RotateCcw, TimerReset } from "lucide-react";

import type {
  ScanDebugTimelineEntry,
  ScanObservabilityMetrics,
} from "@/lib/projectBridge";
import { Badge } from "@/components/ui/Badge";
import { Card } from "@/components/ui/Card";

interface ObservabilityPanelProps {
  timeline: ScanDebugTimelineEntry[];
  metrics: ScanObservabilityMetrics | null;
}

function formatMetricSeconds(value: number): string {
  if (!Number.isFinite(value) || value <= 0) {
    return "0s";
  }
  if (value >= 60) {
    return `${(value / 60).toFixed(1)}m`;
  }
  return `${value.toFixed(1)}s`;
}

function formatRate(value: number): string {
  if (!Number.isFinite(value) || value <= 0) {
    return "0%";
  }
  return `${(value * 100).toFixed(1)}%`;
}

function formatTimelineTime(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return "--:--:--";
  }
  return parsed.toLocaleTimeString();
}

function levelVariant(level: ScanDebugTimelineEntry["level"]): "default" | "running" | "completed" | "stopped" | "error" {
  if (level === "success") return "completed";
  if (level === "warn") return "stopped";
  if (level === "error") return "error";
  return "running";
}

export function ObservabilityPanel({ timeline, metrics }: ObservabilityPanelProps) {
  const scrollContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollContainerRef.current) {
      scrollContainerRef.current.scrollTop = scrollContainerRef.current.scrollHeight;
    }
  }, [timeline.length]);

  const metricCards = [
    {
      label: "Avg Cycle",
      value: metrics ? formatMetricSeconds(metrics.average_cycle_time_seconds) : "0s",
      hint: metrics ? `${metrics.cycle_count} measured cycles` : "No cycles measured",
      icon: Clock3,
    },
    {
      label: "Approval Delay",
      value: metrics ? formatMetricSeconds(metrics.average_approval_delay_seconds) : "0s",
      hint: metrics ? `${metrics.approval_count} resolved approvals` : "No approvals measured",
      icon: TimerReset,
    },
    {
      label: "Tool Failure",
      value: metrics ? formatRate(metrics.tool_failure_rate) : "0%",
      hint: metrics ? `${metrics.failed_tool_log_count}/${metrics.tool_log_count} tool records` : "No tool records",
      icon: AlertTriangle,
    },
    {
      label: "False Positives",
      value: metrics ? formatRate(metrics.false_positive_rate) : "0%",
      hint: metrics ? `${metrics.false_positive_count} dismissed / ${metrics.verified_vulnerability_count} verified` : "No findings verified",
      icon: ActivitySquare,
    },
    {
      label: "Resume Success",
      value: metrics ? formatRate(metrics.resume_success_rate) : "0%",
      hint: metrics ? `${metrics.resume_success_count}/${metrics.resume_attempt_count} resumed scans reached terminal state` : "No resume attempts",
      icon: RotateCcw,
    },
  ];

  return (
    <Card className="space-y-4 p-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-text-primary">Debug Timeline</h2>
        </div>
        <p className="text-sm text-text-muted">{timeline.length} timeline rows</p>
      </div>

      <div className="grid gap-3 lg:grid-cols-5">
        {metricCards.map((metric) => {
          const Icon = metric.icon;
          return (
            <div
              key={metric.label}
              className="rounded-xl border border-border/60 bg-surface-0/35 px-3 py-3 dark:border-border"
            >
              <div className="flex items-center gap-2 text-text-muted">
                <Icon size={14} />
                <p className="text-[11px] font-semibold uppercase tracking-[0.18em]">
                  {metric.label}
                </p>
              </div>
              <p className="mt-2 text-lg font-semibold text-text-primary">{metric.value}</p>
              <p className="mt-1 text-xs leading-5 text-text-secondary">{metric.hint}</p>
            </div>
          );
        })}
      </div>

      <div className="overflow-hidden rounded-xl border border-border/60 bg-surface-0/35 dark:border-border">
        <div className="grid grid-cols-[90px_160px_140px_1fr] gap-2 border-b border-border/60 px-3 py-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-text-muted dark:border-border">
          <span>Time</span>
          <span>Phase</span>
          <span>Reason</span>
          <span>Message</span>
        </div>
        <div 
          ref={scrollContainerRef}
          className="max-h-[360px] overflow-y-auto"
        >
          {timeline.length === 0 ? (
            <div className="px-3 py-4 text-sm text-text-muted">
              No debug timeline rows yet. Start a scan or wait for the next cached event snapshot.
            </div>
          ) : (
            [...timeline].reverse().map((item) => (
              <div
                key={item.id}
                className="grid grid-cols-[90px_160px_140px_1fr] gap-2 border-b border-border/40 px-3 py-2 text-sm last:border-b-0 dark:border-border"
              >
                <div className="space-y-1 min-w-0">
                  <p className="font-mono text-text-muted truncate">{formatTimelineTime(item.at)}</p>
                  <Badge variant={levelVariant(item.level)} className="text-[10px] truncate max-w-full block">
                    {item.kind === "tool_audit" ? "audit" : item.level}
                  </Badge>
                </div>
                <div className="space-y-1 min-w-0">
                  <p className="font-medium text-text-primary truncate" title={item.phase || "system"}>{item.phase || "system"}</p>
                  <p className="font-mono text-[11px] text-text-muted truncate" title={item.cycle ? `cycle ${item.cycle}` : item.agent || "n/a"}>
                    {item.cycle ? `cycle ${item.cycle}` : item.agent || "n/a"}
                  </p>
                </div>
                <div className="space-y-1 min-w-0">
                  <p className="text-text-primary truncate" title={item.reason_code || "n/a"}>{item.reason_code || "n/a"}</p>
                  <p className="font-mono text-[11px] text-text-muted truncate" title={item.tool || item.scenario_id || item.approval_id || "n/a"}>
                    {item.tool || item.scenario_id || item.approval_id || "n/a"}
                  </p>
                </div>
                <div className="space-y-1 min-w-0">
                  <p className="text-text-secondary">{item.message}</p>
                  <p className="font-mono text-[11px] text-text-muted">
                    evt={item.id.slice(0, 12)}
                    {item.finding_id ? ` · finding=${item.finding_id}` : ""}
                    {item.worker_id ? ` · worker=${item.worker_id}` : ""}
                  </p>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </Card>
  );
}
