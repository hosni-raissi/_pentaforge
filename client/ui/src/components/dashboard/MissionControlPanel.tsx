import type { ReactNode } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  PauseCircle,
  Radar,
  RefreshCw,
  ShieldAlert,
} from "lucide-react";

import { Badge } from "@/components/ui/Badge";
import { Card } from "@/components/ui/Card";
import { cn } from "@/lib/utils";

export type MissionControlState =
  | "idle"
  | "initializing"
  | "running"
  | "paused_for_approval"
  | "reconnecting_sse"
  | "error"
  | "completed";

export type MissionControlPhaseKey =
  | "intel"
  | "information_gathering"
  | "brain"
  | "planner"
  | "executer"
  | "analyzer";

export interface MissionControlPhase {
  key: MissionControlPhaseKey;
  label: string;
  status: "pending" | "active" | "completed";
  detail: string;
}

export interface MissionControlSignal {
  label: string;
  value: string;
  hint?: string;
}

export interface MissionControlWorkerItem {
  label: string;
  status: "active" | "completed" | "waiting";
  detail: string;
  at?: string;
}

export interface MissionControlAction {
  title: string;
  detail: string;
  tone?: "info" | "warn" | "danger";
  controls?: ReactNode;
}

interface MissionControlPanelProps {
  state: MissionControlState;
  title: string;
  detail: string;
  streamLabel: string;
  phases: MissionControlPhase[];
  signals: MissionControlSignal[];
  workers: MissionControlWorkerItem[];
  findingSummary?: string;
  findingSeverity?: string;
  action?: MissionControlAction | null;
}

const STATE_META: Record<
  MissionControlState,
  {
    label: string;
    icon: typeof Radar;
    badgeVariant: "idle" | "running" | "stopped" | "completed" | "error";
    shellClass: string;
  }
> = {
  idle: {
    label: "Idle",
    icon: Radar,
    badgeVariant: "idle",
    shellClass: "border-border/60 bg-surface-1",
  },
  initializing: {
    label: "Initializing",
    icon: RefreshCw,
    badgeVariant: "running",
    shellClass: "border-pf-500/30 bg-pf-500/10",
  },
  running: {
    label: "Running",
    icon: Activity,
    badgeVariant: "running",
    shellClass: "border-pf-500/30 bg-pf-500/10",
  },
  paused_for_approval: {
    label: "Approval Required",
    icon: PauseCircle,
    badgeVariant: "stopped",
    shellClass: "border-yellow-500/30 bg-yellow-500/10",
  },
  reconnecting_sse: {
    label: "Reconnecting",
    icon: RefreshCw,
    badgeVariant: "stopped",
    shellClass: "border-yellow-500/30 bg-yellow-500/10",
  },
  error: {
    label: "Failed",
    icon: AlertTriangle,
    badgeVariant: "error",
    shellClass: "border-red-500/30 bg-red-500/10",
  },
  completed: {
    label: "Completed",
    icon: CheckCircle2,
    badgeVariant: "completed",
    shellClass: "border-emerald-500/30 bg-emerald-500/10",
  },
};

function phaseDotClass(status: MissionControlPhase["status"]): string {
  if (status === "completed") {
    return "border-emerald-500/60 bg-emerald-500/20 text-emerald-300";
  }
  if (status === "active") {
    return "border-pf-500/60 bg-pf-500/20 text-pf-300 ring-1 ring-pf-500/30";
  }
  return "border-border/70 bg-surface-2 text-text-muted";
}

function workerTone(status: MissionControlWorkerItem["status"]): string {
  if (status === "completed") {
    return "border-emerald-500/30 bg-emerald-500/10";
  }
  if (status === "active") {
    return "border-pf-500/30 bg-pf-500/10";
  }
  return "border-border/60 bg-surface-0/35";
}

function actionTone(tone: MissionControlAction["tone"]): string {
  if (tone === "danger") {
    return "border-red-500/30 bg-red-500/10";
  }
  if (tone === "warn") {
    return "border-yellow-500/30 bg-yellow-500/10";
  }
  return "border-pf-500/30 bg-pf-500/10";
}

export function MissionControlPanel({
  state,
  title,
  detail,
  streamLabel,
  phases,
  signals,
  workers,
  findingSummary,
  findingSeverity,
  action,
}: MissionControlPanelProps) {
  const meta = STATE_META[state];
  const Icon = meta.icon;

  return (
    <Card className={cn("space-y-4 border shadow-sm", meta.shellClass)}>
      <div className="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-white/10 bg-surface-0/50">
              <Icon
                size={18}
                className={cn(
                  state === "running" || state === "initializing"
                    ? "animate-pulse text-pf-300"
                    : state === "completed"
                      ? "text-emerald-300"
                      : state === "error"
                        ? "text-red-300"
                        : "text-yellow-300",
                )}
              />
            </div>
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-text-muted">
                Mission Control
              </p>
              <div className="mt-1 flex flex-wrap items-center gap-2">
                <h2 className="text-lg font-semibold text-text-primary">{title}</h2>
                <Badge variant={meta.badgeVariant} dot>
                  {meta.label}
                </Badge>
              </div>
            </div>
          </div>
          <p className="max-w-4xl text-sm leading-6 text-text-secondary">{detail}</p>
        </div>

        <div className="rounded-xl border border-border/60 bg-surface-0/50 px-3 py-2 text-sm">
          <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-text-muted">
            Event Stream
          </p>
          <p className="mt-1 font-medium text-text-primary">{streamLabel}</p>
        </div>
      </div>

      <div className="grid gap-2 xl:grid-cols-6">
        {phases.map((phase, index) => (
          <div
            key={phase.key}
            className={cn(
              "rounded-xl border px-3 py-3 transition-all",
              phaseDotClass(phase.status),
            )}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="text-[11px] font-semibold uppercase tracking-[0.18em]">
                {String(index + 1).padStart(2, "0")}
              </span>
              <span className="text-[10px] uppercase tracking-[0.18em]">
                {phase.status}
              </span>
            </div>
            <p className="mt-2 text-sm font-semibold text-text-primary">{phase.label}</p>
            <p className="mt-1 text-xs leading-5 text-text-secondary">{phase.detail}</p>
          </div>
        ))}
      </div>

      <div className="grid gap-3 lg:grid-cols-4">
        {signals.map((signal) => (
          <div
            key={signal.label}
            className="rounded-xl border border-border/60 bg-surface-0/45 px-3 py-3"
          >
            <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-text-muted">
              {signal.label}
            </p>
            <p className="mt-2 text-lg font-semibold text-text-primary">{signal.value}</p>
            {signal.hint ? (
              <p className="mt-1 text-xs leading-5 text-text-secondary">{signal.hint}</p>
            ) : null}
          </div>
        ))}
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
        <div className="space-y-3 rounded-xl border border-border/60 bg-surface-0/45 p-3">
          <div className="flex items-center justify-between gap-2">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-text-muted">
                Worker Activity
              </p>
              <p className="mt-1 text-sm text-text-secondary">
                Current scenarios and the most recent operator-visible activity.
              </p>
            </div>
          </div>

          {workers.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border/70 bg-surface-0/35 px-3 py-4 text-sm text-text-muted">
              No worker activity yet. The executer will list active scenarios here once the scan enters its cycle loop.
            </div>
          ) : (
            <div className="space-y-2">
              {workers.map((worker) => (
                <div
                  key={`${worker.label}-${worker.at ?? worker.detail}`}
                  className={cn("rounded-lg border px-3 py-3", workerTone(worker.status))}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-sm font-semibold text-text-primary">{worker.label}</p>
                    <Badge
                      variant={
                        worker.status === "completed"
                          ? "completed"
                          : worker.status === "active"
                            ? "running"
                            : "stopped"
                      }
                      dot={worker.status !== "waiting"}
                      className="text-[10px]"
                    >
                      {worker.status}
                    </Badge>
                  </div>
                  <p className="mt-2 text-sm leading-6 text-text-secondary">{worker.detail}</p>
                  {worker.at ? (
                    <p className="mt-1 text-[11px] text-text-muted">{worker.at}</p>
                  ) : null}
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="space-y-3">
          <div className="rounded-xl border border-border/60 bg-surface-0/45 p-3">
            <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-text-muted">
              Finding Impact
            </p>
            {findingSummary ? (
              <>
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <p className="text-sm font-semibold text-text-primary">{findingSummary}</p>
                  {findingSeverity ? (
                    <Badge variant="default" className="text-[10px] uppercase">
                      {findingSeverity}
                    </Badge>
                  ) : null}
                </div>
                <p className="mt-2 text-sm leading-6 text-text-secondary">
                  Latest verified finding in operator view. Use it to judge whether the current cycle is producing meaningful impact.
                </p>
              </>
            ) : (
              <div className="mt-2 rounded-lg border border-dashed border-border/70 bg-surface-0/35 px-3 py-4 text-sm text-text-muted">
                No verified findings yet. Confirmed issues will appear here once the analyzer saves them.
              </div>
            )}
          </div>

          <div className={cn("rounded-xl border p-3", actionTone(action?.tone))}>
            <div className="flex items-start gap-3">
              <div className="mt-0.5 flex h-9 w-9 items-center justify-center rounded-lg border border-white/10 bg-surface-0/40">
                <ShieldAlert size={16} className="text-text-primary" />
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-text-muted">
                  Operator Action
                </p>
                <p className="mt-1 text-sm font-semibold text-text-primary">
                  {action?.title ?? "No action waiting"}
                </p>
                <p className="mt-1 text-sm leading-6 text-text-secondary">
                  {action?.detail ?? "Approvals, reconnect notices, and failure guidance will appear here instead of being scattered across the page."}
                </p>
              </div>
            </div>
            {action?.controls ? <div className="mt-3">{action.controls}</div> : null}
          </div>
        </div>
      </div>
    </Card>
  );
}
