import { useMemo } from "react";
import { Bot, Clock3, Pencil, Play, Repeat2, Square, X, Maximize2, Zap, Check, RotateCw, FileArchive } from "lucide-react";

import { ObservabilityPanel } from "@/components/dashboard/ObservabilityPanel";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Dialog } from "@/components/ui/Dialog";
import { cn } from "@/lib/utils";
import type {
  FindingEvidence,
  FindingEvidenceStatus,
  FindingProofQuality,
  ProjectStatus,
  RealtimeVulnFinding,
  DashboardSeverity,
} from "@/types";
import type {
  ScanDebugTimelineEntry,
  ScanObservabilityMetrics,
} from "@/lib/projectBridge";


interface ArchitectureHost {
  id: string;
  name: string;
  role: string;
  ports: string[];
  note: string;
  x: number;
  y: number;
}

interface ArchitectureFlow {
  fromId: string;
  toId: string;
  label: string;
}

interface ArchitectureBoardBox {
  id: string;
  title: string;
  subtitle?: string;
  kind?: string;
  x: number;
  y: number;
  w: number;
  h: number;
  lines?: string[];
  tags?: string[];
  hostIds?: string[];
  emphasis?: "primary" | "normal" | "muted";
}

interface ArchitectureBoardLink {
  fromId: string;
  toId: string;
  label?: string;
}

interface ArchitectureBoard {
  theme?: string;
  canvas?: {
    width: number;
    height: number;
  };
  boxes: ArchitectureBoardBox[];
  links: ArchitectureBoardLink[];
}

interface TargetArchitectureDraft {
  title: string;
  hosts: ArchitectureHost[];
  flows?: ArchitectureFlow[];
  board?: ArchitectureBoard;
}

interface ArchitectureEdge {
  from: ArchitectureHost;
  to: ArchitectureHost;
}

function splitNoteIntoLines(note: string, maxLines = 3): string[] {
  return note
    .split(/(?<=[.!?])\s+/)
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(0, maxLines);
}

function architectureZoneLabel(host: ArchitectureHost): string {
  const role = host.role.trim().toLowerCase();
  if (role.includes("edge")) return "ENTRY";
  if (role.includes("data")) return "DATA";
  if (role.includes("service")) return "SERVICE";
  return "NODE";
}

function boardBoxKindLabel(kind: string | undefined): string {
  const value = String(kind || "").trim().toLowerCase();
  if (value === "host") return "HOST";
  if (value === "ports") return "PORTS";
  if (value === "service") return "SERVICE";
  if (value === "backend") return "BACKEND";
  if (value === "data") return "DATA";
  if (value === "auth") return "AUTH";
  if (value === "infra") return "INFRA";
  if (value === "attack" || value === "vector") return "ATTACK VECTOR";
  if (value === "vuln" || value === "vulnerability") return "VULNERABILITY";
  return "NOTES";
}

function boardBoxTone(emphasis: string | undefined) {
  if (emphasis === "primary") {
    return {
      frame: "border-zinc-300 bg-white shadow-sm dark:border-border dark:bg-surface-1",
      chip: "border-zinc-300 bg-zinc-50 text-zinc-900 dark:border-border/50 dark:bg-surface-2 dark:text-text-primary",
    };
  }
  if (emphasis === "muted") {
    return {
      frame: "border-zinc-200 bg-zinc-50 shadow-none dark:border-border/50 dark:bg-surface-0/50",
      chip: "border-zinc-200 bg-white text-zinc-500 dark:border-border/30 dark:bg-surface-1 dark:text-text-muted",
    };
  }
  return {
    frame: "border-zinc-200 bg-white shadow-sm dark:border-border dark:bg-surface-1",
    chip: "border-zinc-200 bg-zinc-50 text-zinc-800 dark:border-border/50 dark:bg-surface-2 dark:text-text-primary",
  };
}

function estimateBoardBoxHeight(box: ArchitectureBoardBox): number {
  const titleHeight = 20;
  const subtitleHeight = box.subtitle ? 34 : 0;
  const tagsHeight = box.tags && box.tags.length > 0
    ? 30 * Math.max(1, Math.ceil(box.tags.length / Math.max(1, Math.floor((box.w - 24) / 84))))
    : 0;

  const lineBlocks = (box.lines ?? []).reduce((total, line) => {
    const estimatedCharsPerRow = Math.max(18, Math.floor((box.w - 56) / 7));
    const wrappedRows = Math.max(1, Math.ceil(line.length / estimatedCharsPerRow));
    return total + wrappedRows;
  }, 0);
  const linesHeight = lineBlocks > 0 ? lineBlocks * 22 + (box.lines?.length ?? 0) * 10 : 0;

  return Math.max(box.h, 28 + titleHeight + subtitleHeight + tagsHeight + linesHeight + 24);
}

function boxesOverlap(
  a: Pick<ArchitectureBoardBox, "x" | "y" | "w" | "h">,
  b: Pick<ArchitectureBoardBox, "x" | "y" | "w" | "h">,
  gap = 18,
): boolean {
  return !(
    a.x + a.w + gap <= b.x
    || b.x + b.w + gap <= a.x
    || a.y + a.h + gap <= b.y
    || b.y + b.h + gap <= a.y
  );
}

function resolveBoardBoxLayout(
  boxes: ArchitectureBoardBox[],
  canvasWidth: number,
  canvasHeight: number,
): { boxes: ArchitectureBoardBox[]; canvasHeight: number } {
  const margin = 24;
  const gap = 24;
  const placed: ArchitectureBoardBox[] = [];
  let nextCanvasHeight = canvasHeight;

  for (const source of boxes) {
    const box: ArchitectureBoardBox = {
      ...source,
      x: Math.max(margin, Math.min(source.x, Math.max(margin, canvasWidth - source.w - margin))),
      y: Math.max(margin, source.y),
      h: estimateBoardBoxHeight(source),
    };

    let safety = 0;
    while (safety < 200) {
      const collision = placed.find((candidate) => boxesOverlap(box, candidate, gap));
      if (!collision) {
        break;
      }
      box.y = collision.y + collision.h + gap;
      safety += 1;
    }

    placed.push(box);
    nextCanvasHeight = Math.max(nextCanvasHeight, box.y + box.h + margin);
  }

  return {
    boxes: placed,
    canvasHeight: nextCanvasHeight,
  };
}

interface DashboardFindingDetail extends RealtimeVulnFinding {
  target?: string;
  timestamp?: string;
  verificationMethods?: string[];
  [key: string]: unknown;
}

interface DashboardProjectHeaderProps {
  projectName: string;
  effectiveStatus: ProjectStatus;
  isRunning: boolean;
  canRun: boolean;
  isStarting: boolean;
  startingMessage?: string | null;
  isStopping?: boolean;
  stoppingMessage?: string | null;
  hasAnotherRunningProject: boolean;
  onStartScan: () => void;
  onStopScan: () => void;
  onChangeProject: () => void;
  onCloseProject: () => void;
}

export function DashboardProjectHeader({
  projectName,
  effectiveStatus,
  isRunning,
  canRun,
  isStarting,
  startingMessage,
  isStopping,
  stoppingMessage,
  hasAnotherRunningProject,
  onStartScan,
  onStopScan,
  onChangeProject,
  onCloseProject,
}: DashboardProjectHeaderProps) {
  return (
    <div className="sticky -top-4 z-20 -mx-4 mb-6 p-3 bg-background/80 backdrop-blur-3xl border-b border-border shadow-sm transition-all duration-200">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-xl font-extrabold text-text-primary tracking-tight">{projectName}</h1>
            <Badge variant={effectiveStatus} dot className="text-[10px] font-black uppercase">
              {effectiveStatus}
            </Badge>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {!isRunning ? (
            <Button
              size="xs"
              onClick={onStartScan}
              disabled={!canRun}
              loading={isStarting}
              title={
                hasAnotherRunningProject
                  ? "Another scan is already running"
                  : "Start scan"
              }
              className="font-bold uppercase tracking-wider"
            >
              <Play size={12} />
              Start Scan
            </Button>
          ) : (
            <div className="flex items-center gap-2">
              <Button
                size="xs"
                variant="danger"
                onClick={onStopScan}
                loading={Boolean(isStopping)}
                disabled={Boolean(isStopping)}
                title="Stop running scan"
                className="font-bold uppercase tracking-wider"
              >
                <Square size={12} />
                Stop Scan
              </Button>
            </div>
          )}
          {isStarting ? (
            <span className="text-[11px] font-bold text-pf-500 uppercase animate-pulse">
              {startingMessage || 'Starting scan...'}
            </span>
          ) : null}
          {isStopping ? (
            <span className="text-[11px] font-bold text-red-500 uppercase animate-pulse">
              {stoppingMessage || 'Stopping scan...'}
            </span>
          ) : null}
          <Button size="xs" variant="secondary" onClick={onChangeProject} className="font-bold uppercase tracking-wider">
            <Repeat2 size={12} />
            Change
          </Button>
          <Button size="xs" variant="ghost" onClick={onCloseProject} className="hover:text-red-500 hover:bg-red-500/5">
            <X size={12} />
            Close
          </Button>
        </div>
      </div>
    </div>
  );
}

interface DashboardTargetOverviewCardProps {
  target: string;
  targetType: string;
  createdAt: string;
  updatedAt: string;
  effectiveStatus: ProjectStatus;
  displayedPentestElapsed: string;
  runtimeNotice?: {
    tone: "success" | "warning" | "info";
    title: string;
    detail: string;
  } | null;
  onEditProject: () => void;
  formatDateTime: (value: string) => string;
}

export function DashboardTargetOverviewCard({
  target,
  targetType,
  createdAt,
  updatedAt,
  effectiveStatus,
  displayedPentestElapsed,
  runtimeNotice,
  onEditProject,
  formatDateTime,
}: DashboardTargetOverviewCardProps) {
  return (
    <Card className="space-y-2 p-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-text-primary">
          Target Overview
        </h2>
        <div className="flex items-center gap-2">
          <Button
            size="xs"
            variant="secondary"
            onClick={onEditProject}
            title="Edit project details"
          >
            <Pencil size={12} />
            Edit
          </Button>
          <span className="inline-flex items-center gap-1 text-xs text-text-muted">
            <Clock3 size={12} />
            Updated {formatDateTime(updatedAt)}
          </span>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-5">
        <div className="rounded-xl bg-surface-0/40 p-3 border border-border/40 shadow-sm dark:border-border">
          <p className="text-[11px] font-bold uppercase tracking-wider text-text-muted">
            Target
          </p>
          <p className="mt-1.5 break-all font-mono text-sm font-semibold text-pf-500 dark:text-pf-400">
            {target}
          </p>
        </div>
        <div className="rounded-xl bg-surface-0/40 p-3 border border-border/40 shadow-sm dark:border-border">
          <p className="text-[11px] font-bold uppercase tracking-wider text-text-muted">
            Target Type
          </p>
          <p className="mt-1.5 text-sm font-semibold text-text-primary capitalize">
            {targetType.replaceAll("_", " ")}
          </p>
        </div>
        <div className="rounded-xl bg-surface-0/40 p-3 border border-border/40 shadow-sm dark:border-border">
          <p className="text-[11px] font-bold uppercase tracking-wider text-text-muted">
            Created
          </p>
          <p className="mt-1.5 text-sm font-semibold text-text-primary">
            {formatDateTime(createdAt)}
          </p>
        </div>
        <div
          className={`rounded-xl p-3 border shadow-sm transition-all duration-300 ${effectiveStatus === "running"
              ? "bg-pf-500/15 border-pf-500/30 ring-1 ring-pf-500/20"
              : "bg-surface-0/40 border-border/40 dark:border-border"
            }`}
        >
          <p
            className={`text-[11px] font-bold uppercase tracking-wider ${effectiveStatus === "running"
                ? "text-pf-600 dark:text-pf-400"
                : "text-text-muted"
              }`}
          >
            Status
          </p>
          <p
            className={`mt-1.5 text-sm md:text-base lg:text-lg font-bold capitalize break-words ${effectiveStatus === "running"
                ? "text-pf-700 dark:text-pf-300 animate-pulse"
                : "text-text-primary"
              }`}
          >
            {effectiveStatus.replaceAll("_", " ")}
          </p>
        </div>
        <div className="rounded-xl bg-surface-0/40 p-3 border border-border/40 shadow-sm dark:border-border">
          <p className="text-[11px] font-bold uppercase tracking-wider text-text-muted">
            Pentest Timer
          </p>
          <p className="mt-1.5 font-mono text-lg font-semibold text-text-primary">
            {displayedPentestElapsed}
          </p>
        </div>
      </div>
      {runtimeNotice ? (
        <div className={`rounded-xl border px-3 py-2.5 ${
          runtimeNotice.tone === "success"
            ? "border-emerald-500/25 bg-emerald-500/10"
            : runtimeNotice.tone === "warning"
              ? "border-amber-500/25 bg-amber-500/10"
              : "border-sky-500/25 bg-sky-500/10"
        }`}>
          <p className={`text-xs font-bold uppercase tracking-wider ${
            runtimeNotice.tone === "success"
              ? "text-emerald-300"
              : runtimeNotice.tone === "warning"
                ? "text-amber-300"
                : "text-sky-300"
          }`}>
            {runtimeNotice.title}
          </p>
          <p className="mt-1 text-sm text-text-secondary">
            {runtimeNotice.detail}
          </p>
        </div>
      ) : null}
    </Card>
  );
}

interface DashboardFindingsPanelProps {
  findings: RealtimeVulnFinding[];
  findingsEmptyMessage: string;
  onSelectFinding: (finding: RealtimeVulnFinding) => void;
  onMarkFalsePositive: (finding: RealtimeVulnFinding) => void;
  onAddToEchoPrompt: (finding: RealtimeVulnFinding) => void;
  falsePositiveLoadingId?: string | null;
  severityBadgeClass: (severity: DashboardSeverity) => string;
  evidenceBadgeClass: (status: FindingEvidenceStatus) => string;
  proofQualityBadgeClass: (quality: FindingProofQuality) => string;
  formatTime: (value: string) => string;
}

export function DashboardFindingsPanel({
  findings,
  findingsEmptyMessage,
  onSelectFinding,
  onMarkFalsePositive,
  onAddToEchoPrompt,
  falsePositiveLoadingId,
  severityBadgeClass,
  evidenceBadgeClass,
  proofQualityBadgeClass,
  formatTime,
}: DashboardFindingsPanelProps) {
  return (
    <Card className="flex h-[650px] flex-col space-y-3 p-3">
      <div className="flex items-center justify-between">
        <h2 className="text-base font-semibold text-text-primary">
          Confirmed Vulnerabilities
        </h2>
        <p className="text-sm text-text-muted">{findings.length} verified</p>
      </div>
      <div className="min-h-0 flex-1 space-y-2 overflow-y-auto rounded-md border border-border bg-surface-0/35 p-2">
        {findings.length === 0 ? (
          <p className="px-1 py-2 text-sm text-text-muted">
            {findingsEmptyMessage}
          </p>
        ) : (
          findings.map((item) => (
            <div
              key={item.id}
              onClick={() => onSelectFinding(item)}
              className="group cursor-pointer rounded-xl border border-border/60 bg-surface-1/40 p-4 space-y-3 transition-all duration-200 hover:bg-surface-1/60 hover:border-pf-500/30 dark:hover:border-pf-500/30 dark:border-border hover:shadow-md active:scale-[0.99]"
            >
              <div className="flex items-start justify-between gap-3">
                <h3 className="text-sm font-extrabold text-text-primary leading-tight flex-1 tracking-tight">
                  {item.title}
                </h3>
                <Badge
                  variant="default"
                  className={cn(
                    "px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-widest border shadow-sm shrink-0",
                    severityBadgeClass(item.severity)
                  )}
                >
                  {item.severity}
                </Badge>
              </div>

              <div className="flex flex-wrap gap-2">
                {item.proofQuality ? (
                  <Badge
                    variant="default"
                    className={cn(
                      "px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border",
                      proofQualityBadgeClass(item.proofQuality)
                    )}
                  >
                    {item.proofQuality} proof
                  </Badge>
                ) : null}
              </div>

              {item.cve || item.cvss ? (
                <div className="text-[11px] text-pf-600 dark:text-pf-400 font-mono bg-pf-500/5 px-2 py-1 rounded border border-pf-500/10 inline-block">
                  {item.cve ? <span>{item.cve}</span> : null}
                  {item.cve && item.cvss ? <span> • </span> : null}
                  {item.cvss ? <span>CVSS {item.cvss}</span> : null}
                </div>
              ) : null}

              <div className="space-y-1.5 pt-1">
                {item.endpoint ? (
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-bold text-text-muted uppercase tracking-widest min-w-[50px]">Target</span>
                    <span className="text-[11px] text-text-secondary truncate font-mono bg-surface-2/50 px-2 py-0.5 rounded border border-border/30 dark:border-border">
                      {item.endpoint}
                    </span>
                  </div>
                ) : null}
                {item.category ? (
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-bold text-text-muted uppercase tracking-widest min-w-[50px]">Class</span>
                    <span className="text-[11px] text-text-secondary font-medium">{item.category}</span>
                  </div>
                ) : null}
              </div>

              <div className="flex items-center justify-between pt-2 border-t border-border/30 dark:border-border">
                <div className="flex items-center gap-1.5">
                  <span
                    className={cn(
                      "flex h-1.5 w-1.5 rounded-full animate-pulse",
                      item.status === "inconclusive" ? "bg-amber-500" : "bg-emerald-500"
                    )}
                  />
                  <span
                    className={cn(
                      "text-[10px] font-bold uppercase tracking-widest",
                      item.status === "inconclusive"
                        ? "text-amber-600 dark:text-amber-400"
                        : "text-emerald-600 dark:text-emerald-400"
                    )}
                  >
                    {item.status === "inconclusive" ? "Inconclusive" : "Verified"}
                  </span>
                </div>
                <span className="text-[10px] font-medium text-text-muted">
                  {formatTime(item.at)}
                </span>
              </div>

              <div className="flex flex-wrap items-center justify-end gap-2 pt-1 opacity-60 group-hover:opacity-100 transition-opacity">
                <Button
                  size="xs"
                  variant="secondary"
                  className="h-7 border-red-200/60 bg-red-50/50 text-red-800 hover:bg-red-100/60 dark:border-red-500/20 dark:bg-red-500/8 dark:text-red-400 dark:hover:bg-red-500/12 text-[10px] font-bold uppercase tracking-wider"
                  loading={falsePositiveLoadingId === item.id}
                  onClick={(event) => {
                    event.stopPropagation();
                    onMarkFalsePositive(item);
                  }}
                >
                  <X size={10} />
                  False Positive
                </Button>
                <Button
                  size="xs"
                  variant="secondary"
                  className="h-7 text-[10px] font-bold uppercase tracking-wider"
                  onClick={(event) => {
                    event.stopPropagation();
                    onAddToEchoPrompt(item);
                  }}
                >
                  <Bot size={10} />
                  Echo
                </Button>
              </div>
            </div>
          ))
        )}
      </div>
    </Card>
  );
}

interface DashboardArchitecturePanelProps {
  architectureDraft: TargetArchitectureDraft;
  architectureEdges: ArchitectureEdge[];
  debugTimeline: ScanDebugTimelineEntry[];
  observabilityMetrics: ScanObservabilityMetrics | null;
  onRefresh?: () => void;
  isRefreshing?: boolean;
  isCompressing?: boolean;
}

export function DashboardArchitecturePanel({
  architectureDraft,
  architectureEdges,
  debugTimeline,
  observabilityMetrics,
  onRefresh,
  isRefreshing,
  isCompressing,
}: DashboardArchitecturePanelProps) {
  const board = architectureDraft.board;
  const hasBoardSpec = Boolean(board && Array.isArray(board.boxes) && board.boxes.length > 0);
  const boardCanvasWidth = Math.max(820, Number(board?.canvas?.width || 1200));
  const rawBoardCanvasHeight = Math.max(430, Number(board?.canvas?.height || 680));
  const rawBoardBoxes = hasBoardSpec ? board?.boxes ?? [] : [];
  const resolvedBoard = useMemo(
    () => resolveBoardBoxLayout(rawBoardBoxes, boardCanvasWidth, rawBoardCanvasHeight),
    [rawBoardBoxes, boardCanvasWidth, rawBoardCanvasHeight],
  );
  const boardCanvasHeight = resolvedBoard.canvasHeight;
  const boardBoxes = resolvedBoard.boxes;
  const boardBoxMap = new Map(boardBoxes.map((box) => [box.id, box]));
  const boardLinks = hasBoardSpec ? board?.links ?? [] : [];

  return (
    <>
      <Card className="space-y-1 p-3">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-3">
            <h2 className="text-sm font-bold uppercase tracking-wider text-text-primary">
              Target Architecture (Draft)
            </h2>
          </div>
          <div className="flex items-center gap-2">
            <Button
              size="xs"
              variant="secondary"
              onClick={onRefresh}
              disabled={isRefreshing || isCompressing}
              className={cn(
                "h-7 px-2 font-bold uppercase tracking-wider text-[10px] transition-all duration-300",
                isRefreshing && "bg-pf-500/10 border-pf-500/30",
                isCompressing && "bg-amber-500/10 border-amber-500/30 text-amber-600"
              )}
            >
              {isCompressing ? (
                <>
                  <FileArchive size={12} className="animate-bounce" />
                  Compressing...
                </>
              ) : (
                <>
                  <RotateCw size={12} className={cn(isRefreshing && "animate-spin")} />
                  {isRefreshing ? "Synthesizing..." : "Refresh"}
                </>
              )}
            </Button>
          </div>
        </div>
        <p className="text-xs text-text-muted">{architectureDraft.title}</p>

        <div className="hidden md:block">
          {hasBoardSpec ? (
            <div className="h-[430px] overflow-auto rounded-xl border border-border/80 bg-white dark:border-border">
              <div
                className="relative"
                style={{
                  width: `${boardCanvasWidth}px`,
                  minHeight: `${boardCanvasHeight}px`,
                  backgroundImage: [
                    "linear-gradient(rgba(15,23,42,0.03) 1px, transparent 1px)",
                    "linear-gradient(90deg, rgba(15,23,42,0.03) 1px, transparent 1px)",
                  ].join(", "),
                  backgroundSize: "30px 30px, 30px 30px",
                }}
              >
                <div className="pointer-events-none absolute inset-0 opacity-40" />

                <svg
                  className="pointer-events-none absolute inset-0 h-full w-full"
                  viewBox={`0 0 ${boardCanvasWidth} ${boardCanvasHeight}`}
                  preserveAspectRatio="none"
                >
                  <defs>
                    <marker
                      id="architecture-arrow"
                      markerWidth="6"
                      markerHeight="6"
                      refX="5"
                      refY="3"
                      orient="auto"
                      markerUnits="strokeWidth"
                    >
                      <path d="M0,0 L6,3 L0,6 z" fill="rgba(161,161,170,0.8)" />
                    </marker>
                  </defs>
                  {boardLinks.map((link, index) => {
                    const fromBox = boardBoxMap.get(link.fromId);
                    const toBox = boardBoxMap.get(link.toId);
                    if (!fromBox || !toBox) {
                      return null;
                    }
                    const x1 = fromBox.x + fromBox.w;
                    const y1 = fromBox.y + fromBox.h / 2;
                    const x2 = toBox.x;
                    const y2 = toBox.y + toBox.h / 2;
                    const midX = (x1 + x2) / 2;
                    return (
                      <g key={`${link.fromId}-${link.toId}-${index}`}>
                        <path
                          d={`M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`}
                          fill="none"
                          stroke="rgba(161,161,170,0.5)"
                          strokeWidth="1.5"
                          strokeDasharray="4 4"
                          markerEnd="url(#architecture-arrow)"
                        />
                        {link.label ? (
                          <text
                            x={midX}
                            y={(y1 + y2) / 2 - 8}
                            textAnchor="middle"
                            fontSize="12"
                            fill="rgba(15,23,42,0.82)"
                            fontWeight="700"
                            letterSpacing="0.14em"
                          >
                            {link.label}
                          </text>
                        ) : null}
                      </g>
                    );
                  })}
                </svg>

                {boardBoxes.map((box) => {
                  const tone = boardBoxTone(box.emphasis);
                  return (
                    <div
                      key={box.id}
                      className={cn("absolute rounded-md border-2 p-3", tone.frame)}
                      style={{
                        left: `${box.x}px`,
                        top: `${box.y}px`,
                        width: `${box.w}px`,
                        minHeight: `${box.h}px`,
                      }}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <p className="text-[10px] font-bold uppercase tracking-widest text-zinc-400">
                            {box.title}
                          </p>
                          {box.subtitle ? (
                            <p className="mt-1 text-sm font-bold text-zinc-900">{box.subtitle}</p>
                          ) : null}
                        </div>
                        <span className={cn("rounded-sm border px-2 py-1 text-[10px] font-bold uppercase tracking-[0.16em]", tone.chip)}>
                          {boardBoxKindLabel(box.kind)}
                        </span>
                      </div>
                      {box.tags && box.tags.length > 0 ? (
                        <div className="mt-3 flex flex-wrap gap-1">
                          {box.tags.map((tag) => (
                            <span
                              key={`${box.id}-${tag}`}
                              className="rounded bg-zinc-100 px-1.5 py-0.5 font-mono text-[10px] font-medium text-zinc-600"
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      ) : null}
                      <div className="mt-3 space-y-2">
                        {(box.lines ?? []).map((line, index) => (
                          <div key={`${box.id}-line-${index}`} className="flex gap-2">
                            <span className="mt-[6px] h-1.5 w-1.5 shrink-0 rounded-full bg-zinc-400" />
                            <p className="text-[11px] leading-relaxed text-zinc-600">{line}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : (
            <div className="relative h-[430px] overflow-hidden rounded-xl border border-border/70 bg-surface-0/55 dark:border-border">
              <svg
                className="pointer-events-none absolute inset-0 h-full w-full"
                viewBox="0 0 100 100"
                preserveAspectRatio="none"
              >
                <defs>
                  <marker
                    id="architecture-arrow-fallback"
                    markerWidth="8"
                    markerHeight="8"
                    refX="7"
                    refY="3.5"
                    orient="auto"
                    markerUnits="strokeWidth"
                  >
                    <path d="M0,0 L7,3.5 L0,7 z" fill="rgba(15,23,42,0.9)" />
                  </marker>
                </defs>
                {architectureEdges.map((edge, index) => (
                  <line
                    key={`${edge.from.id}-${edge.to.id}-${index}`}
                    x1={edge.from.x}
                    y1={edge.from.y}
                    x2={edge.to.x}
                    y2={edge.to.y}
                    stroke="rgba(15,23,42,0.85)"
                    strokeWidth="0.45"
                    strokeDasharray="1.4 0.8"
                    markerEnd="url(#architecture-arrow-fallback)"
                  />
                ))}
              </svg>
              {architectureDraft.hosts.map((host) => (
                <div
                  key={host.id}
                  className="absolute w-[230px] -translate-x-1/2 -translate-y-1/2 rounded-md border-2 border-border/40 bg-surface-0 dark:border-border dark:bg-surface-1 p-3 shadow-md"
                  style={{
                    left: `${host.x}%`,
                    top: `${host.y}%`,
                  }}
                >
                  <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-text-muted">
                    {architectureZoneLabel(host)}
                  </p>
                  <p className="mt-2 text-sm font-black text-text-primary">{host.name}</p>
                  <p className="mt-1 font-mono text-[11px] uppercase tracking-[0.16em] text-text-secondary">{host.role}</p>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {host.ports.map((port) => (
                      <span
                        key={`${host.id}-${port}`}
                        className="rounded-sm border border-border/50 px-1.5 py-0.5 font-mono text-[11px] font-semibold text-text-primary"
                      >
                        {port}
                      </span>
                    ))}
                  </div>
                  <div className="mt-3 space-y-1">
                    {splitNoteIntoLines(host.note, 2).map((line, index) => (
                      <p key={`${host.id}-line-${index}`} className="text-[12px] leading-5 text-text-secondary">
                        {line}
                      </p>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="space-y-2 md:hidden">
          {hasBoardSpec
            ? boardBoxes.map((box) => {
                const tone = boardBoxTone(box.emphasis);
                return (
                  <div
                    key={box.id}
                    className={cn("space-y-2 rounded-md border-2 p-3", tone.frame)}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-text-muted">
                          {box.title}
                        </p>
                        {box.subtitle ? (
                          <p className="mt-1 text-sm font-black text-black">{box.subtitle}</p>
                        ) : null}
                      </div>
                      <span className={cn("rounded-sm border px-2 py-1 text-[10px] font-bold uppercase tracking-[0.16em]", tone.chip)}>
                        {boardBoxKindLabel(box.kind)}
                      </span>
                    </div>
                    {box.tags && box.tags.length > 0 ? (
                      <div className="flex flex-wrap gap-1.5">
                        {box.tags.map((tag) => (
                          <span
                            key={`${box.id}-mobile-${tag}`}
                            className="rounded-sm border border-black px-1.5 py-0.5 font-mono text-[11px] font-semibold text-black"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    ) : null}
                    {(box.lines ?? []).map((line, index) => (
                      <p key={`${box.id}-mobile-line-${index}`} className="text-[12px] leading-5 text-black">
                        {line}
                      </p>
                    ))}
                  </div>
                );
              })
            : architectureDraft.hosts.map((host) => (
                <div
                  key={host.id}
                  className="space-y-2 rounded-md border-2 border-black bg-white p-3"
                >
                  <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-text-muted">
                    {architectureZoneLabel(host)}
                  </p>
                  <p className="text-sm font-black text-black">{host.name}</p>
                  <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-text-secondary">{host.role}</p>
                  <div className="flex flex-wrap gap-1.5">
                    {host.ports.map((port) => (
                      <span
                        key={`${host.id}-mobile-${port}`}
                        className="rounded-sm border border-black px-1.5 py-0.5 font-mono text-[11px] font-semibold text-black"
                      >
                        {port}
                      </span>
                    ))}
                  </div>
                  {splitNoteIntoLines(host.note, 2).map((line, index) => (
                    <p key={`${host.id}-mobile-line-${index}`} className="text-[12px] leading-5 text-black">
                      {line}
                    </p>
                  ))}
                </div>
              ))}
        </div>
      </Card>

      <ObservabilityPanel
        timeline={debugTimeline}
        metrics={observabilityMetrics}
      />
    </>
  );
}

interface DashboardFindingDialogProps {
  selectedFinding: DashboardFindingDetail | null;
  onClose: () => void;
  normalizeDashboardSeverity: (value: string) => DashboardSeverity;
  severityBadgeClass: (severity: DashboardSeverity) => string;
  normalizeEvidenceStatus: (
    value: unknown,
  ) => FindingEvidenceStatus | undefined;
  evidenceBadgeClass: (status: FindingEvidenceStatus) => string;
  normalizeProofQuality: (value: unknown) => FindingProofQuality | undefined;
  proofQualityBadgeClass: (quality: FindingProofQuality) => string;
  findingUsesOobProof: (finding: DashboardFindingDetail) => boolean;
  findingOobProtocol: (finding: DashboardFindingDetail) => string | undefined;
  formatVerificationMethod: (value: string) => string;
  formatTime: (value: string) => string;
  onMarkFalsePositive: (finding: any) => void;
  onAddToEchoPrompt: (finding: any) => void;
}

export function DashboardFindingDialog({
  selectedFinding,
  onClose,
  normalizeDashboardSeverity,
  severityBadgeClass,
  normalizeEvidenceStatus,
  evidenceBadgeClass,
  normalizeProofQuality,
  proofQualityBadgeClass,
  findingUsesOobProof,
  findingOobProtocol,
  formatVerificationMethod,
  formatTime,
  onMarkFalsePositive,
  onAddToEchoPrompt,
}: DashboardFindingDialogProps) {
  const severity = selectedFinding ? normalizeDashboardSeverity(selectedFinding.severity) : "low";

  // Severity-based gradient for header
  const headerGradient = useMemo(() => {
    if (severity === "critical") return "from-red-600/20 via-red-600/5 to-transparent";
    if (severity === "high") return "from-orange-600/20 via-orange-600/5 to-transparent";
    if (severity === "medium") return "from-orange-400/20 via-orange-400/5 to-transparent";
    if (severity === "low") return "from-emerald-500/20 via-emerald-500/5 to-transparent";
    return "from-slate-500/20 via-slate-500/5 to-transparent";
  }, [severity]);

  return (
    <Dialog
      open={Boolean(selectedFinding)}
      onClose={onClose}
      title="Vulnerability Report"
      className="max-w-2xl"
    >
      {selectedFinding ? (
        <div className="space-y-6 px-1 pb-4">
          {(() => {
            const cleanCommand = (cmd: string) => {
              // Strip run_python(code=..., reason=...)
              const pythonMatch = cmd.match(/run_python\(code=['"]([\s\S]*?)['"](?:,\s*reason=.*)?\)/);
              if (pythonMatch) return pythonMatch[1].replace(/\\n/g, '\n').replace(/\\'/g, "'").replace(/\\"/g, '"');

              // Strip run_custom(cmd=..., reason=...)
              const customMatch = cmd.match(/run_custom\(cmd=['"]([\s\S]*?)['"](?:,\s*reason=.*)?\)/);
              if (customMatch) return customMatch[1].replace(/\\n/g, '\n').replace(/\\'/g, "'").replace(/\\"/g, '"');

              return cmd;
            };

            return (
              <>
                {/* ── Premium Header ────────────────────────────────────────── */}
                <div className={cn(
                  "relative -mx-6 -mt-6 overflow-hidden border-b border-border p-6 pt-10",
                  "bg-gradient-to-br",
                  headerGradient
                )}>
                  <div className="absolute top-0 right-0 p-4 opacity-10">
                    <Bot size={120} className="rotate-12" />
                  </div>

                  <div className="relative space-y-3">
                    <div className="flex flex-wrap items-center gap-3">
                      <Badge
                        variant="default"
                        className={cn(
                          "px-2.5 py-0.5 text-xs font-bold uppercase tracking-widest border shadow-sm",
                          severityBadgeClass(severity)
                        )}
                      >
                        {selectedFinding.severity}
                      </Badge>
                      {selectedFinding.cwe_id && (
                        <span className="text-[11px] font-bold text-text-muted bg-surface-2/60 px-2 py-0.5 rounded border border-border/50 uppercase tracking-wider">
                          {selectedFinding.cwe_id}
                        </span>
                      )}
                      {selectedFinding.category && (
                        <span className="text-[11px] font-bold text-pf-600 dark:text-pf-400 bg-pf-500/10 px-2 py-0.5 rounded border border-pf-500/20 uppercase tracking-wider">
                          {selectedFinding.category}
                        </span>
                      )}
                    </div>

                    <h2 className="text-2xl font-extrabold text-text-primary tracking-tight leading-tight">
                      {selectedFinding.title}
                    </h2>

                    <div className="flex flex-wrap items-center gap-4 text-xs text-text-muted">
                      <div className="flex items-center gap-1.5">
                        <Clock3 size={14} className="text-pf-500" />
                        <span>
                          {selectedFinding.status === "inconclusive" ? "Marked inconclusive at " : "Verified at "}
                          {formatTime(selectedFinding.timestamp || selectedFinding.at)}
                        </span>
                      </div>
                      {selectedFinding.target && (
                        <div className="flex items-center gap-1.5 font-mono bg-surface-2/40 px-2 py-0.5 rounded border border-border/30">
                          <Maximize2 size={12} className="text-pf-500" />
                          <span className="truncate max-w-[300px]">{selectedFinding.target}</span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* ── Description ───────────────────────────────────────────── */}
                <section className="space-y-2">
                  <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-pf-600 dark:text-pf-400 flex items-center gap-2">
                    <span className="h-px w-4 bg-pf-500/40" />
                    Technical Overview
                  </h3>
                  <div className="rounded-xl border border-border/60 bg-surface-1/40 p-4 shadow-sm backdrop-blur-sm">
                    <p className="text-sm text-text-secondary leading-relaxed whitespace-pre-wrap">
                      {selectedFinding.description}
                    </p>
                  </div>
                </section>

                {/* ── Reproduction Steps ────────────────────────────────────── */}
                {((selectedFinding.steps_to_reproduce?.length ?? 0) > 0) && (
                  <section className="space-y-3">
                    <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-pf-600 dark:text-pf-400 flex items-center gap-2">
                      <span className="h-px w-4 bg-pf-500/40" />
                      Steps to Reproduce
                    </h3>
                    <div className="space-y-2 pl-4">
                      {selectedFinding.steps_to_reproduce?.map((step, idx) => (
                        <div key={idx} className="flex gap-4 group">
                          <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-surface-2 border border-border text-[11px] font-bold text-pf-500 group-hover:bg-pf-500/10 transition-colors">
                            {idx + 1}
                          </span>
                          <p className="text-sm text-text-secondary pt-0.5 leading-snug">
                            {step}
                          </p>
                        </div>
                      ))}
                    </div>
                  </section>
                )}

                {/* ── Technical Verification ────────────────────────────────── */}
                {((selectedFinding.verification_commands?.length ?? 0) > 0) && (
                  <section className="space-y-3">
                    <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-pf-600 dark:text-pf-400 flex items-center gap-2">
                      <span className="h-px w-4 bg-pf-500/40" />
                      Technical Verification
                    </h3>
                    <div className="space-y-2">
                      {selectedFinding.verification_commands?.map((cmd, idx) => (
                        <div key={idx} className="relative group/code">
                          <pre className="p-3 rounded-lg bg-surface-2 text-text-secondary font-mono text-[11px] overflow-x-auto border border-border/50">
                            <code>{cleanCommand(cmd)}</code>
                          </pre>
                        </div>
                      ))}
                    </div>
                  </section>
                )}

                {/* ── Exploit Code ──────────────────────────────────────────── */}
                {selectedFinding.exploit_script && (
                  <section className="space-y-3">
                    <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-pf-600 dark:text-pf-400 flex items-center gap-2">
                      <span className="h-px w-4 bg-pf-500/40" />
                      Exploit Code (PoC)
                    </h3>
                    <div className="relative group overflow-hidden rounded-xl border border-pf-500/30 bg-pf-950/95 shadow-lg">
                      <div className="absolute top-3 right-3 z-10 opacity-0 group-hover:opacity-100 transition-opacity">
                        <Button
                          variant="secondary"
                          size="xs"
                          className="bg-surface-2/80 hover:bg-surface-2"
                          onClick={() => {
                            navigator.clipboard.writeText(selectedFinding.exploit_script || "");
                          }}
                        >
                          Copy
                        </Button>
                      </div>
                      <div className="p-4 font-mono text-xs text-pf-100 overflow-x-auto scrollbar-thin scrollbar-thumb-pf-500/30 scrollbar-track-transparent">
                        <pre className="leading-relaxed">{selectedFinding.exploit_script}</pre>
                      </div>
                    </div>
                  </section>
                )}

                {/* ── Visual Evidence (Screenshots) ────────────────────────── */}
                {((selectedFinding.visual_evidence_paths?.length ?? 0) > 0) && (
                  <section className="space-y-3">
                    <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-pf-600 dark:text-pf-400 flex items-center gap-2">
                      <span className="h-px w-4 bg-pf-500/40" />
                      Visual Evidence
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {selectedFinding.visual_evidence_paths?.map((path, idx) => (
                        <div key={idx} className="group relative aspect-video overflow-hidden rounded-xl border border-border bg-surface-2 shadow-sm">
                          <img
                            src={`/api/scans/artifacts?path=${encodeURIComponent(path)}`}
                            alt={`Evidence ${idx + 1}`}
                            className="h-full w-full object-cover transition-transform duration-500 group-hover:scale-105"
                            onError={(e) => {
                              (e.target as HTMLImageElement).src = "https://placehold.co/600x400/1e293b/64748b?text=Evidence+Asset+Not+Found";
                            }}
                          />
                          <div className="absolute inset-0 bg-gradient-to-t from-pf-950/80 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity flex items-end p-3">
                            <p className="text-[10px] font-bold text-pf-200 uppercase tracking-widest bg-pf-950/50 px-2 py-1 rounded backdrop-blur-sm border border-pf-500/30">
                              Asset #{idx + 1}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </section>
                )}

                {/* ── Impact Assessment ─────────────────────────────────────── */}
                {selectedFinding.impact_assessment && Object.keys(selectedFinding.impact_assessment).length > 0 && (
                  <section className="space-y-3">
                    <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-pf-600 dark:text-pf-400 flex items-center gap-2">
                      <span className="h-px w-4 bg-pf-500/40" />
                      Impact Analysis
                    </h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      {Object.entries(selectedFinding.impact_assessment).map(([key, value]) => (
                        <div key={key} className="rounded-xl border border-border/50 bg-surface-1/30 p-3 flex gap-3 shadow-sm hover:border-pf-500/30 transition-all group">
                          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-surface-2 border border-border group-hover:bg-pf-500/10 transition-colors">
                            <Zap size={18} className="text-pf-500" />
                          </div>
                          <div className="space-y-0.5">
                            <p className="text-[10px] font-bold uppercase tracking-widest text-text-muted">{key.replace(/_/g, ' ')}</p>
                            <p className="text-sm text-text-primary leading-tight font-medium">{value}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </section>
                )}

                {/* ── Remediation Plan ──────────────────────────────────────── */}
                {(selectedFinding.remediation || (selectedFinding.remediation_steps?.length ?? 0) > 0) && (
                  <section className="space-y-3">
                    <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-pf-600 dark:text-pf-400 flex items-center gap-2">
                      <span className="h-px w-4 bg-pf-500/40" />
                      Remediation Plan
                    </h3>
                    <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4 space-y-3 shadow-inner">
                      {selectedFinding.remediation && (
                        <p className="text-sm text-emerald-900 dark:text-emerald-200 leading-relaxed font-medium">
                          {selectedFinding.remediation}
                        </p>
                      )}
                      {((selectedFinding.remediation_steps?.length ?? 0) > 0) && (
                        <ul className="space-y-2">
                          {selectedFinding.remediation_steps?.map((step, idx) => (
                            <li key={idx} className="flex gap-2.5 items-start">
                              <Check size={14} className="text-emerald-500 mt-0.5 shrink-0" />
                              <span className="text-sm text-text-secondary leading-tight">{step}</span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  </section>
                )}

                {/* ── Secondary Evidence & Metadata ───────────────────────── */}
                <section className="pt-4 border-t border-border flex flex-wrap items-center justify-between gap-6">
                  <div className="flex items-center gap-4">
                    <div className="space-y-1">
                      <p className="text-[10px] font-bold text-text-muted uppercase tracking-[0.15em]">AI Confidence Score</p>
                      <div className="flex items-center gap-2.5">
                        <div className="h-2 w-32 bg-surface-2 rounded-full overflow-hidden border border-border/50">
                          <div
                            className="h-full bg-pf-500 shadow-[0_0_12px_rgba(14,165,233,0.6)]"
                            style={{ width: `${(selectedFinding.evidence?.verification_confidence ?? 0.9) * 100}%` }}
                          />
                        </div>
                        <span className="text-xs font-extrabold text-text-primary">
                          {Math.round((selectedFinding.evidence?.verification_confidence ?? 0.9) * 100)}%
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <Button
                      size="sm"
                      variant="secondary"
                      className="h-9 px-4 border-red-200/60 bg-red-50/50 text-red-800 hover:bg-red-100/60 dark:border-red-500/20 dark:bg-red-500/8 dark:text-red-400 dark:hover:bg-red-500/12 text-[11px] font-bold uppercase tracking-wider"
                      onClick={(event) => {
                        event.stopPropagation();
                        onMarkFalsePositive(selectedFinding);
                        onClose();
                      }}
                    >
                      <X size={12} />
                      False Positive
                    </Button>
                    <Button
                      size="sm"
                      variant="secondary"
                      className="h-9 px-4 text-[11px] font-bold uppercase tracking-wider"
                      onClick={(event) => {
                        event.stopPropagation();
                        onAddToEchoPrompt(selectedFinding);
                      }}
                    >
                      <Bot size={12} />
                      Echo
                    </Button>
                  </div>
                </section>
              </>
            );
          })()}
        </div>
      ) : null}
    </Dialog>
  );
}
