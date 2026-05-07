import { Bot, Clock3, Pencil, Play, Repeat2, Square, X } from "lucide-react";

import { ObservabilityPanel } from "@/components/dashboard/ObservabilityPanel";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Dialog } from "@/components/ui/Dialog";
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

interface TargetArchitectureDraft {
  title: string;
  hosts: ArchitectureHost[];
}

interface ArchitectureEdge {
  from: ArchitectureHost;
  to: ArchitectureHost;
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
  hasAnotherRunningProject,
  onStartScan,
  onStopScan,
  onChangeProject,
  onCloseProject,
}: DashboardProjectHeaderProps) {
  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-2xl font-bold">{projectName}</h1>
            <Badge variant={effectiveStatus} dot>
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
                title="Stop running scan"
              >
                <Square size={12} />
                Stop Scan
              </Button>
            </div>
          )}
          {isStarting ? (
            <span className="text-sm text-text-muted">Starting scan...</span>
          ) : null}
          <Button size="xs" variant="secondary" onClick={onChangeProject}>
            <Repeat2 size={12} />
            Change
          </Button>
          <Button size="xs" variant="ghost" onClick={onCloseProject}>
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
        <div className="rounded-xl bg-surface-0/40 p-3 border border-border/40 shadow-sm">
          <p className="text-[11px] font-bold uppercase tracking-wider text-text-muted">
            Target
          </p>
          <p className="mt-1.5 break-all font-mono text-sm font-semibold text-pf-500 dark:text-pf-400">
            {target}
          </p>
        </div>
        <div className="rounded-xl bg-surface-0/40 p-3 border border-border/40 shadow-sm">
          <p className="text-[11px] font-bold uppercase tracking-wider text-text-muted">
            Target Type
          </p>
          <p className="mt-1.5 text-sm font-semibold text-text-primary capitalize">
            {targetType.replaceAll("_", " ")}
          </p>
        </div>
        <div className="rounded-xl bg-surface-0/40 p-3 border border-border/40 shadow-sm">
          <p className="text-[11px] font-bold uppercase tracking-wider text-text-muted">
            Created
          </p>
          <p className="mt-1.5 text-sm font-semibold text-text-primary">
            {formatDateTime(createdAt)}
          </p>
        </div>
        <div
          className={`rounded-xl p-3 border shadow-sm transition-all duration-300 ${
            effectiveStatus === "running"
              ? "bg-pf-500/15 border-pf-500/30 ring-1 ring-pf-500/20"
              : "bg-surface-0/40 border-border/40"
          }`}
        >
          <p
            className={`text-[11px] font-bold uppercase tracking-wider ${
              effectiveStatus === "running"
                ? "text-pf-600 dark:text-pf-400"
                : "text-text-muted"
            }`}
          >
            Status
          </p>
          <p
            className={`mt-1.5 text-lg font-bold capitalize ${
              effectiveStatus === "running"
                ? "text-pf-700 dark:text-pf-300 animate-pulse"
                : "text-text-primary"
            }`}
          >
            {effectiveStatus}
          </p>
        </div>
        <div className="rounded-xl bg-surface-0/40 p-3 border border-border/40 shadow-sm">
          <p className="text-[11px] font-bold uppercase tracking-wider text-text-muted">
            Pentest Timer
          </p>
          <p className="mt-1.5 font-mono text-lg font-semibold text-text-primary">
            {displayedPentestElapsed}
          </p>
        </div>
      </div>
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
              className="cursor-pointer rounded-md border border-border bg-surface-1/45 p-3 space-y-2 transition-colors hover:bg-surface-1/65"
            >
              <div className="flex items-start justify-between gap-2">
                <h3 className="text-sm font-bold text-text-primary leading-snug flex-1">
                  {item.title}
                </h3>
                <Badge
                  variant="default"
                  className={`border text-xs uppercase tracking-wide whitespace-nowrap font-semibold ${severityBadgeClass(item.severity)}`}
                >
                  {item.severity}
                </Badge>
              </div>

              <div className="flex flex-wrap gap-2">
                {item.proofQuality ? (
                  <Badge
                    variant="default"
                    className={`border text-[11px] uppercase tracking-wide ${proofQualityBadgeClass(item.proofQuality)}`}
                  >
                    {item.proofQuality} proof
                  </Badge>
                ) : null}
              </div>

              {item.cve || item.cvss ? (
                <div className="text-xs text-text-secondary font-mono bg-surface-0/40 px-2 py-1 rounded">
                  {item.cve ? <span>{item.cve}</span> : null}
                  {item.cve && item.cvss ? <span> • </span> : null}
                  {item.cvss ? <span>CVSS {item.cvss}</span> : null}
                </div>
              ) : null}

              <div className="space-y-1 text-xs">
                {item.endpoint ? (
                  <div className="flex items-start gap-2">
                    <span className="text-text-muted min-w-fit font-semibold">
                      Target:
                    </span>
                    <span className="text-text-secondary break-all font-mono">
                      {item.endpoint}
                    </span>
                  </div>
                ) : null}
                {item.category ? (
                  <div className="flex items-start gap-2">
                    <span className="text-text-muted min-w-fit font-semibold">
                      Type:
                    </span>
                    <span className="text-text-secondary">{item.category}</span>
                  </div>
                ) : null}
              </div>

              <div className="flex items-center justify-between pt-1 border-t border-border/30">
                <span className="text-xs text-text-muted uppercase tracking-wide">
                  ✅ Verified
                </span>
                <span className="text-xs text-text-muted">
                  {formatTime(item.at)}
                </span>
              </div>

              <div className="flex flex-wrap items-center justify-end gap-2 pt-1">
                <Button
                  size="xs"
                  variant="secondary"
                  onClick={(event) => {
                    event.stopPropagation();
                    onSelectFinding(item);
                  }}
                >
                  View
                </Button>
                <Button
                  size="xs"
                  variant="secondary"
                  className="border-amber-300/60 bg-amber-50 text-amber-900 hover:bg-amber-100 dark:border-amber-500/30 dark:bg-amber-500/12 dark:text-amber-200 dark:hover:bg-amber-500/18"
                  loading={falsePositiveLoadingId === item.id}
                  onClick={(event) => {
                    event.stopPropagation();
                    onMarkFalsePositive(item);
                  }}
                >
                  <X size={12} />
                  False Positive
                </Button>
                <Button
                  size="xs"
                  variant="secondary"
                  onClick={(event) => {
                    event.stopPropagation();
                    onAddToEchoPrompt(item);
                  }}
                >
                  <Bot size={12} />
                  Add To Echo
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
}

export function DashboardArchitecturePanel({
  architectureDraft,
  architectureEdges,
  debugTimeline,
  observabilityMetrics,
}: DashboardArchitecturePanelProps) {
  return (
    <>
      <Card className="space-y-3 p-3">
        <div className="flex items-center justify-between gap-2">
          <h2 className="text-sm font-semibold text-text-primary">
            Target Architecture (Draft)
          </h2>
          <span className="rounded-md border border-border bg-surface-0/40 px-2 py-0.5 text-xs uppercase tracking-wide text-text-muted">
            Planned View
          </span>
        </div>
        <p className="text-xs text-text-muted">{architectureDraft.title}</p>

        <div className="hidden md:block">
          <div
            className="relative h-[430px] overflow-hidden rounded-xl border border-border/70 bg-surface-0/55"
            style={{
              backgroundImage: [
                "radial-gradient(circle at 22% 18%, rgba(56,189,248,0.10), transparent 36%)",
                "radial-gradient(circle at 84% 14%, rgba(59,130,246,0.09), transparent 33%)",
                "radial-gradient(circle at 72% 78%, rgba(14,165,233,0.08), transparent 40%)",
                "radial-gradient(circle at 10% 88%, rgba(148,163,184,0.10), transparent 45%)",
              ].join(", "),
            }}
          >
            <div
              className="pointer-events-none absolute inset-0 opacity-40"
              style={{
                backgroundImage: [
                  "radial-gradient(circle at 12% 18%, rgba(100,116,139,0.38) 1px, transparent 2px)",
                  "radial-gradient(circle at 42% 26%, rgba(100,116,139,0.30) 1px, transparent 2px)",
                  "radial-gradient(circle at 64% 10%, rgba(100,116,139,0.34) 1px, transparent 2px)",
                  "radial-gradient(circle at 77% 39%, rgba(100,116,139,0.28) 1px, transparent 2px)",
                  "radial-gradient(circle at 21% 58%, rgba(100,116,139,0.36) 1px, transparent 2px)",
                  "radial-gradient(circle at 56% 72%, rgba(100,116,139,0.26) 1px, transparent 2px)",
                  "radial-gradient(circle at 89% 82%, rgba(100,116,139,0.32) 1px, transparent 2px)",
                ].join(", "),
              }}
            />

            <svg
              className="pointer-events-none absolute inset-0 h-full w-full"
              viewBox="0 0 100 100"
              preserveAspectRatio="none"
            >
              <defs>
                <marker
                  id="architecture-arrow"
                  markerWidth="8"
                  markerHeight="8"
                  refX="7"
                  refY="3.5"
                  orient="auto"
                  markerUnits="strokeWidth"
                >
                  <path
                    d="M0,0 L7,3.5 L0,7 z"
                    fill="rgba(125,211,252,0.8)"
                  />
                </marker>
              </defs>
              {architectureEdges.map((edge, index) => (
                <g key={`${edge.from.id}-${edge.to.id}-${index}`}>
                  <line
                    x1={edge.from.x}
                    y1={edge.from.y}
                    x2={edge.to.x}
                    y2={edge.to.y}
                    stroke="rgba(125,211,252,0.75)"
                    strokeWidth="0.45"
                    strokeDasharray="1.4 0.8"
                    markerEnd="url(#architecture-arrow)"
                  />
                  <circle
                    cx={edge.from.x}
                    cy={edge.from.y}
                    r="0.7"
                    fill="rgba(167,243,208,0.9)"
                  />
                  <circle
                    cx={edge.to.x}
                    cy={edge.to.y}
                    r="0.7"
                    fill="rgba(191,219,254,0.9)"
                  />
                </g>
              ))}
            </svg>

            {architectureDraft.hosts.map((host) => (
              <div
                key={host.id}
                className="absolute w-[210px] -translate-x-1/2 -translate-y-1/2 rounded-xl border border-border/65 bg-surface-1/85 p-2 shadow-sm backdrop-blur-sm"
                style={{
                  left: `${host.x}%`,
                  top: `${host.y}%`,
                }}
              >
                <p className="text-xs font-semibold text-text-primary">
                  {host.name}
                </p>
                <p className="mt-0.5 text-xs text-text-muted">{host.role}</p>
                <div className="mt-1 flex flex-wrap gap-1">
                  {host.ports.map((port) => (
                    <span
                      key={`${host.id}-${port}`}
                      className="rounded border border-border/55 bg-surface-0/70 px-1.5 py-0.5 text-xs text-text-secondary"
                    >
                      {port}
                    </span>
                  ))}
                </div>
                <p className="mt-1 text-xs text-text-secondary">{host.note}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="space-y-2 md:hidden">
          <p className="text-xs text-text-muted">
            Graph view opens on larger screens. Mobile fallback:
          </p>
          {architectureDraft.hosts.map((host) => (
            <div
              key={host.id}
              className="space-y-1 rounded-md border border-border/70 bg-surface-1/45 p-2"
            >
              <p className="text-xs font-semibold text-text-primary">
                {host.name}
              </p>
              <p className="text-xs text-text-muted">{host.role}</p>
              <p className="text-xs text-text-secondary">{host.note}</p>
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
}: DashboardFindingDialogProps) {
  return (
    <Dialog open={Boolean(selectedFinding)} onClose={onClose} title="Vulnerability Details">
      {selectedFinding ? (
        <div className="space-y-4 max-h-[75vh] overflow-y-auto">
          <div className="space-y-2 border-b border-border pb-3">
            <h2 className="text-lg font-bold text-text-primary">
              {selectedFinding.title}
            </h2>
            <div className="flex items-center gap-3">
              <Badge
                variant="default"
                className={`border text-sm uppercase tracking-wide font-semibold ${severityBadgeClass(
                  normalizeDashboardSeverity(selectedFinding.severity),
                )}`}
              >
                {selectedFinding.severity}
              </Badge>
              {selectedFinding.category ? (
                <span className="text-sm text-text-secondary bg-surface-0/50 px-2 py-1 rounded">
                  {selectedFinding.category}
                </span>
              ) : null}
              {normalizeEvidenceStatus(
                selectedFinding.evidenceStatus ??
                  selectedFinding.evidence?.evidence_status,
              ) ? (
                <Badge
                  variant="default"
                  className={`border text-xs uppercase tracking-wide ${evidenceBadgeClass(
                    normalizeEvidenceStatus(
                      selectedFinding.evidenceStatus ??
                        selectedFinding.evidence?.evidence_status,
                    )!,
                  )}`}
                >
                  {String(
                    normalizeEvidenceStatus(
                      selectedFinding.evidenceStatus ??
                        selectedFinding.evidence?.evidence_status,
                    ),
                  ).replace(/_/g, " ")}
                </Badge>
              ) : null}
              {normalizeProofQuality(
                selectedFinding.proofQuality ??
                  selectedFinding.evidence?.proof_quality,
              ) ? (
                <Badge
                  variant="default"
                  className={`border text-xs uppercase tracking-wide ${proofQualityBadgeClass(
                    normalizeProofQuality(
                      selectedFinding.proofQuality ??
                        selectedFinding.evidence?.proof_quality,
                    )!,
                  )}`}
                >
                  {
                    normalizeProofQuality(
                      selectedFinding.proofQuality ??
                        selectedFinding.evidence?.proof_quality,
                    )
                  }{" "}
                  proof
                </Badge>
              ) : null}
              {findingUsesOobProof(selectedFinding) ? (
                <Badge
                  variant="default"
                  className="border border-sky-500/40 bg-sky-500/15 text-sky-200 text-xs uppercase tracking-wide"
                >
                  {findingOobProtocol(selectedFinding)
                    ? `OOB ${findingOobProtocol(selectedFinding)?.toUpperCase()}`
                    : "OOB"}
                </Badge>
              ) : null}
            </div>
          </div>

          {selectedFinding.evidenceStatus ||
          selectedFinding.proofQuality ||
          selectedFinding.deterministicValidation !== undefined ||
          selectedFinding.verificationMethods?.length ? (
            <div className="space-y-1 bg-surface-0/40 p-3 rounded border border-border">
              <p className="text-xs font-semibold text-text-muted uppercase">
                Proof Summary
              </p>
              <div className="space-y-1 text-sm text-text-secondary">
                {selectedFinding.evidenceStatus ||
                selectedFinding.evidence?.evidence_status ? (
                  <div>
                    Evidence Tier:{" "}
                    {String(
                      selectedFinding.evidenceStatus ??
                        selectedFinding.evidence?.evidence_status,
                    ).replace(/_/g, " ")}
                  </div>
                ) : null}
                {selectedFinding.proofQuality ||
                selectedFinding.evidence?.proof_quality ? (
                  <div>
                    Proof Quality:{" "}
                    {selectedFinding.proofQuality ??
                      selectedFinding.evidence?.proof_quality}
                  </div>
                ) : null}
                {selectedFinding.deterministicValidation !== undefined ||
                selectedFinding.evidence?.deterministic_validation !==
                  undefined ? (
                  <div>
                    Deterministic Validation:{" "}
                    {(
                      selectedFinding.deterministicValidation ??
                      selectedFinding.evidence?.deterministic_validation
                    )
                      ? "yes"
                      : "no"}
                  </div>
                ) : null}
                {findingUsesOobProof(selectedFinding) ? (
                  <div>
                    OOB Confirmation:{" "}
                    {findingOobProtocol(selectedFinding)
                      ? `yes (${findingOobProtocol(selectedFinding)?.toUpperCase()} callback)`
                      : "yes"}
                  </div>
                ) : null}
                {Array.isArray(selectedFinding.evidence?.callbacks) &&
                selectedFinding.evidence.callbacks.length > 0 ? (
                  <div>
                    OOB Callback Count:{" "}
                    {selectedFinding.evidence.callbacks.length}
                  </div>
                ) : null}
                {typeof selectedFinding.evidence?.remote_address === "string" &&
                selectedFinding.evidence.remote_address.trim() ? (
                  <div>
                    OOB Remote Address:{" "}
                    {selectedFinding.evidence.remote_address}
                  </div>
                ) : null}
                {(Array.isArray(selectedFinding.verificationMethods) &&
                  selectedFinding.verificationMethods.length > 0) ||
                (Array.isArray(selectedFinding.evidence?.verification_methods) &&
                  selectedFinding.evidence.verification_methods.length > 0) ? (
                  <div>
                    Verification Methods:{" "}
                    {(
                      (selectedFinding.verificationMethods ??
                        selectedFinding.evidence
                          ?.verification_methods) as string[]
                    )
                      .map((item) => formatVerificationMethod(item))
                      .filter(Boolean)
                      .join(", ")}
                  </div>
                ) : null}
              </div>
            </div>
          ) : null}

          {selectedFinding.cve || selectedFinding.cvss ? (
            <div className="space-y-1 bg-surface-0/40 p-3 rounded border border-border">
              <p className="text-xs font-semibold text-text-muted uppercase">
                Identifiers
              </p>
              <div className="text-sm text-text-secondary font-mono">
                {selectedFinding.cve ? <div>CVE: {selectedFinding.cve}</div> : null}
                {selectedFinding.cvss ? (
                  <div>CVSS Score: {selectedFinding.cvss}</div>
                ) : null}
              </div>
            </div>
          ) : null}

          {selectedFinding.target ? (
            <div className="space-y-1">
              <p className="text-xs font-semibold text-text-muted uppercase">
                Target
              </p>
              <p className="text-sm text-text-secondary font-mono bg-surface-0/40 px-3 py-2 rounded break-all">
                {selectedFinding.target}
              </p>
            </div>
          ) : null}

          {selectedFinding.description ? (
            <div className="space-y-1">
              <p className="text-xs font-semibold text-text-muted uppercase">
                Description
              </p>
              <div className="text-sm text-text-secondary whitespace-pre-wrap break-words bg-surface-0/40 p-3 rounded border border-border">
                {selectedFinding.description}
              </div>
            </div>
          ) : null}

          {selectedFinding.evidence &&
          Object.keys(selectedFinding.evidence).length > 0 ? (
            <div className="space-y-1">
              <p className="text-xs font-semibold text-text-muted uppercase">
                Verification Evidence
              </p>
              <div className="text-xs text-text-secondary space-y-1 bg-surface-0/40 p-3 rounded border border-border max-h-48 overflow-y-auto">
                {Object.entries(selectedFinding.evidence).map(([key, value]) => (
                  <div
                    key={key}
                    className="border-b border-border/30 pb-2 last:border-b-0 last:pb-0"
                  >
                    <div className="font-semibold text-text-secondary">{key}:</div>
                    <div className="text-text-muted break-all ml-2">
                      {String(value).slice(0, 300)}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {selectedFinding.remediation ? (
            <div className="space-y-1">
              <p className="text-xs font-semibold text-text-muted uppercase">
                Remediation
              </p>
              <div className="text-sm text-indigo-900 dark:text-indigo-100 bg-indigo-50 dark:bg-indigo-500/15 border border-indigo-100 dark:border-indigo-500/30 p-3 rounded whitespace-pre-wrap break-words shadow-inner font-medium">
                {selectedFinding.remediation}
              </div>
            </div>
          ) : null}

          <div className="border-t border-border pt-3 space-y-1">
            <p className="text-xs font-semibold text-text-muted uppercase">
              Status
            </p>
            <p className="text-sm text-text-secondary">✅ Verified & Saved</p>
            <p className="text-xs text-text-muted">
              {formatTime(selectedFinding.timestamp || selectedFinding.at)}
            </p>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="primary" size="sm" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
      ) : null}
    </Dialog>
  );
}
