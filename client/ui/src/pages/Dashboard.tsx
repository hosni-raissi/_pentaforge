import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { CheckCircle, Circle, Clock3, FolderOpen, Play, Repeat2, Square, X } from "lucide-react";

import { AIPromptPanel } from "@/components/dashboard/AIPromptPanel";
import { AgentStatePath, type AgentGraphRole, type AgentInsightPanelData } from "@/components/dashboard/AgentStatePath";
import { FindingsTable } from "@/components/dashboard/FindingsTable";
import { StatsGrid } from "@/components/dashboard/StatsGrid";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Dialog } from "@/components/ui/Dialog";
import {
  listProjectScanEventsFromDesktop,
  streamProjectScanEvents,
  type ScanEventPayload,
} from "@/lib/projectBridge";
import { useProjects } from "@/stores/projects";
import type { ProjectStatus } from "@/types";

type InsightTab = "plan" | "checklist";
type LogLevel = "info" | "success" | "warn" | "error";

interface DashboardLogEntry {
  id: string;
  level: LogLevel;
  message: string;
  at: string;
  source: string;
}

const PROJECT_STATUSES: ProjectStatus[] = ["idle", "running", "paused", "completed", "error"];
const AGENT_ROLES: AgentGraphRole[] = ["intel", "planner", "recon", "exploit", "verify", "report", "retest", "perceptor"];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isAgentRole(value: unknown): value is AgentGraphRole {
  return typeof value === "string" && AGENT_ROLES.includes(value as AgentGraphRole);
}

function detectEventAgentRole(event: ScanEventPayload): AgentGraphRole | null {
  const dataAgent = isRecord(event.data) ? event.data.agent : undefined;
  if (isAgentRole(dataAgent)) {
    return dataAgent;
  }

  const stage = isRecord(event.data) ? event.data.stage : undefined;
  if (typeof stage === "string") {
    const normalized = stage.trim().toLowerCase();
    if (normalized === "intel") {
      return "intel";
    }
    if (isAgentRole(normalized)) {
      return normalized;
    }
  }

  const text = `${event.event} ${event.message}`.toLowerCase();
  if (text.includes("intel")) return "intel";
  if (text.includes("planner")) return "planner";
  if (text.includes("recon")) return "recon";
  if (text.includes("exploit")) return "exploit";
  if (text.includes("verify")) return "verify";
  if (text.includes("retest")) return "retest";
  if (text.includes("report")) return "report";
  if (text.includes("perceptor")) return "perceptor";
  return null;
}

function toProjectStatus(value: unknown): ProjectStatus | null {
  if (typeof value !== "string") {
    return null;
  }
  return PROJECT_STATUSES.includes(value as ProjectStatus) ? (value as ProjectStatus) : null;
}

function normalizeRunningStatus(project: {
  status: ProjectStatus;
  lastScan?: unknown;
}): ProjectStatus {
  if (project.status !== "running") {
    return project.status;
  }
  const lastScan = isRecord(project.lastScan) ? project.lastScan : null;
  const lastScanStatus = typeof lastScan?.status === "string"
    ? lastScan.status.trim().toLowerCase()
    : "";
  if (
    lastScanStatus === "completed"
    || lastScanStatus === "paused"
    || lastScanStatus === "idle"
    || lastScanStatus === "error"
  ) {
    return lastScanStatus as ProjectStatus;
  }
  return project.status;
}

function toLogLevel(value: unknown): LogLevel {
  if (value === "success" || value === "warn" || value === "error") {
    return value;
  }
  return "info";
}

function formatDateTime(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return "Unknown";
  }
  return parsed.toLocaleString();
}

function formatTime(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return "--:--:--";
  }
  return parsed.toLocaleTimeString();
}

function detectLogSource(event: ScanEventPayload): string {
  const role = detectEventAgentRole(event);
  if (role) {
    return role;
  }

  const stage = isRecord(event.data) ? event.data.stage : undefined;
  if (typeof stage === "string" && stage.trim().length > 0) {
    return stage.trim().toLowerCase();
  }

  if (event.event.startsWith("scan_") || event.event === "project_status") {
    return "system";
  }

  return "system";
}

function formatSourceLabel(source: string): string {
  if (source === "system") return "System";
  if (source === "intel") return "Intel";
  if (source === "planner") return "Planner";
  if (source === "recon") return "Recon";
  if (source === "exploit") return "Exploit";
  if (source === "verify") return "Verify";
  if (source === "report") return "Report";
  if (source === "retest") return "Retest";
  if (source === "perceptor") return "Perceptor";
  return source.charAt(0).toUpperCase() + source.slice(1);
}

function eventDedupKey(event: ScanEventPayload): string {
  return `${event.project_id}|${event.scan_id}|${event.timestamp}|${event.event}|${event.level}|${event.message}`;
}

export default function Dashboard() {
  const navigate = useNavigate();
  const projects = useProjects((state) => state.projects);
  const activeProject = useProjects((state) => state.getActive());
  const setActive = useProjects((state) => state.setActive);
  const setRunning = useProjects((state) => state.setRunning);
  const stopScan = useProjects((state) => state.stopScan);
  const updateProject = useProjects((state) => state.updateProject);
  const hydrateFromDatabase = useProjects((state) => state.hydrateFromDatabase);
  const startingProjectId = useProjects((state) => state.startingProjectId);
  const activeProjectId = activeProject?.id ?? null;
  const activeScanId = (() => {
    const scanMeta = isRecord(activeProject?.lastScan) ? activeProject.lastScan : null;
    return typeof scanMeta?.scanId === "string" ? scanMeta.scanId.trim() : "";
  })();
  const shouldStreamScanEvents = Boolean(activeProjectId && activeScanId);

  const [insightTab, setInsightTab] = useState<InsightTab>("plan");
  const [streamLogs, setStreamLogs] = useState<DashboardLogEntry[]>([]);
  const [scanEvents, setScanEvents] = useState<ScanEventPayload[]>([]);
  const [logLevelFilter, setLogLevelFilter] = useState<"all" | LogLevel>("all");
  const [logSourceFilter, setLogSourceFilter] = useState<string>("all");
  const [autoScrollLogs, setAutoScrollLogs] = useState(true);
  const logsContainerRef = useRef<HTMLDivElement | null>(null);
  const [streamRetry, setStreamRetry] = useState(0);
  const streamRetryRef = useRef(0);
  const lastStreamErrorRef = useRef(0);
  const lastLiveEventAtRef = useRef(0);
  const streamDegradedRef = useRef(true);
  const seenEventKeysRef = useRef<Set<string>>(new Set());
  const [stopDialogOpen, setStopDialogOpen] = useState(false);

  const handleCloseProject = () => {
    setActive(null);
    navigate("/projects");
  };

  const ingestScanEvent = useCallback((event: ScanEventPayload) => {
    if (!activeProjectId) {
      return;
    }
    const key = eventDedupKey(event);
    if (seenEventKeysRef.current.has(key)) {
      return;
    }
    seenEventKeysRef.current.add(key);
    if (seenEventKeysRef.current.size > 6000) {
      const pruned = new Set(Array.from(seenEventKeysRef.current).slice(-3000));
      seenEventKeysRef.current = pruned;
    }

    setScanEvents((previous) => [event, ...previous].slice(0, 400));

    setStreamLogs((previous) => {
      const nextEntry: DashboardLogEntry = {
        id: `${event.timestamp}-${Math.random().toString(36).slice(2, 10)}`,
        level: toLogLevel(event.level),
        message: event.message,
        at: event.timestamp,
        source: detectLogSource(event),
      };
      return [...previous, nextEntry].slice(-120);
    });

    const nextStatus = toProjectStatus(event.data.status);
    const rawProgress = event.data.scan_progress;
    const nextProgress = typeof rawProgress === "number" && Number.isFinite(rawProgress)
      ? rawProgress
      : undefined;

    if (nextStatus || typeof nextProgress === "number") {
      updateProject(activeProjectId, {
        ...(nextStatus ? { status: nextStatus } : {}),
        ...(typeof nextProgress === "number" ? { scanProgress: nextProgress } : {}),
      }, { persist: false });
    }

    if (
      event.event === "scan_completed"
      || event.event === "scan_failed"
      || event.event === "intel_complete"
    ) {
      void hydrateFromDatabase();
    }
  }, [activeProjectId, updateProject, hydrateFromDatabase]);

  useEffect(() => {
    if (!activeProjectId) {
      setStreamLogs([]);
      setScanEvents([]);
      streamRetryRef.current = 0;
      setStreamRetry(0);
      lastLiveEventAtRef.current = 0;
      streamDegradedRef.current = true;
      seenEventKeysRef.current.clear();
      return;
    }

    setLogLevelFilter("all");
    setLogSourceFilter("all");
    setAutoScrollLogs(true);
    setStreamLogs([]);
    setScanEvents([]);
    streamRetryRef.current = 0;
    setStreamRetry(0);
    lastLiveEventAtRef.current = 0;
    streamDegradedRef.current = true;
    seenEventKeysRef.current.clear();
  }, [activeProjectId]);

  useEffect(() => {
    if (!activeProjectId || !shouldStreamScanEvents) {
      return;
    }

    return streamProjectScanEvents(activeProjectId, {
      onEvent: (event) => {
        streamRetryRef.current = 0;
        lastLiveEventAtRef.current = Date.now();
        streamDegradedRef.current = false;
        ingestScanEvent(event);
      },
      onError: () => {
        streamDegradedRef.current = true;
        const now = Date.now();
        if (now - lastStreamErrorRef.current < 1200) {
          return;
        }
        lastStreamErrorRef.current = now;
        setStreamLogs((previous) => {
          const nextEntry: DashboardLogEntry = {
            id: `stream-disconnected-${Math.random().toString(36).slice(2, 10)}`,
            level: "warn",
            message: "Scan event stream disconnected. Syncing project state...",
            at: new Date().toISOString(),
            source: "system",
          };
          return [...previous, nextEntry].slice(-120);
        });
        void hydrateFromDatabase();
        if (streamRetryRef.current < 3) {
          streamRetryRef.current += 1;
          const delayMs = 800 * streamRetryRef.current;
          window.setTimeout(() => {
            setStreamRetry((value) => value + 1);
          }, delayMs);
        }
      },
    });
  }, [activeProjectId, shouldStreamScanEvents, ingestScanEvent, hydrateFromDatabase, streamRetry]);

  useEffect(() => {
    if (!autoScrollLogs) {
      return;
    }
    const container = logsContainerRef.current;
    if (!container) {
      return;
    }
    container.scrollTop = container.scrollHeight;
  }, [streamLogs.length, autoScrollLogs, logLevelFilter, logSourceFilter]);

  useEffect(() => {
    if (!activeProjectId || !shouldStreamScanEvents) {
      return;
    }

    let cancelled = false;
    const fetchRecent = async () => {
      const now = Date.now();
      const streamLooksStale = now - lastLiveEventAtRef.current > 7000;
      if (!streamDegradedRef.current && !streamLooksStale) {
        return;
      }
      try {
        const recent = await listProjectScanEventsFromDesktop(activeProjectId, 220);
        if (cancelled || recent.length === 0) {
          return;
        }
        for (const event of recent) {
          ingestScanEvent(event);
        }
      } catch {
        // Ignore polling errors; SSE remains primary channel.
      }
    };

    void fetchRecent();
    const timer = window.setInterval(() => {
      void fetchRecent();
    }, 3000);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [activeProjectId, shouldStreamScanEvents, ingestScanEvent]);

  if (!activeProject) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3">
        <FolderOpen size={48} className="text-text-muted" />
        <p className="text-sm text-text-secondary">No project selected.</p>
        <Button onClick={() => navigate("/projects")}>Open Projects</Button>
      </div>
    );
  }

  const effectiveStatus = normalizeRunningStatus(activeProject);
  const isRunning = effectiveStatus === "running";
  const isStarting = startingProjectId === activeProject.id;
  const hasAnotherRunningProject = projects.some(
    (project) => project.id !== activeProject.id && normalizeRunningStatus(project) === "running",
  );
  const canRun = !isRunning && !isStarting && !hasAnotherRunningProject;

  const fallbackLogs: DashboardLogEntry[] = [];
  const baseTimestamp = activeProject.updatedAt || new Date().toISOString();
  const fallbackLastScan = isRecord(activeProject.lastScan) ? activeProject.lastScan : null;
  const fallbackLastScanError = typeof fallbackLastScan?.error === "string"
    ? fallbackLastScan.error.trim()
    : "";
  fallbackLogs.push({
    id: "fallback-status",
    level: effectiveStatus === "error" ? "warn" : "info",
    message: `Scan status changed to ${effectiveStatus}.`,
    at: baseTimestamp,
    source: "system",
  });
  if (effectiveStatus === "error" && fallbackLastScanError.length > 0) {
    fallbackLogs.push({
      id: "fallback-error-detail",
      level: "error",
      message: `Scan failed: ${fallbackLastScanError}`,
      at: typeof fallbackLastScan?.finishedAt === "string" && fallbackLastScan.finishedAt
        ? fallbackLastScan.finishedAt
        : baseTimestamp,
      source: "system",
    });
  }
  for (const phase of activeProject.phases) {
    if (phase.status === "pending" && phase.progress <= 0) {
      continue;
    }
    fallbackLogs.push({
      id: `fallback-phase-${phase.name}`,
      level: phase.status === "completed" ? "success" : "info",
      message: `${phase.name} is ${phase.status} (${Math.round(phase.progress)}%).`,
      at: phase.completedAt ?? phase.startedAt ?? baseTimestamp,
      source: "system",
    });
  }
  const baseLogs = (
    streamLogs.length > 0
      ? streamLogs
      : fallbackLogs.sort((a, b) => new Date(a.at).getTime() - new Date(b.at).getTime()).slice(-14)
  );
  const sourceOptions = Array.from(new Set(baseLogs.map((entry) => entry.source)));
  const displayedLogs = baseLogs.filter((entry) => {
    if (logLevelFilter !== "all" && entry.level !== logLevelFilter) {
      return false;
    }
    if (logSourceFilter !== "all" && entry.source !== logSourceFilter) {
      return false;
    }
    return true;
  });

  const handleLogsScroll = () => {
    const container = logsContainerRef.current;
    if (!container) {
      return;
    }
    const distanceToBottom = container.scrollHeight - container.scrollTop - container.clientHeight;
    const nearBottom = distanceToBottom <= 24;
    if (nearBottom !== autoScrollLogs) {
      setAutoScrollLogs(nearBottom);
    }
  };

  const planSteps = activeProject.phases.length > 0
    ? activeProject.phases.map((phase) => ({
      name: phase.name,
      status: phase.status,
      progress: Math.round(phase.progress),
    }))
    : [
      { name: "Reconnaissance", status: "pending", progress: 0 },
      { name: "Enumeration", status: "pending", progress: 0 },
      { name: "Exploitation", status: "pending", progress: 0 },
      { name: "Post-Exploitation", status: "pending", progress: 0 },
      { name: "Reporting", status: "pending", progress: 0 },
    ];
  const overviewPhases = planSteps.slice(0, 5);

  const criticalFindings = activeProject.findings.filter((finding) => finding.severity === "critical");
  const criticalResolved = criticalFindings.every(
    (finding) => finding.status === "verified" || finding.status === "fixed",
  );
  const checklistItems = [
    { label: "Target is configured", done: activeProject.target.trim().length > 0 },
    { label: "Target type is selected", done: activeProject.targetType.trim().length > 0 },
    {
      label: "At least one phase has started",
      done: activeProject.phases.some((phase) => phase.status !== "pending" || phase.progress > 0),
    },
    {
      label: "At least one agent has executed",
      done: activeProject.agents.some((agent) => agent.state !== "idle"),
    },
    { label: "Critical findings are verified/fixed", done: criticalResolved },
  ];

  const agentInsights = (() => {
    const byRole = Object.fromEntries(
      AGENT_ROLES.map((role) => [role, { history: [] as AgentInsightPanelData["history"] }]),
    ) as Record<AgentGraphRole, AgentInsightPanelData>;

    const scanMeta = isRecord(activeProject.lastScan) ? activeProject.lastScan : null;
    const currentScanId = typeof scanMeta?.scanId === "string" ? scanMeta.scanId.trim() : "";
    const allEvents = [...scanEvents];
    const latestStartedScanId = allEvents.find(
      (event) => event.event === "scan_started" && event.scan_id.trim().length > 0,
    )?.scan_id ?? "";
    const latestAnyScanId = allEvents.find(
      (event) => event.scan_id.trim().length > 0,
    )?.scan_id ?? "";

    // Prefer the active running scan id from events if metadata is stale.
    let scopedScanId = currentScanId;
    if (effectiveStatus === "running" && latestStartedScanId && latestStartedScanId !== currentScanId) {
      scopedScanId = latestStartedScanId;
    }
    if (!scopedScanId) {
      scopedScanId = latestStartedScanId || latestAnyScanId;
    }

    const scopedEvents = scopedScanId
      ? allEvents.filter(
        (event) => event.scan_id === scopedScanId || event.event === "scan_status_snapshot",
      )
      : allEvents;

    const filteredEvents = [...scopedEvents].reverse(); // chronological (oldest -> newest)

    for (const event of filteredEvents) {
      const role = detectEventAgentRole(event);
      if (!role) {
        continue;
      }
      byRole[role].history.push({
        id: `${event.timestamp}-${event.event}-${Math.random().toString(36).slice(2, 7)}`,
        at: event.timestamp,
        level: toLogLevel(event.level),
        message: event.message,
        event: event.event,
      });
    }

    let intelSummary = "";
    let intelStatus = "";
    let intelError = "";

    for (let index = filteredEvents.length - 1; index >= 0; index -= 1) {
      const event = filteredEvents[index];
      if (!isRecord(event.data)) {
        continue;
      }

      if (event.event === "intel_complete") {
        const summaryCandidate = typeof event.data.summary === "string"
          ? event.data.summary.trim()
          : "";
        if (summaryCandidate.length > 0) {
          intelSummary = summaryCandidate;
          intelStatus = typeof event.data.intel_status === "string"
            ? event.data.intel_status.trim()
            : "complete";
          break;
        }
      }

      if (!intelError && (event.event === "intel_crashed" || event.event === "scan_failed")) {
        const errorCandidate = typeof event.data.error === "string"
          ? event.data.error.trim()
          : "";
        if (errorCandidate.length > 0) {
          intelError = errorCandidate;
        }
      }
    }

    if (intelSummary.length > 0) {
      byRole.intel.resultLabel = intelStatus ? `Intel Result (${intelStatus})` : "Intel Result";
      byRole.intel.result = intelSummary;
    } else if (intelError.length > 0) {
      byRole.intel.resultLabel = "Intel Error";
      byRole.intel.result = intelError;
    }

    byRole.perceptor.resultLabel = "Perceptor Summary";
    byRole.perceptor.result = `Scan status: ${effectiveStatus}. Progress: ${activeProject.scanProgress}%.`;

    return byRole;
  })();

  return (
    <div className="space-y-4">
      <div>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-2xl font-bold">{activeProject.name}</h1>
              <Badge variant={effectiveStatus} dot>{effectiveStatus}</Badge>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {!isRunning ? (
              <Button
                size="xs"
                onClick={() => {
                  if (effectiveStatus === "completed") {
                    const confirmed = window.confirm("This scan already completed. Start a new scan and clear previous results?");
                    if (!confirmed) {
                      return;
                    }
                    setStreamLogs([]);
                    setScanEvents([]);
                    setRunning(activeProject.id, { triggerScan: true, force: true });
                    return;
                  }
                  if (effectiveStatus === "paused") {
                    const confirmed = window.confirm("Resume will start a new scan and keep previous history visible. Continue?");
                    if (!confirmed) {
                      return;
                    }
                    setRunning(activeProject.id, { triggerScan: true, resume: true });
                    return;
                  }
                  if (effectiveStatus === "idle") {
                    setStreamLogs([]);
                    setScanEvents([]);
                  }
                  setRunning(activeProject.id, { triggerScan: true });
                }}
                disabled={!canRun}
                loading={isStarting}
                title={hasAnotherRunningProject ? "Another scan is already running" : "Start scan"}
              >
                <Play size={12} />
                Start Scan
              </Button>
            ) : (
              <Button
                size="xs"
                variant="danger"
                onClick={() => {
                  setStopDialogOpen(true);
                }}
                title="Stop running scan"
              >
                <Square size={12} />
                Stop Scan
              </Button>
            )}
            {isStarting && (
              <span className="text-[11px] text-text-muted">Starting scan...</span>
            )}
            <Button size="xs" variant="secondary" onClick={() => navigate("/projects")}>
              <Repeat2 size={12} />
              Change
            </Button>
            <Button
              size="xs"
              variant="ghost"
              onClick={handleCloseProject}
            >
              <X size={12} />
              Close
            </Button>
          </div>
        </div>
      </div>

      <Card className="space-y-2 p-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-text-primary">Target Overview</h2>
          <span className="inline-flex items-center gap-1 text-[11px] text-text-muted">
            <Clock3 size={12} />
            Updated {formatDateTime(activeProject.updatedAt)}
          </span>
        </div>

        <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-md bg-surface-0/40 p-1.5">
            <p className="text-[11px] text-text-muted">Target</p>
            <p className="mt-0.5 break-all font-mono text-xs text-text-primary">{activeProject.target}</p>
          </div>
          <div className="rounded-md bg-surface-0/40 p-1.5">
            <p className="text-[11px] text-text-muted">Target Type</p>
            <p className="mt-0.5 text-xs text-text-primary">{activeProject.targetType.replaceAll("_", " ")}</p>
          </div>
          <div className="rounded-md bg-surface-0/40 p-1.5">
            <p className="text-[11px] text-text-muted">Created</p>
            <p className="mt-0.5 text-xs text-text-primary">{formatDateTime(activeProject.createdAt)}</p>
          </div>
          <div className="rounded-md bg-surface-0/40 p-1.5">
            <p className="text-[11px] text-text-muted">Status</p>
            <p className="mt-0.5 text-xs text-text-primary">{effectiveStatus}</p>
          </div>
        </div>

        <div className="rounded-md border border-border bg-surface-0/35 p-2">
          <div className="mb-2 flex items-center justify-between">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-text-secondary">Scan Progress</h3>
            <span className="text-xs font-mono text-pf-400">{activeProject.scanProgress}%</span>
          </div>

          <div className="mb-2 h-1.5 overflow-hidden rounded-full bg-surface-2">
            <div
              className="h-full rounded-full bg-pf-600 transition-all duration-500"
              style={{ width: `${activeProject.scanProgress}%` }}
            />
          </div>

          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
            {overviewPhases.map((phase) => (
              <div key={phase.name} className="rounded-md border border-border/70 bg-surface-1/40 p-2">
                <div className="mb-1 flex items-center justify-between gap-2">
                  <p className="truncate text-[11px] font-medium text-text-primary" title={phase.name}>{phase.name}</p>
                  <span className="text-[11px] font-mono text-text-muted">{phase.progress}%</span>
                </div>
                <div className="h-1 overflow-hidden rounded-full bg-surface-2">
                  <div
                    className={
                      phase.status === "completed"
                        ? "h-full rounded-full bg-emerald-400 transition-all duration-300"
                        : phase.status === "active"
                          ? "h-full rounded-full bg-pf-500 transition-all duration-300"
                          : "h-full rounded-full bg-surface-3 transition-all duration-300"
                    }
                    style={{ width: `${phase.progress}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </Card>

      <StatsGrid findings={activeProject.findings} />

      <div className="grid gap-4 xl:grid-cols-2">
        <Card className="flex h-[420px] flex-col space-y-3 p-3">
          <div className="flex items-center justify-between">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-sm font-semibold text-text-primary">Real-Time Logs</h2>

              <select
                value={logLevelFilter}
                onChange={(event) => setLogLevelFilter(event.target.value as "all" | LogLevel)}
                className="rounded-md border border-border bg-transparent px-2 py-1 text-[11px] text-text-primary"
                title="Filter by level"
              >
                <option value="all" style={{ backgroundColor: "var(--surface-1)", color: "var(--text-primary)" }}>All Levels</option>
                <option value="info" style={{ backgroundColor: "var(--surface-1)", color: "var(--text-primary)" }}>Info</option>
                <option value="success" style={{ backgroundColor: "var(--surface-1)", color: "var(--text-primary)" }}>Success</option>
                <option value="warn" style={{ backgroundColor: "var(--surface-1)", color: "var(--text-primary)" }}>Warn</option>
                <option value="error" style={{ backgroundColor: "var(--surface-1)", color: "var(--text-primary)" }}>Error</option>
              </select>

              <select
                value={logSourceFilter}
                onChange={(event) => setLogSourceFilter(event.target.value)}
                className="rounded-md border border-border bg-transparent px-2 py-1 text-[11px] text-text-primary"
                title="Filter by source"
              >
                <option value="all" style={{ backgroundColor: "var(--surface-1)", color: "var(--text-primary)" }}>All Sources</option>
                {sourceOptions.map((source) => (
                  <option
                    key={source}
                    value={source}
                    style={{ backgroundColor: "var(--surface-1)", color: "var(--text-primary)" }}
                  >
                    {formatSourceLabel(source)}
                  </option>
                ))}
              </select>
            </div>
            <div className="text-right">
              <p className="text-[11px] text-text-muted">{displayedLogs.length}/{baseLogs.length} events</p>
              <p className="text-[10px] text-text-muted">{autoScrollLogs ? "auto-scroll on" : "auto-scroll paused"}</p>
            </div>
          </div>
          <div
            ref={logsContainerRef}
            onScroll={handleLogsScroll}
            className="min-h-0 flex-1 space-y-1 overflow-y-auto rounded-md border border-border bg-surface-0/35 p-2"
          >
            {displayedLogs.length === 0 ? (
              <p className="px-1 py-2 text-xs text-text-muted">No logs match current filters.</p>
            ) : (
              displayedLogs.map((entry) => (
                <div key={entry.id} className="grid grid-cols-[70px_1fr] gap-2 rounded px-1 py-1 text-xs">
                  <span className="font-mono text-[10px] text-text-muted">{formatTime(entry.at)}</span>
                  <p
                    className={
                      entry.level === "warn" || entry.level === "error"
                        ? "text-red-300"
                        : entry.level === "success"
                          ? "text-emerald-300"
                          : "text-text-secondary"
                    }
                  >
                    <span className="mr-1 text-[10px] uppercase tracking-wide text-text-muted">
                      [{entry.source}]
                    </span>
                    {entry.message}
                  </p>
                </div>
              ))
            )}
          </div>
        </Card>

        <AIPromptPanel
          projectId={activeProject.id}
          projectName={activeProject.name}
          target={activeProject.target}
          targetType={activeProject.targetType}
          agents={activeProject.agents}
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
        <Card className="space-y-3 p-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-text-primary">Execution Notes</h2>
            <div className="inline-flex items-center gap-1 rounded-md border border-border bg-surface-0/40 p-1">
              <Button
                size="xs"
                variant={insightTab === "plan" ? "secondary" : "ghost"}
                onClick={() => setInsightTab("plan")}
              >
                Plan
              </Button>
              <Button
                size="xs"
                variant={insightTab === "checklist" ? "secondary" : "ghost"}
                onClick={() => setInsightTab("checklist")}
              >
                Checklist
              </Button>
            </div>
          </div>

          {insightTab === "plan" ? (
            <div className="max-h-[430px] space-y-2 overflow-y-auto rounded-md border border-border bg-surface-0/35 p-2">
              {planSteps.map((step, index) => (
                <div key={`${step.name}-${index}`} className="rounded-md border border-border/70 bg-surface-1/50 p-2">
                  <p className="text-xs font-medium text-text-primary">{index + 1}. {step.name}</p>
                  <p className="mt-1 text-[11px] text-text-muted">
                    Status: {step.status} • Progress: {step.progress}%
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="max-h-[430px] space-y-2 overflow-y-auto rounded-md border border-border bg-surface-0/35 p-2">
              {checklistItems.map((item) => (
                <div key={item.label} className="flex items-center gap-2 rounded-md border border-border/70 bg-surface-1/50 p-2 text-xs">
                  {item.done ? (
                    <CheckCircle size={14} className="shrink-0 text-emerald-400" />
                  ) : (
                    <Circle size={14} className="shrink-0 text-text-muted" />
                  )}
                  <p className={item.done ? "text-text-primary" : "text-text-secondary"}>{item.label}</p>
                </div>
              ))}
            </div>
          )}
        </Card>

        <AgentStatePath
          agents={activeProject.agents}
          agentInsights={agentInsights}
          showHeader
          subtitle="Intel → Planner → Executor Layer (parallel) → Perceptor"
          graphHeightClassName="h-[430px]"
        />
      </div>

      <FindingsTable findings={activeProject.findings} />

      <Dialog
        open={stopDialogOpen}
        onClose={() => setStopDialogOpen(false)}
        title="Stop Scan"
        description="Choose whether to pause or cancel the current scan."
      >
        <div className="space-y-3 text-xs text-text-secondary">
          <p>
            Pause will keep current logs and results so you can review them. Cancel will clear logs,
            agent results, and reset status to idle.
          </p>
          <div className="flex flex-col gap-2 sm:flex-row sm:justify-end">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setStopDialogOpen(false)}
            >
              Back
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                setStopDialogOpen(false);
                void stopScan(activeProject.id, "pause");
              }}
            >
              Pause Scan
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={() => {
                setStopDialogOpen(false);
                setStreamLogs([]);
                setScanEvents([]);
                void stopScan(activeProject.id, "cancel");
              }}
            >
              Cancel Scan
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}
