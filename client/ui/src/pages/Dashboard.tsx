import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Bot,
  Check,
  Clock3,
  FolderOpen,
  Maximize2,
  Minimize2,
  Pencil,
  Play,
  Plus,
  Repeat2,
  Square,
  Trash2,
  X,
} from "lucide-react";

import { AIPromptPanel } from "@/components/dashboard/AIPromptPanel";
import {
  AgentStatePath,
  type AgentGraphRole,
  type AgentInsightPanelData,
} from "@/components/dashboard/AgentStatePath";
import { FindingsTable } from "@/components/dashboard/FindingsTable";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Dialog } from "@/components/ui/Dialog";
import { Input } from "@/components/ui/Input";
import {
  approveToolForProjectScanFromDesktop,
  approvePlannerForProjectScanFromDesktop,
  listProjectScanEventsFromDesktop,
  saveProjectToDesktop,
  streamProjectScanEvents,
  type ScanEventPayload,
} from "@/lib/projectBridge";
import { useProjects } from "@/stores/projects";
import type { ProjectStatus } from "@/types";

type InsightTab = "plan" | "checklist";
type LogLevel = "info" | "success" | "warn" | "error";
type DashboardSeverity = "critical" | "high" | "medium" | "low" | "info";

interface StructuredChecklistItem {
  name: string;
  priority: number;
}

interface StructuredChecklistBlock {
  phase: string;
  title: string;
  items: StructuredChecklistItem[];
}

interface StructuredChecklistPayload {
  target_type: string;
  available_total: number;
  checklist: StructuredChecklistBlock[];
}

interface PlannerPhaseSummary {
  name: string;
  priority: number;
  stepCount: number;
  scenarioCount: number;
  completedScenarioCount: number;
}

interface PlannerPlanSummary {
  target: string;
  scope: string;
  phases: PlannerPhaseSummary[];
}

interface PlannerScenarioView {
  scenario: string;
  agent: string;
}

interface PlannerStepView {
  step: string;
  scenarios: PlannerScenarioView[];
}

interface PlannerPhaseView {
  phase: string;
  steps: PlannerStepView[];
}

interface PlannerPlanView {
  phases: PlannerPhaseView[];
}

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

interface TargetArchitectureDraft {
  title: string;
  hosts: ArchitectureHost[];
  flows: ArchitectureFlow[];
}

interface DashboardLogEntry {
  id: string;
  level: LogLevel;
  message: string;
  at: string;
  source: string;
}

interface RealtimeVulnFinding {
  id: string;
  title: string;
  severity: DashboardSeverity;
  source: string;
  at: string;
}

interface PendingToolApprovalView {
  approvalId: string;
  role: string;
  toolName: string;
  callId: string;
  args: Record<string, unknown>;
}

const PROJECT_STATUSES: ProjectStatus[] = [
  "idle",
  "running",
  "paused",
  "completed",
  "error",
];
const AGENT_ROLES: AgentGraphRole[] = [
  "intel",
  "planner",
  "recon",
  "exploit",
  "verify",
  "report",
  "retest",
  "perceptor",
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isAgentRole(value: unknown): value is AgentGraphRole {
  return (
    typeof value === "string" && AGENT_ROLES.includes(value as AgentGraphRole)
  );
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
  return PROJECT_STATUSES.includes(value as ProjectStatus)
    ? (value as ProjectStatus)
    : null;
}

function normalizeRunningStatus(project: {
  status: ProjectStatus;
  lastScan?: unknown;
}): ProjectStatus {
  if (project.status !== "running") {
    return project.status;
  }
  const lastScan = isRecord(project.lastScan) ? project.lastScan : null;
  const lastScanStatus =
    typeof lastScan?.status === "string"
      ? lastScan.status.trim().toLowerCase()
      : "";
  if (
    lastScanStatus === "completed" ||
    lastScanStatus === "paused" ||
    lastScanStatus === "idle" ||
    lastScanStatus === "error"
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

function severityRank(value: DashboardSeverity): number {
  if (value === "critical") return 5;
  if (value === "high") return 4;
  if (value === "medium") return 3;
  if (value === "low") return 2;
  return 1;
}

function isOperationalToolEvent(event: ScanEventPayload): boolean {
  const message = String(event.message || "").toLowerCase();
  return (
    message.includes("[run tool]") ||
    message.includes("search_rag(") ||
    message.includes("calling tools")
  );
}

function inferEventSeverity(event: ScanEventPayload): DashboardSeverity {
  if (isOperationalToolEvent(event)) {
    return "info";
  }
  const eventName = String(event.event || "").toLowerCase();
  if (eventName.includes("crashed") || eventName.includes("failed")) {
    return "high";
  }
  const text = `${event.event} ${event.message}`.toLowerCase();
  if (text.includes("critical")) return "critical";
  if (
    text.includes("high") ||
    text.includes("rce") ||
    text.includes("sqli") ||
    text.includes("exploit")
  ) {
    return "high";
  }
  if (
    text.includes("vuln") ||
    text.includes("finding") ||
    text.includes("xss") ||
    text.includes("ssrf") ||
    text.includes("idor") ||
    text.includes("injection")
  ) {
    return "medium";
  }
  if (event.level === "error") return "medium";
  if (event.level === "warn") return "medium";
  return "low";
}

function severityBadgeClass(value: DashboardSeverity): string {
  if (value === "critical") {
    return "border-red-500/40 bg-red-500/15 text-red-200";
  }
  if (value === "high") {
    return "border-orange-500/40 bg-orange-500/15 text-orange-200";
  }
  if (value === "medium") {
    return "border-amber-500/40 bg-amber-500/15 text-amber-200";
  }
  if (value === "low") {
    return "border-emerald-500/40 bg-emerald-500/15 text-emerald-200";
  }
  return "border-slate-500/40 bg-slate-500/15 text-slate-200";
}

function buildPendingApprovalCommand(view: PendingToolApprovalView | null): string {
  if (!view) {
    return "";
  }
  const args = view.args;
  if (view.toolName === "run_custom") {
    const command = typeof args.command === "string" ? args.command.trim() : "";
    const rawArgs = Array.isArray(args.args) ? args.args : [];
    const joinedArgs = rawArgs
      .map((entry) => String(entry ?? "").trim())
      .filter((entry) => entry.length > 0)
      .join(" ");
    const full = `${command} ${joinedArgs}`.trim();
    if (full) {
      return full;
    }
  }
  return view.toolName;
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

function normalizePriority(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }
  const rounded = Math.round(value);
  if (rounded < 1) {
    return 1;
  }
  if (rounded > 5) {
    return 5;
  }
  return rounded;
}

function normalizeText(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function normalizePhase(value: unknown): string {
  const raw = normalizeText(value);
  if (!raw) {
    return "";
  }
  const digitMatch = raw.match(/\d+/);
  if (!digitMatch) {
    return raw;
  }
  return digitMatch[0];
}

function toStructuredChecklist(
  value: unknown,
): StructuredChecklistPayload | null {
  if (!isRecord(value)) {
    return null;
  }
  const rawBlocks = value.checklist;
  if (!Array.isArray(rawBlocks) || rawBlocks.length === 0) {
    return null;
  }

  const blocks: StructuredChecklistBlock[] = [];
  for (const block of rawBlocks) {
    if (!isRecord(block)) {
      continue;
    }
    const phase = normalizePhase(block.phase);
    const title =
      normalizeText(block.title) || (phase ? `Phase ${phase}` : "Checklist");
    const rawItems = block.items;
    if (!Array.isArray(rawItems)) {
      continue;
    }

    const items: StructuredChecklistItem[] = [];
    for (const item of rawItems) {
      if (typeof item === "string") {
        const name = item.trim();
        if (!name) {
          continue;
        }
        items.push({ name, priority: 3 });
        continue;
      }
      if (!isRecord(item)) {
        continue;
      }
      const name = normalizeText(item.name);
      if (!name) {
        continue;
      }
      items.push({
        name,
        priority: normalizePriority(item.priority) ?? 3,
      });
    }
    if (items.length === 0) {
      continue;
    }
    blocks.push({
      phase,
      title,
      items,
    });
  }

  if (blocks.length === 0) {
    return null;
  }

  const targetType = normalizeText(value.target_type) || "web_app";
  const availableTotal =
    typeof value.available_total === "number" &&
      Number.isFinite(value.available_total)
      ? value.available_total
      : blocks.reduce((count, block) => count + block.items.length, 0);

  return {
    target_type: targetType,
    available_total: availableTotal,
    checklist: blocks,
  };
}

function cloneStructuredChecklist(
  payload: StructuredChecklistPayload,
): StructuredChecklistPayload {
  return {
    target_type: payload.target_type,
    available_total: payload.available_total,
    checklist: payload.checklist.map((block) => ({
      phase: block.phase,
      title: block.title,
      items: block.items.map((item) => ({
        name: item.name,
        priority: item.priority,
      })),
    })),
  };
}

function checklistFromLabels(
  labels: string[],
  targetType = "web_app",
): StructuredChecklistPayload | null {
  if (labels.length === 0) {
    return null;
  }
  const items: StructuredChecklistItem[] = labels.map((label) => {
    const trimmed = label.trim();
    const match = trimmed.match(/^\[[PS]([1-5])\]\s+(.+)$/i);
    if (match && match[2]) {
      return {
        name: match[2].trim(),
        priority: Number(match[1]),
      };
    }
    return {
      name: trimmed,
      priority: 3,
    };
  });
  return {
    target_type: targetType,
    available_total: items.length,
    checklist: [
      {
        phase: "4",
        title: "Checklist",
        items,
      },
    ],
  };
}

function extractChecklistLabels(summary: string): string[] {
  const text = summary.trim();
  if (!text) {
    return [];
  }
  const match = text.match(/CHECKLIST:\s*([\s\S]*?)(?:\n[A-Z_ ]+:\s*|$)/i);
  const body = match && match[1] ? match[1] : text;
  const lines = body.split("\n");
  const labels: string[] = [];
  const seen = new Set<string>();
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) {
      continue;
    }
    let clean = "";
    if (line.startsWith("- ") || line.startsWith("* ")) {
      clean = line.slice(2).trim();
    } else if (line.startsWith("[ ] ")) {
      clean = line.slice(4).trim();
    } else if (/^\d+[\.\)]\s+/.test(line)) {
      clean = line.replace(/^\d+[\.\)]\s+/, "").trim();
    }
    if (!clean || clean === "(none found)") {
      continue;
    }
    const key = clean.toLowerCase();
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    labels.push(clean);
  }
  return labels;
}

function extractChecklistLabelsFromStructuredChecklist(
  value: unknown,
): string[] {
  const structured = toStructuredChecklist(value);
  if (!structured) {
    return [];
  }

  const labels: string[] = [];
  const seen = new Set<string>();
  for (const block of structured.checklist) {
    for (const item of block.items) {
      const key = item.name.toLowerCase();
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      labels.push(`[S${item.priority}] ${item.name}`);
    }
  }
  return labels;
}

function buildChecklistInsightText(value: unknown, maxItems = 18): string {
  const structured = toStructuredChecklist(value);
  if (!structured) {
    return "";
  }

  const totalItems = structured.checklist.reduce(
    (count, block) => count + block.items.length,
    0,
  );
  const phaseCount = structured.checklist.length;
  const lines: string[] = [
    `Checklist finalized: ${totalItems} items across ${phaseCount} phases.`,
    "",
    "Phase coverage:",
  ];

  for (const block of structured.checklist) {
    const phaseLabel = block.phase ? `Phase ${block.phase}` : "Phase";
    lines.push(`- ${phaseLabel} - ${block.title}: ${block.items.length} items`);
  }

  lines.push("", "Top checklist items:");
  let shown = 0;
  for (const block of structured.checklist) {
    for (const item of block.items) {
      if (shown >= maxItems) {
        break;
      }
      lines.push(`- [S${item.priority}] ${item.name}`);
      shown += 1;
    }
    if (shown >= maxItems) {
      break;
    }
  }

  if (shown < totalItems) {
    lines.push(`- ... and ${totalItems - shown} more items`);
  }

  return lines.join("\n");
}

function toPlannerPlanSummary(value: unknown): PlannerPlanSummary | null {
  if (!isRecord(value)) {
    return null;
  }
  const rawPhases = Array.isArray(value.phases) ? value.phases : [];
  if (rawPhases.length === 0) {
    return null;
  }

  const phases: PlannerPhaseSummary[] = [];
  for (let phaseIndex = 0; phaseIndex < rawPhases.length; phaseIndex += 1) {
    const rawPhase = rawPhases[phaseIndex];
    if (!isRecord(rawPhase)) {
      continue;
    }
    const rawSteps = Array.isArray(rawPhase.steps) ? rawPhase.steps : [];
    let scenarioCount = 0;
    let completedScenarioCount = 0;

    for (const rawStep of rawSteps) {
      if (!isRecord(rawStep)) {
        continue;
      }
      const rawScenarios = Array.isArray(rawStep.scenarios)
        ? rawStep.scenarios
        : [];
      for (const rawScenario of rawScenarios) {
        if (!isRecord(rawScenario)) {
          continue;
        }
        scenarioCount += 1;
        if (rawScenario.done === true) {
          completedScenarioCount += 1;
        }
      }
    }

    phases.push({
      name: normalizeText(rawPhase.name) || `Phase ${phaseIndex + 1}`,
      priority: normalizePriority(rawPhase.priority) ?? phaseIndex + 1,
      stepCount: rawSteps.filter((step) => isRecord(step)).length,
      scenarioCount,
      completedScenarioCount,
    });
  }

  if (phases.length === 0) {
    return null;
  }

  return {
    target: normalizeText(value.target),
    scope: normalizeText(value.scope),
    phases,
  };
}

function plannerNeedToText(value: unknown): string {
  if (typeof value === "string") {
    return value.trim();
  }
  if (!isRecord(value)) {
    return "";
  }
  const preferredKeys = ["need", "item", "description", "message", "task"];
  for (const key of preferredKeys) {
    const candidate = normalizeText(value[key]);
    if (candidate) {
      return candidate;
    }
  }
  try {
    return JSON.stringify(value);
  } catch {
    return "";
  }
}

function buildPlannerInsightText(
  summary: string,
  planData: unknown,
  needsValue: unknown,
  maxNeeds = 8,
): string {
  const lines: string[] = [];
  if (summary.trim().length > 0) {
    lines.push(summary.trim());
  }

  const plan = toPlannerPlanSummary(planData);
  if (plan) {
    const totalSteps = plan.phases.reduce(
      (count, phase) => count + phase.stepCount,
      0,
    );
    const totalScenarios = plan.phases.reduce(
      (count, phase) => count + phase.scenarioCount,
      0,
    );
    const totalDone = plan.phases.reduce(
      (count, phase) => count + phase.completedScenarioCount,
      0,
    );
    const targetLabel = plan.target || "target";
    lines.push(
      `${targetLabel}: ${plan.phases.length} phases, ${totalSteps} steps, ${totalScenarios} scenarios (${totalDone} completed).`,
    );
    lines.push("", "Phase breakdown:");
    for (const phase of plan.phases) {
      const pending = Math.max(
        phase.scenarioCount - phase.completedScenarioCount,
        0,
      );
      lines.push(
        `- S${phase.priority} ${phase.name}: ${phase.stepCount} steps, ${phase.scenarioCount} scenarios, ${pending} pending`,
      );
    }
  }

  if (Array.isArray(needsValue) && needsValue.length > 0) {
    const needs = needsValue
      .map((need) => plannerNeedToText(need))
      .filter((need) => need.length > 0)
      .slice(0, maxNeeds);
    if (needs.length > 0) {
      lines.push("", "Needs:");
      for (const need of needs) {
        lines.push(`- ${need}`);
      }
      if (Array.isArray(needsValue) && needsValue.length > needs.length) {
        lines.push(`- ... and ${needsValue.length - needs.length} more`);
      }
    }
  }

  return lines.join("\n").trim();
}

function toPlannerPlanView(value: unknown): PlannerPlanView | null {
  if (!isRecord(value)) {
    return null;
  }
  const rawPhases = Array.isArray(value.phases) ? value.phases : [];
  if (rawPhases.length === 0) {
    return null;
  }

  const phases: PlannerPhaseView[] = [];
  for (let phaseIndex = 0; phaseIndex < rawPhases.length; phaseIndex += 1) {
    const rawPhase = rawPhases[phaseIndex];
    if (!isRecord(rawPhase)) {
      continue;
    }
    const rawSteps = Array.isArray(rawPhase.steps) ? rawPhase.steps : [];
    const steps: PlannerStepView[] = [];

    for (let stepIndex = 0; stepIndex < rawSteps.length; stepIndex += 1) {
      const rawStep = rawSteps[stepIndex];
      if (!isRecord(rawStep)) {
        continue;
      }
      const rawScenarios = Array.isArray(rawStep.scenarios)
        ? rawStep.scenarios
        : [];
      const scenarios: PlannerScenarioView[] = [];
      for (const rawScenario of rawScenarios) {
        if (!isRecord(rawScenario)) {
          continue;
        }
        const task = normalizeText(rawScenario.task);
        if (!task) {
          continue;
        }
        scenarios.push({
          scenario: task,
          agent: normalizeText(rawScenario.agent) || "recon",
        });
      }

      const description =
        normalizeText(rawStep.description) || normalizeText(rawStep.id);
      if (!description && scenarios.length === 0) {
        continue;
      }
      steps.push({
        step: description || `Step ${stepIndex + 1}`,
        scenarios,
      });
    }

    phases.push({
      phase: normalizeText(rawPhase.name) || `Phase ${phaseIndex + 1}`,
      steps,
    });
  }

  if (phases.length === 0) {
    return null;
  }

  return { phases };
}

function buildTargetArchitectureDraft(
  targetType: string,
  target: string,
): TargetArchitectureDraft {
  const normalized = targetType.trim().toLowerCase();
  const targetLabel = target.trim() || "target";

  if (normalized === "network") {
    return {
      title: `Network architecture draft for ${targetLabel}`,
      hosts: [
        {
          id: "gw",
          name: "Gateway / Firewall",
          role: "Edge",
          ports: ["443/tcp", "80/tcp"],
          note: "Initial ingress and egress filtering point.",
          x: 12,
          y: 54,
        },
        {
          id: "web-01",
          name: "Web Host",
          role: "Service",
          ports: ["80/tcp", "443/tcp"],
          note: "Public-facing application host.",
          x: 36,
          y: 34,
        },
        {
          id: "app-01",
          name: "Application Host",
          role: "Internal",
          ports: ["8080/tcp", "8443/tcp"],
          note: "Business logic / API processing tier.",
          x: 60,
          y: 50,
        },
        {
          id: "db-01",
          name: "Database Host",
          role: "Data",
          ports: ["5432/tcp", "3306/tcp", "27017/tcp"],
          note: "Validate segmentation and direct-access exposure.",
          x: 84,
          y: 64,
        },
      ],
      flows: [
        { fromId: "gw", toId: "web-01", label: "Ingress web traffic" },
        { fromId: "web-01", toId: "app-01", label: "App routing" },
        { fromId: "app-01", toId: "db-01", label: "DB queries" },
      ],
    };
  }

  return {
    title: `Web architecture draft for ${targetLabel}`,
    hosts: [
      {
        id: "edge",
        name: targetLabel,
        role: "Public Web Edge",
        ports: ["443/tcp", "80/tcp"],
        note: "Entry point for public traffic and recon.",
        x: 12,
        y: 54,
      },
      {
        id: "app",
        name: "Application Service",
        role: "Business Logic",
        ports: ["8080/tcp", "8443/tcp"],
        note: "Focus for auth/session/input validation tests.",
        x: 44,
        y: 36,
      },
      {
        id: "nosql",
        name: "NoSQL Database",
        role: "Data Store",
        ports: ["27017/tcp"],
        note: "Focus for injection, auth, and access-control paths.",
        x: 76,
        y: 68,
      },
      {
        id: "auth",
        name: "Session / Auth Layer",
        role: "Identity",
        ports: ["443/tcp"],
        note: "Token, cookie, and privilege boundary checks.",
        x: 72,
        y: 24,
      },
    ],
    flows: [
      { fromId: "edge", toId: "app", label: "HTTP requests" },
      { fromId: "app", toId: "nosql", label: "Query path" },
      { fromId: "app", toId: "auth", label: "Auth/session checks" },
    ],
  };
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
    const scanMeta = isRecord(activeProject?.lastScan)
      ? activeProject.lastScan
      : null;
    return typeof scanMeta?.scanId === "string" ? scanMeta.scanId.trim() : "";
  })();
  const shouldStreamScanEvents = Boolean(activeProjectId && activeScanId);

  const [insightTab, setInsightTab] = useState<InsightTab>("checklist");
  const [isInsightFullscreen, setIsInsightFullscreen] = useState(false);
  const [streamLogs, setStreamLogs] = useState<DashboardLogEntry[]>([]);
  const [scanEvents, setScanEvents] = useState<ScanEventPayload[]>([]);
  const [locallyAckedApprovalId, setLocallyAckedApprovalId] = useState<string | null>(null);
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
  const [plannerApprovalLoading, setPlannerApprovalLoading] = useState(false);
  const [toolApprovalLoading, setToolApprovalLoading] = useState<"approve" | "skip" | null>(null);
  const [checklistActionKey, setChecklistActionKey] = useState<string | null>(
    null,
  );
  const [checklistError, setChecklistError] = useState("");
  const [addItemName, setAddItemName] = useState("");
  const [addItemPhase, setAddItemPhase] = useState("0");
  const [addItemPriority, setAddItemPriority] = useState(3);
  const [isAddEditorOpen, setIsAddEditorOpen] = useState(false);
  const [editingRowKey, setEditingRowKey] = useState<string | null>(null);
  const [editItemName, setEditItemName] = useState("");
  const [editItemPriority, setEditItemPriority] = useState(3);
  const [projectEditOpen, setProjectEditOpen] = useState(false);
  const [projectEditName, setProjectEditName] = useState("");
  const [projectEditTarget, setProjectEditTarget] = useState("");
  const [projectEditDescription, setProjectEditDescription] = useState("");
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);
  const dashboardSelectClass =
    "h-7 rounded-md border border-border bg-surface-1 px-2 py-1 text-sm text-text-primary outline-none transition-colors focus:border-pf-500/50 dark:[color-scheme:dark]";

  const handleCloseProject = () => {
    setActive(null);
    navigate("/projects");
  };

  const handleOpenProjectEdit = () => {
    if (!activeProject) {
      return;
    }
    setProjectEditName(activeProject.name);
    setProjectEditTarget(activeProject.target);
    setProjectEditDescription(activeProject.description ?? "");
    setProjectEditOpen(true);
  };

  const handleSaveProjectEdit = () => {
    if (!activeProject) {
      return;
    }
    updateProject(activeProject.id, {
      name: projectEditName.trim() || activeProject.name,
      target: projectEditTarget.trim() || activeProject.target,
      description: projectEditDescription.trim(),
    });
    setProjectEditOpen(false);
  };

  const ingestScanEvent = useCallback(
    (event: ScanEventPayload) => {
      if (!activeProjectId) {
        return;
      }
      const key = eventDedupKey(event);
      if (seenEventKeysRef.current.has(key)) {
        return;
      }
      seenEventKeysRef.current.add(key);
      if (seenEventKeysRef.current.size > 6000) {
        const pruned = new Set(
          Array.from(seenEventKeysRef.current).slice(-3000),
        );
        seenEventKeysRef.current = pruned;
      }

      setScanEvents((previous) => {
        const next = [event, ...previous];
        next.sort(
          (a, b) =>
            new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
        );
        return next.slice(0, 400);
      });

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
      const nextProgress =
        typeof rawProgress === "number" && Number.isFinite(rawProgress)
          ? rawProgress
          : undefined;

      if (nextStatus || typeof nextProgress === "number") {
        updateProject(
          activeProjectId,
          {
            ...(nextStatus ? { status: nextStatus } : {}),
            ...(typeof nextProgress === "number"
              ? { scanProgress: nextProgress }
              : {}),
          },
          { persist: false },
        );
      }

      if (
        event.event === "scan_completed" ||
        event.event === "scan_failed" ||
        event.event === "intel_complete"
      ) {
        void hydrateFromDatabase();
      }
    },
    [activeProjectId, updateProject, hydrateFromDatabase],
  );

  useEffect(() => {
    if (!activeProjectId) {
      setStreamLogs([]);
      setScanEvents([]);
      setLocallyAckedApprovalId(null);
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
    setLocallyAckedApprovalId(null);
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
  }, [
    activeProjectId,
    shouldStreamScanEvents,
    ingestScanEvent,
    hydrateFromDatabase,
    streamRetry,
  ]);

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
        const recent = await listProjectScanEventsFromDesktop(
          activeProjectId,
          220,
        );
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

  // Handle Escape key to exit fullscreen mode
  useEffect(() => {
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key !== "Escape") {
        return;
      }
      if (isCopilotOpen) {
        setIsCopilotOpen(false);
        return;
      }
      if (isInsightFullscreen) {
        setIsInsightFullscreen(false);
      }
    };
    window.addEventListener("keydown", handleEscape);
    return () => window.removeEventListener("keydown", handleEscape);
  }, [isInsightFullscreen, isCopilotOpen]);

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
    (project) =>
      project.id !== activeProject.id &&
      normalizeRunningStatus(project) === "running",
  );
  const canRun = !isRunning && !isStarting && !hasAnotherRunningProject;
  const awaitingPlannerApproval = (() => {
    for (const event of scanEvents) {
      if (event.event === "planner_waiting_approval") {
        return true;
      }
      if (
        event.event === "planner_approval_received" ||
        event.event === "planner_started" ||
        event.event === "planner_complete" ||
        event.event === "planner_failed" ||
        event.event === "planner_crashed" ||
        event.event === "scan_completed" ||
        event.event === "scan_failed" ||
        event.event === "scan_paused" ||
        event.event === "scan_cancelled"
      ) {
        return false;
      }
    }

    const lastScan = isRecord(activeProject.lastScan)
      ? activeProject.lastScan
      : null;
    const waitingFlag = lastScan?.awaitingPlannerApproval;
    if (typeof waitingFlag === "boolean") {
      return waitingFlag;
    }
    return lastScan?.status === "awaiting_planner_approval";
  })();

  const pendingToolApproval: PendingToolApprovalView | null = (() => {
    for (const event of scanEvents) {
      if (event.event === "executer_tool_waiting_approval") {
        const data = event.data;
        const candidate = {
          approvalId: typeof data.approval_id === "string" ? data.approval_id : "",
          role: typeof data.role === "string" ? data.role : "",
          toolName: typeof data.tool_name === "string" ? data.tool_name : "",
          callId: typeof data.call_id === "string" ? data.call_id : "",
          args: isRecord(data.args) ? data.args : {},
        };
        if (
          candidate.approvalId &&
          locallyAckedApprovalId &&
          candidate.approvalId === locallyAckedApprovalId
        ) {
          return null;
        }
        return candidate;
      }
      if (
        event.event === "executer_tool_approval_decision" ||
        event.event === "scan_completed" ||
        event.event === "scan_failed" ||
        event.event === "scan_paused" ||
        event.event === "scan_cancelled"
      ) {
        return null;
      }
    }

    const lastScan = isRecord(activeProject.lastScan)
      ? activeProject.lastScan
      : null;
    const waitingFlag = lastScan?.awaitingToolApproval;
    const pending = isRecord(lastScan?.pendingToolApproval)
      ? lastScan.pendingToolApproval
      : null;
    if (waitingFlag === true && pending) {
      const candidate = {
        approvalId: typeof pending.approval_id === "string" ? pending.approval_id : "",
        role: typeof pending.role === "string" ? pending.role : "",
        toolName: typeof pending.tool_name === "string" ? pending.tool_name : "",
        callId: typeof pending.call_id === "string" ? pending.call_id : "",
        args: isRecord(pending.args) ? pending.args : {},
      };
      if (
        candidate.approvalId &&
        locallyAckedApprovalId &&
        candidate.approvalId === locallyAckedApprovalId
      ) {
        return null;
      }
      return candidate;
    }
    return null;
  })();
  const pendingToolCommandPreview = buildPendingApprovalCommand(pendingToolApproval);

  const handleApprovePlanner = async () => {
    if (!activeProjectId || plannerApprovalLoading || !isRunning) {
      return;
    }
    setPlannerApprovalLoading(true);
    try {
      await approvePlannerForProjectScanFromDesktop(activeProjectId);
      setChecklistError("");
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Failed to approve planner start.";
      setStreamLogs((previous) => {
        const nextEntry: DashboardLogEntry = {
          id: `planner-approve-error-${Math.random().toString(36).slice(2, 10)}`,
          level: "warn",
          message: `Planner approval failed: ${message}`,
          at: new Date().toISOString(),
          source: "planner",
        };
        return [...previous, nextEntry].slice(-120);
      });
    } finally {
      setPlannerApprovalLoading(false);
    }
  };

  const handleToolApproval = async (action: "approve" | "skip") => {
    if (!activeProjectId || !isRunning || !pendingToolApproval?.approvalId || toolApprovalLoading) {
      return;
    }
    const approvalId = pendingToolApproval.approvalId;
    setLocallyAckedApprovalId(approvalId);
    setToolApprovalLoading(action);
    try {
      await approveToolForProjectScanFromDesktop(activeProjectId, {
        approvalId,
        action,
      });
    } catch (error) {
      setLocallyAckedApprovalId(null);
      let message = "Failed to submit tool approval.";
      if (error instanceof Error) {
        message =
          error.name === "AbortError"
            ? "Approval request timed out while waiting for server response."
            : error.message;
      }
      setStreamLogs((previous) => {
        const nextEntry: DashboardLogEntry = {
          id: `tool-approve-error-${Math.random().toString(36).slice(2, 10)}`,
          level: "warn",
          message: `Tool approval failed: ${message}`,
          at: new Date().toISOString(),
          source: "executer",
        };
        return [...previous, nextEntry].slice(-120);
      });
    } finally {
      setToolApprovalLoading(null);
    }
  };

  const fallbackLogs: DashboardLogEntry[] = [];
  const baseTimestamp = activeProject.updatedAt || new Date().toISOString();
  const fallbackLastScan = isRecord(activeProject.lastScan)
    ? activeProject.lastScan
    : null;
  const fallbackLastScanError =
    typeof fallbackLastScan?.error === "string"
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
      at:
        typeof fallbackLastScan?.finishedAt === "string" &&
          fallbackLastScan.finishedAt
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
  const baseLogs =
    streamLogs.length > 0
      ? streamLogs
      : fallbackLogs
        .sort((a, b) => new Date(a.at).getTime() - new Date(b.at).getTime())
        .slice(-14);
  const sourceOptions = Array.from(
    new Set(baseLogs.map((entry) => entry.source)),
  );
  const displayedLogs = baseLogs.filter((entry) => {
    if (logLevelFilter !== "all" && entry.level !== logLevelFilter) {
      return false;
    }
    if (logSourceFilter !== "all" && entry.source !== logSourceFilter) {
      return false;
    }
    return true;
  });
  const realtimeVulnFindings: RealtimeVulnFinding[] = (() => {
    const feed: RealtimeVulnFinding[] = [];

    for (const finding of activeProject.findings) {
      feed.push({
        id: `finding-${finding.id}`,
        title: finding.title,
        severity: finding.severity,
        source: "finding",
        at: finding.timestamp,
      });
    }

    for (const event of scanEvents) {
      if (isOperationalToolEvent(event)) {
        continue;
      }
      const source = detectLogSource(event);
      const text = `${event.event} ${event.message}`.toLowerCase();
      const isFailureEvent =
        event.event.toLowerCase().includes("failed") ||
        event.event.toLowerCase().includes("crashed");
      const looksSecurityRelevant =
        isFailureEvent ||
        text.includes("vuln") ||
        text.includes("finding") ||
        text.includes("exploit") ||
        text.includes("injection") ||
        text.includes("xss") ||
        text.includes("sqli") ||
        text.includes("ssrf") ||
        text.includes("idor") ||
        text.includes("misconfig");
      const isSystemFailureSignal =
        source === "system" && (text.includes("scan failed") || isFailureEvent);
      if (!looksSecurityRelevant && !isSystemFailureSignal) {
        continue;
      }
      if (
        !isFailureEvent &&
        source === "system" &&
        !text.includes("scan failed")
      ) {
        continue;
      }
      feed.push({
        id: `event-${eventDedupKey(event)}`,
        title: event.message,
        severity: inferEventSeverity(event),
        source,
        at: event.timestamp,
      });
    }

    const deduped = new Map<string, RealtimeVulnFinding>();
    for (const item of feed) {
      const key = `${item.title.toLowerCase()}|${item.at}`;
      if (!deduped.has(key)) {
        deduped.set(key, item);
      }
    }

    return Array.from(deduped.values())
      .sort((a, b) => {
        const severityDiff = severityRank(b.severity) - severityRank(a.severity);
        if (severityDiff !== 0) {
          return severityDiff;
        }
        return new Date(b.at).getTime() - new Date(a.at).getTime();
      })
      .slice(0, 24);
  })();

  const handleLogsScroll = () => {
    const container = logsContainerRef.current;
    if (!container) {
      return;
    }
    const distanceToBottom =
      container.scrollHeight - container.scrollTop - container.clientHeight;
    const nearBottom = distanceToBottom <= 24;
    if (nearBottom !== autoScrollLogs) {
      setAutoScrollLogs(nearBottom);
    }
  };

  const resolvedPlannerResult = (() => {
    let plannerError = "";
    for (const event of scanEvents) {
      if (!isRecord(event.data)) {
        continue;
      }
      if (event.event === "planner_complete") {
        return {
          summary: normalizeText(event.data.summary),
          needs: event.data.needs,
          planData: event.data.plan_data,
          status: "completed",
          error: "",
        };
      }
      if (
        !plannerError &&
        (event.event === "planner_failed" || event.event === "planner_crashed")
      ) {
        plannerError =
          normalizeText(event.data.error) || normalizeText(event.data.summary);
      }
    }

    const lastScan = isRecord(activeProject.lastScan)
      ? activeProject.lastScan
      : null;
    const result = isRecord(lastScan?.result) ? lastScan.result : null;
    const planner = isRecord(result?.planner) ? result.planner : null;
    return {
      summary: normalizeText(planner?.summary),
      needs: planner?.needs,
      planData: planner?.plan_data,
      status: normalizeText(lastScan?.status),
      error: plannerError || normalizeText(lastScan?.error),
    };
  })();
  const plannerResultText = buildPlannerInsightText(
    resolvedPlannerResult.summary,
    resolvedPlannerResult.planData,
    resolvedPlannerResult.needs,
  );
  const plannerPlanView = toPlannerPlanView(resolvedPlannerResult.planData);
  const architectureDraft = buildTargetArchitectureDraft(
    activeProject.targetType,
    activeProject.target,
  );
  const architectureHostMap = new Map(
    architectureDraft.hosts.map((host) => [host.id, host]),
  );
  const architectureEdges = architectureDraft.flows
    .map((flow) => {
      const from = architectureHostMap.get(flow.fromId);
      const to = architectureHostMap.get(flow.toId);
      if (!from || !to) {
        return null;
      }
      return { from, to, label: flow.label };
    })
    .filter(
      (
        edge,
      ): edge is {
        from: ArchitectureHost;
        to: ArchitectureHost;
        label: string;
      } => edge !== null,
    );

  const resolvedChecklist = (() => {
    for (const event of scanEvents) {
      if (event.event !== "intel_complete" || !isRecord(event.data)) {
        continue;
      }
      const structured = toStructuredChecklist(event.data.checklist);
      if (structured) {
        return structured;
      }
      const summary =
        typeof event.data.summary === "string" ? event.data.summary.trim() : "";
      const summaryFallback = checklistFromLabels(
        extractChecklistLabels(summary),
        activeProject.targetType,
      );
      if (summaryFallback) {
        return summaryFallback;
      }
    }

    const lastScan = isRecord(activeProject.lastScan)
      ? activeProject.lastScan
      : null;
    const result = isRecord(lastScan?.result) ? lastScan.result : null;
    const intel = isRecord(result?.intel) ? result.intel : null;
    const persisted = toStructuredChecklist(intel?.checklist);
    if (persisted) {
      return persisted;
    }

    const persistedSummary =
      typeof intel?.summary === "string" ? intel.summary.trim() : "";
    return checklistFromLabels(
      extractChecklistLabels(persistedSummary),
      activeProject.targetType,
    );
  })();
  const displayChecklist = resolvedChecklist
    ? cloneStructuredChecklist(resolvedChecklist)
    : null;

  const persistChecklist = async (
    nextChecklist: StructuredChecklistPayload,
    actionKey: string,
  ): Promise<boolean> => {
    if (checklistActionKey) {
      return false;
    }
    if (!activeProject) {
      return false;
    }
    setChecklistActionKey(actionKey);
    setChecklistError("");
    const nowIso = new Date().toISOString();
    const lastScan = isRecord(activeProject.lastScan)
      ? activeProject.lastScan
      : {};
    const result = isRecord(lastScan.result) ? lastScan.result : {};
    const intel = isRecord(result.intel) ? result.intel : {};
    const nextLastScan = {
      ...lastScan,
      result: {
        ...result,
        intel: {
          ...intel,
          checklist: nextChecklist as unknown as Record<string, unknown>,
        },
      },
    };

    updateProject(
      activeProject.id,
      {
        lastScan: nextLastScan,
        updatedAt: nowIso,
      },
      { persist: false },
    );

    try {
      const currentProject =
        useProjects
          .getState()
          .projects.find((project) => project.id === activeProject.id) ??
        activeProject;
      await saveProjectToDesktop({
        ...currentProject,
        lastScan: nextLastScan,
        updatedAt: nowIso,
      });
      await hydrateFromDatabase();
      return true;
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Failed to save checklist changes.";
      setChecklistError(message);
      await hydrateFromDatabase();
      return false;
    } finally {
      setChecklistActionKey(null);
    }
  };

  const handleAddChecklistItem = async () => {
    if (checklistActionKey || !activeProject) {
      return;
    }
    const name = addItemName.trim();
    if (!name) {
      setChecklistError("Item name is required.");
      return;
    }

    const nextChecklist = displayChecklist
      ? cloneStructuredChecklist(displayChecklist)
      : {
        target_type: activeProject.targetType,
        available_total: 0,
        checklist: [],
      };
    const duplicate = nextChecklist.checklist.some((block) =>
      block.items.some(
        (item) => item.name.trim().toLowerCase() === name.toLowerCase(),
      ),
    );
    if (duplicate) {
      setChecklistError("Checklist item already exists.");
      return;
    }

    if (nextChecklist.checklist.length === 0) {
      nextChecklist.checklist.push({
        phase: "4",
        title: "Authentication, Authorization & Injection Testing",
        items: [],
      });
    }

    const selectedIndex = Number.parseInt(addItemPhase, 10);
    const blockIndex =
      Number.isInteger(selectedIndex) &&
        selectedIndex >= 0 &&
        selectedIndex < nextChecklist.checklist.length
        ? selectedIndex
        : 0;

    nextChecklist.checklist[blockIndex].items.push({
      name,
      priority: addItemPriority,
    });
    nextChecklist.available_total = nextChecklist.checklist.reduce(
      (count, block) => count + block.items.length,
      0,
    );

    const saved = await persistChecklist(nextChecklist, "checklist-add");
    if (saved) {
      setAddItemName("");
      setAddItemPriority(3);
      setChecklistError("");
      setIsAddEditorOpen(false);
    }
  };

  const handleRemoveChecklistItem = async (
    blockIndex: number,
    itemIndex: number,
  ) => {
    if (!displayChecklist || checklistActionKey) {
      return;
    }
    const nextChecklist = cloneStructuredChecklist(displayChecklist);
    const block = nextChecklist.checklist[blockIndex];
    if (!block) {
      return;
    }
    block.items = block.items.filter((_, index) => index !== itemIndex);
    nextChecklist.checklist = nextChecklist.checklist.filter(
      (entry) => entry.items.length > 0,
    );
    nextChecklist.available_total = nextChecklist.checklist.reduce(
      (count, entry) => count + entry.items.length,
      0,
    );

    const saved = await persistChecklist(
      nextChecklist,
      `checklist-remove-${blockIndex}-${itemIndex}`,
    );
    if (saved) {
      setChecklistError("");
      setEditingRowKey(null);
    }
  };

  const handleUpdateChecklistItem = async (
    blockIndex: number,
    itemIndex: number,
    rowKey: string,
  ) => {
    if (!displayChecklist || checklistActionKey) {
      return;
    }
    const normalizedName = editItemName.trim();
    if (!normalizedName) {
      setChecklistError("Item name is required.");
      return;
    }

    const nextChecklist = cloneStructuredChecklist(displayChecklist);
    const block = nextChecklist.checklist[blockIndex];
    if (!block || !block.items[itemIndex]) {
      return;
    }

    const duplicate = nextChecklist.checklist.some(
      (checklistBlock, blockCursor) =>
        checklistBlock.items.some(
          (item, itemCursor) =>
            !(blockCursor === blockIndex && itemCursor === itemIndex) &&
            item.name.trim().toLowerCase() === normalizedName.toLowerCase(),
        ),
    );
    if (duplicate) {
      setChecklistError("Checklist item already exists.");
      return;
    }

    block.items[itemIndex] = {
      name: normalizedName,
      priority: editItemPriority,
    };
    const saved = await persistChecklist(
      nextChecklist,
      `checklist-update-${blockIndex}-${itemIndex}`,
    );
    if (saved) {
      setChecklistError("");
      setEditingRowKey((current) => (current === rowKey ? null : current));
    }
  };

  const checklistBlocks = displayChecklist?.checklist ?? [];
  const isChecklistSaving = checklistActionKey !== null;
  const selectedAddPhase = (() => {
    if (checklistBlocks.length === 0) {
      return "0";
    }
    const parsed = Number.parseInt(addItemPhase, 10);
    if (
      !Number.isInteger(parsed) ||
      parsed < 0 ||
      parsed >= checklistBlocks.length
    ) {
      return "0";
    }
    return String(parsed);
  })();

  const agentInsights = (() => {
    const byRole = Object.fromEntries(
      AGENT_ROLES.map((role) => [
        role,
        { history: [] as AgentInsightPanelData["history"] },
      ]),
    ) as Record<AgentGraphRole, AgentInsightPanelData>;

    const scanMeta = isRecord(activeProject.lastScan)
      ? activeProject.lastScan
      : null;
    const currentScanId =
      typeof scanMeta?.scanId === "string" ? scanMeta.scanId.trim() : "";
    const allEvents = [...scanEvents];
    const latestStartedScanId =
      allEvents.find(
        (event) =>
          event.event === "scan_started" && event.scan_id.trim().length > 0,
      )?.scan_id ?? "";
    const latestAnyScanId =
      allEvents.find((event) => event.scan_id.trim().length > 0)?.scan_id ?? "";

    // Prefer the active running scan id from events if metadata is stale.
    let scopedScanId = currentScanId;
    if (
      effectiveStatus === "running" &&
      latestStartedScanId &&
      latestStartedScanId !== currentScanId
    ) {
      scopedScanId = latestStartedScanId;
    }
    if (!scopedScanId) {
      scopedScanId = latestStartedScanId || latestAnyScanId;
    }

    const scopedEvents = scopedScanId
      ? allEvents.filter(
        (event) =>
          event.scan_id === scopedScanId ||
          event.event === "scan_status_snapshot",
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
        const summaryCandidate =
          typeof event.data.summary === "string"
            ? event.data.summary.trim()
            : "";
        const checklistInsight = buildChecklistInsightText(
          event.data.checklist,
        );
        if (summaryCandidate.length > 0) {
          intelSummary = checklistInsight
            ? `${summaryCandidate}\n\n${checklistInsight}`
            : summaryCandidate;
          intelStatus =
            typeof event.data.intel_status === "string"
              ? event.data.intel_status.trim()
              : "complete";
          break;
        }
        if (checklistInsight.length > 0) {
          intelSummary = checklistInsight;
          intelStatus =
            typeof event.data.intel_status === "string"
              ? event.data.intel_status.trim()
              : "complete";
          break;
        }
      }

      if (
        !intelError &&
        (event.event === "intel_crashed" || event.event === "scan_failed")
      ) {
        const errorCandidate =
          typeof event.data.error === "string" ? event.data.error.trim() : "";
        if (errorCandidate.length > 0) {
          intelError = errorCandidate;
        }
      }
    }

    if (intelSummary.length === 0) {
      const persistedLastScan = isRecord(activeProject.lastScan)
        ? activeProject.lastScan
        : null;
      const persistedResult = isRecord(persistedLastScan?.result)
        ? persistedLastScan.result
        : null;
      const persistedIntel = isRecord(persistedResult?.intel)
        ? persistedResult.intel
        : null;
      const persistedSummary =
        typeof persistedIntel?.summary === "string"
          ? persistedIntel.summary.trim()
          : "";
      const persistedChecklistInsight = buildChecklistInsightText(
        persistedIntel?.checklist,
      );
      if (persistedSummary || persistedChecklistInsight) {
        intelSummary =
          persistedSummary && persistedChecklistInsight
            ? `${persistedSummary}\n\n${persistedChecklistInsight}`
            : persistedSummary || persistedChecklistInsight;
        intelStatus =
          typeof persistedIntel?.status === "string"
            ? persistedIntel.status.trim()
            : typeof persistedLastScan?.status === "string"
              ? persistedLastScan.status.trim()
              : "";
      }
    }

    if (intelSummary.length > 0) {
      byRole.intel.resultLabel = intelStatus
        ? `Intel Final Result (${intelStatus})`
        : "Intel Final Result";
      byRole.intel.result = intelSummary;
    } else if (intelError.length > 0) {
      byRole.intel.resultLabel = "Intel Error";
      byRole.intel.result = intelError;
    }

    if (plannerResultText.length > 0) {
      const plannerStatus = resolvedPlannerResult.status || "completed";
      byRole.planner.resultLabel = `Planner Final Result (${plannerStatus})`;
      byRole.planner.result = plannerResultText;
    } else if (resolvedPlannerResult.error.length > 0) {
      byRole.planner.resultLabel = "Planner Error";
      byRole.planner.result = resolvedPlannerResult.error;
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
              <Badge variant={effectiveStatus} dot>
                {effectiveStatus}
              </Badge>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {!isRunning ? (
              <Button
                size="xs"
                onClick={() => {
                  if (effectiveStatus === "completed") {
                    const confirmed = window.confirm(
                      "This scan already completed. Start a new scan and clear previous results?",
                    );
                    if (!confirmed) {
                      return;
                    }
                    setStreamLogs([]);
                    setScanEvents([]);
                    setRunning(activeProject.id, {
                      triggerScan: true,
                      force: true,
                    });
                    return;
                  }
                  if (effectiveStatus === "paused") {
                    const confirmed = window.confirm(
                      "Resume will start a new scan and keep previous history visible. Continue?",
                    );
                    if (!confirmed) {
                      return;
                    }
                    setRunning(activeProject.id, {
                      triggerScan: true,
                      resume: true,
                    });
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
                {awaitingPlannerApproval ? (
                  <Button
                    size="xs"
                    variant="secondary"
                    onClick={() => {
                      void handleApprovePlanner();
                    }}
                    loading={plannerApprovalLoading}
                    title="Approve checklist and continue to Planner"
                  >
                    <Check size={12} />
                    Continue to Planner
                  </Button>
                ) : null}
                {pendingToolApproval ? (
                  <>
                    <Button
                      size="xs"
                      variant="primary"
                      onClick={() => {
                        void handleToolApproval("approve");
                      }}
                      loading={toolApprovalLoading === "approve"}
                      title={`Approve ${pendingToolCommandPreview} (${pendingToolApproval.role})`}
                    >
                      <Check size={12} />
                      Approve Tool
                    </Button>
                    <Button
                      size="xs"
                      variant="secondary"
                      onClick={() => {
                        void handleToolApproval("skip");
                      }}
                      loading={toolApprovalLoading === "skip"}
                      title={`Skip ${pendingToolCommandPreview} (${pendingToolApproval.role})`}
                    >
                      <X size={12} />
                      Skip Tool
                    </Button>
                  </>
                ) : null}
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
              </div>
            )}
            {isStarting && (
              <span className="text-sm text-text-muted">
                Starting scan...
              </span>
            )}
            <Button
              size="xs"
              variant="secondary"
              onClick={() => navigate("/projects")}
            >
              <Repeat2 size={12} />
              Change
            </Button>
            <Button size="xs" variant="ghost" onClick={handleCloseProject}>
              <X size={12} />
              Close
            </Button>
          </div>
        </div>
      </div>

      <Card className="space-y-2 p-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-text-primary">
            Target Overview
          </h2>
          <div className="flex items-center gap-2">
            <Button
              size="xs"
              variant="secondary"
              onClick={handleOpenProjectEdit}
              title="Edit project details"
            >
              <Pencil size={12} />
              Edit
            </Button>
            <span className="inline-flex items-center gap-1 text-xs text-text-muted">
              <Clock3 size={12} />
              Updated {formatDateTime(activeProject.updatedAt)}
            </span>
          </div>
        </div>

        <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-md bg-surface-0/40 p-1.5">
            <p className="text-xs text-text-muted">Target</p>
            <p className="mt-0.5 break-all font-mono text-xs text-text-primary">
              {activeProject.target}
            </p>
          </div>
          <div className="rounded-md bg-surface-0/40 p-1.5">
            <p className="text-xs text-text-muted">Target Type</p>
            <p className="mt-0.5 text-xs text-text-primary">
              {activeProject.targetType.replaceAll("_", " ")}
            </p>
          </div>
          <div className="rounded-md bg-surface-0/40 p-1.5">
            <p className="text-xs text-text-muted">Created</p>
            <p className="mt-0.5 text-xs text-text-primary">
              {formatDateTime(activeProject.createdAt)}
            </p>
          </div>
          <div className="rounded-md bg-surface-0/40 p-1.5">
            <p className="text-xs text-text-muted">Status</p>
            <p className="mt-0.5 text-xs text-text-primary">
              {effectiveStatus}
            </p>
          </div>
        </div>

        <div className="rounded-md border border-border bg-surface-0/35 p-2">
          <div className="mb-2 flex items-center justify-between">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-text-secondary">
              Scan Progress
            </h3>
            <span className="text-xs font-mono text-pf-400">
              {activeProject.scanProgress}%
            </span>
          </div>

          <div className="mb-2 h-1.5 overflow-hidden rounded-full bg-surface-2">
            <div
              className="h-full rounded-full bg-pf-600 transition-all duration-500"
              style={{ width: `${activeProject.scanProgress}%` }}
            />
          </div>
        </div>
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card className="flex h-[560px] flex-col space-y-3 p-3">
          <div className="flex items-center justify-between">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-base font-semibold text-text-primary">
                Real-Time Logs
              </h2>

              <select
                value={logLevelFilter}
                onChange={(event) =>
                  setLogLevelFilter(event.target.value as "all" | LogLevel)
                }
                className="rounded-md border border-border bg-surface-1 px-2 py-1 text-sm text-text-primary outline-none transition-colors focus:border-pf-500/50 dark:[color-scheme:dark]"
                title="Filter by level"
              >
                <option
                  value="all"
                  style={{
                    backgroundColor: "var(--surface-1)",
                    color: "var(--text-primary)",
                  }}
                >
                  All Levels
                </option>
                <option
                  value="info"
                  style={{
                    backgroundColor: "var(--surface-1)",
                    color: "var(--text-primary)",
                  }}
                >
                  Info
                </option>
                <option
                  value="success"
                  style={{
                    backgroundColor: "var(--surface-1)",
                    color: "var(--text-primary)",
                  }}
                >
                  Success
                </option>
                <option
                  value="warn"
                  style={{
                    backgroundColor: "var(--surface-1)",
                    color: "var(--text-primary)",
                  }}
                >
                  Warn
                </option>
                <option
                  value="error"
                  style={{
                    backgroundColor: "var(--surface-1)",
                    color: "var(--text-primary)",
                  }}
                >
                  Error
                </option>
              </select>

              <select
                value={logSourceFilter}
                onChange={(event) => setLogSourceFilter(event.target.value)}
                className="rounded-md border border-border bg-surface-1 px-2 py-1 text-sm text-text-primary outline-none transition-colors focus:border-pf-500/50 dark:[color-scheme:dark]"
                title="Filter by source"
              >
                <option
                  value="all"
                  style={{
                    backgroundColor: "var(--surface-1)",
                    color: "var(--text-primary)",
                  }}
                >
                  All Sources
                </option>
                {sourceOptions.map((source) => (
                  <option
                    key={source}
                    value={source}
                    style={{
                      backgroundColor: "var(--surface-1)",
                      color: "var(--text-primary)",
                    }}
                  >
                    {formatSourceLabel(source)}
                  </option>
                ))}
              </select>
            </div>
            <div className="text-right">
              <p className="text-sm text-text-muted">
                {displayedLogs.length}/{baseLogs.length} events
              </p>
            </div>
          </div>
          <div
            ref={logsContainerRef}
            onScroll={handleLogsScroll}
            className="min-h-0 flex-1 space-y-1 overflow-y-auto rounded-md border border-border bg-surface-0/35 p-2"
          >
            {displayedLogs.length === 0 ? (
              <p className="px-1 py-2 text-sm text-text-muted">
                No logs match current filters.
              </p>
            ) : (
              displayedLogs.map((entry) => (
                <div
                  key={entry.id}
                  className="grid grid-cols-[100px_1fr] gap-2 rounded px-1 py-1 text-sm"
                >
                  <span className="font-mono text-sm text-text-muted">
                    {formatTime(entry.at)}
                  </span>
                  <p
                    title={`[${entry.source}] ${entry.message}`}
                    className={
                      entry.level === "warn" || entry.level === "error"
                        ? "min-w-0 truncate whitespace-nowrap text-red-300"
                        : entry.level === "success"
                          ? "min-w-0 truncate whitespace-nowrap text-emerald-300"
                          : "min-w-0 truncate whitespace-nowrap text-text-secondary"
                    }
                  >
                    <span className="mr-1 text-sm uppercase tracking-wide text-text-muted">
                      [{entry.source}]
                    </span>
                    {entry.message}
                  </p>
                </div>
              ))
            )}
          </div>
          {awaitingPlannerApproval ? (
            <div className="flex justify-center pt-2">
              <Button
                size="sm"
                variant="primary"
                className="bg-blue-600 hover:bg-blue-700"
                onClick={() => {
                  void handleApprovePlanner();
                }}
                loading={plannerApprovalLoading}
                title="Approve checklist and continue to Planner"
              >
                <Check size={14} />
                Continue to Planner
              </Button>
            </div>
          ) : null}
          {pendingToolApproval ? (
            <div className="mt-2 flex flex-col items-center gap-2 pt-2">
              <p className="text-xs text-text-muted text-center">
                Executer requests approval: <span className="font-semibold">{pendingToolApproval.role}</span> →{" "}
                <span className="font-semibold break-all">{pendingToolCommandPreview}</span>
              </p>
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  variant="primary"
                  onClick={() => {
                    void handleToolApproval("approve");
                  }}
                  loading={toolApprovalLoading === "approve"}
                >
                  <Check size={14} />
                  Approve Tool
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => {
                    void handleToolApproval("skip");
                  }}
                  loading={toolApprovalLoading === "skip"}
                >
                  <X size={14} />
                  Skip Tool
                </Button>
              </div>
            </div>
          ) : null}
        </Card>

        <Card className="flex h-[560px] flex-col space-y-3 p-3">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-text-primary">
              Real-Time Vulnerability Findings
            </h2>
            <p className="text-sm text-text-muted">
              {realtimeVulnFindings.length} items
            </p>
          </div>
          <div className="min-h-0 flex-1 space-y-2 overflow-y-auto rounded-md border border-border bg-surface-0/35 p-2">
            {realtimeVulnFindings.length === 0 ? (
              <p className="px-1 py-2 text-sm text-text-muted">
                No vulnerability signals yet. Findings and risk-oriented events will appear here in real time.
              </p>
            ) : (
              realtimeVulnFindings.map((item) => (
                <div
                  key={item.id}
                  className="rounded-md border border-border bg-surface-1/45 p-2"
                >
                  <div className="mb-1 flex items-center justify-between gap-2">
                    <Badge
                      variant="default"
                      className={`border text-xs uppercase tracking-wide ${severityBadgeClass(item.severity)}`}
                    >
                      {item.severity}
                    </Badge>
                    <span className="text-xs text-text-muted">
                      {formatTime(item.at)}
                    </span>
                  </div>
                  <p className="text-sm text-text-primary">{item.title}</p>
                  <p className="mt-1 text-xs uppercase tracking-wide text-text-muted">
                    source: {formatSourceLabel(item.source)}
                  </p>
                </div>
              ))
            )}
          </div>
        </Card>
      </div>

      {/* Fullscreen overlay for Execution Notes */}
      {isInsightFullscreen && (
        <div
          className="fixed inset-0 z-50 bg-surface-0/95 backdrop-blur-sm"
          onClick={() => setIsInsightFullscreen(false)}
        />
      )}

      <div className={isInsightFullscreen ? "" : "grid gap-4 xl:grid-cols-[1.15fr_0.85fr]"}>
        <Card
          className={
            isInsightFullscreen
              ? "fixed inset-4 z-50 flex flex-col space-y-3 overflow-hidden p-4"
              : "flex h-[560px] flex-col space-y-3 p-3"
          }
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <h2 className={`font-semibold text-text-primary ${isInsightFullscreen ? "text-lg" : "text-base"}`}>
                Execution Notes
              </h2>
              {insightTab === "checklist" ? (
                <Button
                  size="icon"
                  variant="secondary"
                  onClick={() => {
                    setChecklistError("");
                    setIsAddEditorOpen((open) => !open);
                  }}
                  disabled={isChecklistSaving}
                  title={
                    isAddEditorOpen
                      ? "Close add item form"
                      : "Add checklist item"
                  }
                >
                  <Plus size={13} />
                </Button>
              ) : null}
            </div>
            <div className="flex items-center gap-2">
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
              <Button
                size="icon"
                variant="ghost"
                onClick={() => setIsInsightFullscreen((prev) => !prev)}
                title={isInsightFullscreen ? "Exit fullscreen (Esc)" : "Fullscreen"}
              >
                {isInsightFullscreen ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
              </Button>
            </div>
          </div>

          {insightTab === "plan" ? (
            <div className="min-h-0 flex-1 space-y-2 overflow-y-auto rounded-md border border-border bg-surface-0/35 p-2">
              {plannerPlanView?.phases?.length ? (
                <div className={`space-y-2 ${isInsightFullscreen ? "space-y-3" : ""}`}>
                  {plannerPlanView.phases.map((phase, phaseIndex) => (
                    <div
                      key={`${phase.phase}-${phaseIndex}`}
                      className="rounded-md border border-border bg-surface-1/45"
                    >
                      <div className={`flex items-center justify-between gap-2 border-b border-border ${isInsightFullscreen ? "px-3 py-2" : "px-2 py-1.5"}`}>
                        <p className={`font-semibold text-text-primary text-[15px]`}>
                          Phase {phaseIndex + 1}: {phase.phase}
                        </p>
                        <span className={`text-text-muted ${isInsightFullscreen ? "text-sm" : "text-xs"}`}>
                          {phase.steps.length} steps
                        </span>
                      </div>
                      <div className={`space-y-2 ${isInsightFullscreen ? "p-3 space-y-3" : "p-2"}`}>
                        {phase.steps.length === 0 ? (
                          <p className={`text-text-muted text-sm`}>
                            No steps yet.
                          </p>
                        ) : (
                          phase.steps.map((step, stepIndex) => (
                            <div
                              key={`${phase.phase}-${step.step}-${stepIndex}`}
                              className="rounded-md border border-border bg-surface-0/35"
                            >
                              <p className={`border-b border-border font-medium text-text-primary ${isInsightFullscreen ? "px-3 py-2 text-sm" : "px-2 py-1.5 text-sm"}`}>
                                {stepIndex + 1}. {step.step}
                              </p>
                              {step.scenarios.length === 0 ? (
                                <p className={`text-text-muted ${isInsightFullscreen ? "px-3 py-2 text-sm" : "px-2 py-1.5 text-sm"}`}>
                                  No scenarios yet.
                                </p>
                              ) : (
                                <div className="divide-y divide-border">
                                  {step.scenarios.map(
                                    (scenario, scenarioIndex) => (
                                      <div
                                        key={`${phase.phase}-${step.step}-scenario-${scenarioIndex}`}
                                        className={`flex items-center justify-between gap-2 ${isInsightFullscreen ? "px-3 py-2" : "px-2 py-1.5"}`}
                                      >
                                        <p className="text-text-secondary text-[13px]">
                                          {scenario.scenario}
                                        </p>
                                        <span className={`rounded border border-border bg-surface-1/55 px-1.5 py-0.5 text-text-muted text-xs`}>
                                          {scenario.agent}
                                        </span>
                                      </div>
                                    ),
                                  )}
                                </div>
                              )}
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className={`px-1 py-2 text-text-muted text-sm`}>
                  {isRunning
                    ? "Plan is loading. We will show planner phases as soon as they are persisted."
                    : "No planner result available yet."}
                </p>
              )}
            </div>
          ) : (
            <div className="min-h-0 flex-1 space-y-2 overflow-y-auto rounded-md border border-border bg-surface-0/35 p-2">
              {isAddEditorOpen ? (
                <div className="space-y-2 rounded-md border border-border bg-surface-1/50 p-2">
                  <div className="grid gap-2 lg:grid-cols-[1fr_auto_auto_auto]">
                    <input
                      value={addItemName}
                      onChange={(event) => setAddItemName(event.target.value)}
                      placeholder="New checklist item"
                      disabled={isChecklistSaving}
                      className="h-7 rounded-md border border-border bg-surface-0/60 px-2 text-sm text-text-primary outline-none focus:border-pf-500/50"
                    />
                    <select
                      value={selectedAddPhase}
                      onChange={(event) => setAddItemPhase(event.target.value)}
                      disabled={isChecklistSaving}
                      className={dashboardSelectClass}
                      title="Target phase"
                    >
                      {checklistBlocks.length === 0 ? (
                        <option
                          value="0"
                          style={{
                            backgroundColor: "var(--surface-1)",
                            color: "var(--text-primary)",
                          }}
                        >
                          Phase 4 - Authentication, Authorization & Injection Testing
                        </option>
                      ) : (
                        checklistBlocks.map((block, blockIndex) => (
                          <option
                            key={`${block.phase}-${block.title}-${blockIndex}`}
                            value={String(blockIndex)}
                            style={{
                              backgroundColor: "var(--surface-1)",
                              color: "var(--text-primary)",
                            }}
                          >
                            {block.phase ? `Phase ${block.phase}` : "Phase"} -{" "}
                            {block.title}
                          </option>
                        ))
                      )}
                    </select>
                    <select
                      value={String(addItemPriority)}
                      onChange={(event) => {
                        const next = Number.parseInt(event.target.value, 10);
                        setAddItemPriority(Number.isInteger(next) ? next : 3);
                      }}
                      disabled={isChecklistSaving}
                      className={dashboardSelectClass}
                      title="Severity"
                    >
                      {[1, 2, 3, 4, 5].map((priority) => (
                        <option
                          key={priority}
                          value={String(priority)}
                          style={{
                            backgroundColor: "var(--surface-1)",
                            color: "var(--text-primary)",
                          }}
                        >
                          S{priority}
                        </option>
                      ))}
                    </select>
                    <div className="flex items-center justify-end gap-1">
                      <Button
                        size="icon"
                        variant="secondary"
                        onClick={() => {
                          void handleAddChecklistItem();
                        }}
                        loading={checklistActionKey === "checklist-add"}
                        disabled={
                          isChecklistSaving || addItemName.trim().length === 0
                        }
                        title="Save new item"
                      >
                        <Check size={13} />
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => {
                          setIsAddEditorOpen(false);
                          setChecklistError("");
                        }}
                        disabled={isChecklistSaving}
                        title="Cancel"
                      >
                        <X size={13} />
                      </Button>
                    </div>
                  </div>
                </div>
              ) : null}

              {checklistBlocks.length === 0 ? (
                <p className={`px-1 py-2 text-text-muted ${isInsightFullscreen ? "text-sm" : "text-xs"}`}>
                  {isRunning
                    ? "Checklist is generating and will appear after Intel finalizes set_checklist."
                    : "No checklist generated yet."}
                </p>
              ) : (
                checklistBlocks.map((block, blockIndex) => (
                  <div
                    key={`${block.phase}-${block.title}-${blockIndex}`}
                    className={`rounded-md border border-border bg-surface-1/45 ${isInsightFullscreen ? "space-y-3 p-3" : "space-y-2 p-2"}`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-[15px] font-semibold leading-5 text-text-primary">
                        {block.phase ? `Phase ${block.phase}` : "Phase"} -{" "}
                        {block.title}
                      </p>
                      <span className={`text-text-muted ${isInsightFullscreen ? "text-sm" : "text-xs"}`}>
                        {block.items.length} items
                      </span>
                    </div>
                    <div className={isInsightFullscreen ? "space-y-2" : "space-y-1.5"}>
                      {block.items.map((item, itemIndex) => {
                        const rowKey = `${blockIndex}:${itemIndex}`;
                        const updateActionKey = `checklist-update-${blockIndex}-${itemIndex}`;
                        const removeActionKey = `checklist-remove-${blockIndex}-${itemIndex}`;
                        const isEditingThisRow = editingRowKey === rowKey;
                        return (
                          <div
                            key={rowKey}
                            className={`space-y-2 rounded-md border border-border bg-surface-0/35 text-sm ${isInsightFullscreen ? "px-3 py-2" : "px-2 py-1.5"}`}
                          >
                            <div className="flex flex-wrap items-center gap-2">
                              <p className={`flex-1 text-text-secondary ${isInsightFullscreen ? "min-w-[280px]" : "min-w-[220px]"}`}>
                                {item.name}
                              </p>
                              <span className={`rounded-md border border-border bg-surface-1/55 px-1.5 py-0.5 text-text-muted ${isInsightFullscreen ? "text-xs" : "text-xs"}`}>
                                S{item.priority}
                              </span>
                              <Button
                                size="icon"
                                variant="secondary"
                                onClick={() => {
                                  if (isEditingThisRow) {
                                    setEditingRowKey(null);
                                    setChecklistError("");
                                    return;
                                  }
                                  setChecklistError("");
                                  setEditingRowKey(rowKey);
                                  setEditItemName(item.name);
                                  setEditItemPriority(item.priority);
                                }}
                                disabled={isChecklistSaving}
                                title="Edit item"
                              >
                                <Pencil size={isInsightFullscreen ? 15 : 13} />
                              </Button>
                              <Button
                                size="icon"
                                variant="secondary"
                                onClick={() => {
                                  void handleRemoveChecklistItem(
                                    blockIndex,
                                    itemIndex,
                                  );
                                }}
                                loading={checklistActionKey === removeActionKey}
                                disabled={isChecklistSaving}
                                title="Remove item"
                              >
                                <Trash2 size={isInsightFullscreen ? 15 : 13} />
                              </Button>
                            </div>
                            {isEditingThisRow ? (
                              <div className="grid gap-2 border-t border-border pt-2 lg:grid-cols-[1fr_auto_auto_auto]">
                                <input
                                  value={editItemName}
                                  onChange={(event) =>
                                    setEditItemName(event.target.value)
                                  }
                                  disabled={isChecklistSaving}
                                  className="h-7 rounded-md border border-border bg-surface-0/60 px-2 text-xs text-text-primary outline-none focus:border-pf-500/50"
                                />
                                <select
                                  value={String(editItemPriority)}
                                  onChange={(event) => {
                                    const next = Number.parseInt(
                                      event.target.value,
                                      10,
                                    );
                                    setEditItemPriority(
                                      Number.isInteger(next)
                                        ? next
                                        : item.priority,
                                    );
                                  }}
                                  disabled={isChecklistSaving}
                                  className={dashboardSelectClass}
                                  title="Severity"
                                >
                                  {[1, 2, 3, 4, 5].map((priority) => (
                                    <option
                                      key={priority}
                                      value={String(priority)}
                                      style={{
                                        backgroundColor: "var(--surface-1)",
                                        color: "var(--text-primary)",
                                      }}
                                    >
                                      S{priority}
                                    </option>
                                  ))}
                                </select>
                                <Button
                                  size="icon"
                                  variant="secondary"
                                  onClick={() => {
                                    void handleUpdateChecklistItem(
                                      blockIndex,
                                      itemIndex,
                                      rowKey,
                                    );
                                  }}
                                  loading={
                                    checklistActionKey === updateActionKey
                                  }
                                  disabled={
                                    isChecklistSaving ||
                                    editItemName.trim().length === 0
                                  }
                                  title="Save edit"
                                >
                                  <Check size={13} />
                                </Button>
                                <Button
                                  size="icon"
                                  variant="ghost"
                                  onClick={() => {
                                    setEditingRowKey(null);
                                    setChecklistError("");
                                  }}
                                  disabled={isChecklistSaving}
                                  title="Cancel edit"
                                >
                                  <X size={13} />
                                </Button>
                              </div>
                            ) : null}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))
              )}
              {checklistError ? (
                <p className="px-1 text-xs text-red-300">
                  {checklistError}
                </p>
              ) : null}
            </div>
          )}
        </Card>

        <AgentStatePath
          agents={activeProject.agents}
          agentInsights={agentInsights}
          showHeader
          subtitle="Intel ↓ Planner ↓ Executor Layer (parallel) ↓ Perceptor ↺ Planner"
          className="flex h-[560px] flex-col"
          graphHeightClassName="min-h-0 flex-1"
        />
      </div>

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
                  <path d="M0,0 L7,3.5 L0,7 z" fill="rgba(125,211,252,0.8)" />
                </marker>
              </defs>
              {architectureEdges.map((edge, index) => {
                return (
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
                );
              })}
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
                <p className="mt-0.5 text-xs text-text-muted">
                  {host.role}
                </p>
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
                <p className="mt-1 text-xs text-text-secondary">
                  {host.note}
                </p>
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

      <FindingsTable findings={activeProject.findings} />

      {isCopilotOpen ? (
        <div
          className="fixed inset-0 z-40 bg-surface-0/45 backdrop-blur-[1px]"
          onClick={() => setIsCopilotOpen(false)}
        />
      ) : null}
      <div
        className={`fixed bottom-24 right-4 z-50 w-[min(460px,calc(100vw-1.5rem))] transition-all duration-300 sm:right-6 ${isCopilotOpen
            ? "pointer-events-auto translate-y-0 opacity-100"
            : "pointer-events-none translate-y-4 opacity-0"
          }`}
      >
        <AIPromptPanel
          projectId={activeProject.id}
          projectName={activeProject.name}
          target={activeProject.target}
          targetType={activeProject.targetType}
          agents={activeProject.agents}
        />
      </div>
      <Button
        size="sm"
        variant="primary"
        onClick={() => setIsCopilotOpen((open) => !open)}
        className="fixed bottom-4 right-4 z-50 h-12 w-12 rounded-full shadow-lg sm:bottom-6 sm:right-6"
        title={isCopilotOpen ? "Hide AI chat" : "Open AI chat"}
      >
        <Bot size={18} />
      </Button>

      <Dialog
        open={projectEditOpen}
        onClose={() => setProjectEditOpen(false)}
        title="Edit Project"
      >
        <div className="space-y-3">
          <Input
            label="Project Name"
            value={projectEditName}
            onChange={(event) => setProjectEditName(event.target.value)}
            placeholder="Project name"
          />
          <Input
            label="Target"
            value={projectEditTarget}
            onChange={(event) => setProjectEditTarget(event.target.value)}
            placeholder="Target URL / IP"
          />
          <Input
            label="Description"
            value={projectEditDescription}
            onChange={(event) => setProjectEditDescription(event.target.value)}
            placeholder="Optional scope/notes"
          />
          <div className="flex justify-end gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setProjectEditOpen(false)}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={handleSaveProjectEdit}
              disabled={!projectEditName.trim() || !projectEditTarget.trim()}
            >
              Save
            </Button>
          </div>
        </div>
      </Dialog>

      <Dialog
        open={stopDialogOpen}
        onClose={() => setStopDialogOpen(false)}
        title="Stop Scan"
        description="Choose whether to pause or cancel the current scan."
      >
        <div className="space-y-3 text-sm text-text-secondary">
          <p>
            Pause will keep current logs and results so you can review them.
            Cancel will clear logs, agent results, and reset status to idle.
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
                setLocallyAckedApprovalId(null);
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
