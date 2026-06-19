import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  Bell,
  BellOff,
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
import type {
  AgentGraphRole,
  AgentInsightPanelData,
} from "@/components/dashboard/AgentStatePath";
import {
  DashboardArchitecturePanel,
  DashboardFindingDialog,
  DashboardFindingsPanel,
  DashboardProjectHeader,
  DashboardTargetOverviewCard,
} from "@/components/dashboard/DashboardPanels";
import {
  MissionControlPanel,
  type MissionControlAction,
  type MissionControlPhaseKey,
  type MissionControlState,
} from "@/components/dashboard/MissionControlPanel";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Dialog } from "@/components/ui/Dialog";
import { Input } from "@/components/ui/Input";
import { Textarea } from "@/components/ui/Textarea";
import { OrchestratorPipeline, type OrchestratorStage, type OrchestratorStatus } from "@/components/dashboard/OrchestratorPipeline";
import {
  Brain,
  Zap,
  Search,
  LayoutDashboard,
} from "lucide-react";

import {
  approveInformationGatheringForProjectScanFromDesktop,
  approvePasswordForProjectScanFromDesktop,
  approveToolForProjectScanFromDesktop,
  approvePlannerForProjectScanFromDesktop,
  getProjectScanObservabilityFromDesktop,
  listProjectScanEventsFromDesktop,
  markProjectFindingFalsePositiveFromDesktop,
  saveProjectToDesktop,
  streamProjectScanEvents,
  type ScanDebugTimelineEntry,
  type ScanObservabilityMetrics,
  type ScanEventPayload,
} from "@/lib/projectBridge";
import { getProjectMobileRuntimeNotice } from "@/lib/mobileRuntime";
import { cn } from "@/lib/utils";
import { useProjects } from "@/stores/projects";
import { useConfig } from "@/stores/config";
import type {
  AgentInfo,
  Finding,
  FindingEvidence,
  FindingEvidenceStatus,
  FindingProofQuality,
  Project,
  ProjectStatus,
  RealtimeVulnFinding,
  DashboardSeverity,
} from "@/types";

type InsightTab = "plan" | "checklist";
type LogLevel = "info" | "success" | "warn" | "error";

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
  priority?: number;
  status: "completed" | "working" | "not yet";
  plannerRound: string;
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

interface InformationGatheringProgramToolView {
  label: string;
  kind: "builtin" | "custom";
}

interface InformationGatheringProgramBlockView {
  id: string;
  name: string;
  goal: string;
  interaction: string;
  status: string;
  selectionRationale: string;
  skippedTools: string[];
  plannedTools: InformationGatheringProgramToolView[];
}

interface InformationGatheringResultView {
  tool: string;
  status: string;
  summary: string;
  command: string;
}

interface InformationGatheringBlockView {
  id: string;
  name: string;
  goal: string;
  interaction: string;
  status: string;
  summary: string;
  keyFindings: string[];
  riskSignals: string[];
  openQuestions: string[];
  selectionRationale: string;
  skippedTools: string[];
  plannedTools: string[];
  results: InformationGatheringResultView[];
}

interface InformationGatheringView {
  status: string;
  program: InformationGatheringProgramBlockView[];
  blocks: InformationGatheringBlockView[];
  workingBlockId: string;
  paths: {
    json: string;
    markdown: string;
  };
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
  flows: ArchitectureFlow[];
  board?: ArchitectureBoard;
}

interface DashboardLogEntry {
  id: string;
  level: LogLevel;
  message: string;
  at: string;
  source: string;
}


interface PendingToolApprovalView {
  approvalId: string;
  role: string;
  toolName: string;
  callId: string;
  args: Record<string, unknown>;
}

interface PendingPasswordRequestView {
  passwordId: string;
  toolName: string;
  prompt: string;
  reason: string;
  callId: string;
}

type AnalyzerAgentReportRole = "information_gathering" | "recon" | "exploit";

interface AnalyzerScenarioReportItem {
  scenario_ran?: string;
  agent?: string;
  status?: string;
  tools_ran?: string[];
  tool_results?: Array<{
    tool?: string;
    command?: string;
    status?: string;
    raw_status?: string;
    summary?: string;
  }>;
  findings_summary?: string[];
  execution_summary?: string;
}

interface AnalyzerAgentReportEntry {
  id: string;
  scan_id?: string;
  agent: AnalyzerAgentReportRole;
  phase?: string;
  cycle_number?: number;
  scenario_index?: number;
  sequence_label?: string;
  scenario_task?: string;
  execution_status?: string;
  verdict?: string;
  summary?: string;
  objective?: string;
  confirmed_facts?: string[];
  security_signals?: string[];
  unknowns?: string[];
  why_it_matters?: string;
  next_actions?: string[];
  raw_tool_evidence?: string[];
  markdown: string;
  updated_at?: string;
  scenario_report?: AnalyzerScenarioReportItem[];
}

interface AnalyzerReportViewerState {
  open: boolean;
  title: string;
  description: string;
  markdown: string;
}

const FINDINGS_HISTORY_KEY = "findings_history";
const LEGACY_FINDINGS_HISTORY_KEY = "analyzer_agent_reports";

type ApprovalMode = "custom" | "auto";

const NOTIFICATION_PREF_KEY = "pentaforge_notifications_enabled";

const PROJECT_STATUSES: ProjectStatus[] = [
  "idle",
  "running",
  "stopped",
  "completed",
  "error",
  "awaiting_tool_approval",
  "awaiting_planner_approval",
  "awaiting_information_gathering_approval",
];
const AGENT_ROLES: AgentGraphRole[] = [
  "planner",
  "executer",
  "analyzer",
];
const MISSION_PHASE_ORDER: Array<{
  key: MissionControlPhaseKey;
  label: string;
  detail: string;
}> = [
    {
      key: "intel",
      label: "Intel",
      detail: "Refreshes global knowledge and primes the target-specific brief.",
    },
    {
      key: "information_gathering",
      label: "Information Gathering",
      detail: "Runs the grouped deterministic target profiling and static mapping pass.",
    },
    {
      key: "brain",
      label: "Brain",
      detail: "Normalizes raw evidence into memory the agents can safely reason over.",
    },
    {
      key: "planner",
      label: "Planner",
      detail: "Synthesizes the checklist, scenarios, and next execution wave.",
    },
    {
      key: "executer",
      label: "Executer",
      detail: "Runs recon and exploit scenarios inside the active scan cycle.",
    },
    {
      key: "analyzer",
      label: "Analyzer",
      detail: "Verifies findings, rejects false positives, and saves confirmed impact.",
    },
  ];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function normalizeScenarioToolResults(
  value: unknown,
): Array<{
  tool?: string;
  command?: string;
  status?: string;
  raw_status?: string;
  summary?: string;
}> {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .filter((item): item is Record<string, unknown> => isRecord(item))
    .map((item) => ({
      tool: typeof item.tool === "string" ? item.tool : undefined,
      command: typeof item.command === "string" ? item.command : undefined,
      status: typeof item.status === "string" ? item.status : undefined,
      raw_status: typeof item.raw_status === "string" ? item.raw_status : undefined,
      summary: typeof item.summary === "string" ? item.summary : undefined,
    }))
    .filter((item) => Boolean(item.command || item.tool));
}

function getFindingsHistoryRoot(payload: unknown): Record<string, unknown> | null {
  if (!isRecord(payload)) {
    return null;
  }
  const nextRoot = isRecord(payload[FINDINGS_HISTORY_KEY])
    ? payload[FINDINGS_HISTORY_KEY]
    : null;
  if (nextRoot) {
    return nextRoot;
  }
  return isRecord(payload[LEGACY_FINDINGS_HISTORY_KEY])
    ? payload[LEGACY_FINDINGS_HISTORY_KEY]
    : null;
}

function normalizeAnalyzerAgentReportRole(
  role: string,
): AnalyzerAgentReportRole | null {
  const normalized = role
    .replace(/\[worker\s*\d+\]\s*/gi, "")
    .trim()
    .toLowerCase();
  if (
    normalized.includes("information_gathering")
    || normalized.includes("information gathering")
    || normalized.includes("target_info_gathering")
  ) {
    return "information_gathering";
  }
  if (normalized.includes("recon")) {
    return "recon";
  }
  if (normalized.includes("exploit")) {
    return "exploit";
  }
  return null;
}

function getLatestAnalyzerAgentReportEntry(
  payload: unknown,
  role: AnalyzerAgentReportRole,
): AnalyzerAgentReportEntry | null {
  if (!isRecord(payload)) {
    return null;
  }
  const reportsRoot = getFindingsHistoryRoot(payload);
  if (!reportsRoot) {
    return null;
  }
  const bucket = isRecord(reportsRoot[role]) ? reportsRoot[role] : null;
  if (!bucket || !Array.isArray(bucket.entries)) {
    return null;
  }

  for (const entry of bucket.entries) {
    if (!isRecord(entry)) {
      continue;
    }
    const markdown = typeof entry.markdown === "string" ? entry.markdown : "";
    const agent = normalizeAnalyzerAgentReportRole(
      typeof entry.agent === "string" ? entry.agent : role,
    );
    if (!markdown.trim() || agent !== role) {
      continue;
    }
    return {
      id: typeof entry.id === "string" ? entry.id : `${role}-${Date.now()}`,
      scan_id: typeof entry.scan_id === "string" ? entry.scan_id : undefined,
      agent,
      phase: typeof entry.phase === "string" ? entry.phase : undefined,
      cycle_number: typeof entry.cycle_number === "number" ? entry.cycle_number : undefined,
      scenario_index: typeof entry.scenario_index === "number" ? entry.scenario_index : undefined,
      sequence_label: typeof entry.sequence_label === "string" ? entry.sequence_label : undefined,
      scenario_task:
        typeof entry.scenario_task === "string" ? entry.scenario_task : undefined,
      execution_status:
        typeof entry.execution_status === "string" ? entry.execution_status : undefined,
      verdict: typeof entry.verdict === "string" ? entry.verdict : undefined,
      summary: typeof entry.summary === "string" ? entry.summary : undefined,
      objective: typeof entry.objective === "string" ? entry.objective : undefined,
      confirmed_facts: Array.isArray(entry.confirmed_facts)
        ? uniqueNormalizedStrings(entry.confirmed_facts)
        : undefined,
      security_signals: Array.isArray(entry.security_signals)
        ? uniqueNormalizedStrings(entry.security_signals)
        : undefined,
      unknowns: Array.isArray(entry.unknowns)
        ? uniqueNormalizedStrings(entry.unknowns)
        : undefined,
      why_it_matters: typeof entry.why_it_matters === "string" ? entry.why_it_matters : undefined,
      next_actions: Array.isArray(entry.next_actions)
        ? uniqueNormalizedStrings(entry.next_actions)
        : undefined,
      raw_tool_evidence: Array.isArray(entry.raw_tool_evidence)
        ? uniqueNormalizedStrings(entry.raw_tool_evidence)
        : undefined,
      markdown,
      updated_at: typeof entry.updated_at === "string" ? entry.updated_at : undefined,
      scenario_report: Array.isArray(entry.scenario_report)
        ? entry.scenario_report
          .filter((item): item is Record<string, unknown> => isRecord(item))
          .map((item) => ({
            scenario_ran: typeof item.scenario_ran === "string" ? item.scenario_ran : undefined,
            agent: typeof item.agent === "string" ? item.agent : undefined,
            status: typeof item.status === "string" ? item.status : undefined,
            tools_ran: Array.isArray(item.tools_ran)
              ? uniqueNormalizedStrings(item.tools_ran)
              : undefined,
            tool_results: normalizeScenarioToolResults(item.tool_results),
            findings_summary: Array.isArray(item.findings_summary)
              ? uniqueNormalizedStrings(item.findings_summary)
              : undefined,
            execution_summary: typeof item.execution_summary === "string" ? item.execution_summary : undefined,
          }))
        : undefined,
    };
  }

  return null;
}

function getAnalyzerAgentReportEntries(
  payload: unknown,
  scanId?: string,
): AnalyzerAgentReportEntry[] {
  if (!isRecord(payload)) {
    return [];
  }
  const reportsRoot = getFindingsHistoryRoot(payload);
  if (!reportsRoot) {
    return [];
  }

  const entries: AnalyzerAgentReportEntry[] = [];
  for (const role of ["information_gathering", "recon", "exploit"] as const) {
    const bucket = isRecord(reportsRoot[role]) ? reportsRoot[role] : null;
    if (!bucket || !Array.isArray(bucket.entries)) {
      continue;
    }
    for (const rawEntry of bucket.entries) {
      if (!isRecord(rawEntry)) {
        continue;
      }
      const entry = getLatestAnalyzerAgentReportEntry(
        { [FINDINGS_HISTORY_KEY]: { [role]: { entries: [rawEntry] } } },
        role,
      );
      if (!entry) {
        continue;
      }
      if (scanId && entry.scan_id && entry.scan_id !== scanId) {
        continue;
      }
      entries.push(entry);
    }
  }

  return entries.sort((left, right) => {
    const leftCycle = typeof left.cycle_number === "number" ? left.cycle_number : 9999;
    const rightCycle = typeof right.cycle_number === "number" ? right.cycle_number : 9999;
    if (leftCycle !== rightCycle) {
      return leftCycle - rightCycle;
    }
    const leftScenario = typeof left.scenario_index === "number" ? left.scenario_index : 9999;
    const rightScenario = typeof right.scenario_index === "number" ? right.scenario_index : 9999;
    if (leftScenario !== rightScenario) {
      return leftScenario - rightScenario;
    }
    return new Date(left.updated_at || 0).getTime() - new Date(right.updated_at || 0).getTime();
  });
}

function getFallbackInformationGatheringEntries(
  project: Project | null | undefined,
  scanId?: string,
): AnalyzerAgentReportEntry[] {
  if (!project || !isRecord(project.lastScan)) {
    return [];
  }
  const lastScan = project.lastScan;
  const currentScanId = typeof lastScan.scanId === "string" ? lastScan.scanId : "";
  if (scanId && currentScanId && currentScanId !== scanId) {
    return [];
  }
  const result = isRecord(lastScan.result) ? lastScan.result : null;
  const gathering = result && isRecord(result.targetInfoGathering)
    ? result.targetInfoGathering
    : null;
  const blocks = gathering && Array.isArray(gathering.blocks) ? gathering.blocks : [];
  const entries: AnalyzerAgentReportEntry[] = [];
  for (let index = 0; index < blocks.length; index += 1) {
    const block = blocks[index];
    if (!isRecord(block)) {
      continue;
    }
    const scenarioIndex = typeof block.index === "number" ? block.index : index + 1;
    const total = typeof block.total === "number" ? block.total : blocks.length;
    const scenarioTask = normalizeText(block.goal) || normalizeText(block.name) || `Gathering block ${scenarioIndex}`;
    const objective = normalizeText(block.objective) || scenarioTask;
    const results = Array.isArray(block.results) ? block.results.filter((item): item is Record<string, unknown> => isRecord(item)) : [];
    const confirmedFacts = Array.isArray(block.confirmed_facts)
      ? uniqueNormalizedStrings(block.confirmed_facts)
      : [];
    const securitySignals = Array.isArray(block.security_signals)
      ? uniqueNormalizedStrings(block.security_signals)
      : [];
    const unknowns = Array.isArray(block.unknowns)
      ? uniqueNormalizedStrings(block.unknowns)
      : [];
    const toolsRan = results
      .map((item) => normalizeText(item.command) || normalizeText(item.tool))
      .filter(Boolean);
    const findingsSummary = results
      .map((item) => {
        const toolName = normalizeText(item.tool) || "tool";
        const summary = normalizeText(item.summary);
        return summary ? `${toolName}: ${summary}` : "";
      })
      .filter(Boolean);
    const executionSummary = `Completed information-gathering block ${scenarioIndex}/${total} with ${results.length} tool result(s). Status: ${normalizeText(block.status) || "completed"}.`;
    entries.push({
      id: `${currentScanId || scanId || "scan"}:information_gathering:g${scenarioIndex}:fallback`,
      scan_id: currentScanId || scanId || undefined,
      agent: "information_gathering",
      phase: "classified",
      cycle_number: 0,
      scenario_index: scenarioIndex,
      sequence_label: `g${scenarioIndex}`,
      scenario_task: objective,
      execution_status: normalizeText(block.status) || "completed",
      verdict: "info",
      summary: normalizeText(block.summary) || objective,
      objective,
      confirmed_facts: uniqueNormalizedStrings(confirmedFacts),
      security_signals: uniqueNormalizedStrings(securitySignals),
      unknowns: uniqueNormalizedStrings(unknowns),
      why_it_matters: normalizeText(block.why_it_matters),
      next_actions: Array.isArray(block.next_actions)
        ? uniqueNormalizedStrings(block.next_actions)
        : [],
      raw_tool_evidence: uniqueNormalizedStrings(findingsSummary),
      markdown: "",
      updated_at: typeof project.updatedAt === "string" ? project.updatedAt : undefined,
      scenario_report: [{
        scenario_ran: objective,
        agent: "information_gathering",
        status: normalizeText(block.status) || "completed",
        tools_ran: uniqueNormalizedStrings(toolsRan),
        tool_results: results.map((item) => ({
          tool: normalizeText(item.tool),
          command: normalizeText(item.command) || normalizeText(item.tool),
          status: normalizeText(item.status) === "completed"
            ? "passed"
            : normalizeText(item.status) === "error"
              ? "failed"
              : normalizeText(item.status),
          raw_status: normalizeText(item.status),
          summary: normalizeText(item.summary),
        })).filter((item) => item.command),
        findings_summary: uniqueNormalizedStrings([...confirmedFacts, ...securitySignals]),
        execution_summary: executionSummary,
      }],
    });
  }
  return entries;
}

function buildCombinedAnalyzerMarkdown(
  entries: AnalyzerAgentReportEntry[],
  scanId?: string,
): string {
  const classifiedEntries = entries.filter((entry) => (entry.phase || "classified") === "classified");
  if (classifiedEntries.length === 0) {
    return [
      "# Findings History Markdown",
      "",
      "No classified findings history entries are available yet for this scan.",
    ].join("\n");
  }

  const lines: string[] = [
    "# Findings History Markdown",
    "",
    scanId ? `- Scan ID: \`${scanId}\`` : "- Scan ID: `unknown`",
    `- Scenario Count: \`${classifiedEntries.length}\``,
  ];

  for (const [index, entry] of classifiedEntries.entries()) {
    const report = Array.isArray(entry.scenario_report) ? entry.scenario_report[0] : null;
    const label = entry.sequence_label
      || (
        entry.agent === "information_gathering"
          ? `g${entry.scenario_index ?? "?"}`
          : `c${entry.cycle_number ?? "?"}s${entry.scenario_index ?? "?"}`
      );
    const scenario = typeof report?.scenario_ran === "string" && report.scenario_ran.trim()
      ? report.scenario_ran.trim()
      : entry.scenario_task?.trim() || "Untitled scenario";
    const tools = Array.isArray(report?.tools_ran)
      ? report.tools_ran.map((item: string) => String(item || "").trim()).filter(Boolean)
      : [];
    const toolResults = Array.isArray(report?.tool_results)
      ? report.tool_results
        .map((item) => ({
          command: String(item.command || item.tool || "").trim(),
          status: String(item.status || "").trim(),
          summary: String(item.summary || "").trim(),
        }))
        .filter((item) => item.command)
      : [];
    const findings = Array.isArray(report?.findings_summary)
      ? uniqueNormalizedStrings(report.findings_summary)
      : [];
    const executionSummary = typeof report?.execution_summary === "string"
      ? report.execution_summary.trim()
      : "";
    const nodeLabel = entry.agent === "information_gathering" ? "block" : "cycle";
    const scenarioStatus = entry.agent === "information_gathering"
      ? normalizeText(report?.status) || normalizeText(entry.execution_status) || "completed"
      : (entry.verdict || "unknown");
    const confirmedFacts = uniqueNormalizedStrings(entry.confirmed_facts ?? []);
    const securitySignals = uniqueNormalizedStrings(entry.security_signals ?? []);
    const unknowns = uniqueNormalizedStrings(entry.unknowns ?? []);
    const nextActions = uniqueNormalizedStrings(entry.next_actions ?? []);
    const whatWeFound = entry.agent === "information_gathering"
      ? uniqueNormalizedStrings(
        confirmedFacts.length > 0 || securitySignals.length > 0
          ? [...confirmedFacts, ...securitySignals]
          : findings,
      )
      : findings.length > 0
        ? uniqueNormalizedStrings(findings)
        : uniqueNormalizedStrings(entry.summary?.trim() ? [entry.summary.trim()] : []);

    lines.push(
      "",
      `## ${label} [${entry.agent.replace(/_/g, " ").toUpperCase()}]`,
      "",
      `- Agent / Node: ${entry.agent}`,
      `- ${nodeLabel === "block" ? "Block" : "Cycle"}: ${label}`,
      `- Scenario: ${entry.objective?.trim() || scenario}`,
      `- Status: \`${scenarioStatus}\``,
    );
    if (executionSummary) {
      lines.push(`- Execution Summary: ${executionSummary}`);
    }

    lines.push("", "### Full Tool History", "");
    if (toolResults.length > 0) {
      for (const item of toolResults) {
        const commandLabel = `\`${item.command}\``;
        const statusLabel = item.status ? `\`${item.status}\`` : "`unknown`";
        lines.push(
          item.summary
            ? `- ${statusLabel} ${commandLabel} -> ${item.summary}`
            : `- ${statusLabel} ${commandLabel}`,
        );
      }
    } else if (tools.length > 0) {
      for (const item of tools) {
        lines.push(`- \`observed\` \`${item}\``);
      }
    } else {
      lines.push("- No tool history recorded.");
    }

    lines.push("", "### What We Find", "");
    if (whatWeFound.length > 0) {
      for (const item of whatWeFound) {
        lines.push(`- ${item}`);
      }
    } else if (entry.summary?.trim()) {
      lines.push(`- ${entry.summary.trim()}`);
    } else {
      lines.push("- No findings were recorded.");
    }

    lines.push("", "### What We Should Do", "");
    if (nextActions.length > 0) {
      for (const item of nextActions) {
        lines.push(`- ${item}`);
      }
    } else {
      lines.push("- No next action was recorded.");
    }

    lines.push("", "### Unknowns / Gaps", "");
    if (unknowns.length > 0) {
      for (const item of unknowns) {
        lines.push(`- ${item}`);
      }
    } else {
      lines.push("- No unresolved unknowns were recorded.");
    }

    if (index < classifiedEntries.length - 1) {
      lines.push("", "-----------------------------------------------------------");
    }
  }

  return lines.join("\n");
}

function getAnalyzerPipelineActivities(
  entries: AnalyzerAgentReportEntry[],
): Array<{ type: "thinking" | "command" | "result" | "info"; message: string; at?: string }> | undefined {
  const classifiedEntries = entries.filter((entry) => (entry.phase || "classified") === "classified");
  if (!classifiedEntries.length) {
    return undefined;
  }

  const activities: Array<{ type: "thinking" | "command" | "result" | "info"; message: string; at?: string }> = [];
  for (const entry of classifiedEntries.slice(-2)) {
    const report = Array.isArray(entry.scenario_report) ? entry.scenario_report[0] : null;
    const label = entry.sequence_label
      || (
        entry.agent === "information_gathering"
          ? `g${entry.scenario_index ?? "?"}`
          : `c${entry.cycle_number ?? "?"}s${entry.scenario_index ?? "?"}`
      );
    const scenario = typeof report?.scenario_ran === "string" && report.scenario_ran.trim()
      ? report.scenario_ran.trim()
      : entry.scenario_task?.trim() || "";
    const tools = Array.isArray(report?.tools_ran)
      ? report.tools_ran.map((item: string) => String(item || "").trim()).filter(Boolean)
      : [];
    const findings = Array.isArray(report?.findings_summary)
      ? report.findings_summary.map((item: string) => String(item || "").trim()).filter(Boolean)
      : [];
    const executionSummary = typeof report?.execution_summary === "string"
      ? report.execution_summary.trim()
      : "";

    if (scenario) {
      activities.push({
        type: "info",
        message: `${label} ${entry.agent}: ${scenario}`,
        at: entry.updated_at,
      });
    }
    if (tools.length > 0) {
      activities.push({
        type: "command",
        message: `${label} tools: ${tools.join(", ")}`,
        at: entry.updated_at,
      });
    }
    if (findings.length > 0) {
      activities.push({
        type: "result",
        message: findings[0],
        at: entry.updated_at,
      });
    } else if (executionSummary) {
      activities.push({
        type: "result",
        message: `${label} ${executionSummary}`,
        at: entry.updated_at,
      });
    }
  }

  return activities.length > 0 ? activities.slice(0, 4) : undefined;
}

function isAgentRole(value: unknown): value is AgentGraphRole {
  return (
    typeof value === "string" && AGENT_ROLES.includes(value as AgentGraphRole)
  );
}

function workflowRoleForPhase(
  phase: MissionControlPhaseKey | null,
): AgentGraphRole {
  if (phase === "intel" || phase === "information_gathering" || phase === "planner") {
    return "planner";
  }
  if (phase === "brain" || phase === "analyzer") {
    return "analyzer";
  }
  return "executer";
}

function detectEventAgentRole(event: ScanEventPayload): AgentGraphRole | null {
  const eventName = String(event.event || "").trim().toLowerCase();
  if (eventName.startsWith("executer_password_")) {
    return null;
  }

  const dataAgent = isRecord(event.data) ? event.data.agent : undefined;
  if (isAgentRole(dataAgent)) {
    return dataAgent;
  }
  if (dataAgent === "recon" || dataAgent === "exploit") {
    return "executer";
  }
  if (
    dataAgent === "verify"
    || dataAgent === "report"
    || dataAgent === "retest"
    || dataAgent === "perceptor"
  ) {
    return "analyzer";
  }

  const stage = isRecord(event.data) ? event.data.stage : undefined;
  if (typeof stage === "string") {
    const normalized = stage.trim().toLowerCase();
    if (isAgentRole(normalized)) {
      return normalized;
    }
    if (
      normalized === "intel"
      || normalized === "information_gathering"
      || normalized === "information gathering"
      || normalized === "checklist"
    ) {
      return "planner";
    }
    if (normalized === "recon" || normalized === "exploit" || normalized === "executer") {
      return "executer";
    }
    if (
      normalized === "verify"
      || normalized === "report"
      || normalized === "retest"
      || normalized === "perceptor"
      || normalized === "analyzer"
    ) {
      return "analyzer";
    }
  }

  const text = `${event.event} ${event.message}`.toLowerCase();
  if (
    text.includes("planner")
    || text.includes("information gathering")
    || text.includes("information_gathering")
    || text.includes("intel")
    || text.includes("checklist")
  ) {
    return "planner";
  }
  if (text.includes("recon") || text.includes("exploit") || text.includes("executer")) {
    return "executer";
  }
  if (
    text.includes("verify")
    || text.includes("retest")
    || text.includes("report")
    || text.includes("perceptor")
    || text.includes("analyzer")
  ) {
    return "analyzer";
  }
  return null;
}

function detectMissionPhaseFromText(value: string): MissionControlPhaseKey | null {
  const text = value.trim().toLowerCase();
  if (!text) {
    return null;
  }
  if (
    text.includes("intel")
    || text.includes("profiling")
    || text.includes("pre-scan")
    || text.includes("system memory")
    || text.includes("system_memory")
  ) {
    return "intel";
  }
  if (
    text.includes("brain")
    || text.includes("target memory")
    || text.includes("memory projection")
  ) {
    return "brain";
  }
  if (
    text.includes("information gathering")
    || text.includes("information_gathering")
    || text.includes("target_info_gathering")
    || text.includes("fingerprinting")
    || text.includes("surface mapping")
    || text.includes("trust and auth")
    || text.includes("reconnaissance")
  ) {
    return "information_gathering";
  }
  if (text.includes("planner") || text.includes("checklist")) {
    return "planner";
  }
  if (
    text.includes("executer")
    || text.includes("exploit")
    || text.includes("scenario")
    || text.includes("worker")
  ) {
    return "executer";
  }
  if (
    text.includes("analyzer")
    || text.includes("verify")
    || text.includes("retest")
    || text.includes("perceptor")
    || text.includes("report")
  ) {
    return "analyzer";
  }
  return null;
}

function isArchitectEvent(event: ScanEventPayload): boolean {
  const data = isRecord(event.data) ? event.data : null;
  const stage = typeof data?.stage === "string" ? data.stage.toLowerCase() : "";
  const phase = typeof data?.phase === "string" ? data.phase.toLowerCase() : "";
  const eventName = String(event.event || "").toLowerCase();
  const message = String(event.message || "").toLowerCase();
  return (
    eventName.startsWith("architect_")
    || stage.includes("architect")
    || phase.includes("architect")
    || message.includes("architect")
  );
}

function detectMissionPhase(event: ScanEventPayload): MissionControlPhaseKey | null {
  if (isArchitectEvent(event)) {
    return null;
  }
  const data = isRecord(event.data) ? event.data : null;
  const stage = typeof data?.stage === "string" ? data.stage : "";
  const phase = typeof data?.phase === "string" ? data.phase : "";
  const reason = typeof data?.reason === "string" ? data.reason : "";
  const prompt = typeof data?.prompt === "string" ? data.prompt : "";

  // Check content-rich fields (message, reason, prompt) FIRST to catch specific tasks like "reconnaissance"
  const fromContent =
    detectMissionPhaseFromText(event.message || "") ??
    detectMissionPhaseFromText(reason) ??
    detectMissionPhaseFromText(prompt);

  if (fromContent) return fromContent;

  // Then check specific stage/phase metadata if provided
  const fromMetadata = detectMissionPhaseFromText(stage) ?? detectMissionPhaseFromText(phase);
  if (fromMetadata) return fromMetadata;

  // Fallback to the generic event name (e.g., executer_password_request)
  return detectMissionPhaseFromText(event.event);
}

function detectWorkflowPhase(event: ScanEventPayload): MissionControlPhaseKey | null {
  const eventName = String(event.event || "").trim().toLowerCase();
  if (eventName.startsWith("executer_password_")) {
    return null;
  }

  return detectMissionPhase(event);
}

function toProjectStatus(value: unknown): ProjectStatus | null {
  if (typeof value !== "string") {
    return null;
  }
  if (value.trim().toLowerCase() === "paused") {
    return "stopped";
  }
  return PROJECT_STATUSES.includes(value as ProjectStatus)
    ? (value as ProjectStatus)
    : null;
}

export function normalizeRunningStatus(project: {
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
  if (lastScanStatus === "paused") {
    return "stopped";
  }
  if (
    lastScanStatus === "completed" ||
    lastScanStatus === "stopped" ||
    lastScanStatus === "idle" ||
    lastScanStatus === "error" ||
    lastScanStatus === "awaiting_tool_approval" ||
    lastScanStatus === "awaiting_planner_approval" ||
    lastScanStatus === "awaiting_information_gathering_approval"
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

function normalizeDashboardSeverity(value: unknown): DashboardSeverity {
  const raw = normalizeText(value).toLowerCase();
  if (
    raw === "critical" ||
    raw === "high" ||
    raw === "medium" ||
    raw === "low" ||
    raw === "info"
  ) {
    return raw;
  }
  const priority = normalizePriority(value);
  if (priority === 1) return "critical";
  if (priority === 2) return "high";
  if (priority === 3) return "medium";
  if (priority === 4) return "low";
  if (priority === 5) return "info";
  return "medium";
}

function severityBadgeClass(value: DashboardSeverity): string {
  if (value === "critical") {
    return "border-red-500/40 bg-red-500/15 text-red-900 dark:text-red-200";
  }
  if (value === "high") {
    return "border-orange-600/40 bg-orange-600/15 text-orange-950 dark:text-orange-200";
  }
  if (value === "medium") {
    return "border-orange-500/40 bg-orange-500/15 text-orange-900 dark:text-orange-200";
  }
  if (value === "low") {
    return "border-emerald-500/40 bg-emerald-500/15 text-emerald-900 dark:text-emerald-200";
  }
  return "border-slate-500/40 bg-slate-500/15 text-slate-900 dark:text-slate-200";
}

function normalizeEvidenceStatus(value: unknown): FindingEvidenceStatus | undefined {
  const raw = normalizeText(value).toLowerCase();
  if (raw === "suspicion" || raw === "evidence_backed" || raw === "confirmed") {
    return raw;
  }
  return undefined;
}

function normalizeProofQuality(value: unknown): FindingProofQuality | undefined {
  const raw = normalizeText(value).toLowerCase();
  if (raw === "weak" || raw === "moderate" || raw === "strong") {
    return raw;
  }
  return undefined;
}

function evidenceBadgeClass(value?: FindingEvidenceStatus): string {
  if (value === "confirmed") {
    return "border-emerald-500/40 bg-emerald-500/15 text-emerald-900 dark:text-emerald-200";
  }
  if (value === "evidence_backed") {
    return "border-orange-500/40 bg-orange-500/15 text-orange-900 dark:text-orange-200";
  }
  if (value === "suspicion") {
    return "border-slate-500/40 bg-slate-500/15 text-slate-900 dark:text-slate-200";
  }
  return "border-slate-500/40 bg-slate-500/15 text-slate-900 dark:text-slate-200";
}

function proofQualityBadgeClass(value?: FindingProofQuality): string {
  if (value === "strong") {
    return "border-emerald-500/40 bg-emerald-500/15 text-emerald-900 dark:text-emerald-200";
  }
  if (value === "moderate") {
    return "border-orange-500/40 bg-orange-500/15 text-orange-900 dark:text-orange-200";
  }
  if (value === "weak") {
    return "border-slate-500/40 bg-slate-500/15 text-slate-900 dark:text-slate-200";
  }
  return "border-slate-500/40 bg-slate-500/15 text-slate-900 dark:text-slate-200";
}

function findingUsesOobProof(finding: Pick<Finding, "evidence" | "verificationMethods">): boolean {
  const methods = Array.isArray(finding.verificationMethods)
    ? finding.verificationMethods
    : (Array.isArray(finding.evidence?.verification_methods) ? finding.evidence.verification_methods : []);
  const normalizedMethods = methods
    .filter((item): item is string => typeof item === "string")
    .map((item) => item.trim().toLowerCase());
  return (
    normalizedMethods.includes("oob_callback")
    || finding.evidence?.oob_confirmed === true
  );
}

function findingOobProtocol(finding: Pick<Finding, "evidence">): string | undefined {
  const protocol = normalizeText(finding.evidence?.protocol).toLowerCase();
  return protocol || undefined;
}

function formatVerificationMethod(value: string): string {
  const raw = normalizeText(value).toLowerCase();
  if (!raw) {
    return "";
  }
  if (raw === "oob_callback") {
    return "OOB callback";
  }
  return raw.replace(/_/g, " ");
}

function formatRealtimeFindingStatus(value: string): string {
  const normalized = normalizeText(value).toLowerCase();
  if (!normalized) {
    return "unknown";
  }
  if (normalized === "possible_checking") return "possible vuln - checking";
  if (normalized === "verify_working") return "verifying...";
  if (normalized === "real_vulnerability") return "real vulnerability";
  if (normalized === "false_positive") return "false positive";
  if (normalized === "inconclusive") return "inconclusive";
  if (normalized === "verified_saved") return "verified & saved";
  return normalized.replace(/_/g, " ");
}

function realtimeStatusRank(value: string): number {
  const normalized = normalizeText(value).toLowerCase();
  if (normalized === "verified_saved") return 5;
  if (normalized === "real_vulnerability") return 4;
  if (normalized === "verify_working") return 3;
  if (normalized === "false_positive") return 2;
  if (normalized === "inconclusive") return 2;
  if (normalized === "possible_checking") return 1;
  return 0;
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
  if (view.toolName === "run_python") {
    const code = typeof args.code === "string" ? args.code.trim() : "";
    if (code) {
      return `run_python:\n${code}`;
    }
    return "Python Script Execution";
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

function formatPentestElapsed(seconds: number): string {
  const safe = Math.max(0, Math.floor(seconds));
  const days = Math.floor(safe / 86400);
  const hours = Math.floor((safe % 86400) / 3600);
  const minutes = Math.floor((safe % 3600) / 60);
  const secs = safe % 60;

  if (days > 0) {
    return `${days}d ${String(hours).padStart(2, "0")}h ${String(minutes).padStart(2, "0")}m`;
  }

  return `${String(hours).padStart(2, "0")}h ${String(minutes).padStart(2, "0")}m ${String(secs).padStart(2, "0")}s`;
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
  if (source === "executer" || source === "recon" || source === "exploit") return "Executer";
  if (
    source === "analyzer"
    || source === "verify"
    || source === "report"
    || source === "retest"
    || source === "perceptor"
  ) {
    return "Analyzer";
  }
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

function uniqueNormalizedStrings(values: unknown[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    const text = normalizeText(value);
    const key = text.toLowerCase();
    if (!text || seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(text);
  }
  return out;
}

function normalizeFindingReference(value: string): string {
  return value.trim().toLowerCase().replace(/[_-]+/g, " ").replace(/\s+/g, " ");
}

function findingMatchesReference(
  finding: Finding,
  matchedId: string,
  matchedTitle: string,
  requestedReference: string,
): boolean {
  if (matchedId && finding.id === matchedId) {
    return true;
  }

  const findingTitle = normalizeFindingReference(finding.title || "");
  const expectedTitle = normalizeFindingReference(matchedTitle);
  if (expectedTitle && findingTitle === expectedTitle) {
    return true;
  }

  const requested = normalizeFindingReference(requestedReference);
  if (!requested) {
    return false;
  }

  const description = normalizeFindingReference(finding.description || "");
  return (
    (findingTitle.length >= 12 && requested.includes(findingTitle))
    || (description.length >= 20 && requested.includes(description))
    || (requested.length >= 20 && description.includes(requested))
  );
}

function normalizeScenarioStatus(
  value: unknown,
  done = false,
): "completed" | "working" | "not yet" {
  if (done) {
    return "completed";
  }
  const normalized = normalizeText(value).toLowerCase();
  if (
    normalized === "completed" ||
    normalized === "complete" ||
    normalized === "done"
  ) {
    return "completed";
  }
  if (
    normalized === "working" ||
    normalized === "running" ||
    normalized === "in progress" ||
    normalized === "in_progress"
  ) {
    return "working";
  }
  return "not yet";
}

function normalizeRoundLabel(value: unknown): string {
  const raw = normalizeText(value).toLowerCase();
  if (!raw) {
    return "";
  }
  if (raw.startsWith("r") && /^\d+$/.test(raw.slice(1))) {
    return raw;
  }
  if (/^\d+$/.test(raw)) {
    return `r${raw}`;
  }
  return "";
}

function scenarioStatusRank(value: PlannerScenarioView["status"]): number {
  switch (value) {
    case "completed":
      return 2;
    case "working":
      return 1;
    default:
      return 0;
  }
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
        if (
          rawScenario.done === true ||
          normalizeScenarioStatus(rawScenario.status, rawScenario.done === true) ===
          "completed"
        ) {
          completedScenarioCount += 1;
        }
      }
    }

    phases.push({
      name: normalizeText(rawPhase.name)?.replace(/^Phase \d+:\s*/i, "") || `Phase ${phaseIndex + 1}`,
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
      const scenarioMap = new Map<string, PlannerScenarioView>();
      for (const rawScenario of rawScenarios) {
        if (!isRecord(rawScenario)) {
          continue;
        }
        const task = normalizeText(rawScenario.task);
        if (!task) {
          continue;
        }
        const nextScenario: PlannerScenarioView = {
          scenario: task,
          agent: normalizeText(rawScenario.agent) || "recon",
          priority: normalizePriority(rawScenario.priority) ?? undefined,
          status: normalizeScenarioStatus(
            rawScenario.status,
            rawScenario.done === true,
          ),
          plannerRound: normalizeRoundLabel(rawScenario.planner_round_added),
        };
        const dedupeKey = `${nextScenario.agent}::${nextScenario.scenario}`.toLowerCase();
        const existingScenario = scenarioMap.get(dedupeKey);
        if (!existingScenario) {
          scenarioMap.set(dedupeKey, nextScenario);
          continue;
        }
        const existingRank = scenarioStatusRank(existingScenario.status);
        const nextRank = scenarioStatusRank(nextScenario.status);
        if (nextRank > existingRank) {
          existingScenario.status = nextScenario.status;
        }
        if (!existingScenario.plannerRound && nextScenario.plannerRound) {
          existingScenario.plannerRound = nextScenario.plannerRound;
        }
      }
      const scenarios = Array.from(scenarioMap.values());

      const description =
        normalizeText(rawStep.description) || normalizeText(rawStep.id);
      if (scenarios.length === 0) {
        continue;
      }
      steps.push({
        step: description?.replace(/^Step \d+:\s*/i, "") || `Step ${stepIndex + 1}`,
        scenarios,
      });
    }

    phases.push({
      phase: normalizeText(rawPhase.name)?.replace(/^Phase \d+:\s*/i, "") || `Phase ${phaseIndex + 1}`,
      steps,
    });
  }

  const nonEmptyPhases = phases.filter((phase) => phase.steps.length > 0);

  if (nonEmptyPhases.length === 0) {
    return null;
  }

  return { phases: nonEmptyPhases };
}

function toInformationGatheringToolLabel(value: unknown): InformationGatheringProgramToolView | null {
  if (typeof value === "string") {
    const label = normalizeText(value);
    if (!label) {
      return null;
    }
    return { label, kind: "builtin" };
  }
  if (!isRecord(value)) {
    return null;
  }
  const tool = normalizeText(value.tool) || "run_custom";
  const command = normalizeText(value.command);
  const args = Array.isArray(value.args)
    ? value.args.map((item) => normalizeText(item)).filter((item) => item.length > 0)
    : [];
  const label = command
    ? `${tool}: ${command}${args.length ? ` ${args.join(" ")}` : ""}`
    : tool;
  return label ? { label, kind: tool === "run_custom" ? "custom" : "builtin" } : null;
}

function toInformationGatheringProgramBlock(value: unknown): InformationGatheringProgramBlockView | null {
  if (!isRecord(value)) {
    return null;
  }
  const name = normalizeText(value.name) || normalizeText(value.id);
  if (!name) {
    return null;
  }
  const rawTools = Array.isArray(value.tools)
    ? value.tools
    : Array.isArray(value.planned_tools)
      ? value.planned_tools
      : [];
  return {
    id: normalizeText(value.id) || name.toLowerCase().replace(/\s+/g, "_"),
    name,
    goal: normalizeText(value.goal),
    interaction: normalizeText(value.interaction),
    status: normalizeText(value.status) || "keep",
    selectionRationale: normalizeText(value.selection_rationale) || normalizeText(value.rationale),
    skippedTools: Array.isArray(value.skipped_tools)
      ? value.skipped_tools.map((item) => normalizeText(item)).filter((item) => item.length > 0)
      : [],
    plannedTools: rawTools
      .map((item) => toInformationGatheringToolLabel(item))
      .filter((item): item is InformationGatheringProgramToolView => item !== null),
  };
}

function toInformationGatheringResult(value: unknown): InformationGatheringResultView | null {
  if (!isRecord(value)) {
    return null;
  }
  const tool = normalizeText(value.tool);
  if (!tool) {
    return null;
  }
  return {
    tool,
    status: normalizeText(value.status) || "completed",
    summary: normalizeText(value.summary),
    command: normalizeText(value.command),
  };
}

function toInformationGatheringBlock(value: unknown): InformationGatheringBlockView | null {
  if (!isRecord(value)) {
    return null;
  }
  const name = normalizeText(value.name) || normalizeText(value.id);
  if (!name) {
    return null;
  }
  return {
    id: normalizeText(value.id) || name.toLowerCase().replace(/\s+/g, "_"),
    name,
    goal: normalizeText(value.goal),
    interaction: normalizeText(value.interaction),
    status: normalizeText(value.status) || "completed",
    summary: normalizeText(value.summary),
    keyFindings: Array.isArray(value.key_findings)
      ? value.key_findings.map((item) => normalizeText(item)).filter((item) => item.length > 0)
      : [],
    riskSignals: Array.isArray(value.risk_signals)
      ? value.risk_signals.map((item) => normalizeText(item)).filter((item) => item.length > 0)
      : [],
    openQuestions: Array.isArray(value.open_questions)
      ? value.open_questions.map((item) => normalizeText(item)).filter((item) => item.length > 0)
      : [],
    selectionRationale: normalizeText(value.selection_rationale),
    skippedTools: Array.isArray(value.skipped_tools)
      ? value.skipped_tools.map((item) => normalizeText(item)).filter((item) => item.length > 0)
      : [],
    plannedTools: Array.isArray(value.planned_tools)
      ? value.planned_tools.map((item) => normalizeText(item)).filter((item) => item.length > 0)
      : [],
    results: Array.isArray(value.results)
      ? value.results.map((item) => toInformationGatheringResult(item)).filter((item): item is InformationGatheringResultView => item !== null)
      : [],
  };
}

function toInformationGatheringView(value: unknown): InformationGatheringView | null {
  if (!isRecord(value)) {
    return null;
  }
  const rawProgram = Array.isArray(value.program) ? value.program : [];
  const rawBlocks = Array.isArray(value.blocks) ? value.blocks : [];
  const paths = isRecord(value.paths) ? value.paths : {};
  const program = rawProgram
    .map((item) => toInformationGatheringProgramBlock(item))
    .filter((item): item is InformationGatheringProgramBlockView => item !== null);
  const blocks = rawBlocks
    .map((item) => toInformationGatheringBlock(item))
    .filter((item): item is InformationGatheringBlockView => item !== null);
  if (program.length === 0 && blocks.length === 0 && !normalizeText(value.status)) {
    return null;
  }
  return {
    status: normalizeText(value.status) || (blocks.length > 0 ? "completed" : "running"),
    program,
    blocks,
    workingBlockId: normalizeText(value.workingBlockId),
    paths: {
      json: normalizeText(paths.json),
      markdown: normalizeText(paths.markdown),
    },
  };
}

function buildInformationGatheringViewFromEvents(
  events: ScanEventPayload[],
): InformationGatheringView | null {
  const gathering: Record<string, unknown> = {};

  for (const event of events) {
    if (
      event.event !== "target_info_gathering_program_organized" &&
      event.event !== "target_info_gathering_block_started" &&
      event.event !== "target_info_gathering_block_completed" &&
      event.event !== "target_info_gathering_waiting_approval" &&
      event.event !== "target_info_gathering_approval_received" &&
      event.event !== "target_info_gathering_complete"
    ) {
      continue;
    }

    if (event.event === "target_info_gathering_program_organized" && isRecord(event.data.program)) {
      gathering.status = "organized";
      const blocks = Array.isArray(event.data.program.blocks) ? event.data.program.blocks : [];
      if (blocks.length > 0) {
        gathering.program = blocks;
      }
      if (isRecord(event.data.program.paths)) {
        gathering.paths = event.data.program.paths;
      }
    }

    if (event.event === "target_info_gathering_block_started" && isRecord(event.data.block)) {
      gathering.status = "running";
      gathering.workingBlockId = normalizeText(event.data.block.id);
    }

    if (event.event === "target_info_gathering_block_completed" && isRecord(event.data.block)) {
      const block = event.data.block;
      const currentBlocks = Array.isArray(gathering.blocks) ? [...gathering.blocks] : [];
      const blockId = normalizeText(block.id);
      const existingIndex = currentBlocks.findIndex(
        (item) => isRecord(item) && normalizeText(item.id) === blockId,
      );
      if (existingIndex >= 0) {
        currentBlocks[existingIndex] = block;
      } else {
        currentBlocks.push(block);
      }
      gathering.status = "running";
      gathering.blocks = currentBlocks;
      if (normalizeText(gathering.workingBlockId) === blockId) {
        gathering.workingBlockId = "";
      }
    }

    if (event.event === "target_info_gathering_waiting_approval") {
      gathering.status = "organized";
    }

    if (event.event === "target_info_gathering_approval_received") {
      gathering.status = "running";
    }

    if (event.event === "target_info_gathering_complete") {
      gathering.status = "completed";
      gathering.workingBlockId = "";
      if (isRecord(event.data.gathering)) {
        const completed = event.data.gathering;
        if (Array.isArray(completed.program) && completed.program.length > 0) {
          gathering.program = completed.program;
        }
        if (Array.isArray(completed.blocks) && completed.blocks.length > 0) {
          gathering.blocks = completed.blocks;
        }
      }
      if (isRecord(event.data.target_memory)) {
        gathering.paths = event.data.target_memory;
      }
    }
  }

  return toInformationGatheringView(gathering);
}

function buildTargetArchitectureDraft(
  targetType: string,
  target: string,
): TargetArchitectureDraft {
  const targetLabel = target.trim() || "target";

  return {
    title: `Initial architecture for ${targetLabel}`,
    hosts: [
      {
        id: "target-node",
        name: targetLabel,
        role: "Target",
        ports: [],
        note: "Initial target identified. Architecture synthesis will begin once findings are verified.",
        x: 50,
        y: 50,
      },
    ],
    flows: [],
  };
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const projects = useProjects((state) => state.projects);
  const activeProject = useProjects((state) => state.getActive());
  const setActive = useProjects((state) => state.setActive);
  const setRunning = useProjects((state) => state.setRunning);
  const stopScan = useProjects((state) => state.stopScan);
  const updateProject = useProjects((state) => state.updateProject);
  const hydrateFromDatabase = useProjects((state) => state.hydrateFromDatabase);
  const startingProjectId = useProjects((state) => state.startingProjectId);
  const startingProjectMessage = useProjects((state) => state.startingProjectMessage);
  const stoppingProjectId = useProjects((state) => state.stoppingProjectId);
  const stoppingProjectMessage = useProjects((state) => state.stoppingProjectMessage);
  const activeProjectId = activeProject?.id ?? null;
  const activeScanId = (() => {
    const scanMeta = isRecord(activeProject?.lastScan)
      ? activeProject?.lastScan
      : null;
    return typeof scanMeta?.scanId === "string" ? scanMeta.scanId.trim() : "";
  })();
  const activeLastScanStatus = (() => {
    const scanMeta = isRecord(activeProject?.lastScan)
      ? activeProject?.lastScan
      : null;
    return typeof scanMeta?.status === "string" ? scanMeta.status.trim().toLowerCase() : "";
  })();
  const shouldStreamScanEvents = Boolean(
    activeProjectId &&
    activeScanId &&
    (
      activeProject?.status === "running" ||
      activeLastScanStatus === "running" ||
      activeLastScanStatus === "awaiting_tool_approval" ||
      activeLastScanStatus === "awaiting_planner_approval" ||
      activeLastScanStatus === "awaiting_information_gathering_approval"
    ),
  );

  const [insightTab, setInsightTab] = useState<InsightTab>("checklist");
  const [isInsightFullscreen, setIsInsightFullscreen] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<any | null>(null);
  const [analyzerReportViewer, setAnalyzerReportViewer] = useState<AnalyzerReportViewerState>({
    open: false,
    title: "",
    description: "",
    markdown: "",
  });
  const [streamLogs, setStreamLogs] = useState<DashboardLogEntry[]>([]);
  const [scanEvents, setScanEvents] = useState<ScanEventPayload[]>([]);
  const [locallyAckedApprovalId, setLocallyAckedApprovalId] = useState<string | null>(null);
  const [locallyAckedPasswordId, setLocallyAckedPasswordId] = useState<string | null>(null);
  const [fallbackApprovalMode, setFallbackApprovalMode] = useState<ApprovalMode>(() => {
    const saved = typeof window !== "undefined" ? localStorage.getItem("pentaforge_approval_mode") : null;
    if (saved === "auto") return "auto";
    if (saved === "custom") return "custom";
    return "custom";
  });
  const approvalMode: ApprovalMode = activeProject?.approval_mode === "auto"
    ? "auto"
    : activeProject?.approval_mode === "custom"
      ? "custom"
      : fallbackApprovalMode;
  const [showApprovalModeMenu, setShowApprovalModeMenu] = useState(false);

  useEffect(() => {
    if (typeof window !== "undefined") {
      localStorage.setItem("pentaforge_approval_mode", fallbackApprovalMode);
    }
  }, [fallbackApprovalMode]);

  useEffect(() => {
    const refreshState =
      activeProject?.payload && isRecord(activeProject.payload) && isRecord(activeProject.payload.architecture_refresh)
        ? activeProject.payload.architecture_refresh
        : null;
    const status =
      typeof refreshState?.status === "string" ? refreshState.status.trim().toLowerCase() : "";
    const phase =
      typeof refreshState?.phase === "string" ? refreshState.phase.trim().toLowerCase() : "";
    const isRunning = status === "running";
    setIsArchitectRefreshing(isRunning);
    setIsArchitectCompressing(isRunning && phase === "compressing");
  }, [activeProject?.id, activeProject?.payload]);
  const approvalModeMenuRef = useRef<HTMLDivElement | null>(null);
  const [notificationPermission, setNotificationPermission] = useState<
    NotificationPermission | "unsupported"
  >(
    typeof window !== "undefined" && "Notification" in window
      ? Notification.permission
      : "unsupported",
  );
  const [notificationsEnabled, setNotificationsEnabled] = useState(false);
  const [logSourceFilter, setLogSourceFilter] = useState<string>("all");
  const [autoScrollLogs, setAutoScrollLogs] = useState(true);
  const [elapsedClockMs, setElapsedClockMs] = useState(() => Date.now());
  const logsContainerRef = useRef<HTMLDivElement | null>(null);
  const findingsSectionRef = useRef<HTMLDivElement | null>(null);
  const [streamRetry, setStreamRetry] = useState(0);
  const streamRetryRef = useRef(0);
  const lastStreamErrorRef = useRef(0);
  const lastLiveEventAtRef = useRef(0);
  const streamDegradedRef = useRef(true);
  const seenEventKeysRef = useRef<Set<string>>(new Set());
  const [stopDialogOpen, setStopDialogOpen] = useState(false);

  const [plannerApprovalLoading, setPlannerApprovalLoading] = useState(false);
  const [toolApprovalLoading, setToolApprovalLoading] = useState<"approve" | "skip" | null>(null);
  const [passwordResponseLoading, setPasswordResponseLoading] = useState<"approve" | "deny" | null>(null);
  const [pendingPasswordValue, setPendingPasswordValue] = useState("");
  const [falsePositiveLoadingId, setFalsePositiveLoadingId] = useState<string | null>(null);
  const [isArchitectRefreshing, setIsArchitectRefreshing] = useState(false);
  const [isArchitectCompressing, setIsArchitectCompressing] = useState(false);
  const [copilotDraft, setCopilotDraft] = useState<{ token: string; text: string } | null>(null);
  const [debugTimeline, setDebugTimeline] = useState<ScanDebugTimelineEntry[]>([]);
  const [observabilityMetrics, setObservabilityMetrics] = useState<ScanObservabilityMetrics>({
    average_cycle_time_seconds: 0,
    average_approval_delay_seconds: 0,
    tool_failure_rate: 0,
    false_positive_rate: 0,
    resume_success_rate: 0,
    cycle_count: 0,
    approval_count: 0,
    tool_log_count: 0,
    failed_tool_log_count: 0,
    false_positive_count: 0,
    verified_vulnerability_count: 0,
    resume_attempt_count: 0,
    resume_success_count: 0,
  });
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

  const syncArchitectureRefreshState = useCallback(
    (
      projectId: string,
      status: "running" | "idle" | "error",
      phase: string,
      opts?: { persist?: boolean; error?: string },
    ) => {
      const currentProject = useProjects
        .getState()
        .projects.find((project) => project.id === projectId);
      const currentPayload = isRecord(currentProject?.payload) ? currentProject.payload : {};
      const currentRefresh = isRecord(currentPayload.architecture_refresh)
        ? currentPayload.architecture_refresh
        : {};
      const nowIso = new Date().toISOString();
      const startedAt =
        typeof currentRefresh.started_at === "string" && currentRefresh.started_at.trim()
          ? currentRefresh.started_at
          : nowIso;

      updateProject(
        projectId,
        {
          payload: {
            ...currentPayload,
            architecture_refresh: {
              status,
              phase,
              updated_at: nowIso,
              ...(status === "running"
                ? { started_at: startedAt }
                : { started_at: startedAt, completed_at: nowIso }),
              ...(opts?.error ? { error: opts.error } : {}),
            },
          },
        } as any,
        { persist: opts?.persist ?? false },
      );
    },
    [updateProject],
  );
  const handleApprovalModeChange = useCallback(
    (mode: ApprovalMode) => {
      setFallbackApprovalMode(mode);
      if (activeProject && activeProject.approval_mode !== mode) {
        updateProject(activeProject.id, { approval_mode: mode });
      }
    },
    [activeProject, updateProject],
  );

  const config = useConfig();
  const isCopilotOpen = config.isAssistantOpen;
  const setIsCopilotOpen = (open: boolean) => config.updateConfig({ isAssistantOpen: open });
  const lastApprovalNotifiedRef = useRef<string>("");
  const lastPlannerApprovalNotifiedRef = useRef<string>("");
  const autoApprovalFailedIdsRef = useRef<Set<string>>(new Set());
  const dashboardSelectClass =
    "h-7 rounded-md border border-border bg-surface-1 px-2 py-1 text-sm text-text-primary outline-none transition-colors focus:border-pf-500/50 dark:[color-scheme:dark]";
  const approvalModeLabel: Record<ApprovalMode, string> = {
    custom: "Custom Approve",
    auto: "Auto",
  };
  const notificationsUnavailable = notificationPermission === "unsupported";

  const shouldAutoApproveForRole = useCallback(
    (role: string) => {
      // Worker callbacks prefix the role with "[worker N] " (e.g. "[worker 0] exploit").
      // Strip any bracket-prefixed segments to extract the base role.
      const pendingRole = role
        .replace(/\[worker\s*\d+\]\s*/gi, "")
        .trim()
        .toLowerCase();
      return approvalMode === "auto";
    },
    [approvalMode],
  );

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
    (event: ScanEventPayload & { is_cached?: boolean }, isLiveParam = true) => {
      const isLive = isLiveParam && !event.is_cached;
      if (!activeProjectId) {
        return;
      }
      if (isLive && event.event === "scan_started") {
        const isSavedPlanResume = isRecord(event.data.resume_plan);
        if (!isSavedPlanResume) {
          seenEventKeysRef.current.clear();
          setScanEvents([]);
          setStreamLogs([]);
          const activeProject = useProjects
            .getState()
            .projects.find((project) => project.id === activeProjectId);
          if (activeProject) {
            const currentPayload = isRecord(activeProject.payload) ? { ...activeProject.payload } : {};
            delete currentPayload[FINDINGS_HISTORY_KEY];
            delete currentPayload[LEGACY_FINDINGS_HISTORY_KEY];
            updateProject(
              activeProjectId,
              {
                findings: [],
                payload: Object.keys(currentPayload).length > 0 ? currentPayload : undefined,
                lastScan: {
                  scanId: event.scan_id,
                  status: "running",
                  startedAt: event.timestamp,
                  finishedAt: undefined,
                  elapsedSeconds: 0,
                  durationSeconds: undefined,
                  error: "",
                  result: undefined,
                },
              } as any,
              { persist: false },
            );
          }
        }
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
        const nextList = [...previous, nextEntry];
        if (nextList.length > 500) return nextList.slice(-500);
        return nextList;
      });

      if (!isLive) {
        return;
      }

      const nextStatus = toProjectStatus(event.data.status);
      const rawProgress = event.data.scan_progress;
      const nextProgress =
        typeof rawProgress === "number" && Number.isFinite(rawProgress)
          ? rawProgress
          : undefined;
      const rawElapsedSeconds = event.data.elapsed_seconds;
      const nextElapsedSeconds =
        typeof rawElapsedSeconds === "number" && Number.isFinite(rawElapsedSeconds)
          ? Math.max(0, Math.floor(rawElapsedSeconds))
          : undefined;
      const nextStartedAt =
        typeof event.data.started_at === "string" ? event.data.started_at : undefined;
      const nextFinishedAt =
        typeof event.data.finished_at === "string" ? event.data.finished_at : undefined;

      const activeProject = useProjects
        .getState()
        .projects.find((project) => project.id === activeProjectId);
      const currentLastScan = isRecord(activeProject?.lastScan)
        ? activeProject?.lastScan
        : {};
      const currentLastScanStatus =
        typeof currentLastScan.status === "string"
          ? currentLastScan.status.trim().toLowerCase()
          : "";
      const isCurrentlyWaiting =
        currentLastScanStatus === "awaiting_tool_approval" ||
        currentLastScanStatus === "awaiting_planner_approval" ||
        currentLastScanStatus === "awaiting_information_gathering_approval";

      // If we are currently in a waiting state, do not let generic status updates
      // overwrite it back to "running".
      const shouldUpdateStatus =
        nextStatus &&
        !(isCurrentlyWaiting && nextStatus === "running");

      if (
        shouldUpdateStatus ||
        typeof nextProgress === "number" ||
        typeof nextElapsedSeconds === "number" ||
        nextStartedAt ||
        nextFinishedAt
      ) {
        updateProject(
          activeProjectId,
          {
            ...(shouldUpdateStatus ? { status: nextStatus } : {}),
            ...(typeof nextProgress === "number"
              ? { scanProgress: nextProgress }
              : {}),
            lastScan: {
              ...currentLastScan,
              ...(shouldUpdateStatus ? { status: nextStatus } : {}),
              ...(nextStartedAt ? { startedAt: nextStartedAt } : {}),
              ...(nextFinishedAt ? { finishedAt: nextFinishedAt } : {}),
              ...(typeof nextElapsedSeconds === "number"
                ? {
                  elapsedSeconds: nextElapsedSeconds,
                  ...(shouldUpdateStatus && nextStatus !== "running"
                    ? { durationSeconds: nextElapsedSeconds }
                    : {}),
                }
                : {}),
            },
          },
          { persist: false },
        );
      }

      // Architecture Agent States
      if (event.event === "architect_synthesizing") {
        syncArchitectureRefreshState(activeProjectId, "running", "synthesizing");
        setIsArchitectRefreshing(true);
      }
      if (event.event === "architect_compressing") {
        syncArchitectureRefreshState(activeProjectId, "running", "compressing");
        setIsArchitectCompressing(true);
      }
      if (event.event === "architect_updated") {
        syncArchitectureRefreshState(activeProjectId, "idle", "idle");
        setIsArchitectRefreshing(false);
        setIsArchitectCompressing(false);
        const architecture_draft = event.data.architecture_draft;
        if (isRecord(architecture_draft)) {
          const currentProject = useProjects
            .getState()
            .projects.find((project) => project.id === activeProjectId);
          updateProject(activeProjectId, {
            payload: {
              ...(currentProject?.payload ?? {}),
              architecture_draft: architecture_draft as any,
            }
          } as any, { persist: false });
        }
      }
      if (event.event === "architect_no_update") {
        syncArchitectureRefreshState(activeProjectId, "idle", "idle");
        setIsArchitectRefreshing(false);
        setIsArchitectCompressing(false);
      }
      if (event.event === "architect_failed") {
        const errorText =
          typeof event.data?.error === "string" ? event.data.error.slice(0, 300) : "Architect refresh failed";
        syncArchitectureRefreshState(activeProjectId, "error", "error", { error: errorText });
        setIsArchitectRefreshing(false);
        setIsArchitectCompressing(false);
      }

      if (event.event === "analyzer_report_saved" && isRecord(event.data.report)) {
        const incomingReport = event.data.report as Record<string, unknown>;
        const reportRole = normalizeAnalyzerAgentReportRole(
          typeof incomingReport.agent === "string" ? incomingReport.agent : "",
        );
        if (reportRole) {
          const currentProject = useProjects
            .getState()
            .projects.find((project) => project.id === activeProjectId);
          const currentPayload = isRecord(currentProject?.payload) ? currentProject.payload : {};
          const currentRoot = getFindingsHistoryRoot(currentPayload) || {};
          const currentBucket = isRecord(currentRoot[reportRole]) ? currentRoot[reportRole] : {};
          const currentEntries = Array.isArray(currentBucket.entries)
            ? currentBucket.entries.filter((item): item is Record<string, unknown> => isRecord(item))
            : [];
          const nextEntries = [
            incomingReport,
            ...currentEntries.filter((item) => String(item.id || "") !== String(incomingReport.id || "")),
          ];

          updateProject(
            activeProjectId,
            {
              updatedAt: event.timestamp,
              payload: {
                ...currentPayload,
                [FINDINGS_HISTORY_KEY]: {
                  ...currentRoot,
                  [reportRole]: {
                    ...currentBucket,
                    updated_at: typeof incomingReport.updated_at === "string"
                      ? incomingReport.updated_at
                      : event.timestamp,
                    entries: nextEntries,
                  },
                },
              },
            } as any,
            { persist: false },
          );
        }
      }

      if (event.event === "verify_finding_saved" && isRecord(event.data.finding)) {
        const finding = event.data.finding as Record<string, unknown>;
        const activeProject = useProjects
          .getState()
          .projects.find((project) => project.id === activeProjectId);
        if (activeProject) {
          const currentFindings = Array.isArray(activeProject.findings)
            ? [...activeProject.findings]
            : [];
          const incomingId = typeof finding.id === "string" ? finding.id : "";
          const incomingTitle = typeof finding.title === "string" ? finding.title.trim().toLowerCase() : "";
          const incomingTarget = typeof finding.target === "string" ? finding.target.trim().toLowerCase() : "";
          const incomingCategory = typeof finding.category === "string" ? finding.category.trim().toLowerCase() : "";
          const existingIndex = currentFindings.findIndex((row) => {
            const rowId = typeof row.id === "string" ? row.id : "";
            if (incomingId && rowId === incomingId) {
              return true;
            }
            return (
              String(row.title ?? "").trim().toLowerCase() === incomingTitle
              && String(row.target ?? "").trim().toLowerCase() === incomingTarget
              && String(row.category ?? "").trim().toLowerCase() === incomingCategory
            );
          });

          const normalizedFinding: Finding = {
            id: incomingId,
            title: typeof finding.title === "string" ? finding.title : "Verified finding",
            severity: normalizeDashboardSeverity(
              typeof finding.severity === "string" ? finding.severity : "medium",
            ),
            category: typeof finding.category === "string" ? finding.category : "unknown",
            target: typeof finding.target === "string" ? finding.target : "",
            status:
              finding.status === "open"
                || finding.status === "verified"
                || finding.status === "fixed"
                || finding.status === "false_positive"
                ? finding.status
                : "verified",
            cvss:
              typeof finding.cvss === "number" && Number.isFinite(finding.cvss)
                ? finding.cvss
                : undefined,
            cve: typeof finding.cve === "string" ? finding.cve : undefined,
            description: typeof finding.description === "string" ? finding.description : "",
            evidence: (isRecord(finding.evidence) ? finding.evidence : undefined) as Finding["evidence"],
            evidenceStatus: normalizeEvidenceStatus(
              isRecord(finding.evidence)
                ? finding.evidence.evidence_status
                : finding.evidence_status,
            ),
            proofQuality: normalizeProofQuality(
              isRecord(finding.evidence)
                ? finding.evidence.proof_quality
                : finding.proof_quality,
            ),
            deterministicValidation:
              typeof finding.deterministic_validation === "boolean"
                ? finding.deterministic_validation
                : (
                  isRecord(finding.evidence) && typeof finding.evidence.deterministic_validation === "boolean"
                    ? finding.evidence.deterministic_validation
                    : undefined
                ),
            verificationMethods:
              Array.isArray(finding.verification_methods)
                ? finding.verification_methods.filter((item): item is string => typeof item === "string")
                : (
                  isRecord(finding.evidence) && Array.isArray(finding.evidence.verification_methods)
                    ? finding.evidence.verification_methods.filter((item): item is string => typeof item === "string")
                    : undefined
                ),
            remediation: typeof finding.remediation === "string" ? finding.remediation : undefined,
            timestamp: typeof finding.timestamp === "string" ? finding.timestamp : event.timestamp,
          };
          if (existingIndex >= 0) {
            currentFindings[existingIndex] = {
              ...currentFindings[existingIndex],
              ...normalizedFinding,
            };
          } else {
            currentFindings.unshift(normalizedFinding);
          }

          updateProject(
            activeProjectId,
            {
              updatedAt: event.timestamp,
              findings: currentFindings,
            },
            { persist: false },
          );
        }
      }

      const eventPlanData = isRecord(event.data.plan_data)
        ? event.data.plan_data
        : null;
      const eventNeeds = Array.isArray(event.data.needs)
        ? event.data.needs
        : undefined;
      const eventSummary = normalizeText(event.data.summary);
      const isWarmupPlanEvent =
        event.event === "warmup_plan_ready"
        || event.data.warmup === true
        || normalizeText(event.data.stage) === "warmup";
      const isPlannerPlanEvent =
        event.event === "plan_updated_by_planner"
        || event.event === "planner_complete"
        || event.event === "warmup_plan_ready"
        || (event.event === "scenario_state_change" && eventPlanData !== null);

      if (eventPlanData || eventNeeds || eventSummary) {
        const activeProject = useProjects
          .getState()
          .projects.find((project) => project.id === activeProjectId);
        if (activeProject) {
          const lastScan = isRecord(activeProject?.lastScan)
            ? activeProject?.lastScan
            : {};
          const result = isRecord(lastScan.result) ? lastScan.result : {};
          const currentPlanner = isRecord(result.planner) ? result.planner : {};
          const currentWarmup = isRecord(result.warmup) ? result.warmup : {};

          const nextPlanner = isPlannerPlanEvent
            ? {
              ...currentPlanner,
              ...(eventPlanData ? { plan_data: eventPlanData } : {}),
              ...(eventNeeds ? { needs: eventNeeds } : {}),
              ...(eventSummary ? { summary: eventSummary } : {}),
            }
            : currentPlanner;

          const nextWarmup = isWarmupPlanEvent
            ? {
              ...currentWarmup,
              ...(eventPlanData ? { plan: eventPlanData } : {}),
            }
            : currentWarmup;

          useProjects.setState((state) => {
            const innerActive = state.projects.find((p) => p.id === activeProjectId);
            if (!innerActive) return state;
            const innerLastScan = isRecord(innerActive.lastScan) ? innerActive.lastScan : {};
            const innerResult = isRecord(innerLastScan.result) ? innerLastScan.result : {};

            return {
              projects: state.projects.map((p) =>
                p.id === activeProjectId
                  ? {
                    ...p,
                    updatedAt: event.timestamp,
                    lastScan: {
                      ...innerLastScan,
                      result: {
                        ...innerResult,
                        ...(isPlannerPlanEvent ? { planner: nextPlanner } : {}),
                        ...(isWarmupPlanEvent ? { warmup: nextWarmup } : {}),
                      },
                    },
                  }
                  : p
              ),
            };
          });
        }
      }

      if (
        event.event === "planner_checklist_started" ||
        event.event === "planner_checklist_complete" ||
        event.event === "planner_waiting_approval" ||
        event.event === "planner_approval_received" ||
        event.event === "planner_started" ||
        event.event === "planner_complete" ||
        event.event === "planner_failed" ||
        event.event === "planner_crashed"
      ) {
        const activeProject = useProjects
          .getState()
          .projects.find((project) => project.id === activeProjectId);
        if (activeProject) {
          const lastScan = isRecord(activeProject?.lastScan)
            ? activeProject?.lastScan
            : {};
          const result = isRecord(lastScan.result) ? lastScan.result : {};
          const currentIntel = isRecord(result.intel) ? result.intel : {};
          const nextIntel: Record<string, unknown> = { ...currentIntel };

          if (event.event === "planner_checklist_started") {
            nextIntel.status = "running";
          }

          if (event.event === "planner_checklist_complete") {
            nextIntel.status = normalizeText(event.data.intel_status) || "complete";
            if (event.data.checklist) {
              nextIntel.checklist = event.data.checklist;
            }
            if (eventSummary) {
              nextIntel.summary = eventSummary;
            }
          }

          if (event.event === "planner_waiting_approval") {
            nextIntel.status = "awaiting_approval";
          }

          const clearPlannerApproval =
            event.event === "planner_approval_received" ||
            event.event === "planner_started" ||
            event.event === "planner_complete" ||
            event.event === "planner_failed" ||
            event.event === "planner_crashed";

          useProjects.setState((state) => {
            const innerActive = state.projects.find((p) => p.id === activeProjectId);
            if (!innerActive) return state;
            const innerLastScan = isRecord(innerActive.lastScan) ? innerActive.lastScan : {};
            const innerResult = isRecord(innerLastScan.result) ? innerLastScan.result : {};

            return {
              projects: state.projects.map((p) =>
                p.id === activeProjectId
                  ? {
                    ...p,
                    updatedAt: event.timestamp,
                    lastScan: {
                      ...innerLastScan,
                      ...(event.event === "planner_waiting_approval"
                        ? { awaitingPlannerApproval: true, status: "awaiting_planner_approval" }
                        : {}),
                      ...(event.event === "planner_checklist_started"
                        ? { status: "running" }
                        : {}),
                      ...(clearPlannerApproval
                        ? { awaitingPlannerApproval: false, status: "running" }
                        : {}),
                      result: {
                        ...innerResult,
                        intel: nextIntel,
                      },
                    },
                  }
                  : p
              ),
            };
          });
        }
      }

      if (
        event.event === "target_info_gathering_program_organized" ||
        event.event === "target_info_gathering_block_started" ||
        event.event === "target_info_gathering_block_completed" ||
        event.event === "target_info_gathering_waiting_approval" ||
        event.event === "target_info_gathering_approval_received" ||
        event.event === "target_info_gathering_complete"
      ) {
        const activeProject = useProjects
          .getState()
          .projects.find((project) => project.id === activeProjectId);
        if (activeProject) {
          const lastScan = isRecord(activeProject?.lastScan)
            ? activeProject?.lastScan
            : {};
          const result = isRecord(lastScan.result) ? lastScan.result : {};
          const currentGathering = isRecord(result.targetInfoGathering)
            ? result.targetInfoGathering
            : {};
          const nextGathering: Record<string, unknown> = { ...currentGathering };

          if (event.event === "target_info_gathering_program_organized" && isRecord(event.data.program)) {
            nextGathering.status = "organized";
            const blocks = Array.isArray(event.data.program.blocks) ? event.data.program.blocks : [];
            if (blocks.length > 0) {
              nextGathering.program = blocks;
            }
            if (isRecord(event.data.program.paths)) {
              nextGathering.paths = event.data.program.paths;
            }
          }

          if (event.event === "target_info_gathering_block_started" && isRecord(event.data.block)) {
            const block = event.data.block;
            nextGathering.status = "running";
            nextGathering.workingBlockId = normalizeText(block.id);
          }

          if (event.event === "target_info_gathering_block_completed" && isRecord(event.data.block)) {
            const block = event.data.block;
            const currentBlocks = Array.isArray(nextGathering.blocks) ? [...nextGathering.blocks] : [];
            const blockId = normalizeText(block.id);
            const existingIndex = currentBlocks.findIndex(
              (item) => isRecord(item) && normalizeText(item.id) === blockId,
            );
            if (existingIndex >= 0) {
              currentBlocks[existingIndex] = block;
            } else {
              currentBlocks.push(block);
            }
            nextGathering.status = "running";
            nextGathering.blocks = currentBlocks;
            if (normalizeText(nextGathering.workingBlockId) === blockId) {
              nextGathering.workingBlockId = "";
            }
          }

          if (event.event === "target_info_gathering_waiting_approval") {
            nextGathering.status = "organized";
          }

          if (event.event === "target_info_gathering_approval_received") {
            nextGathering.status = "running";
          }

          if (event.event === "target_info_gathering_complete") {
            nextGathering.status = "completed";
            nextGathering.workingBlockId = "";
            if (isRecord(event.data.gathering)) {
              const gathering = event.data.gathering;
              if (Array.isArray(gathering.program)) {
                if (gathering.program.length > 0) {
                  nextGathering.program = gathering.program;
                }
              }
              if (Array.isArray(gathering.blocks)) {
                if (gathering.blocks.length > 0) {
                  nextGathering.blocks = gathering.blocks;
                }
              }
            }
            if (isRecord(event.data.target_memory)) {
              nextGathering.paths = event.data.target_memory;
            }
          }

          useProjects.setState((state) => {
            const innerActive = state.projects.find((p) => p.id === activeProjectId);
            if (!innerActive) return state;
            const innerLastScan = isRecord(innerActive.lastScan) ? innerActive.lastScan : {};
            const innerResult = isRecord(innerLastScan.result) ? innerLastScan.result : {};

            return {
              projects: state.projects.map((p) =>
                p.id === activeProjectId
                  ? {
                    ...p,
                    updatedAt: event.timestamp,
                    lastScan: {
                      ...innerLastScan,
                      ...(event.event === "target_info_gathering_waiting_approval"
                        ? {}
                        : {}),
                      ...(event.event === "target_info_gathering_approval_received" ||
                        event.event === "target_info_gathering_complete"
                        ? { status: "running" }
                        : {}),
                      result: {
                        ...innerResult,
                        targetInfoGathering: nextGathering,
                      },
                    },
                  }
                  : p
              ),
            };
          });
        }
      }

      if (
        event.event === "executer_tool_waiting_approval" ||
        event.event === "executer_tool_approval_decision" ||
        event.event === "executer_tool_approval_cleared" ||
        event.event === "executer_tool_approval_timeout"
      ) {
        const clearToolApproval =
          event.event === "executer_tool_approval_decision" ||
          event.event === "executer_tool_approval_cleared" ||
          event.event === "executer_tool_approval_timeout";

        useProjects.setState((state) => {
          const innerActive = state.projects.find((p) => p.id === activeProjectId);
          if (!innerActive) return state;
          const innerLastScan = isRecord(innerActive.lastScan) ? innerActive.lastScan : {};

          return {
            projects: state.projects.map((p) =>
              p.id === activeProjectId
                ? {
                  ...p,
                  updatedAt: event.timestamp,
                  lastScan: {
                    ...innerLastScan,
                    ...(event.event === "executer_tool_waiting_approval"
                      ? { awaitingToolApproval: true, status: "awaiting_tool_approval" }
                      : {}),
                    ...(clearToolApproval
                      ? { awaitingToolApproval: false, status: "running" }
                      : {}),
                  },
                }
                : p
            ),
          };
        });
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

    void hydrateFromDatabase();
  }, [activeProjectId, hydrateFromDatabase]);

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
          const nextList = [...previous, nextEntry];
          if (nextList.length > 500) return nextList.slice(-500);
          return nextList;
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
  }, [streamLogs.length, autoScrollLogs, logSourceFilter]);

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
          700,
        );
        if (cancelled || recent.length === 0) {
          return;
        }
        const chronological = [...recent].reverse();
        for (const event of chronological) {
          ingestScanEvent(event, false);
        }
      } catch {
        // Ignore polling errors; SSE remains primary channel.
      }
    };

    void fetchRecent();
    const timer = window.setInterval(() => {
      void fetchRecent();
    }, 5000);  // Reduced polling frequency to 5s to avoid rate limiter

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [activeProjectId, shouldStreamScanEvents, ingestScanEvent]);

  useEffect(() => {
    if (!activeProjectId || !isArchitectRefreshing) {
      return;
    }

    let cancelled = false;
    let failedHydrates = 0;
    const pollProjectState = async () => {
      try {
        const ok = await hydrateFromDatabase();
        if (cancelled) {
          return;
        }
        if (ok) {
          failedHydrates = 0;
          return;
        }
        failedHydrates += 1;
        if (failedHydrates >= 2) {
          syncArchitectureRefreshState(
            activeProjectId,
            "error",
            "server_unavailable",
            { error: "Architecture refresh stopped because the server is unavailable." },
          );
          setIsArchitectRefreshing(false);
          setIsArchitectCompressing(false);
        }
      } catch {
        if (cancelled) {
          return;
        }
        failedHydrates += 1;
        if (failedHydrates >= 2) {
          syncArchitectureRefreshState(
            activeProjectId,
            "error",
            "server_unavailable",
            { error: "Architecture refresh stopped because the server is unavailable." },
          );
          setIsArchitectRefreshing(false);
          setIsArchitectCompressing(false);
        }
      }
    };

    void pollProjectState();
    const timer = window.setInterval(() => {
      if (!cancelled) {
        void pollProjectState();
      }
    }, 2000);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [activeProjectId, isArchitectRefreshing, hydrateFromDatabase]);

  useEffect(() => {
    if (!activeProjectId) {
      setDebugTimeline([]);
      setObservabilityMetrics({
        average_cycle_time_seconds: 0,
        average_approval_delay_seconds: 0,
        tool_failure_rate: 0,
        false_positive_rate: 0,
        resume_success_rate: 0,
        cycle_count: 0,
        approval_count: 0,
        tool_log_count: 0,
        failed_tool_log_count: 0,
        false_positive_count: 0,
        verified_vulnerability_count: 0,
        resume_attempt_count: 0,
        resume_success_count: 0,
      });
      return;
    }

    let cancelled = false;
    const load = async () => {
      try {
        const snapshot = await getProjectScanObservabilityFromDesktop(
          activeProjectId,
          700,
          activeScanId || undefined,
        );
        if (cancelled) {
          return;
        }
        setDebugTimeline(snapshot.timeline);
        setObservabilityMetrics(snapshot.metrics);
      } catch {
        // Keep the last successful snapshot visible.
      }
    };

    void load();
    const intervalId = window.setInterval(() => {
      if (!cancelled) {
        void load();
      }
    }, 5000);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [activeProjectId, activeScanId, scanEvents.length, activeProject?.findings.length]);

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

  useEffect(() => {
    setElapsedClockMs(Date.now());

    const lastScan = isRecord(activeProject?.lastScan) ? activeProject?.lastScan : null;
    const startedAt =
      typeof lastScan?.startedAt === "string" ? lastScan.startedAt.trim() : "";
    const status =
      typeof lastScan?.status === "string" ? lastScan.status.trim().toLowerCase() : "";

    if (!startedAt || status !== "running") {
      return undefined;
    }

    const intervalId = window.setInterval(() => {
      setElapsedClockMs(Date.now());
    }, 1000);

    return () => window.clearInterval(intervalId);
  }, [activeProject?.lastScan]);

  useEffect(() => {
    if (searchParams.get("focus") !== "findings") {
      return;
    }
    const frame = window.requestAnimationFrame(() => {
      findingsSectionRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [searchParams, activeProject?.id]);

  const effectiveStatus = activeProject ? normalizeRunningStatus(activeProject) : "idle";

  useEffect(() => {
    if (effectiveStatus === "idle") {
      setStreamLogs([]);
      setScanEvents([]);
      setLocallyAckedApprovalId(null);
      seenEventKeysRef.current.clear();
    }
  }, [effectiveStatus]);
  const isRunning = effectiveStatus === "running";
  const isScanActive =
    effectiveStatus === "running" ||
    effectiveStatus === "awaiting_tool_approval" ||
    effectiveStatus === "awaiting_planner_approval" ||
    effectiveStatus === "awaiting_information_gathering_approval";
  const isStarting = activeProject ? startingProjectId === activeProject.id : false;
  const activeLastScan = isRecord(activeProject?.lastScan)
    ? activeProject?.lastScan
    : null;
  const analyzerReportEntries = useMemo(() => {
    const savedEntries = getAnalyzerAgentReportEntries(activeProject?.payload, activeScanId || undefined);
    const hasSavedInfoGathering = savedEntries.some((entry) => entry.agent === "information_gathering");
    if (hasSavedInfoGathering) {
      return savedEntries;
    }
    const fallbackEntries = getFallbackInformationGatheringEntries(activeProject ?? null, activeScanId || undefined);
    return [...fallbackEntries, ...savedEntries];
  }, [activeProject, activeScanId]);
  const pendingToolApproval: PendingToolApprovalView | null = (() => {
    if (!activeProject) return null;
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
        event.event === "executer_tool_approval_cleared" ||
        event.event === "scan_completed" ||
        event.event === "scan_failed" ||
        event.event === "scan_paused" ||
        event.event === "scan_cancelled"
      ) {
        return null;
      }
    }

    const lastScan = isRecord(activeProject?.lastScan)
      ? activeProject?.lastScan
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
  const openAnalyzerAgentReport = useCallback(
    () => {
      const markdown = analyzerReportEntries.length > 0
        ? buildCombinedAnalyzerMarkdown(analyzerReportEntries, activeScanId || undefined)
        : [
          "# Findings History Markdown",
          "",
          "No saved findings history markdown is available yet for this pipeline.",
          "",
          `- Project: ${activeProject?.name || "Unknown Project"}`,
          `- Status: ${effectiveStatus}`,
          `- Pending Tool Approval: ${pendingToolApproval?.toolName || "none"}`,
          `- Current Scan ID: ${activeScanId || "none"}`,
          `- Classified Analyzer Entries Saved: ${analyzerReportEntries.length}`,
          "",
          "Findings history is saved after information gathering, recon, or exploit results are returned and organized.",
        ].join("\n");
      const latestEntry = analyzerReportEntries[analyzerReportEntries.length - 1] ?? null;
      const summaryLine = latestEntry?.sequence_label?.trim()
        || latestEntry?.summary?.trim()
        || latestEntry?.scenario_task?.trim()
        || pendingToolApproval?.toolName?.trim()
        || "Combined findings history markdown for this scan";
      setAnalyzerReportViewer({
        open: true,
        title: "Findings History Markdown",
        description: summaryLine,
        markdown,
      });
    },
    [
      activeScanId,
      activeProject?.name,
      analyzerReportEntries,
      effectiveStatus,
      pendingToolApproval?.toolName,
      setAnalyzerReportViewer,
    ],
  );

  useEffect(() => {
    if (!analyzerReportViewer.open) {
      return;
    }
    const markdown = analyzerReportEntries.length > 0
      ? buildCombinedAnalyzerMarkdown(analyzerReportEntries, activeScanId || undefined)
      : [
        "# Findings History Markdown",
        "",
        "No saved findings history markdown is available yet for this pipeline.",
        "",
        `- Project: ${activeProject?.name || "Unknown Project"}`,
        `- Status: ${effectiveStatus}`,
        `- Pending Tool Approval: ${pendingToolApproval?.toolName || "none"}`,
        `- Current Scan ID: ${activeScanId || "none"}`,
        `- Classified Findings History Entries Saved: ${analyzerReportEntries.length}`,
        "",
        "Findings history is saved after information gathering, recon, or exploit results are returned and organized.",
      ].join("\n");
    const latestEntry = analyzerReportEntries[analyzerReportEntries.length - 1] ?? null;
    const description = latestEntry?.sequence_label?.trim()
      || latestEntry?.summary?.trim()
      || latestEntry?.scenario_task?.trim()
      || pendingToolApproval?.toolName?.trim()
      || "Combined findings history markdown for this scan";
    setAnalyzerReportViewer((current) => {
      if (
        current.title === "Findings History Markdown"
        && current.description === description
        && current.markdown === markdown
      ) {
        return current;
      }
      return {
        ...current,
        title: "Findings History Markdown",
        description,
        markdown,
      };
    });
  }, [
    activeProject?.name,
    activeScanId,
    analyzerReportEntries,
    analyzerReportViewer.open,
    effectiveStatus,
    pendingToolApproval?.toolName,
  ]);

  const persistedElapsedSeconds =
    typeof activeLastScan?.elapsedSeconds === "number" &&
      Number.isFinite(activeLastScan.elapsedSeconds)
      ? Math.max(0, Math.floor(activeLastScan.elapsedSeconds))
      : 0;
  const timerStartedAt =
    typeof activeLastScan?.startedAt === "string"
      ? activeLastScan.startedAt.trim()
      : "";
  const liveElapsedSeconds = (() => {
    if (!isRunning || !timerStartedAt) {
      return persistedElapsedSeconds;
    }
    const parsed = new Date(timerStartedAt);
    if (Number.isNaN(parsed.getTime())) {
      return persistedElapsedSeconds;
    }
    return Math.max(
      persistedElapsedSeconds,
      Math.floor((elapsedClockMs - parsed.getTime()) / 1000),
    );
  })();
  const displayedPentestElapsed = formatPentestElapsed(liveElapsedSeconds);
  const hasAnotherRunningProject = projects.some((project) => {
    if (project.id === activeProject?.id) return false;
    const status = normalizeRunningStatus(project);
    return (
      status === "running" ||
      status === "awaiting_tool_approval" ||
      status === "awaiting_planner_approval" ||
      status === "awaiting_information_gathering_approval"
    );
  });
  const canRun = !isScanActive && !isStarting && stoppingProjectId !== activeProjectId && !hasAnotherRunningProject;

  const awaitingPlannerApproval = (() => {
    if (!activeProject) return false;
    for (const event of scanEvents) {
      if (
        event.event === "planner_waiting_approval" ||
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
        return event.event === "planner_waiting_approval";
      }
    }

    const lastScan = isRecord(activeProject?.lastScan)
      ? activeProject?.lastScan
      : null;
    const waitingFlag = lastScan?.awaitingPlannerApproval;
    if (typeof waitingFlag === "boolean") {
      return waitingFlag;
    }
    return lastScan?.status === "awaiting_planner_approval";
  })();

  const pendingToolCommandPreview = buildPendingApprovalCommand(pendingToolApproval);
  const autoApprovingPendingTool = Boolean(
    isScanActive
    && pendingToolApproval
    && shouldAutoApproveForRole(String(pendingToolApproval.role || ""))
    && !autoApprovalFailedIdsRef.current.has(pendingToolApproval.approvalId)
    && !toolApprovalLoading,
  );
  const orchestratorPipelineHeaderReport = analyzerReportEntries[analyzerReportEntries.length - 1] ?? null;
  const analyzerPipelineActivities = useMemo(
    () => getAnalyzerPipelineActivities(analyzerReportEntries),
    [analyzerReportEntries],
  );
  const pendingPasswordRequest: PendingPasswordRequestView | null = (() => {
    if (!activeProject) return null;
    for (const event of scanEvents) {
      if (event.event === "executer_password_request") {
        const data = event.data;
        const candidate = {
          passwordId: typeof data.password_id === "string" ? data.password_id : "",
          toolName: typeof data.tool_name === "string" ? data.tool_name : "",
          prompt: typeof data.prompt === "string" ? data.prompt : "",
          reason: typeof data.reason === "string" ? data.reason : "",
          callId: typeof data.call_id === "string" ? data.call_id : "",
        };
        if (
          candidate.passwordId &&
          locallyAckedPasswordId &&
          candidate.passwordId === locallyAckedPasswordId
        ) {
          return null;
        }
        return candidate;
      }
      if (
        event.event === "executer_password_response" ||
        event.event === "executer_password_timeout" ||
        event.event === "scan_completed" ||
        event.event === "scan_failed" ||
        event.event === "scan_paused" ||
        event.event === "scan_cancelled"
      ) {
        return null;
      }
    }
    return null;
  })();


  const handleRefreshArchitecture = async () => {
    if (!activeProjectId || isArchitectRefreshing || isArchitectCompressing) {
      return;
    }
    syncArchitectureRefreshState(activeProjectId, "running", "synthesizing");
    setIsArchitectRefreshing(true);
    setIsArchitectCompressing(false);
    try {
      const { synthesizeProjectArchitectureFromDesktop } = await import("@/lib/projectBridge");
      const result = await synthesizeProjectArchitectureFromDesktop(activeProjectId);
      const architectureDraft = result?.architecture_draft;
      if (
        isRecord(architectureDraft) &&
        Array.isArray(architectureDraft.hosts) &&
        architectureDraft.hosts.length > 0
      ) {
        updateProject(activeProjectId, {
          payload: {
            ...(activeProject?.payload ?? {}),
            architecture_draft: architectureDraft as any,
          },
        } as any, { persist: false });
      }
    } catch (error) {
      console.error("Failed to refresh architecture:", error);
      syncArchitectureRefreshState(
        activeProjectId,
        "error",
        "error",
        {
          error: error instanceof Error ? error.message : "Failed to refresh architecture.",
        },
      );
      setIsArchitectRefreshing(false);
      setIsArchitectCompressing(false);
    }
  };

  const handleApprovePlanner = async () => {
    if (!activeProjectId || plannerApprovalLoading || !isScanActive) {
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
        const nextList = [...previous, nextEntry];
        if (nextList.length > 500) return nextList.slice(-500);
        return nextList;
      });
    } finally {
      setPlannerApprovalLoading(false);
    }
  };

  const handleToolApproval = async (action: "approve" | "skip") => {
    if (!activeProject || !activeProjectId || !isScanActive || !pendingToolApproval?.approvalId || toolApprovalLoading) {
      return;
    }
    const approvalId = pendingToolApproval.approvalId;
    setLocallyAckedApprovalId(approvalId);
    setToolApprovalLoading(action);

    // Optimistically update the UI to "running"
    updateProject(
      activeProject.id,
      {
        status: "running",
      },
      { persist: false }
    );
    useProjects.setState((state) => {
      const innerActive = state.projects.find((p) => p.id === activeProject.id);
      if (!innerActive) return state;
      const innerLastScan = isRecord(innerActive.lastScan) ? innerActive.lastScan : {};
      return {
        projects: state.projects.map((p) =>
          p.id === activeProject.id
            ? {
              ...p,
              lastScan: {
                ...innerLastScan,
                awaitingToolApproval: false,
                status: "running",
              },
            }
            : p
        ),
      };
    });

    try {
      await approveToolForProjectScanFromDesktop(activeProjectId, {
        approvalId,
        action,
      });
      autoApprovalFailedIdsRef.current.delete(approvalId);
    } catch (error) {
      setLocallyAckedApprovalId(null);
      let message = "Failed to submit tool approval.";
      if (error instanceof Error) {
        message =
          error.name === "AbortError"
            ? "Approval request timed out while waiting for server response."
            : error.message;
      }
      autoApprovalFailedIdsRef.current.add(approvalId);
      setStreamLogs((previous) => {
        const nextEntry: DashboardLogEntry = {
          id: `tool-approve-error-${Math.random().toString(36).slice(2, 10)}`,
          level: "warn",
          message: `Tool approval failed: ${message}`,
          at: new Date().toISOString(),
          source: "executer",
        };
        const nextList = [...previous, nextEntry];
        if (nextList.length > 500) return nextList.slice(-500);
        return nextList;
      });
    } finally {
      setToolApprovalLoading(null);
    }
  };

  const handlePasswordResponse = async (approved: boolean) => {
    if (!activeProjectId || !isScanActive || !pendingPasswordRequest?.passwordId || passwordResponseLoading) {
      return;
    }
    const passwordId = pendingPasswordRequest.passwordId;
    const submittedPassword = approved ? pendingPasswordValue : "";
    setLocallyAckedPasswordId(passwordId);
    setPasswordResponseLoading(approved ? "approve" : "deny");
    try {
      await approvePasswordForProjectScanFromDesktop(activeProjectId, {
        passwordId,
        password: submittedPassword,
        approved,
      });
      setPendingPasswordValue("");
    } catch (error) {
      setLocallyAckedPasswordId(null);
      let message = "Failed to submit password response.";
      if (error instanceof Error) {
        message =
          error.name === "AbortError"
            ? "Password response timed out while waiting for server response."
            : error.message;
      }
      setStreamLogs((previous) => {
        const nextEntry: DashboardLogEntry = {
          id: `password-response-error-${Math.random().toString(36).slice(2, 10)}`,
          level: "warn",
          message: `Password response failed: ${message}`,
          at: new Date().toISOString(),
          source: "executer",
        };
        const nextList = [...previous, nextEntry];
        if (nextList.length > 500) return nextList.slice(-500);
        return nextList;
      });
    } finally {
      setPasswordResponseLoading(null);
    }
  };

  const requestNotificationAccess = async () => {
    if (typeof window === "undefined" || !("Notification" in window)) {
      setNotificationPermission("unsupported");
      setNotificationsEnabled(false);
      return;
    }
    if (notificationsEnabled) {
      setNotificationsEnabled(false);
      try {
        window.localStorage.setItem(NOTIFICATION_PREF_KEY, "0");
      } catch {
        // ignore storage failures
      }
      return;
    }
    if (Notification.permission === "denied") {
      setNotificationPermission("denied");
      setNotificationsEnabled(false);
      try {
        window.localStorage.setItem(NOTIFICATION_PREF_KEY, "0");
      } catch {
        // ignore storage failures
      }
      setStreamLogs((previous) => {
        const nextEntry: DashboardLogEntry = {
          id: `notif-denied-${Math.random().toString(36).slice(2, 10)}`,
          level: "warn",
          message:
            "Notifications are blocked by browser/OS settings. Please enable notifications for this app.",
          at: new Date().toISOString(),
          source: "system",
        };
        const nextList = [...previous, nextEntry];
        if (nextList.length > 500) return nextList.slice(-500);
        return nextList;
      });
      return;
    }
    try {
      const next = await Notification.requestPermission();
      setNotificationPermission(next);
      if (next === "granted") {
        setNotificationsEnabled(true);
        try {
          window.localStorage.setItem(NOTIFICATION_PREF_KEY, "1");
        } catch {
          // ignore storage failures
        }
        try {
          new Notification("PentaForge Notifications Enabled", {
            body: "You will receive approval alerts here.",
            tag: "pentaforge-notification-enabled",
          });
        } catch {
          // ignore notification display issues after permission grant
        }
      } else {
        setNotificationsEnabled(false);
        try {
          window.localStorage.setItem(NOTIFICATION_PREF_KEY, "0");
        } catch {
          // ignore storage failures
        }
      }
    } catch {
      setNotificationPermission(Notification.permission);
      const enabled = Notification.permission === "granted";
      setNotificationsEnabled(enabled);
      try {
        window.localStorage.setItem(NOTIFICATION_PREF_KEY, enabled ? "1" : "0");
      } catch {
        // ignore storage failures
      }
    }
  };

  const pushDesktopNotification = useCallback(
    (title: string, body: string) => {
      if (
        typeof window === "undefined"
        || !("Notification" in window)
        || !notificationsEnabled
        || notificationPermission !== "granted"
      ) {
        return;
      }
      try {
        // Desktop/webview notification for immediate operator awareness.
        new Notification(title, { body, tag: "pentaforge-approval" });
      } catch {
        // Ignore notification failures and keep scan flow uninterrupted.
      }
    },
    [notificationPermission, notificationsEnabled],
  );

  useEffect(() => {
    if (typeof window === "undefined" || !("Notification" in window)) {
      setNotificationPermission("unsupported");
      setNotificationsEnabled(false);
      return;
    }
    const syncNotificationState = () => {
      const permission = Notification.permission;
      setNotificationPermission(permission);
      let prefEnabled = false;
      try {
        prefEnabled = window.localStorage.getItem(NOTIFICATION_PREF_KEY) === "1";
      } catch {
        prefEnabled = false;
      }
      setNotificationsEnabled(permission === "granted" && prefEnabled);
    };
    syncNotificationState();
    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        syncNotificationState();
      }
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => {
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, []);

  useEffect(() => {
    if (!showApprovalModeMenu) {
      return;
    }
    const handlePointerDown = (event: MouseEvent) => {
      const target = event.target;
      if (!(target instanceof Node)) {
        return;
      }
      if (approvalModeMenuRef.current?.contains(target)) {
        return;
      }
      setShowApprovalModeMenu(false);
    };
    document.addEventListener("mousedown", handlePointerDown);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
    };
  }, [showApprovalModeMenu]);



  useEffect(() => {
    if (approvalMode !== "auto" || !isScanActive) {
      return;
    }
    if (awaitingPlannerApproval && !plannerApprovalLoading) {
      void handleApprovePlanner();
    }
  }, [approvalMode, isScanActive, awaitingPlannerApproval, plannerApprovalLoading]);

  useEffect(() => {
    if (!isScanActive || !pendingToolApproval || toolApprovalLoading) {
      return;
    }
    if (autoApprovalFailedIdsRef.current.has(pendingToolApproval.approvalId)) {
      return;
    }
    const shouldAutoApprove = shouldAutoApproveForRole(String(pendingToolApproval.role || ""));
    if (shouldAutoApprove) {
      void handleToolApproval("approve");
    }
  }, [isScanActive, pendingToolApproval, shouldAutoApproveForRole, toolApprovalLoading]);

  useEffect(() => {
    const activeApprovalId = pendingToolApproval?.approvalId ?? "";
    if (!activeApprovalId && autoApprovalFailedIdsRef.current.size > 0) {
      autoApprovalFailedIdsRef.current.clear();
      return;
    }
    if (activeApprovalId) {
      autoApprovalFailedIdsRef.current.forEach((approvalId) => {
        if (approvalId !== activeApprovalId) {
          autoApprovalFailedIdsRef.current.delete(approvalId);
        }
      });
    }
  }, [pendingToolApproval?.approvalId]);

  useEffect(() => {
    if (!pendingToolApproval?.approvalId) {
      return;
    }
    if (lastApprovalNotifiedRef.current === pendingToolApproval.approvalId) {
      return;
    }
    lastApprovalNotifiedRef.current = pendingToolApproval.approvalId;
    pushDesktopNotification(
      "PentaForge Approval Needed",
      `${pendingToolApproval.role}: ${pendingToolCommandPreview || pendingToolApproval.toolName}`,
    );
  }, [pendingToolApproval, pendingToolCommandPreview, pushDesktopNotification]);

  useEffect(() => {
    setPendingPasswordValue("");
  }, [pendingPasswordRequest?.passwordId]);

  useEffect(() => {
    if (!pendingPasswordRequest?.passwordId) {
      return;
    }
    pushDesktopNotification(
      "PentaForge Password Needed",
      `${pendingPasswordRequest.toolName || "Tool"} requires authentication`,
    );
  }, [pendingPasswordRequest, pushDesktopNotification]);

  useEffect(() => {
    if (!awaitingPlannerApproval || !activeProjectId) {
      return;
    }
    if (lastPlannerApprovalNotifiedRef.current === activeProjectId) {
      return;
    }
    lastPlannerApprovalNotifiedRef.current = activeProjectId;
    pushDesktopNotification(
      "PentaForge Planner Approval Needed",
      "Checklist is ready. Approve to continue planner.",
    );
  }, [awaitingPlannerApproval, activeProjectId, pushDesktopNotification]);

  const fallbackLogs: DashboardLogEntry[] = [];
  const baseTimestamp = activeProject?.updatedAt || new Date().toISOString();
  const fallbackLastScan = isRecord(activeProject?.lastScan)
    ? activeProject?.lastScan
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
  for (const phase of activeProject?.phases || []) {
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
    if (logSourceFilter !== "all" && entry.source !== logSourceFilter) {
      return false;
    }
    return true;
  });
  const currentCycle = (() => {
    for (const event of scanEvents) {
      if (event.event !== "executer_cycle_start" || !isRecord(event.data)) {
        continue;
      }
      if (typeof event.data.cycle === "number" && Number.isFinite(event.data.cycle)) {
        return Math.max(1, Math.floor(event.data.cycle));
      }
    }
    return null;
  })();
  const realtimeVulnFindings: RealtimeVulnFinding[] = (() => {
    const feed: RealtimeVulnFinding[] = [];

    // ONLY show confirmed/persisted findings from the project store
    // This is the source of truth for real vulnerabilities
    for (const finding of activeProject?.findings || []) {
      if (finding.status === "false_positive") {
        continue;
      }
      const findingTitle = String(finding.title || "").toLowerCase();
      const findingTarget = String(finding.target || "").toLowerCase();
      const findingKey = `persisted-${findingTitle}|${findingTarget}`;
      const rawFinding = finding as Finding & Record<string, unknown>;
      feed.push({
        id: `finding-${finding.id}`,
        title: finding.title || "Untitled Finding",
        severity: normalizeDashboardSeverity(finding.severity),
        source: "finding",
        at: finding.timestamp || new Date().toISOString(),
        endpoint: finding.target || "",
        status: finding.status || "verified",
        findingKey,
        cve: finding.cve,
        cvss: finding.cvss,
        category: finding.category,
        description: finding.description,
        evidence: finding.evidence,
        evidenceStatus: normalizeEvidenceStatus(
          rawFinding.evidence_status ?? finding.evidenceStatus ?? finding.evidence?.evidence_status,
        ),
        proofQuality: normalizeProofQuality(
          rawFinding.proof_quality ?? finding.proofQuality ?? finding.evidence?.proof_quality,
        ),
        deterministicValidation:
          typeof rawFinding.deterministic_validation === "boolean"
            ? rawFinding.deterministic_validation
            : (
              typeof finding.deterministicValidation === "boolean"
                ? finding.deterministicValidation
                : (
                  typeof finding.evidence?.deterministic_validation === "boolean"
                    ? finding.evidence.deterministic_validation
                    : undefined
                )
            ),
        remediation: finding.remediation,
      });
    }

    // NO DUPLICATION - Skip Perceptor events (they're scenario status, not findings)
    // NO DUPLICATION - Skip Verify verdict events (they become persisted findings, so we already have them above)
    // Only show real-time status if something is currently in progress but NOT yet persisted

    const deduped = new Map<string, RealtimeVulnFinding>();
    for (const item of feed) {
      const fallbackKey = `${item.title.toLowerCase()}|${(item.endpoint ?? "").toLowerCase()}`;
      const key = item.findingKey || fallbackKey;
      deduped.set(key, item);
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
  const streamLooksStale =
    shouldStreamScanEvents
    && lastLiveEventAtRef.current > 0
    && elapsedClockMs - lastLiveEventAtRef.current > 7000;
  const pendingApprovalCount = [

    awaitingPlannerApproval,
    Boolean(pendingToolApproval),
    Boolean(pendingPasswordRequest),
  ].filter(Boolean).length;
  const missionControlState: MissionControlState = (() => {
    if (isStarting) {
      return "initializing";
    }
    if (effectiveStatus === "error") {
      return "error";
    }
    if (pendingApprovalCount > 0) {
      return "paused_for_approval";
    }
    if (effectiveStatus === "completed") {
      return "completed";
    }
    if (effectiveStatus === "running" && (streamDegradedRef.current || streamLooksStale)) {
      return "reconnecting_sse";
    }
    if (effectiveStatus === "running") {
      return "running";
    }
    return "idle";
  })();
  const latestMissionPhase = (() => {
    for (const event of scanEvents) {
      const phase = detectWorkflowPhase(event);
      if (phase) {
        return phase;
      }
    }
    if (effectiveStatus === "completed") {
      return "analyzer" as MissionControlPhaseKey;
    }
    if (activeProject && (activeProject.scanProgress > 0 || effectiveStatus === "running")) {
      // If we are running but have very low progress, it's likely still the Intel/Architect phase
      if (activeProject.scanProgress <= 15) {
        return "intel" as MissionControlPhaseKey;
      }
      return "planner" as MissionControlPhaseKey;
    }
    return "intel" as MissionControlPhaseKey;
  })();
  const activeMissionPhaseIndex = MISSION_PHASE_ORDER.findIndex(
    (phase) => phase.key === latestMissionPhase,
  );
  const missionControlPhases = MISSION_PHASE_ORDER.map((phase, index) => {
    let status: "pending" | "active" | "completed" = "pending";
    if (missionControlState === "completed") {
      status = "completed";
    } else if (missionControlState !== "idle" && index < activeMissionPhaseIndex) {
      status = "completed";
    } else if (missionControlState !== "idle" && index === activeMissionPhaseIndex) {
      status = "active";
    }
    return {
      ...phase,
      status,
    };
  });
  const missionControlTitle = (() => {
    if (missionControlState === "initializing") {
      return "Preparing the scan runtime";
    }
    if (missionControlState === "paused_for_approval") {
      return "Operator confirmation is blocking the next step";
    }
    if (missionControlState === "reconnecting_sse") {
      return "Live event stream is resyncing with backend truth";
    }
    if (missionControlState === "error") {
      return "Scan stopped before the current cycle finished";
    }
    if (missionControlState === "completed") {
      return "Scan finished and the final operator view is stable";
    }
    if (missionControlState === "running") {
      return `Live scan running through ${missionControlPhases[activeMissionPhaseIndex]?.label ?? "active"} phase`;
    }
    return "Ready to launch a new autonomous assessment";
  })();
  const missionControlDetail = (() => {
    if (missionControlState === "paused_for_approval") {
      return pendingPasswordRequest
        ? "A tool hit an authentication gate. Provide credentials or deny the request so the cycle can continue with an explicit operator decision."
        : pendingToolApproval
          ? "The executer wants to run a gated tool step. Review the command and decide whether to approve or skip it."
          : awaitingPlannerApproval
            ? "The planner checklist is ready and waiting for your approval before scenario generation continues."
            : "Static information gathering has been organized and is waiting for your sign-off before execution.";
    }
    if (missionControlState === "reconnecting_sse") {
      return "The UI is keeping the scan alive while it reconnects to the live event stream. Recent history is being backfilled so you do not lose context during a transient disconnect.";
    }
    if (missionControlState === "error") {
      return fallbackLastScanError.length > 0
        ? fallbackLastScanError
        : "The orchestrator reported a fatal error. Review the latest events and resync project state before restarting.";
    }
    if (missionControlState === "completed") {
      return "Review the verified findings, planner output, and report generation paths from this finished run.";
    }
    if (missionControlState === "running") {
      return "The operator console is following the active scan by phase, worker slot, and verified impact so approvals and findings are visible without hunting through logs.";
    }
    if (missionControlState === "initializing") {
      return "Target configuration, scan identifiers, and runtime state are being prepared before the first live events arrive.";
    }
    return "Pick a project target and start the scan to turn this page into live mission control.";
  })();
  const streamStatusLabel = (() => {
    if (!shouldStreamScanEvents) {
      return "Idle until the next scan starts";
    }
    if (missionControlState === "reconnecting_sse") {
      const retries = Math.max(streamRetryRef.current, streamRetry, 1);
      return `Reconnecting live feed (attempt ${retries})`;
    }
    if (lastLiveEventAtRef.current === 0) {
      return "Waiting for first live event";
    }
    return `Live and healthy as of ${formatTime(new Date(lastLiveEventAtRef.current).toISOString())}`;
  })();
  const latestVerifiedFinding = realtimeVulnFindings[0] ?? null;
  const missionControlSignals = [
    {
      label: "Duration",
      value: displayedPentestElapsed,
      hint: timerStartedAt ? `Started ${formatDateTime(timerStartedAt)}` : "Timer begins on scan start",
    },
    {
      label: "Progress",
      value: activeProject ? `${Math.max(0, Math.round(activeProject.scanProgress))}%` : "0%",
      hint: `Current status: ${effectiveStatus}`,
    },
    {
      label: "Approvals",
      value: pendingApprovalCount > 0 ? `${pendingApprovalCount} waiting` : approvalMode === "auto" ? "Auto mode" : "Clear",
      hint: `Approval mode: ${approvalModeLabel[approvalMode]}`,
    },
    {
      label: "Verified Findings",
      value: `${realtimeVulnFindings.length}`,
      hint: currentCycle ? `Current execution cycle ${currentCycle}` : "Pre-cycle or planning stage",
    },
  ];
  const workerActivity = (() => {
    const items: Array<{
      label: string;
      status: "active" | "completed" | "waiting";
      detail: string;
      at?: string;
    }> = [];
    const seen = new Set<string>();
    for (const event of scanEvents) {
      const message = normalizeText(event.message);
      const match = message.match(/\[worker\s*(\d+)\]/i);
      if (!match) {
        continue;
      }
      const workerLabel = `Worker ${match[1]}`;
      if (seen.has(workerLabel)) {
        continue;
      }
      seen.add(workerLabel);
      const normalized = `${event.event} ${message}`.toLowerCase();
      const trimmedMessage = message.replace(/\[worker\s*\d+\]\s*/i, "").trim() || event.event.replaceAll("_", " ");
      const status =
        normalized.includes("completed") || normalized.includes("finished with status=complete")
          ? "completed"
          : normalized.includes("waiting approval") || normalized.includes("approval waiting")
            ? "waiting"
            : "active";
      items.push({
        label: workerLabel,
        status,
        detail: trimmedMessage,
        at: formatTime(event.timestamp),
      });
      if (items.length >= 2) {
        break;
      }
    }
    return items;
  })();
  const missionAction: MissionControlAction | null = (() => {
    if (pendingPasswordRequest) {
      const isSudo = pendingPasswordRequest.toolName?.toLowerCase() === "sudo";

      return {
        title: isSudo ? `Approve sudo command` : `${pendingPasswordRequest.toolName || "External tool"} needs credentials`,
        detail: isSudo
          ? `Review the command: ${pendingPasswordRequest.reason || pendingPasswordRequest.prompt}`
          : pendingPasswordRequest.reason || pendingPasswordRequest.prompt || "Provide credentials or deny the prompt so the scan can continue safely.",
        tone: "warn",
        controls: (
          <div className="flex flex-col gap-2">
            {!isSudo && (
              <Input
                type="password"
                autoFocus
                autoComplete="new-password"
                spellCheck={false}
                value={pendingPasswordValue}
                onChange={(event) => setPendingPasswordValue(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && pendingPasswordValue.length > 0) {
                    void handlePasswordResponse(true);
                  }
                }}
                placeholder="Verification password..."
                className="min-h-9 rounded-xl border-amber-400/50 bg-white/90 px-3 text-sm shadow-sm placeholder:text-slate-400"
              />
            )}
            <div className="grid grid-cols-2 gap-2">
              <Button
                variant="primary"
                className="min-h-8 rounded-xl font-semibold shadow-sm"
                onClick={() => {
                  void handlePasswordResponse(true);
                }}
                loading={passwordResponseLoading === "approve"}
                disabled={!isSudo && pendingPasswordValue.length === 0}
              >
                {isSudo ? "Allow" : "Verify"}
              </Button>
              <Button
                variant="secondary"
                className="min-h-8 rounded-xl border-amber-200/70 bg-white/80 font-semibold text-slate-700"
                onClick={() => {
                  void handlePasswordResponse(false);
                }}
                loading={passwordResponseLoading === "deny"}
              >
                Deny
              </Button>
            </div>
          </div>
        ),
      };
    }
    if (pendingToolApproval && !autoApprovingPendingTool) {
      return {
        title: `Approve ${pendingToolApproval.role} tool call`,
        detail: pendingToolCommandPreview || pendingToolApproval.toolName,
        tone: "warn",
        controls: (
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
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
        ),
      };
    }
    if (pendingToolApproval && autoApprovingPendingTool) {
      return {
        title: `Auto-approving ${pendingToolApproval.role}`,
        detail: pendingToolCommandPreview || pendingToolApproval.toolName,
        tone: "info",
      };
    }
    if (awaitingPlannerApproval) {
      return {
        title: approvalMode === "auto" ? "Planner approval is being handled automatically" : "Planner checklist is waiting for approval",
        detail: approvalMode === "auto"
          ? "The checklist is ready and the UI is letting the auto-approval flow continue to planner execution."
          : "Review the checklist, then continue to planner so scenario generation can begin.",
        tone: approvalMode === "auto" ? "info" : "warn",
        controls: approvalMode === "auto"
          ? undefined
          : (
            <Button
              size="sm"
              onClick={() => {
                void handleApprovePlanner();
              }}
              loading={plannerApprovalLoading}
            >
              <Check size={14} />
              Continue to Planner
            </Button>
          ),
      };
    }

    if (missionControlState === "reconnecting_sse") {
      return {
        title: "Resyncing scan state",
        detail: "Recent scan events are being refetched so the UI catches back up with the orchestrator after the stream interruption.",
        tone: "warn",
        controls: (
          <Button
            size="sm"
            variant="secondary"
            onClick={() => {
              void hydrateFromDatabase();
            }}
          >
            <Repeat2 size={14} />
            Refresh State
          </Button>
        ),
      };
    }
    if (missionControlState === "error") {
      return {
        title: "Review the failure and resync before restart",
        detail: fallbackLastScanError || "The scan failed without a detailed orchestrator message.",
        tone: "danger",
        controls: (
          <Button
            size="sm"
            variant="secondary"
            onClick={() => {
              void hydrateFromDatabase();
            }}
          >
            <Repeat2 size={14} />
            Refresh State
          </Button>
        ),
      };
    }
    return null;
  })();
  const logsEmptyMessage = (() => {
    if (missionControlState === "initializing") {
      return "The scan is bootstrapping. Live events will appear here once the first backend phase starts emitting.";
    }
    if (missionControlState === "paused_for_approval") {
      return "The scan is paused for operator input. Approve or deny the pending action to resume the live feed.";
    }
    if (missionControlState === "reconnecting_sse") {
      return "The live event stream is reconnecting. Recent history will repopulate here once the resync completes.";
    }
    if (missionControlState === "running") {
      return "The scan is active. Waiting for the next live event from the current phase.";
    }
    if (missionControlState === "completed") {
      return "The scan completed. Historical events will remain visible here as they sync.";
    }
    if (missionControlState === "error") {
      return "The scan stopped unexpectedly before more events could be rendered.";
    }
    return "Start a scan to open the live event feed.";
  })();
  const findingsEmptyMessage = (() => {
    if (missionControlState === "running" || missionControlState === "reconnecting_sse") {
      return "Analyzer verification is still in progress. Confirmed vulnerabilities will land here once they are saved.";
    }
    if (missionControlState === "paused_for_approval") {
      return "The next verification step is waiting on your input. Confirmed findings will resume updating after approval.";
    }
    if (missionControlState === "error") {
      return "The scan ended before new findings could be confirmed.";
    }
    return "No vulnerabilities confirmed yet. Real findings will appear here after verification.";
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
    if (!activeProject) {
      return {
        summary: "",
        needs: [],
        planData: null,
        status: "idle",
        error: "",
      };
    }
    let plannerError = "";
    for (const event of scanEvents) {
      if (!isRecord(event.data)) {
        continue;
      }
      if (
        (event.event === "scenario_state_change" ||
          event.event === "warmup_plan_ready" ||
          event.event === "plan_updated_by_planner" ||
          event.event === "planner_complete") &&
        event.data.plan_data
      ) {
        return {
          summary: normalizeText(event.data.summary),
          needs: event.data.needs,
          planData: event.data.plan_data,
          status:
            event.event === "planner_complete"
              ? "completed"
              : normalizeText(event.data.kind) || "running",
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

    const lastScan = isRecord(activeProject?.lastScan)
      ? activeProject?.lastScan
      : null;
    const result = isRecord(lastScan?.result) ? lastScan.result : null;
    const planner = isRecord(result?.planner) ? result.planner : null;
    const warmup = isRecord(result?.warmup) ? result.warmup : null;
    return {
      summary: normalizeText(planner?.summary),
      needs: planner?.needs,
      planData: planner?.plan_data ?? warmup?.plan,
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
  const informationGatheringView = (() => {
    if (!activeProject) return null;
    const activeResult = isRecord(activeProject?.lastScan)
      && isRecord(activeProject?.lastScan?.result)
      ? activeProject?.lastScan?.result
      : null;
    const persisted = toInformationGatheringView(activeResult?.targetInfoGathering);
    if (persisted && (persisted.program.length > 0 || persisted.blocks.length > 0)) {
      return persisted;
    }
    const fromEvents = buildInformationGatheringViewFromEvents(scanEvents);
    if (fromEvents && (fromEvents.program.length > 0 || fromEvents.blocks.length > 0)) {
      return fromEvents;
    }
    return persisted ?? fromEvents;
  })();


  const informationGatheringCompletedIds = new Set(
    (informationGatheringView?.blocks ?? []).map((block) => block.id),
  );
  const architectureDraft = useMemo(() => {
    // 1. Check scan events for real-time updates
    for (const event of [...scanEvents].reverse()) {
      if (event.event === "architect_updated" && isRecord(event.data?.architecture_draft)) {
        return (event.data.architecture_draft as unknown) as TargetArchitectureDraft;
      }
    }
    // 2. Check project payload for persisted state
    if (activeProject?.payload && isRecord(activeProject.payload.architecture_draft)) {
      return (activeProject.payload.architecture_draft as unknown) as TargetArchitectureDraft;
    }
    // 3. Fallback to static initial draft
    return buildTargetArchitectureDraft(
      activeProject?.targetType || "network",
      activeProject?.target || "",
    );
  }, [scanEvents, activeProject]);
  const architectureHostMap = new Map(
    architectureDraft.hosts.map((host) => [host.id, host]),
  );
  const architectureEdges = (architectureDraft.flows ?? [])
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
    if (!activeProject) return null;
    for (const event of scanEvents) {
      if (
        event.event !== "planner_checklist_complete" &&
        event.event !== "planner_waiting_approval" &&
        event.event !== "intel_complete"
      ) {
        continue;
      }
      if (!isRecord(event.data)) {
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
        activeProject?.targetType || "network",
      );
      if (summaryFallback) {
        return summaryFallback;
      }
    }

    const lastScan = isRecord(activeProject?.lastScan)
      ? activeProject?.lastScan
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
      activeProject?.targetType || "network",
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
    const lastScan = isRecord(activeProject?.lastScan)
      ? activeProject?.lastScan
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
  const isPlanRunningOrDone =
    Boolean((activeProject?.lastScan as any)?.result?.planner) ||
    scanEvents.some((e) => e.event === "planner_started" || e.event === "planner_complete" || e.event === "planner_approval_received") ||
    (activeProject?.phases ?? []).some((p) => p.status !== "pending");
  const isChecklistSaving = checklistActionKey !== null || isPlanRunningOrDone;
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
    if (!activeProject) {
      return Object.fromEntries(
        AGENT_ROLES.map((role) => [
          role,
          { history: [] as AgentInsightPanelData["history"] },
        ]),
      ) as Record<AgentGraphRole, AgentInsightPanelData>;
    }
    const byRole = Object.fromEntries(
      AGENT_ROLES.map((role) => [
        role,
        { history: [] as AgentInsightPanelData["history"] },
      ]),
    ) as Record<AgentGraphRole, AgentInsightPanelData>;

    const scanMeta = isRecord(activeProject?.lastScan)
      ? activeProject?.lastScan
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

    if (plannerResultText.length > 0) {
      const plannerStatus = resolvedPlannerResult.status || "completed";
      byRole.planner.resultLabel = `Planner Final Result (${plannerStatus})`;
      byRole.planner.result = plannerResultText;
    } else if (resolvedPlannerResult.error.length > 0) {
      byRole.planner.resultLabel = "Planner Error";
      byRole.planner.result = resolvedPlannerResult.error;
    }

    const latestExecuter = [...byRole.executer.history].reverse().find((entry) => entry.message.trim().length > 0);
    byRole.executer.resultLabel = "Executer Summary";
    byRole.executer.result = latestExecuter
      ? latestExecuter.message
      : "Recon and exploit work will appear here as the two active slots run.";

    const latestAnalyzer = [...byRole.analyzer.history].reverse().find((entry) => entry.message.trim().length > 0);
    byRole.analyzer.resultLabel = "Analyzer Summary";
    byRole.analyzer.result = latestAnalyzer
      ? latestAnalyzer.message
      : `Scan status: ${effectiveStatus}.`;

    return byRole;
  })();

  const visibleAgents = (() => {
    const roleOrder: AgentGraphRole[] = ["planner", "executer", "analyzer"];
    const baseAgents = Array.isArray(activeProject?.agents) ? activeProject.agents : [];
    const baseAgentByRole = new Map(
      baseAgents.map((agent) => [agent.name, agent] as const),
    );
    const roleProgress: Partial<Record<AgentGraphRole, number>> = {
      planner: resolvedPlannerResult.status === "completed" ? 100 : undefined,
      executer: effectiveStatus === "running" || (activeProject?.scanProgress || 0) > 0
        ? activeProject?.scanProgress
        : undefined,
      analyzer: agentInsights.analyzer?.history.length
        ? activeProject?.scanProgress
        : undefined,
    };
    const latestRole = roleOrder.reduce<AgentGraphRole | null>((current, role) => {
      const lastEntry = agentInsights[role]?.history.at(-1);
      if (!lastEntry) {
        return current;
      }
      if (!current) {
        return role;
      }
      const currentEntry = agentInsights[current]?.history.at(-1);
      if (!currentEntry) {
        return role;
      }
      return new Date(lastEntry.at).getTime() >= new Date(currentEntry.at).getTime()
        ? role
        : current;
    }, null);
    const activeWorkflowRole =
      missionControlState === "running"
        || missionControlState === "paused_for_approval"
        || missionControlState === "reconnecting_sse"
        || missionControlState === "initializing"
        ? workflowRoleForPhase(latestMissionPhase)
        : null;

    return roleOrder.map((role): AgentInfo => {
      const baseAgent = baseAgentByRole.get(role);
      const history = agentInsights[role]?.history ?? [];
      const latestEntry = history.at(-1);
      let state: AgentInfo["state"] = baseAgent?.state ?? "idle";
      if (effectiveStatus === "error" && role === latestRole) {
        state = "error";
      } else if (effectiveStatus === "running" && role === activeWorkflowRole) {
        state = "running";
      } else if (history.some((entry) => entry.level === "error")) {
        state = "error";
      } else if (history.length > 0) {
        state = effectiveStatus === "stopped" ? "waiting" : "success";
      } else if (effectiveStatus === "running") {
        state = "waiting";
      }

      return {
        name: role,
        state,
        currentTask: latestEntry?.message || agentInsights[role]?.result || baseAgent?.currentTask,
        progress: roleProgress[role] ?? baseAgent?.progress,
        lastUpdate: latestEntry?.at || baseAgent?.lastUpdate,
      };
    });
  })();

  const pipelineStages = useMemo(() => {
    const plannerAgent = visibleAgents.find(a => a.name === 'planner');
    const executerAgent = visibleAgents.find(a => a.name === 'executer');
    const analyzerAgent = visibleAgents.find(a => a.name === 'analyzer');

    const phaseBelongsToStage = (
      stage: OrchestratorStage,
      phase: MissionControlPhaseKey | null,
    ) => {
      if (!phase) {
        return false;
      }
      if (stage === 'planner') {
        return phase === 'intel' || phase === 'information_gathering' || phase === 'planner';
      }
      if (stage === 'executer') {
        return phase === 'executer';
      }
      return phase === 'brain' || phase === 'analyzer';
    };

    const onlyActiveStageCanRun = (
      stage: OrchestratorStage,
      status: OrchestratorStatus,
    ): OrchestratorStatus => {
      if (
        (status === 'running' || status === 'thinking')
        && (
          missionControlState === 'running'
          || missionControlState === 'paused_for_approval'
          || missionControlState === 'reconnecting_sse'
          || missionControlState === 'initializing'
        )
        && !phaseBelongsToStage(stage, latestMissionPhase)
      ) {
        return 'waiting';
      }
      return status;
    };

    const phaseToStage = (
      phase: MissionControlPhaseKey | null,
    ): OrchestratorStage => {
      if (phase === 'intel' || phase === 'information_gathering' || phase === 'planner') {
        return 'planner';
      }
      if (phase === 'brain' || phase === 'analyzer') {
        return 'analyzer';
      }
      return 'executer';
    };

    const approvalRoleToStage = (role: string): OrchestratorStage => {
      const normalizedRole = role
        .replace(/\[worker\s*\d+\]\s*/gi, '')
        .trim()
        .toLowerCase();
      if (
        normalizedRole.includes('planner')
        || normalizedRole.includes('intel')
        || normalizedRole.includes('information_gathering')
        || normalizedRole.includes('information gathering')
        || normalizedRole.includes('checklist')
      ) {
        return 'planner';
      }
      if (
        normalizedRole.includes('analyzer')
        || normalizedRole.includes('verify')
        || normalizedRole.includes('retest')
        || normalizedRole.includes('brain')
      ) {
        return 'analyzer';
      }
      return 'executer';
    };

    const getStageActionPanel = (
      stage: OrchestratorStage,
    ): {
      title: string;
      detail: string;
      tone?: 'info' | 'warn' | 'danger';
      controls?: React.ReactNode;
    } | null => {
      if (pendingPasswordRequest) {
        const passwordStage = phaseToStage(latestMissionPhase);
        if (stage !== passwordStage) {
          return null;
        }

        const isSudo = pendingPasswordRequest.toolName?.toLowerCase() === "sudo";

        return {
          title: isSudo ? `Approve sudo command` : `${pendingPasswordRequest.toolName || 'External tool'} needs credentials`,
          detail: isSudo
            ? `Review the command: ${pendingPasswordRequest.reason || pendingPasswordRequest.prompt}`
            : pendingPasswordRequest.reason
            || pendingPasswordRequest.prompt
            || 'Provide credentials or deny the prompt so the scan can continue safely.',
          tone: 'warn',
          controls: (
            <div className="flex flex-col gap-2">
              {!isSudo && (
                <Input
                  type="password"
                  autoFocus
                  autoComplete="new-password"
                  spellCheck={false}
                  value={pendingPasswordValue}
                  onChange={(event) => setPendingPasswordValue(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' && pendingPasswordValue.length > 0) {
                      void handlePasswordResponse(true);
                    }
                  }}
                  placeholder="Verification password..."
                  className="min-h-9 rounded-xl border-amber-400/50 bg-white/90 px-3 text-sm shadow-sm placeholder:text-slate-400"
                />
              )}
              <div className="grid grid-cols-2 gap-2">
                <Button
                  size="sm"
                  variant="primary"
                  className="min-h-8 rounded-xl font-semibold shadow-sm"
                  onClick={() => {
                    void handlePasswordResponse(true);
                  }}
                  loading={passwordResponseLoading === 'approve'}
                  disabled={!isSudo && pendingPasswordValue.length === 0}
                >
                  {isSudo ? "Allow" : "Verify"}
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  className="min-h-8 rounded-xl border-amber-200/70 bg-white/80 font-semibold text-slate-700"
                  onClick={() => {
                    void handlePasswordResponse(false);
                  }}
                  loading={passwordResponseLoading === 'deny'}
                >
                  Deny
                </Button>
              </div>
            </div>
          ),
        };
      }

      if (pendingToolApproval) {
        const approvalStage = approvalRoleToStage(String(pendingToolApproval.role || ''));
        if (stage !== approvalStage) {
          return null;
        }
        if (autoApprovingPendingTool) {
          return null;
        }
        return {
          title: `Approve ${pendingToolApproval.role} tool call`,
          detail: pendingToolCommandPreview || pendingToolApproval.toolName,
          tone: 'warn',
          controls: (
            <div className="flex flex-wrap items-center gap-2">
              <Button
                size="sm"
                onClick={() => {
                  void handleToolApproval('approve');
                }}
                loading={toolApprovalLoading === 'approve'}
              >
                <Check size={14} />
                Approve Tool
              </Button>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => {
                  void handleToolApproval('skip');
                }}
                loading={toolApprovalLoading === 'skip'}
              >
                <X size={14} />
                Skip Tool
              </Button>
            </div>
          ),
        };
      }

      if (awaitingPlannerApproval && stage === 'planner') {
        if (approvalMode === 'auto') {
          return null;
        }
        return {
          title: 'Planner checklist is waiting for approval',
          detail: 'Review the checklist, then continue to planner so scenario generation can begin.',
          tone: 'warn',
          controls: (
            <Button
              size="sm"
              onClick={() => {
                void handleApprovePlanner();
              }}
              loading={plannerApprovalLoading}
            >
              <Check size={14} />
              Continue to Planner
            </Button>
          ),
        };
      }


      return null;
    };

    const getStatus = (agent: any, phaseKey?: MissionControlPhaseKey): OrchestratorStatus => {
      if (effectiveStatus === 'idle') return 'idle';

      // Check if this specific phase is active based on scan events
      if (phaseKey) {
        const lastEvent = [...scanEvents].reverse().find(e => {
          const p = detectMissionPhase(e);
          return p === phaseKey;
        });
        if (lastEvent) {
          if (
            lastEvent.event.includes('_started') ||
            lastEvent.event.includes('_running') ||
            lastEvent.event.includes('_step') ||
            lastEvent.event.includes('_batch_progress') ||
            lastEvent.event.includes('_finding_working') ||
            lastEvent.event.includes('_waiting_approval') ||
            lastEvent.event.includes('_approval_decision') ||
            lastEvent.event.includes('_approval_cleared')
          ) {
            return 'running';
          }
          if (lastEvent.event.includes('_complete') || lastEvent.event.includes('_done')) {
            // Only show 'completed' when the scan is finished; otherwise 'waiting'
            return (effectiveStatus === 'completed' || effectiveStatus === 'stopped') ? 'completed' : 'waiting';
          }
          if (lastEvent.event.includes('_failed')) return 'error';
        }
      }

      if (agent?.state === 'running') return 'running';
      if (agent?.state === 'thinking') return 'thinking';
      if (agent?.state === 'success') {
        // Only show 'completed' when the scan is finished; otherwise 'waiting'
        return (effectiveStatus === 'completed' || effectiveStatus === 'stopped') ? 'completed' : 'waiting';
      }
      if (agent?.state === 'error') return 'error';
      if (effectiveStatus === 'running') return 'waiting';
      if (effectiveStatus === 'completed' || effectiveStatus === 'stopped') return 'completed';
      return 'idle';
    };

    // Helper to find the latest specific commands from logs
    const getRecentActivity = (role: string, phaseKey?: MissionControlPhaseKey) => {
      const logs = agentInsights[role as AgentGraphRole]?.history || [];
      const activities: any[] = [];

      // Phase-specific logic (Strict Whitelist)
      if (phaseKey === 'intel') {
        const intelEvents = [...scanEvents].reverse()
          .filter(e => detectMissionPhase(e) === 'intel' && e.message)
          .slice(0, 10);
        intelEvents.forEach(e => {
          activities.push({ type: 'info', message: e.message, at: e.timestamp });
        });
      }

      if (phaseKey === 'information_gathering') {
        const infoEvents = [...scanEvents].reverse()
          .filter(e => detectMissionPhase(e) === 'information_gathering' && e.message)
          .slice(0, 10);
        infoEvents.forEach(e => {
          const msg = e.message?.toLowerCase() || '';
          activities.push({
            type: msg.includes('thinking') ? 'thinking' : 'info',
            message: e.message,
            at: e.timestamp
          });
        });
      }

      // General Agent Logs (Strict Whitelist)
      const filteredLogs = [...logs].reverse()
        .filter(l => {
          if (!l.message || l.message.includes('Mission control')) {
            return false;
          }
          return !l.message.toLowerCase().includes('architect');
        })
        .slice(0, 20);

      filteredLogs.forEach(l => {
        const msg = l.message;
        const lowerMsg = msg.toLowerCase();
        let type: 'thinking' | 'command' | 'result' | 'info' | null = null;
        let displayMsg = msg;

        // Whitelist Logic
        if (lowerMsg.includes('[run tool]') || lowerMsg.includes('executing') || lowerMsg.includes('tool call:')) {
          type = 'command';
          const match = msg.match(/\[run tool\]\s+(.+)/i) || msg.match(/executing\s+(.+)/i) || msg.match(/tool call:\s+(.+)/i);
          displayMsg = match ? match[1] : msg;
        }
        else if (role === 'analyzer') {
          if (lowerMsg.includes('thinking') || lowerMsg.includes('[verify]') || lowerMsg.includes('[retest]')) {
            type = 'thinking';
          } else if (lowerMsg.includes('finished') || lowerMsg.includes('confirmed')) {
            type = 'result';
          }
        }
        else if (role === 'executer') {
          if (lowerMsg.includes('[exploit]') && lowerMsg.includes('thinking')) {
            type = 'thinking';
          }
        }
        else if (role === 'planner') {
          if (lowerMsg.includes('thinking') || lowerMsg.includes('round') || lowerMsg.includes('fetch info')) {
            type = 'thinking';
          }
        }

        // Only add if it matched a whitelisted type and isn't a duplicate
        if (type && !activities.some(a => a.message === displayMsg)) {
          activities.push({ type, message: displayMsg, at: l.at });
        }
      });

      return activities.length > 0 ? activities.slice(0, 4) : undefined;
    };

    const mergeRecentActivities = (
      ...groups: Array<Array<{ type: "thinking" | "command" | "result" | "info"; message: string; at?: string }> | undefined>
    ) => {
      const merged: Array<{ type: "thinking" | "command" | "result" | "info"; message: string; at?: string }> = [];
      const seen = new Set<string>();
      for (const group of groups) {
        for (const activity of group ?? []) {
          const key = `${activity.type}:${activity.message.trim()}`;
          if (!activity.message.trim() || seen.has(key)) {
            continue;
          }
          seen.add(key);
          merged.push(activity);
        }
      }
      const recent = merged.sort((a, b) => {
        if (!a.at || !b.at) return 0;
        return new Date(b.at).getTime() - new Date(a.at).getTime();
      }).slice(0, 4);

      return recent.sort((a, b) => {
        if (!a.at || !b.at) return 0;
        return new Date(a.at).getTime() - new Date(b.at).getTime();
      });
    };

    const plannerStatus = getStatus(plannerAgent);
    const intelStatus = getStatus(null, 'intel');

    const executerStatus = getStatus(executerAgent);
    const infoGatherStatus = getStatus(null, 'information_gathering');

    const analyzerStatus = getStatus(analyzerAgent);
    const brainStatus = getStatus(null, 'brain');
    const pipelineIsIdle = missionControlState === 'idle';
    const analyzerFeedVisible = !(
      (
        missionControlState === 'running'
        || missionControlState === 'paused_for_approval'
        || missionControlState === 'reconnecting_sse'
        || missionControlState === 'initializing'
      )
      && !phaseBelongsToStage('analyzer', latestMissionPhase)
    );

    const plannerDisplayPhase: MissionControlPhaseKey =
      latestMissionPhase === 'intel' || latestMissionPhase === 'information_gathering' || latestMissionPhase === 'brain'
        ? 'intel'
        : latestMissionPhase === 'planner'
          ? 'planner'
          : 'planner';

    const plannerCompositeStatus =
      plannerDisplayPhase === 'intel'
        ? (infoGatherStatus === 'running' || infoGatherStatus === 'thinking' ? 'running' : intelStatus)
        : plannerStatus;

    const plannerIntelActivity = getRecentActivity('planner', 'intel');
    const plannerInfoGatherActivity = getRecentActivity('executer', 'information_gathering');

    // Unified activity feed for the Planner node during intel phase:
    // Collect ALL intel + information_gathering events from scanEvents in chronological order.
    const plannerPhaseActivity = (() => {
      if (plannerDisplayPhase !== 'intel') return undefined;
      const relevantPhases = new Set(['intel', 'information_gathering', 'brain']);
      const items = scanEvents
        .filter(e => {
          const phase = detectMissionPhase(e);
          return phase && relevantPhases.has(phase) && e.message;
        })
        .map(e => ({
          type: 'info' as const,
          message: e.message,
          at: e.timestamp,
        }))
        .sort((a, b) => new Date(a.at || 0).getTime() - new Date(b.at || 0).getTime());
      // Deduplicate by message while keeping chronological phase progression.
      const seen = new Set<string>();
      const deduped = items.filter(item => {
        if (seen.has(item.message)) return false;
        seen.add(item.message);
        return true;
      });
      return deduped.length > 0 ? deduped.slice(-8) : undefined;
    })();

    const formatTaskSubtext = (task: string | undefined, defaultText: string) => {
      if (!task) return defaultText;
      const cleanTask = task.trim();
      if (cleanTask.startsWith('{') || cleanTask.includes('```json') || cleanTask.includes('```')) {
        return defaultText;
      }
      if (cleanTask.length > 80) {
        return cleanTask.slice(0, 80) + '...';
      }
      return cleanTask;
    };

    return {
      planner: {
        stage: 'planner' as OrchestratorStage,
        status: onlyActiveStageCanRun(
          'planner',
          plannerCompositeStatus,
        ),
        label:
          pipelineIsIdle
            ? 'Planner'
            : plannerDisplayPhase === 'intel'
              ? 'Intel Phase'
              : 'Planner',
        icon: Brain,
        subtext:
          pipelineIsIdle
            ? 'Ready for a new scan...'
            : plannerDisplayPhase === 'intel'
              ? (infoGatherStatus === 'running' || infoGatherStatus === 'thinking' ? 'Running automated information gathering...' : 'Refreshing RAG & synthesizing checklist...')
              : formatTaskSubtext(plannerAgent?.currentTask, 'Synthesizing target checklist...'),
        recentActivity:
          plannerDisplayPhase === 'intel'
            ? plannerPhaseActivity
            : getRecentActivity('planner', 'planner'),
        actionPanel: getStageActionPanel('planner'),
      },
      executer: {
        stage: 'executer' as OrchestratorStage,
        status: onlyActiveStageCanRun(
          'executer',
          executerStatus,
        ),
        label: 'Executer',
        icon: Zap,
        subtext: pipelineIsIdle
          ? 'Ready for a new scan...'
          : formatTaskSubtext(executerAgent?.currentTask, 'Waiting for plan execution...'),
        recentActivity: getRecentActivity('executer', 'executer'),
        actionPanel: getStageActionPanel('executer'),
      },
      analyzer: {
        stage: 'analyzer' as OrchestratorStage,
        status: pipelineIsIdle
          ? 'idle'
          : (plannerDisplayPhase === 'intel')
            ? 'waiting'
            : onlyActiveStageCanRun(
              'analyzer',
              (brainStatus === 'running' || brainStatus === 'error') ? brainStatus : analyzerStatus,
            ),
        label: (plannerDisplayPhase !== 'intel' && brainStatus === 'running') ? 'Brain' : 'Analyser',
        icon: Search,
        subtext: pipelineIsIdle
          ? 'Ready for a new scan...'
          : (plannerDisplayPhase !== 'intel' && brainStatus === 'running')
            ? 'Processing findings into system memory...'
            : plannerDisplayPhase === 'intel'
              ? 'Waiting for execution results...'
              : formatTaskSubtext(analyzerAgent?.currentTask, 'Verifying impact and findings...'),
        recentActivity: plannerDisplayPhase !== 'intel' && analyzerFeedVisible
          ? (
            mergeRecentActivities(
              getRecentActivity('analyzer', 'brain'),
              analyzerPipelineActivities,
            ) || (realtimeVulnFindings.length > 0 ? [{ type: 'result', message: `${realtimeVulnFindings.length} findings verified` }] : undefined)
          )
          : undefined,
        actionPanel: getStageActionPanel('analyzer'),
      }
    };
  }, [
    visibleAgents,
    agentInsights,
    realtimeVulnFindings,
    scanEvents,
    effectiveStatus,
    latestMissionPhase,
    missionControlState,
    pendingPasswordRequest,
    pendingPasswordValue,
    passwordResponseLoading,
    pendingToolApproval,
    autoApprovingPendingTool,
    pendingToolCommandPreview,
    analyzerPipelineActivities,
    toolApprovalLoading,
    awaitingPlannerApproval,
    approvalMode,
    plannerApprovalLoading,
    handleApprovePlanner,
  ]);

  const handleStartScanClick = async () => {
    if (effectiveStatus === "completed") {
      const confirmed = window.confirm(
        "This scan already completed. Start a new scan and clear previous results?",
      );
      if (!confirmed) {
        return;
      }
      setStreamLogs([]);
      setScanEvents([]);
      if (activeProject) {
        try {
          await useProjects.getState().stopScan(activeProject.id, "cancel");
        } catch (err) {
          console.error("Failed to reset project before restart:", err);
        }
      }
      setRunning(activeProject?.id || "", {
        triggerScan: true,
        force: true,
      });
      return;
    }
    if (effectiveStatus === "stopped") {
      const confirmed = window.confirm(
        "Resume will start a new scan and keep previous history visible. Continue?",
      );
      if (!confirmed) {
        return;
      }
      setRunning(activeProject?.id || "", {
        triggerScan: true,
        resume: true,
      });
      return;
    }
    if (effectiveStatus === "idle") {
      setStreamLogs([]);
      setScanEvents([]);
    }
    setRunning(activeProject?.id || "", { triggerScan: true });
  };

  const handleSelectRealtimeFinding = (item: RealtimeVulnFinding) => {
    const fullFinding = activeProject?.findings?.find(
      (finding: any) => finding.id === item.id.replace("finding-", ""),
    );
    setSelectedFinding(fullFinding || item);
  };

  const handleAddFindingToEchoPrompt = useCallback((item: RealtimeVulnFinding) => {
    const payload = {
      finding_id: item.id.replace(/^finding-/, ""),
      title: item.title,
      severity: item.severity,
      category: item.category ?? "",
      target: item.endpoint ?? "",
      description: item.description ?? "",
      evidence_status: item.evidenceStatus ?? "",
      proof_quality: item.proofQuality ?? "",
      cve: item.cve ?? "",
      cvss: item.cvss ?? "",
    };
    setIsCopilotOpen(true);
    setCopilotDraft({
      token: `finding-json-${payload.finding_id || Date.now()}`,
      text: JSON.stringify(payload, null, 2),
    });
  }, [setIsCopilotOpen]);

  const handleMarkFindingFalsePositive = useCallback(async (item: RealtimeVulnFinding) => {
    if (!activeProjectId) {
      return;
    }
    const findingReference = item.id.replace(/^finding-/, "") || item.title;
    if (!findingReference) {
      return;
    }

    setFalsePositiveLoadingId(item.id);
    try {
      const result = await markProjectFindingFalsePositiveFromDesktop(activeProjectId, {
        findingId: findingReference,
        reason: "Operator marked as false positive from confirmed vulnerabilities panel.",
      });

      const projectState = useProjects.getState();
      const currentProject = projectState.projects.find((project) => project.id === activeProjectId);
      if (currentProject && Array.isArray(currentProject.findings)) {
        let changed = false;
        const nextFindings = currentProject.findings.map((finding) => {
          if (!findingMatchesReference(
            finding,
            typeof result.matched_finding_id === "string" ? result.matched_finding_id : "",
            typeof result.matched_finding_title === "string" ? result.matched_finding_title : "",
            findingReference,
          )) {
            return finding;
          }
          changed = true;
          return {
            ...finding,
            status: "false_positive" as const,
          };
        });
        if (changed) {
          projectState.updateProject(activeProjectId, { findings: nextFindings }, { persist: false });
        }
      }

      await hydrateFromDatabase();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to mark finding as false positive.";
      setStreamLogs((previous) => {
        const nextList = [
          ...previous,
          {
            id: `false-positive-error-${Math.random().toString(36).slice(2, 10)}`,
            level: "warn",
            message,
            at: new Date().toISOString(),
            source: "system",
          } as DashboardLogEntry,
        ];
        if (nextList.length > 500) return nextList.slice(-500);
        return nextList;
      });
    } finally {
      setFalsePositiveLoadingId(null);
    }
  }, [activeProjectId, hydrateFromDatabase]);

  if (!activeProject) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3">
        <FolderOpen size={48} className="text-text-muted" />
        <p className="text-sm text-text-secondary">No project selected.</p>
        <Button onClick={() => navigate("/projects")}>Open Projects</Button>
      </div>
    );
  }

  const mobileRuntimeNotice = getProjectMobileRuntimeNotice(activeProject);

  return (
    <>
      <style>{`
        .custom-scrollbar::-webkit-scrollbar {
          width: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: transparent;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: rgba(59, 130, 246, 0.2);
          border-radius: 10px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: rgba(59, 130, 246, 0.4);
        }
      `}</style>
      <div className="flex h-full w-full overflow-hidden bg-background">
        <div className="flex-1 min-w-0 overflow-y-auto p-4 space-y-4 transition-all duration-300 ease-in-out scrollbar-pf">
          <DashboardProjectHeader
            projectName={activeProject.name}
            effectiveStatus={effectiveStatus}
            isRunning={isScanActive}
            canRun={canRun}
            isStarting={isStarting}
            startingMessage={isStarting ? startingProjectMessage : null}
            isStopping={stoppingProjectId === activeProject.id}
            stoppingMessage={stoppingProjectId === activeProject.id ? stoppingProjectMessage : null}
            hasAnotherRunningProject={hasAnotherRunningProject}
            onStartScan={handleStartScanClick}
            onStopScan={() => setStopDialogOpen(true)}
            onChangeProject={() => navigate("/projects")}
            onCloseProject={handleCloseProject}
          />

          <DashboardTargetOverviewCard
            target={activeProject.target}
            targetType={activeProject.targetType}
            createdAt={activeProject.createdAt}
            updatedAt={activeProject.updatedAt}
            effectiveStatus={effectiveStatus}
            displayedPentestElapsed={displayedPentestElapsed}
            runtimeNotice={mobileRuntimeNotice}
            onEditProject={handleOpenProjectEdit}
            formatDateTime={formatDateTime}
          />

          <div className="grid gap-3 xl:grid-cols-2">
            <div className="min-w-0 flex flex-col">
              <Card className="flex h-[650px] flex-col space-y-1 p-3 overflow-hidden">
                <div className="flex items-center justify-between">
                  <div className="flex flex-col">
                    <h2 className="text-base font-bold  uppercase tracking-widest">
                      Orchestrator Pipeline
                    </h2>
                  </div>

                  <div className="flex items-center gap-3">
                    <div className="flex items-center gap-1.5">
                      <div className="relative flex items-center" ref={approvalModeMenuRef}>
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-8 w-auto text-text-muted hover:text-text-primary"
                          onClick={() => setShowApprovalModeMenu((open) => !open)}
                          title="Approval mode"
                        >
                          <Check size={16} />
                          <span className="text-[10px] font-bold uppercase tracking-wider text-text-muted/70 mr-1">
                            {approvalMode}
                          </span>
                        </Button>
                        {showApprovalModeMenu ? (
                          <div className="absolute right-0 top-9 z-30 w-48 rounded-md border border-border bg-surface-1 p-2 shadow-xl">
                            <p className="mb-1 text-[10px] font-bold uppercase tracking-wide text-text-secondary">
                              Approval Mode
                            </p>
                            <div className="flex flex-col gap-1">
                              <Button
                                size="xs"
                                variant={approvalMode === "custom" ? "primary" : "secondary"}
                                onClick={() => {
                                  handleApprovalModeChange("custom");
                                  setShowApprovalModeMenu(false);
                                }}
                              >
                                Custom
                              </Button>
                              <Button
                                size="xs"
                                variant={approvalMode === "auto" ? "primary" : "secondary"}
                                onClick={() => {
                                  handleApprovalModeChange("auto");
                                  setShowApprovalModeMenu(false);
                                }}
                              >
                                Auto
                              </Button>
                            </div>
                          </div>
                        ) : null}
                      </div>

                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-8 w-8 text-text-muted hover:text-text-primary"
                        onClick={() => {
                          openAnalyzerAgentReport();
                        }}
                        title={
                          orchestratorPipelineHeaderReport
                            ? "Open combined findings history markdown"
                            : "Open findings history status"
                        }
                        aria-label={
                          orchestratorPipelineHeaderReport
                            ? "Open combined findings history markdown"
                            : "Open findings history status"
                        }
                      >
                        <FolderOpen size={16} />
                      </Button>

                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-8 w-8 text-text-muted hover:text-text-primary"
                        onClick={() => {
                          void requestNotificationAccess();
                        }}
                        disabled={notificationsUnavailable}
                        title={
                          notificationsUnavailable
                            ? "Notifications unsupported"
                            : notificationsEnabled
                              ? "Disable notifications"
                              : "Enable notifications"
                        }
                      >
                        {notificationsUnavailable || !notificationsEnabled ? <BellOff size={16} /> : <Bell size={16} />}
                      </Button>
                    </div>
                  </div>
                </div>
                <div className="h-px w-full bg-border/60" />

                <div className="min-h-0 flex-1 rounded-md border border-border bg-surface-0/35 p-2">
                  <div className="flex h-full flex-col min-h-0">
                    <OrchestratorPipeline stages={pipelineStages} />
                  </div>
                </div>
              </Card>
            </div>

            <div ref={findingsSectionRef} className="min-w-0 flex flex-col">
              <DashboardFindingsPanel
                findings={realtimeVulnFindings}
                findingsEmptyMessage={findingsEmptyMessage}
                onSelectFinding={handleSelectRealtimeFinding}
                onMarkFalsePositive={handleMarkFindingFalsePositive}
                onAddToEchoPrompt={handleAddFindingToEchoPrompt}
                falsePositiveLoadingId={falsePositiveLoadingId}
                severityBadgeClass={severityBadgeClass}
                evidenceBadgeClass={evidenceBadgeClass}
                proofQualityBadgeClass={proofQualityBadgeClass}
                formatTime={formatTime}
              />
            </div>
          </div>

          {/* Fullscreen overlay for Execution Notes */}
          {isInsightFullscreen && (
            <div
              className="fixed inset-0 z-50 bg-surface-0/95 backdrop-blur-sm"
              onClick={() => setIsInsightFullscreen(false)}
            />
          )}

          <div className="grid gap-4">
            <Card
              className={
                isInsightFullscreen
                  ? "fixed inset-4 z-50 flex flex-col space-y-3 overflow-hidden p-4"
                  : "flex h-[650px] flex-col space-y-3 p-3"
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
                      variant={insightTab === "checklist" ? "secondary" : "ghost"}
                      onClick={() => setInsightTab("checklist")}
                    >
                      Checklist
                    </Button>
                    <Button
                      size="xs"
                      variant={insightTab === "plan" ? "secondary" : "ghost"}
                      onClick={() => setInsightTab("plan")}
                    >
                      Plan
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
                                          (() => {
                                            const statusTone =
                                              scenario.status === "completed"
                                                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
                                                : scenario.status === "working"
                                                  ? "border-amber-500/30 bg-amber-500/10 text-amber-200"
                                                  : "border-border bg-surface-1/55 text-text-muted";
                                            return (
                                              <div
                                                key={`${phase.phase}-${step.step}-scenario-${scenarioIndex}`}
                                                className={`flex items-center justify-between gap-2 ${isInsightFullscreen ? "px-3 py-2" : "px-2 py-1.5"}`}
                                              >
                                                <p className="text-text-secondary text-[13px]">
                                                  {scenario.scenario}
                                                </p>
                                                <div className="flex items-center gap-1.5">

                                                  {scenario.plannerRound ? (
                                                    <span className="rounded border border-pf-500/30 bg-pf-500/10 px-1.5 py-0.5 text-[11px] uppercase tracking-wide text-pf-200">
                                                      {scenario.plannerRound}
                                                    </span>
                                                  ) : null}
                                                  <span
                                                    className={`rounded border px-1.5 py-0.5 text-[11px] capitalize ${statusTone}`}
                                                  >
                                                    {scenario.status}
                                                  </span>
                                                  {scenario.priority ? (
                                                    <span className="rounded border border-border bg-surface-1/55 px-1.5 py-0.5 text-text-muted text-[11px]">
                                                      S{scenario.priority}
                                                    </span>
                                                  ) : null}
                                                  <span className="rounded border border-border bg-surface-1/55 px-1.5 py-0.5 text-text-muted text-xs">
                                                    {scenario.agent}
                                                  </span>
                                                </div>
                                              </div>
                                            );
                                          })()
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
                      {isScanActive
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
                      {isScanActive
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
          </div>

          {!isInsightFullscreen ? (
            <DashboardArchitecturePanel
              architectureDraft={architectureDraft}
              architectureEdges={architectureEdges}
              debugTimeline={debugTimeline}
              observabilityMetrics={observabilityMetrics}
              onRefresh={handleRefreshArchitecture}
              isRefreshing={isArchitectRefreshing}
              isCompressing={isArchitectCompressing}
            />
          ) : null}
        </div>

        <div
          className={`border-l border-border bg-surface-1/95 backdrop-blur-md transition-all duration-300 ease-in-out overflow-hidden flex flex-col relative z-30 ${isCopilotOpen ? "w-[460px] opacity-100" : "w-0 opacity-0 border-l-0"
            }`}
        >
          <div className="flex-1 overflow-hidden min-w-[460px] flex flex-col h-full">
            <AIPromptPanel
              projectId={activeProject.id}
              projectName={activeProject.name}
              target={activeProject.target}
              targetType={activeProject.targetType}
              projectStatus={activeProject.status}
              savedContext={activeProject.copilotContext}
              hasScanState={Boolean(activeProject.lastScan)}
              agents={visibleAgents}
              history={activeProject.copilotHistory}
              injectedPrompt={copilotDraft}
              onClose={() => setIsCopilotOpen(false)}
            />
          </div>
        </div>
      </div>

      {!isCopilotOpen && (
        <Button
          size="sm"
          variant="primary"
          onClick={() => setIsCopilotOpen(true)}
          className="fixed bottom-4 right-4 z-50 h-12 w-12 rounded-full shadow-lg transition-all duration-300 sm:bottom-6 sm:right-6"
          title="Open AI chat"
        >
          <Bot size={18} />
        </Button>
      )}

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
          <Textarea
            label="Description"
            value={projectEditDescription}
            onChange={(event) => setProjectEditDescription(event.target.value)}
            placeholder="Optional scope/notes"
            rows={4}
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
              loading={stoppingProjectId === activeProject.id}
              disabled={stoppingProjectId === activeProject.id}
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
              loading={stoppingProjectId === activeProject.id}
              disabled={stoppingProjectId === activeProject.id}
            >
              Cancel Scan
            </Button>
          </div>
        </div>
      </Dialog>

      <DashboardFindingDialog
        selectedFinding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onMarkFalsePositive={handleMarkFindingFalsePositive}
        onAddToEchoPrompt={handleAddFindingToEchoPrompt}
        normalizeDashboardSeverity={normalizeDashboardSeverity}
        severityBadgeClass={severityBadgeClass}
        normalizeEvidenceStatus={normalizeEvidenceStatus}
        evidenceBadgeClass={evidenceBadgeClass}
        normalizeProofQuality={normalizeProofQuality}
        proofQualityBadgeClass={proofQualityBadgeClass}
        findingUsesOobProof={findingUsesOobProof}
        findingOobProtocol={findingOobProtocol}
        formatVerificationMethod={formatVerificationMethod}
        formatTime={formatTime}
      />

      <Dialog
        open={analyzerReportViewer.open}
        onClose={() => {
          setAnalyzerReportViewer((current) => ({
            ...current,
            open: false,
          }));
        }}
        title={analyzerReportViewer.title || "Findings History Markdown"}
        description={analyzerReportViewer.description || "Saved findings history report"}
        width="max-w-4xl"
      >
        <div className="space-y-3">
          <div className="flex items-center justify-between gap-3">
            <p className="text-xs text-text-muted">
              Markdown generated from analyzer output for recon or exploit activity.
            </p>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => {
                if (typeof navigator !== "undefined" && navigator.clipboard) {
                  void navigator.clipboard.writeText(analyzerReportViewer.markdown || "");
                }
              }}
            >
              <Check size={14} />
              Copy Markdown
            </Button>
          </div>
          <pre className="max-h-[70vh] overflow-auto rounded-xl border border-border bg-surface-0/60 p-4 font-mono text-xs leading-6 text-text-secondary whitespace-pre-wrap break-words">
            {analyzerReportViewer.markdown || "No findings history markdown available."}
          </pre>
        </div>
      </Dialog>
    </>
  );
}
