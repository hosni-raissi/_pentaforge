import { useConfig } from "@/stores/config";
import type { CopilotMessage, Project } from "@/types";

export interface ProjectTargetTypeOption {
  value: string;
  label: string;
}

export interface ProjectTargetField {
  key: string;
  label: string;
  required: boolean;
  data_type: "string" | "integer" | "number" | "boolean" | "enum" | "array";
  options: string[];
}

export interface ProjectShareLinkRequest {
  expires_hours: number;
  password?: string | null;
  one_time: boolean;
}

export interface ProjectShareLinkResponse {
  ok: boolean;
  access_url: string;
  tunnel_url?: string | null;
  token: string;
  project_id: string;
  payload: string;
  expires_at: string;
  one_time: boolean;
  password_protected: boolean;
  view_count: number;
  revoked: boolean;
  created_at: string;
}

export interface StartScanResponse {
  ok: boolean;
  scan_id: string;
  project_id: string;
  status: "running" | "completed" | "error" | string;
  started_at: string | null;
  updated_at: string | null;
  finished_at: string | null;
  error: string;
  already_running: boolean;
}

export interface StartScanRequest {
  projectId: string;
  target?: string;
  targetConfig?: Record<string, unknown>;
  scope?: string;
  info?: string;
  resume?: boolean;
  force?: boolean;
}

export interface StopScanRequest {
  projectId: string;
  mode: "pause" | "cancel";
}

export interface ScanEventPayload {
  event: string;
  project_id: string;
  scan_id: string;
  level: "info" | "success" | "warn" | "error";
  message: string;
  timestamp: string;
  data: Record<string, unknown>;
}

export interface IntelTargetTypeOption {
  value: string;
  label: string;
}

export interface IntelResource {
  id: string;
  name: string;
  url: string;
  target_type: string;
  enabled: boolean;
  source_kind: "builtin" | "custom";
  updatable: boolean;
  description: string;
  category: string;
  content_type: string;
  update_mode: string;
  intel_last_update: string | null;
  intel_next_update: string | null;
  intel_refresh_days: number;
  created_at: string | null;
  updated_at: string | null;
}

export interface IntelResourcesPayload {
  resources: IntelResource[];
  target_type_options: IntelTargetTypeOption[];
}

export interface IntelResourceCreatePayload {
  name: string;
  url: string;
  target_type: string;
  content_type: string;
  update_mode: "every_3_days" | "static";
  enabled?: boolean;
}

export interface IntelResourceUpdatePayload {
  name?: string;
  url?: string;
  target_type?: string;
  content_type?: string;
  update_mode?: "every_3_days" | "static";
  enabled?: boolean;
}

export interface IntelUpdateStatusRow {
  target_type: string;
  last_update: string | null;
  next_update: string | null;
  due_now: boolean;
  refresh_days: number;
  seconds_until_next_update: number;
  uses_default_sources: boolean;
  sources: IntelResource[];
  will_update: {
    verify_sources: string[];
    fetch_streams: string[];
    embed_content_types: string[];
  };
}

export interface IntelUpdateStatusPayload {
  checked_at: string;
  refresh_days: number;
  update_days_back: number;
  update_max_results: number;
  pipeline_outputs: string[];
  statuses: IntelUpdateStatusRow[];
}

export interface IntelUpdateScheduleRequest {
  target_type: string;
  refresh_days: number;
}

export interface IntelForceUpdateRequest {
  target_type: string;
  info?: string;
}

export interface IntelForceUpdateStatus {
  target_type: string;
  status: "idle" | "running" | "cancelling" | "cancelled" | "completed" | "error" | string;
  progress: number;
  message: string;
  started_at: string | null;
  finished_at: string | null;
  updated_at: string | null;
  error: string;
}

export interface InformationGatheringProfileBlock {
  id: string;
  name: string;
  interaction: string;
  goal: string;
  tools: string[];
}

export interface InformationGatheringProfile {
  target_type: string;
  version: string;
  generated_from: string;
  max_blocks: number;
  blocks: InformationGatheringProfileBlock[];
  created_at?: string;
  updated_at?: string;
}

export interface AIAssistRequest {
  prompt: string;
  projectId?: string;
  target?: string;
  targetType?: string;
  context?: string;
}

export interface AIAssistResponse {
  ok: boolean;
  blocked: boolean;
  route: "assistant" | "planner" | "reporting" | "blocked";
  reply: string;
  next_context?: string;
  classification: {
    reason: string;
    confidence: number;
    classifier: string;
    detections: string[];
  };
}

export interface AIClearConversationRequest {
  projectId: string;
  target?: string;
  targetType?: string;
}

const VISIBLE_AGENT_ORDER: Project["agents"][number]["name"][] = [
  "planner",
  "executer",
  "analyzer",
];

const LEGACY_AGENT_TO_VISIBLE: Record<string, Project["agents"][number]["name"]> = {
  analyzer: "analyzer",
  executer: "executer",
  exploit: "executer",
  perceptor: "analyzer",
  planner: "planner",
  recon: "executer",
  report: "analyzer",
  retest: "analyzer",
  verify: "analyzer",
};

const AGENT_STATE_RANK: Record<Project["agents"][number]["state"], number> = {
  error: 5,
  running: 4,
  waiting: 3,
  success: 2,
  idle: 1,
};

function normalizeVisibleAgents(value: unknown): Project["agents"] {
  const buckets = new Map<Project["agents"][number]["name"], Project["agents"][number]>();
  for (const name of VISIBLE_AGENT_ORDER) {
    buckets.set(name, { name, state: "idle" });
  }

  if (!Array.isArray(value)) {
    return VISIBLE_AGENT_ORDER.map((name) => ({ ...buckets.get(name)! }));
  }

  for (const item of value) {
    if (typeof item !== "object" || item === null) {
      continue;
    }
    const row = item as Record<string, unknown>;
    const rawName = typeof row.name === "string" ? row.name.trim().toLowerCase() : "";
    const visibleName = LEGACY_AGENT_TO_VISIBLE[rawName];
    if (!visibleName) {
      continue;
    }
    const current = buckets.get(visibleName) ?? { name: visibleName, state: "idle" as const };
    const rawState = row.state;
    const normalizedState =
      rawState === "idle"
      || rawState === "running"
      || rawState === "success"
      || rawState === "error"
      || rawState === "waiting"
        ? rawState
        : "idle";
    if (AGENT_STATE_RANK[normalizedState] < AGENT_STATE_RANK[current.state]) {
      continue;
    }
    buckets.set(visibleName, {
      name: visibleName,
      state: normalizedState,
      currentTask: typeof row.currentTask === "string" ? row.currentTask : current.currentTask,
      progress: typeof row.progress === "number" && Number.isFinite(row.progress)
        ? row.progress
        : current.progress,
      lastUpdate: typeof row.lastUpdate === "string" ? row.lastUpdate : current.lastUpdate,
    });
  }

  return VISIBLE_AGENT_ORDER.map((name) => ({ ...buckets.get(name)! }));
}

export function supportsDesktopProjectBridge(): boolean {
  const { serverUrl } = useConfig.getState();
  return serverUrl.trim().length > 0;
}

function toValidTimestamp(value: unknown, fallback: string): string {
  if (typeof value !== "string") {
    return fallback;
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return fallback;
  }
  return value;
}

function normalizeProjectRow(value: unknown): Project | null {
  if (typeof value !== "object" || value === null) {
    return null;
  }
  const row = value as Record<string, unknown>;
  if (typeof row.id !== "string" || typeof row.name !== "string") {
    return null;
  }

  const now = new Date().toISOString();
  const createdAt = toValidTimestamp(row.createdAt, now);
  const updatedAt = toValidTimestamp(row.updatedAt, createdAt);
  const status = (
    row.status === "idle"
    || row.status === "running"
    || row.status === "paused"
    || row.status === "completed"
    || row.status === "error"
  ) ? row.status : "idle";

  return {
    id: row.id,
    name: row.name,
    target: typeof row.target === "string" ? row.target : "",
    targetType: typeof row.targetType === "string" ? row.targetType : "web_app",
    targetConfig: (
      typeof row.targetConfig === "object" && row.targetConfig !== null
    ) ? (row.targetConfig as Record<string, unknown>) : undefined,
    customChecklistText: typeof row.customChecklistText === "string"
      ? row.customChecklistText
      : undefined,
    customChecklistName: typeof row.customChecklistName === "string"
      ? row.customChecklistName
      : undefined,
    status,
    createdAt,
    updatedAt,
    description: typeof row.description === "string" ? row.description : undefined,
    copilotHistory: Array.isArray(row.copilotHistory)
      ? row.copilotHistory
          .map((item) => {
            if (typeof item !== "object" || item === null) {
              return null;
            }
            const message = item as Record<string, unknown>;
            const role = message.role === "user" || message.role === "assistant"
              ? message.role
              : null;
            const text = typeof message.text === "string" ? message.text : "";
            if (!role || !text.trim()) {
              return null;
            }
            const normalized: CopilotMessage = {
              id: typeof message.id === "string" && message.id.trim()
                ? message.id
                : `${role}-${Math.random().toString(36).slice(2, 10)}`,
              role,
              text,
            };
            if (typeof message.timestamp === "string" && message.timestamp.trim()) {
              normalized.timestamp = message.timestamp;
            }
            if (
              message.route === "assistant"
              || message.route === "planner"
              || message.route === "reporting"
              || message.route === "blocked"
            ) {
              normalized.route = message.route;
            }
            if (typeof message.blocked === "boolean") {
              normalized.blocked = message.blocked;
            }
            return normalized;
          })
          .filter((item): item is CopilotMessage => item !== null)
      : undefined,
    copilotContext: typeof row.copilotContext === "string"
      ? row.copilotContext
      : undefined,
    findings: Array.isArray(row.findings) ? (row.findings as Project["findings"]) : [],
    agents: normalizeVisibleAgents(row.agents),
    phases: Array.isArray(row.phases) ? (row.phases as Project["phases"]) : [],
    scanProgress: (
      typeof row.scanProgress === "number" && Number.isFinite(row.scanProgress)
    ) ? row.scanProgress : 0,
    lastScan: (
      typeof row.lastScan === "object" && row.lastScan !== null
    ) ? (row.lastScan as Project["lastScan"]) : undefined,
  };
}

function apiBaseUrl(): string {
  const { serverUrl, serverPort } = useConfig.getState();
  const raw = serverUrl.trim().replace(/\/+$/, "");
  try {
    const parsed = new URL(raw);
    if (!parsed.port) {
      parsed.port = String(serverPort);
    }
    return parsed.toString().replace(/\/+$/, "");
  } catch {
    return `${raw}:${serverPort}`;
  }
}

async function requestJson<T>(
  path: string,
  init?: RequestInit,
  timeoutMs = 15000,
): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers = new Headers(init?.headers ?? undefined);
    const hasBody = init?.body !== undefined && init?.body !== null;
    if (hasBody && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }

    let response: Response;
    try {
      response = await fetch(`${apiBaseUrl()}${path}`, {
        ...init,
        credentials: "include",
        headers,
        signal: controller.signal,
      });
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        throw new Error(`Request timed out after ${Math.ceil(timeoutMs / 1000)} seconds.`);
      }
      throw error;
    }

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`${response.status} ${response.statusText}: ${body}`);
    }
    return (await response.json()) as T;
  } finally {
    window.clearTimeout(timeout);
  }
}

export interface SystemSettings {
  privacy_gate: boolean;
}

export async function fetchSystemSettingsFromDesktop(): Promise<SystemSettings> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson<SystemSettings>("/api/settings");
}

export async function updateSystemSettingsFromDesktop(
  settings: SystemSettings,
): Promise<{ ok: boolean }> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson("/api/settings", {
    method: "POST",
    body: JSON.stringify(settings),
  });
}

export async function listProjectsFromDesktop(): Promise<Project[]> {
  if (!supportsDesktopProjectBridge()) {
    return [];
  }

  const payload = await requestJson<{ projects?: unknown[] }>("/api/projects");
  const rows = payload.projects;
  if (!Array.isArray(rows)) {
    return [];
  }

  return rows
    .map((row) => normalizeProjectRow(row))
    .filter((row): row is Project => row !== null);
}

export async function saveProjectToDesktop(project: Project): Promise<void> {
  if (!supportsDesktopProjectBridge()) {
    return;
  }
  await requestJson("/api/projects", {
    method: "POST",
    body: JSON.stringify(project),
  });
}

export async function deleteProjectFromDesktop(projectId: string): Promise<void> {
  if (!supportsDesktopProjectBridge()) {
    return;
  }
  await requestJson(`/api/projects/${encodeURIComponent(projectId)}`, {
    method: "DELETE",
  });
}

export async function startProjectScanFromDesktop(
  request: StartScanRequest,
): Promise<StartScanResponse> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson<StartScanResponse>("/api/scans/start", {
    method: "POST",
    body: JSON.stringify({
      project_id: request.projectId,
      target: request.target ?? "",
      target_config: request.targetConfig ?? {},
      scope: request.scope ?? "",
      info: request.info ?? "",
      resume: request.resume ?? false,
      force: request.force ?? false,
    }),
  });
}

export async function stopProjectScanFromDesktop(
  request: StopScanRequest,
): Promise<{ ok: boolean; status?: string; project_id?: string; scan_id?: string }> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson("/api/scans/stop", {
    method: "POST",
    body: JSON.stringify({
      project_id: request.projectId,
      mode: request.mode,
    }),
  });
}

export async function approvePlannerForProjectScanFromDesktop(
  projectId: string,
): Promise<{
  ok: boolean;
  project_id?: string;
  scan_id?: string;
  status?: string;
  awaiting_planner_approval?: boolean;
  already_approved?: boolean;
}> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson(
    `/api/scans/${encodeURIComponent(projectId)}/approve-planner`,
    {
      method: "POST",
    },
    120000,
  );
}

export async function approveInformationGatheringForProjectScanFromDesktop(
  projectId: string,
  modifiedProgram?: any[],
): Promise<{
  ok: boolean;
  project_id?: string;
  scan_id?: string;
  status?: string;
  awaiting_information_gathering_approval?: boolean;
  already_approved?: boolean;
}> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson(
    `/api/scans/${encodeURIComponent(projectId)}/approve-information-gathering`,
    {
      method: "POST",
      body: modifiedProgram ? JSON.stringify({ modified_program: modifiedProgram }) : undefined,
    },
    120000,
  );
}

export async function approveToolForProjectScanFromDesktop(
  projectId: string,
  payload: {
    approvalId: string;
    action: "approve" | "skip";
  },
): Promise<{
  ok: boolean;
  project_id?: string;
  scan_id?: string;
  approval_id?: string;
  action?: string;
  role?: string;
  tool_name?: string;
}> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  const path = `/api/scans/${encodeURIComponent(projectId)}/approve-tool`;
  const init: RequestInit = {
    method: "POST",
    body: JSON.stringify({
      approval_id: payload.approvalId,
      action: payload.action,
    }),
  };

  // Long-running security tools are capped at 5 minutes server-side.
  // Keep the approval request alive slightly longer so the UI does not
  // report a false timeout if the browser/network is briefly delayed.
  return await requestJson(path, init, 310000);
}

export async function approvePasswordForProjectScanFromDesktop(
  projectId: string,
  payload: {
    passwordId: string;
    password: string;
    approved: boolean;
  },
): Promise<{
  ok: boolean;
  project_id?: string;
  scan_id?: string;
  password_id?: string;
  approved?: boolean;
  tool_name?: string;
}> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson(
    `/api/scans/${encodeURIComponent(projectId)}/password-response`,
    {
      method: "POST",
      body: JSON.stringify({
        password_id: payload.passwordId,
        password: payload.password,
        approved: payload.approved,
      }),
    },
    310000,
  );
}

export async function clearProjectScanEventsCacheFromDesktop(projectId: string): Promise<void> {
  if (!supportsDesktopProjectBridge()) {
    return;
  }
  await requestJson(`/api/scans/${encodeURIComponent(projectId)}/events/clear`, {
    method: "POST",
  });
}

function parseScanEventPayload(value: unknown): ScanEventPayload | null {
  if (!isRecord(value)) {
    return null;
  }
  if (
    typeof value.event !== "string"
    || typeof value.project_id !== "string"
    || typeof value.scan_id !== "string"
    || typeof value.message !== "string"
    || typeof value.timestamp !== "string"
    || !isRecord(value.data)
  ) {
    return null;
  }
  const level = value.level;
  if (level !== "info" && level !== "success" && level !== "warn" && level !== "error") {
    return null;
  }
  return {
    event: value.event,
    project_id: value.project_id,
    scan_id: value.scan_id,
    level,
    message: value.message,
    timestamp: value.timestamp,
    data: value.data,
  };
}

export function streamProjectScanEvents(
  projectId: string,
  handlers: {
    onEvent: (event: ScanEventPayload) => void;
    onError?: (error: Error) => void;
  },
): () => void {
  if (!supportsDesktopProjectBridge() || typeof window === "undefined") {
    return () => {};
  }

  const url = `${apiBaseUrl()}/api/scans/${encodeURIComponent(projectId)}/events`;
  const source = new EventSource(url, { withCredentials: true });

  const onEventMessage = (raw: MessageEvent<string>) => {
    try {
      const parsed = JSON.parse(raw.data);
      const payload = parseScanEventPayload(parsed);
      if (payload) {
        handlers.onEvent(payload);
      }
    } catch {
      // Ignore malformed stream events.
    }
  };

  const onError = () => {
    handlers.onError?.(new Error("Scan event stream disconnected"));
  };

  source.addEventListener("scan_event", onEventMessage as EventListener);
  source.onerror = onError;

  return () => {
    source.removeEventListener("scan_event", onEventMessage as EventListener);
    source.onerror = null;
    source.close();
  };
}

export async function listProjectScanEventsFromDesktop(
  projectId: string,
  limit: number = 180,
): Promise<ScanEventPayload[]> {
  if (!supportsDesktopProjectBridge()) {
    return [];
  }

  const safeLimit = Math.max(1, Math.min(2000, Math.floor(limit)));
  const payload = await requestJson<{ events?: unknown[] }>(
    `/api/scans/${encodeURIComponent(projectId)}/events/recent?limit=${safeLimit}`,
  );
  const rows = Array.isArray(payload.events) ? payload.events : [];
  return rows
    .map((row) => parseScanEventPayload(row))
    .filter((row): row is ScanEventPayload => row !== null);
}

export async function listProjectTargetTypesFromDesktop(): Promise<ProjectTargetTypeOption[]> {
  if (!supportsDesktopProjectBridge()) {
    return [];
  }

  const payload = await requestJson<{ target_types?: unknown[] }>("/api/project-target-types");
  const rows = payload.target_types;
  if (!Array.isArray(rows)) {
    return [];
  }

  return rows.filter((row): row is ProjectTargetTypeOption => {
    if (typeof row !== "object" || row === null) {
      return false;
    }
    const candidate = row as Record<string, unknown>;
    return typeof candidate.value === "string" && typeof candidate.label === "string";
  });
}

export async function listProjectTargetFieldsFromDesktop(
  targetType: string,
): Promise<ProjectTargetField[]> {
  if (!supportsDesktopProjectBridge()) {
    return [];
  }

  const payload = await requestJson<{ fields?: unknown[] }>(
    `/api/project-target-types/${encodeURIComponent(targetType)}/fields?required_only=false`,
  );
  const rows = payload.fields;
  if (!Array.isArray(rows)) {
    return [];
  }

  return rows.filter((row): row is ProjectTargetField => {
    if (typeof row !== "object" || row === null) {
      return false;
    }
    const candidate = row as Record<string, unknown>;
    return (
      typeof candidate.key === "string"
      && typeof candidate.label === "string"
      && typeof candidate.required === "boolean"
      && typeof candidate.data_type === "string"
      && Array.isArray(candidate.options)
    );
  });
}

export async function listInformationGatheringProfilesFromDesktop(): Promise<InformationGatheringProfile[]> {
  if (!supportsDesktopProjectBridge()) {
    return [];
  }

  const payload = await requestJson<{ profiles?: unknown[] }>("/api/project-target-types/information-gathering-profiles");
  const rows = Array.isArray(payload.profiles) ? payload.profiles : [];
  return rows
    .map((row) => toInformationGatheringProfile(row))
    .filter((row): row is InformationGatheringProfile => row !== null);
}

export async function getInformationGatheringProfileFromDesktop(targetType: string): Promise<InformationGatheringProfile> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }

  const payload = await requestJson<{ profile?: unknown }>(
    `/api/project-target-types/${encodeURIComponent(targetType)}/information-gathering-profile`,
  );
  const profile = toInformationGatheringProfile(payload.profile);
  if (!profile) {
    throw new Error("Invalid information gathering profile response");
  }
  return profile;
}

export async function saveInformationGatheringProfileFromDesktop(
  targetType: string,
  payload: InformationGatheringProfile,
): Promise<InformationGatheringProfile> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }

  const response = await requestJson<{ profile?: unknown }>(
    `/api/project-target-types/${encodeURIComponent(targetType)}/information-gathering-profile`,
    {
      method: "PUT",
      body: JSON.stringify(payload),
    },
  );
  const profile = toInformationGatheringProfile(response.profile);
  if (!profile) {
    throw new Error("Invalid information gathering profile response");
  }
  return profile;
}

export async function resetInformationGatheringProfileFromDesktop(targetType: string): Promise<InformationGatheringProfile> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }

  const response = await requestJson<{ profile?: unknown }>(
    `/api/project-target-types/${encodeURIComponent(targetType)}/information-gathering-profile`,
    {
      method: "DELETE",
    },
  );
  const profile = toInformationGatheringProfile(response.profile);
  if (!profile) {
    throw new Error("Invalid information gathering profile response");
  }
  return profile;
}

export async function createProjectShareLinkFromDesktop(
  projectId: string,
  payload: ProjectShareLinkRequest,
): Promise<ProjectShareLinkResponse> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson<ProjectShareLinkResponse>(
    `/api/projects/${encodeURIComponent(projectId)}/share-links`,
    {
      method: "POST",
      body: JSON.stringify(payload),
    },
    60000,
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function toInformationGatheringProfileBlock(value: unknown): InformationGatheringProfileBlock | null {
  if (!isRecord(value)) {
    return null;
  }
  if (
    typeof value.id !== "string"
    || typeof value.name !== "string"
    || typeof value.interaction !== "string"
    || typeof value.goal !== "string"
    || !Array.isArray(value.tools)
  ) {
    return null;
  }

  return {
    id: value.id,
    name: value.name,
    interaction: value.interaction,
    goal: value.goal,
    tools: value.tools.filter((item): item is string => typeof item === "string"),
  };
}

function toInformationGatheringProfile(value: unknown): InformationGatheringProfile | null {
  if (!isRecord(value)) {
    return null;
  }
  if (
    typeof value.target_type !== "string"
    || typeof value.version !== "string"
    || typeof value.generated_from !== "string"
    || typeof value.max_blocks !== "number"
    || !Array.isArray(value.blocks)
  ) {
    return null;
  }

  return {
    target_type: value.target_type,
    version: value.version,
    generated_from: value.generated_from,
    max_blocks: value.max_blocks,
    blocks: value.blocks
      .map((item) => toInformationGatheringProfileBlock(item))
      .filter((item): item is InformationGatheringProfileBlock => item !== null),
    created_at: typeof value.created_at === "string" ? value.created_at : undefined,
    updated_at: typeof value.updated_at === "string" ? value.updated_at : undefined,
  };
}

function toIntelResource(value: unknown): IntelResource | null {
  if (!isRecord(value)) {
    return null;
  }
  const sourceKind = value.source_kind;
  if (sourceKind !== "builtin" && sourceKind !== "custom") {
    return null;
  }
  if (
    typeof value.id !== "string"
    || typeof value.name !== "string"
    || typeof value.url !== "string"
    || typeof value.target_type !== "string"
    || typeof value.enabled !== "boolean"
    || typeof value.updatable !== "boolean"
  ) {
    return null;
  }

  return {
    id: value.id,
    name: value.name,
    url: value.url,
    target_type: value.target_type,
    enabled: value.enabled,
    source_kind: sourceKind,
    updatable: value.updatable,
    description: typeof value.description === "string" ? value.description : "",
    category: typeof value.category === "string" ? value.category : "",
    content_type: typeof value.content_type === "string" ? value.content_type : "",
    update_mode: typeof value.update_mode === "string" ? value.update_mode : "every_3_days",
    intel_last_update: typeof value.intel_last_update === "string" ? value.intel_last_update : null,
    intel_next_update: typeof value.intel_next_update === "string" ? value.intel_next_update : null,
    intel_refresh_days: typeof value.intel_refresh_days === "number" ? value.intel_refresh_days : 3,
    created_at: typeof value.created_at === "string" ? value.created_at : null,
    updated_at: typeof value.updated_at === "string" ? value.updated_at : null,
  };
}

export async function listIntelResourcesFromDesktop(
  targetType?: string,
): Promise<IntelResourcesPayload> {
  if (!supportsDesktopProjectBridge()) {
    return {
      resources: [],
      target_type_options: [{ value: "all", label: "All Targets" }],
    };
  }

  const path = targetType
    ? `/api/intel/resources?target_type=${encodeURIComponent(targetType)}`
    : "/api/intel/resources";
  const payload = await requestJson<{
    resources?: unknown[];
    target_type_options?: unknown[];
  }>(path);

  const resources = Array.isArray(payload.resources)
    ? payload.resources
      .map(toIntelResource)
      .filter((entry): entry is IntelResource => entry !== null)
    : [];

  const targetTypeOptions = Array.isArray(payload.target_type_options)
    ? payload.target_type_options.filter((row): row is IntelTargetTypeOption => {
      if (!isRecord(row)) {
        return false;
      }
      return typeof row.value === "string" && typeof row.label === "string";
    })
    : [];

  return {
    resources,
    target_type_options: targetTypeOptions,
  };
}

export async function addIntelResourceFromDesktop(
  payload: IntelResourceCreatePayload,
): Promise<IntelResource> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }

  const response = await requestJson<{ resource?: unknown }>("/api/intel/resources", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  const resource = toIntelResource(response.resource);
  if (!resource) {
    throw new Error("Invalid resource response");
  }
  return resource;
}

export async function updateIntelResourceFromDesktop(
  resourceId: string,
  payload: IntelResourceUpdatePayload,
): Promise<IntelResource> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  const response = await requestJson<{ resource?: unknown }>(
    `/api/intel/resources/${encodeURIComponent(resourceId)}`,
    {
      method: "PATCH",
      body: JSON.stringify(payload),
    },
  );
  const resource = toIntelResource(response.resource);
  if (!resource) {
    throw new Error("Invalid resource response");
  }
  return resource;
}

export async function deleteIntelResourceFromDesktop(resourceId: string): Promise<void> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  await requestJson(`/api/intel/resources/${encodeURIComponent(resourceId)}`, {
    method: "DELETE",
  });
}

export async function listIntelUpdateStatusFromDesktop(
  targetType?: string,
): Promise<IntelUpdateStatusPayload> {
  if (!supportsDesktopProjectBridge()) {
    return {
      checked_at: new Date().toISOString(),
      refresh_days: 3,
      update_days_back: 14,
      update_max_results: 25,
      pipeline_outputs: ["attack_types", "exploits"],
      statuses: [],
    };
  }

  const path = targetType
    ? `/api/intel/update-status?target_type=${encodeURIComponent(targetType)}`
    : "/api/intel/update-status";

  const payload = await requestJson<{
    checked_at?: unknown;
    refresh_days?: unknown;
    update_days_back?: unknown;
    update_max_results?: unknown;
    pipeline_outputs?: unknown;
    statuses?: unknown[];
  }>(path);

  const statuses: IntelUpdateStatusRow[] = Array.isArray(payload.statuses)
    ? payload.statuses.filter((row): row is IntelUpdateStatusRow => {
      if (!isRecord(row)) {
        return false;
      }
      return (
        typeof row.target_type === "string"
        && (typeof row.last_update === "string" || row.last_update === null)
        && (typeof row.next_update === "string" || row.next_update === null)
        && typeof row.due_now === "boolean"
        && typeof row.refresh_days === "number"
        && typeof row.seconds_until_next_update === "number"
        && typeof row.uses_default_sources === "boolean"
        && Array.isArray(row.sources)
        && isRecord(row.will_update)
        && Array.isArray(row.will_update.verify_sources)
        && Array.isArray(row.will_update.fetch_streams)
        && Array.isArray(row.will_update.embed_content_types)
      );
    }).map((row) => ({
      ...row,
      sources: row.sources
        .map(toIntelResource)
        .filter((entry): entry is IntelResource => entry !== null),
      will_update: {
        verify_sources: row.will_update.verify_sources
          .filter((item): item is string => typeof item === "string"),
        fetch_streams: row.will_update.fetch_streams
          .filter((item): item is string => typeof item === "string"),
        embed_content_types: row.will_update.embed_content_types
          .filter((item): item is string => typeof item === "string"),
      },
    }))
    : [];

  return {
    checked_at: typeof payload.checked_at === "string" ? payload.checked_at : new Date().toISOString(),
    refresh_days: typeof payload.refresh_days === "number" ? payload.refresh_days : 3,
    update_days_back: typeof payload.update_days_back === "number" ? payload.update_days_back : 14,
    update_max_results: typeof payload.update_max_results === "number" ? payload.update_max_results : 25,
    pipeline_outputs: Array.isArray(payload.pipeline_outputs)
      ? payload.pipeline_outputs.filter((item): item is string => typeof item === "string")
      : ["attack_types", "exploits"],
    statuses,
  };
}

export async function askAIAssistFromDesktop(
  request: AIAssistRequest,
): Promise<AIAssistResponse> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }

  return await requestJson<AIAssistResponse>("/api/ai/assist", {
    method: "POST",
    body: JSON.stringify({
      prompt: request.prompt,
      project_id: request.projectId ?? "",
      target: request.target ?? "",
      target_type: request.targetType ?? "",
      context: request.context ?? "",
    }),
  }, 180000);
}

export async function clearAIAssistConversationFromDesktop(
  request: AIClearConversationRequest,
): Promise<{ ok: boolean; project_id: string; scope_key: string; cleared: boolean }> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }

  return await requestJson("/api/ai/clear-conversation", {
    method: "POST",
    body: JSON.stringify({
      project_id: request.projectId,
      target: request.target ?? "",
      target_type: request.targetType ?? "",
    }),
  }, 30000);
}

export async function setIntelUpdateScheduleFromDesktop(
  request: IntelUpdateScheduleRequest,
): Promise<{ ok: boolean; schedule: { target_type: string; refresh_days: number } }> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson("/api/intel/update-schedule", {
    method: "POST",
    body: JSON.stringify({
      target_type: request.target_type,
      refresh_days: request.refresh_days,
    }),
  });
}

export async function forceIntelUpdateFromDesktop(
  request: IntelForceUpdateRequest,
): Promise<{ ok: boolean; started: boolean; target_type: string; reason?: string }> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson("/api/intel/force-update", {
    method: "POST",
    body: JSON.stringify({
      target_type: request.target_type,
      info: request.info ?? "",
    }),
  });
}

export async function cancelForceIntelUpdateFromDesktop(
  targetType: string,
): Promise<{ ok: boolean; cancelled: boolean; target_type: string; reason?: string }> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson("/api/intel/force-update/cancel", {
    method: "POST",
    body: JSON.stringify({
      target_type: targetType,
    }),
  });
}

export async function getForceIntelUpdateStatusFromDesktop(
  targetType: string,
): Promise<IntelForceUpdateStatus> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  const payload = await requestJson<Partial<IntelForceUpdateStatus>>(
    `/api/intel/force-update-status?target_type=${encodeURIComponent(targetType)}`,
  );
  return {
    target_type: typeof payload.target_type === "string" ? payload.target_type : targetType,
    status: typeof payload.status === "string" ? payload.status : "idle",
    progress: typeof payload.progress === "number" ? payload.progress : 0,
    message: typeof payload.message === "string" ? payload.message : "",
    started_at: typeof payload.started_at === "string" ? payload.started_at : null,
    finished_at: typeof payload.finished_at === "string" ? payload.finished_at : null,
    updated_at: typeof payload.updated_at === "string" ? payload.updated_at : null,
    error: typeof payload.error === "string" ? payload.error : "",
  };
}

/* ── Report API ──────────────────────────────────────────── */

export interface ReportStatus {
  markdown: boolean;
  html: boolean;
  pdf: boolean;
  generated_at: string | null;
}

export interface GenerateReportResponse {
  ok: boolean;
  report_id: string;
  format: string;
  created_at: string;
}

export interface ReportContentResponse {
  ok: boolean;
  format: string;
  content: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

export async function generateReportFromDesktop(
  projectId: string,
): Promise<GenerateReportResponse> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson<GenerateReportResponse>(
    `/api/projects/${encodeURIComponent(projectId)}/reports/generate`,
    { method: "POST" },
    180000,
  );
}

export async function getReportStatusFromDesktop(
  projectId: string,
): Promise<ReportStatus> {
  if (!supportsDesktopProjectBridge()) {
    return { markdown: false, html: false, pdf: false, generated_at: null };
  }
  const payload = await requestJson<Partial<ReportStatus>>(
    `/api/projects/${encodeURIComponent(projectId)}/reports/status`,
  );
  return {
    markdown: typeof payload.markdown === "boolean" ? payload.markdown : false,
    html: typeof payload.html === "boolean" ? payload.html : false,
    pdf: typeof payload.pdf === "boolean" ? payload.pdf : false,
    generated_at: typeof payload.generated_at === "string" ? payload.generated_at : null,
  };
}

export async function getReportContentFromDesktop(
  projectId: string,
  format: "markdown" | "html",
): Promise<ReportContentResponse> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson<ReportContentResponse>(
    `/api/projects/${encodeURIComponent(projectId)}/reports/${encodeURIComponent(format)}`,
  );
}

export async function downloadReportBlobFromDesktop(
  projectId: string,
  format: "markdown" | "html",
): Promise<{ content: string; filename: string; mimeType: string }> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  const report = await getReportContentFromDesktop(projectId, format);
  const ext = format === "html" ? "html" : "md";
  const mime = format === "html" ? "text/html" : "text/markdown";
  return {
    content: report.content,
    filename: `pentaforge-report-${projectId.slice(0, 8)}.${ext}`,
    mimeType: mime,
  };
}

export async function createShareLinkFromDesktop(
  projectId: string,
  payload: { expires_hours: number; password?: string; one_time: boolean },
): Promise<{ ok: boolean; access_url: string; token: string }> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson(
    `/api/projects/${encodeURIComponent(projectId)}/share-links`,
    {
      method: "POST",
      body: JSON.stringify(payload),
    },
  );
}

export interface ClientMessage {
  id: string;
  project_id: string;
  sender: "client" | "pentester";
  content: string;
  created_at: string;
}

export interface PentesterMessagesResponse {
  messages: ClientMessage[];
  client_typing: boolean;
}

export async function getPentesterMessagesFromDesktop(
  projectId: string,
): Promise<PentesterMessagesResponse> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson<PentesterMessagesResponse>(
    `/api/projects/${encodeURIComponent(projectId)}/messages`,
  );
}

export async function setPentesterTypingFromDesktop(
  projectId: string,
): Promise<{ ok: boolean }> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson(
    `/api/projects/${encodeURIComponent(projectId)}/typing`,
    { method: "POST" },
  );
}

export async function getActiveShareLinkFromDesktop(
  projectId: string,
): Promise<ProjectShareLinkResponse> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson<ProjectShareLinkResponse>(
    `/api/projects/${encodeURIComponent(projectId)}/share-link`,
  );
}

export async function stopTunnelFromDesktop(): Promise<{ ok: boolean }> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson("/api/tunnel/stop", { method: "POST" });
}

export async function revokeShareLinksFromDesktop(
  projectId: string,
): Promise<{ ok: boolean }> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson(
    `/api/projects/${encodeURIComponent(projectId)}/share-links/revoke`,
    { method: "POST" },
  );
}

export async function sendPentesterMessageFromDesktop(
  projectId: string,
  content: string,
  sender: "client" | "pentester" = "pentester",
): Promise<{ ok: boolean }> {
  if (!supportsDesktopProjectBridge()) {
    throw new Error("desktop project bridge is disabled");
  }
  return await requestJson(
    `/api/projects/${encodeURIComponent(projectId)}/messages`,
    {
      method: "POST",
      body: JSON.stringify({ content, sender }),
    },
  );
}
