import { useConfig } from "@/stores/config";
import type { Project } from "@/types";

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
  password?: string;
  one_time: boolean;
}

export interface ProjectShareLinkResponse {
  token: string;
  access_url: string;
  expires_at: string;
  one_time: boolean;
  password_protected: boolean;
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
  targetConfig?: Record<string, string>;
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
  enabled?: boolean;
}

export interface IntelUpdateStatusRow {
  target_type: string;
  last_update: string | null;
  next_update: string | null;
  due_now: boolean;
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
  route: "planner" | "reporting" | "blocked";
  reply: string;
  classification: {
    reason: string;
    confidence: number;
    classifier: string;
    detections: string[];
  };
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
    ) ? (row.targetConfig as Record<string, string>) : undefined,
    status,
    createdAt,
    updatedAt,
    description: typeof row.description === "string" ? row.description : undefined,
    findings: Array.isArray(row.findings) ? (row.findings as Project["findings"]) : [],
    agents: Array.isArray(row.agents) ? (row.agents as Project["agents"]) : [],
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

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 8000);
  try {
    const headers = new Headers(init?.headers ?? undefined);
    const hasBody = init?.body !== undefined && init?.body !== null;
    if (hasBody && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }

    const response = await fetch(`${apiBaseUrl()}${path}`, {
      ...init,
      credentials: "include",
      headers,
      signal: controller.signal,
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`${response.status} ${response.statusText}: ${body}`);
    }
    return (await response.json()) as T;
  } finally {
    window.clearTimeout(timeout);
  }
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
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
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
  });
}
