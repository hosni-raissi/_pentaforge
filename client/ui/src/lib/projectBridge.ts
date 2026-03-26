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

export function supportsDesktopProjectBridge(): boolean {
  const { serverUrl } = useConfig.getState();
  return serverUrl.trim().length > 0;
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
    const response = await fetch(`${apiBaseUrl()}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(init?.headers ?? {}),
      },
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

  return rows.filter((row): row is Project => {
    if (typeof row !== "object" || row === null) {
      return false;
    }
    const candidate = row as Record<string, unknown>;
    return typeof candidate.id === "string" && typeof candidate.name === "string";
  });
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
