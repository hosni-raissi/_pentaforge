import { useCallback, useEffect, useMemo, useState } from "react";
import { Bot, Clock3, Cpu, Palette, Pencil, Plus, RefreshCcw, Server, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { Select } from "@/components/ui/Select";
import { Tabs } from "@/components/ui/Tabs";
import { Toggle } from "@/components/ui/Toggle";
import {
  addIntelResourceFromDesktop,
  cancelForceIntelUpdateFromDesktop,
  deleteIntelResourceFromDesktop,
  forceIntelUpdateFromDesktop,
  getForceIntelUpdateStatusFromDesktop,
  listIntelResourcesFromDesktop,
  listIntelUpdateStatusFromDesktop,
  setIntelUpdateScheduleFromDesktop,
  updateIntelResourceFromDesktop,
  type IntelForceUpdateStatus,
  type IntelResource,
  type IntelTargetTypeOption,
  type IntelUpdateStatusPayload,
} from "@/lib/projectBridge";
import { useConfig } from "@/stores/config";
import { useTheme } from "@/stores/theme";

function formatTimestamp(value: string | null): string {
  if (!value) {
    return "Never";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return "Unknown";
  }
  return parsed.toLocaleString();
}

function formatTargetTypeLabel(value: string): string {
  if (value === "all") {
    return "All Targets";
  }
  return value.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

const RESOURCE_TYPE_OPTIONS = [
  { value: "strategies", label: "Strategies" },
  { value: "exploits", label: "Exploits" },
  { value: "tools", label: "Tools" },
  { value: "standards", label: "Standards" },
  { value: "attack_types", label: "Attack Types" },
  { value: "payload", label: "Payload" },
];

function buildUpdateModeOptions(refreshDays: number) {
  const safeDays = Math.max(1, Number(refreshDays || 3));
  return [
    { value: "every_3_days", label: `Managed by schedule (currently every ${safeDays} day(s))` },
    { value: "static", label: "Static Data" },
  ];
}

function formatResourceCadence(resource: IntelResource): string {
  if (resource.update_mode === "static") {
    return "static (no intel refresh)";
  }
  const days = Number(resource.intel_refresh_days || 3);
  return `updated by intel every ${Math.max(1, days)} day(s)`;
}

function isBuiltinResource(resource: IntelResource): boolean {
  return resource.id.startsWith("builtin::");
}

function resourceSourceFilterValue(resource: IntelResource): "user_custom" | "builtin_custom" | "builtin_fixed" {
  if (resource.source_kind === "custom") {
    return isBuiltinResource(resource) ? "builtin_custom" : "user_custom";
  }
  return "builtin_fixed";
}

function resourceSourceLabel(resource: IntelResource): string {
  const kind = resourceSourceFilterValue(resource);
  if (kind === "user_custom") {
    return "user custom";
  }
  if (kind === "builtin_custom") {
    return "builtin custom";
  }
  return "builtin fixed";
}

const RESOURCE_TARGET_SCOPE: Record<string, Set<string>> = {
  web_app: new Set(["web_app"]),
  api: new Set(["api"]),
  mobile: new Set(["mobile"]),
  infra: new Set(["infra", "network", "linux_server", "cloud", "container", "shared"]),
  network: new Set(["network"]),
  iot: new Set(["iot"]),
  linux_server: new Set(["linux_server"]),
  desktop: new Set(["desktop"]),
  cloud: new Set(["cloud"]),
  container: new Set(["container", "cloud"]),
  database: new Set(["database"]),
  repository: new Set(["repository"]),
  shared: new Set(["shared"]),
};

const EXPECTED_TARGET_FILTERS = [
  "all",
  "web_app",
  "api",
  "mobile",
  "infra",
  "network",
  "iot",
  "linux_server",
  "desktop",
  "cloud",
  "container",
  "database",
  "repository",
  "shared",
];

function resourceMatchesTargetFilter(resourceTargetType: string, selectedTargetFilter: string): boolean {
  const cleanTarget = String(resourceTargetType || "").trim().toLowerCase();
  const cleanFilter = String(selectedTargetFilter || "").trim().toLowerCase();
  if (!cleanFilter || cleanFilter === "all") {
    return true;
  }
  const scope = RESOURCE_TARGET_SCOPE[cleanFilter] ?? new Set([cleanFilter]);
  return scope.has(cleanTarget);
}

function resourceDisplayTarget(resourceTargetType: string, selectedTargetFilter: string): string {
  const cleanTarget = String(resourceTargetType || "").trim().toLowerCase();
  const cleanFilter = String(selectedTargetFilter || "").trim().toLowerCase();
  if (cleanFilter === "infra" && resourceMatchesTargetFilter(cleanTarget, cleanFilter)) {
    return "infra";
  }
  return cleanTarget || "all";
}

export default function Settings() {
  const config = useConfig();
  const { isDark, setDark } = useTheme();
  const activeLLM = config.llmConfigs.find(
    (item) => item.id === config.activeLLM
  );
  const [intelResources, setIntelResources] = useState<IntelResource[]>([]);
  const [intelTargetOptions, setIntelTargetOptions] = useState<IntelTargetTypeOption[]>([
    { value: "all", label: "All Targets" },
  ]);
  const [intelStatuses, setIntelStatuses] = useState<IntelUpdateStatusPayload["statuses"]>([]);
  const [intelMeta, setIntelMeta] = useState({
    checked_at: "",
    refresh_days: 3,
    update_days_back: 14,
    update_max_results: 25,
    pipeline_outputs: ["attack_types", "exploits"],
  });
  const [intelLoading, setIntelLoading] = useState(false);
  const [intelError, setIntelError] = useState("");
  const [resourceName, setResourceName] = useState("");
  const [resourceUrl, setResourceUrl] = useState("");
  const [resourceContentType, setResourceContentType] = useState("strategies");
  const [resourceUpdateMode, setResourceUpdateMode] = useState<"every_3_days" | "static">("every_3_days");
  const [resourceTargetType, setResourceTargetType] = useState("all");
  const [resourceSaveLoading, setResourceSaveLoading] = useState(false);
  const [resourceSaveError, setResourceSaveError] = useState("");
  const [resourceSaveSuccess, setResourceSaveSuccess] = useState("");
  const [resourceSearch, setResourceSearch] = useState("");
  const [resourceTypeFilter, setResourceTypeFilter] = useState("all");
  const [resourceTargetFilter, setResourceTargetFilter] = useState("all");
  const [resourceUpdateFilter, setResourceUpdateFilter] = useState("all");
  const [editingResourceId, setEditingResourceId] = useState<string | null>(null);
  const [scheduleTargetType, setScheduleTargetType] = useState("all");
  const [scheduleRefreshDays, setScheduleRefreshDays] = useState("3");
  const [scheduleSaving, setScheduleSaving] = useState(false);
  const [scheduleSaveError, setScheduleSaveError] = useState("");
  const [scheduleSaveSuccess, setScheduleSaveSuccess] = useState("");
  const [forceUpdateLoading, setForceUpdateLoading] = useState(false);
  const [forceUpdateCancelLoading, setForceUpdateCancelLoading] = useState(false);
  const [forceUpdateError, setForceUpdateError] = useState("");
  const [forceUpdateSuccess, setForceUpdateSuccess] = useState("");
  const [forceUpdateStatus, setForceUpdateStatus] = useState<IntelForceUpdateStatus | null>(null);
  const [showForceUpdatePanel, setShowForceUpdatePanel] = useState(false);
  const forceUpdateStatusValue = String(forceUpdateStatus?.status || "").toLowerCase();
  const forceUpdateIsActive = forceUpdateStatusValue === "running" || forceUpdateStatusValue === "cancelling";

  const loadIntelData = useCallback(async () => {
    setIntelLoading(true);
    setIntelError("");
    try {
      const [resourcesPayload, statusPayload] = await Promise.all([
        listIntelResourcesFromDesktop(),
        listIntelUpdateStatusFromDesktop(),
      ]);
      setIntelResources(resourcesPayload.resources);
      const options = resourcesPayload.target_type_options.length > 0
        ? resourcesPayload.target_type_options
        : [{ value: "all", label: "All Targets" }];
      setIntelTargetOptions(options);
      setResourceTargetType((current) => {
        const hasCurrent = options.some((item) => item.value === current);
        return hasCurrent ? current : options[0].value;
      });
      setScheduleTargetType((current) => {
        const hasCurrent = options.some((item) => item.value === current);
        return hasCurrent ? current : options[0].value;
      });

      setIntelStatuses(statusPayload.statuses);
      setIntelMeta({
        checked_at: statusPayload.checked_at,
        refresh_days: statusPayload.refresh_days,
        update_days_back: statusPayload.update_days_back,
        update_max_results: statusPayload.update_max_results,
        pipeline_outputs: statusPayload.pipeline_outputs,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to load Intel settings";
      setIntelError(message);
    } finally {
      setIntelLoading(false);
    }
  }, []);

  useEffect(() => {
    const selected = intelStatuses.find((status) => status.target_type === scheduleTargetType)
      ?? intelStatuses.find((status) => status.target_type === "all")
      ?? null;
    if (!selected) {
      setScheduleRefreshDays(String(intelMeta.refresh_days || 3));
      return;
    }
    setScheduleRefreshDays(String(selected.refresh_days));
  }, [intelStatuses, scheduleTargetType, intelMeta.refresh_days]);

  useEffect(() => {
    void loadIntelData();
  }, [loadIntelData]);

  const loadForceUpdateStatus = useCallback(async () => {
    try {
      const status = await getForceIntelUpdateStatusFromDesktop(scheduleTargetType);
      setForceUpdateStatus(status);
    } catch {
      // Keep UI usable even when status endpoint is temporarily unavailable.
    }
  }, [scheduleTargetType]);

  useEffect(() => {
    if (!showForceUpdatePanel) {
      return;
    }
    void loadForceUpdateStatus();
  }, [showForceUpdatePanel, loadForceUpdateStatus]);

  useEffect(() => {
    const isActive = forceUpdateStatus?.status === "running" || forceUpdateStatus?.status === "cancelling";
    if (!showForceUpdatePanel || !forceUpdateStatus || !isActive) {
      return;
    }
    const timer = window.setInterval(() => {
      void loadForceUpdateStatus();
    }, 1500);
    return () => window.clearInterval(timer);
  }, [showForceUpdatePanel, forceUpdateStatus, loadForceUpdateStatus]);

  const typeFilterOptions = useMemo(() => {
    const values = new Set<string>();
    for (const resource of intelResources) {
      const contentType = String(resource.content_type || "").trim();
      if (contentType) {
        values.add(contentType);
      }
    }
    return [
      { value: "all", label: "All Types" },
      ...Array.from(values).sort((a, b) => a.localeCompare(b)).map((value) => ({
        value,
        label: formatTargetTypeLabel(value),
      })),
    ];
  }, [intelResources]);

  const targetFilterOptions = useMemo(() => {
    const labels = new Map<string, string>();
    labels.set("all", "All Targets");
    for (const option of intelTargetOptions) {
      const value = String(option.value || "").trim().toLowerCase();
      if (!value) {
        continue;
      }
      labels.set(value, String(option.label || formatTargetTypeLabel(value)));
    }
    for (const value of EXPECTED_TARGET_FILTERS) {
      if (!labels.has(value)) {
        labels.set(value, formatTargetTypeLabel(value));
      }
    }
    for (const resource of intelResources) {
      const targetType = String(resource.target_type || "").trim();
      if (targetType) {
        const cleanValue = targetType.toLowerCase();
        if (!labels.has(cleanValue)) {
          labels.set(cleanValue, formatTargetTypeLabel(cleanValue));
        }
      }
    }
    const rows = Array.from(labels.entries()).map(([value, label]) => ({ value, label }));
    const nonAll = rows
      .filter((row) => row.value !== "all")
      .sort((a, b) => a.label.localeCompare(b.label));
    return [
      { value: "all", label: "All Targets" },
      ...nonAll,
    ];
  }, [intelResources, intelTargetOptions]);

  const updateFilterOptions = useMemo(
    () => [
      { value: "all", label: "All Updates" },
      { value: "every_3_days", label: "Intel Managed" },
      { value: "static", label: "Static" },
    ],
    [],
  );

  const filteredIntelResources = useMemo(() => {
    const needle = resourceSearch.trim().toLowerCase();
    return intelResources.filter((resource) => {
      const contentType = String(resource.content_type || "").trim().toLowerCase();
      const targetType = String(resource.target_type || "").trim().toLowerCase();
      const updateMode = String(resource.update_mode || "").trim().toLowerCase();
      const typeFilter = resourceTypeFilter.trim().toLowerCase();
      const targetFilter = resourceTargetFilter.trim().toLowerCase();
      const updateFilter = resourceUpdateFilter.trim().toLowerCase();

      if (typeFilter !== "all" && contentType !== typeFilter) {
        return false;
      }
      if (!resourceMatchesTargetFilter(targetType, targetFilter)) {
        return false;
      }
      if (updateFilter !== "all" && updateMode !== updateFilter) {
        return false;
      }
      if (!needle) {
        return true;
      }
      const text = `${resource.name} ${resource.url} ${resource.target_type} ${resourceSourceLabel(resource)} ${resource.content_type} ${resource.update_mode}`.toLowerCase();
      return text.includes(needle);
    });
  }, [
    intelResources,
    resourceSearch,
    resourceTypeFilter,
    resourceTargetFilter,
    resourceUpdateFilter,
  ]);

  useEffect(() => {
    const validTypes = new Set(typeFilterOptions.map((item) => item.value));
    if (!validTypes.has(resourceTypeFilter)) {
      setResourceTypeFilter("all");
    }
  }, [typeFilterOptions, resourceTypeFilter]);

  useEffect(() => {
    const validTargets = new Set(targetFilterOptions.map((item) => item.value));
    if (!validTargets.has(resourceTargetFilter)) {
      setResourceTargetFilter("all");
    }
  }, [targetFilterOptions, resourceTargetFilter]);

  const refreshDaysByTarget = useMemo(() => {
    const map = new Map<string, number>();
    for (const status of intelStatuses) {
      const days = Number(status.refresh_days || 0);
      if (!Number.isFinite(days) || days < 1) {
        continue;
      }
      map.set(status.target_type, Math.floor(days));
    }
    if (!map.has("all")) {
      const fallback = Number(intelMeta.refresh_days || 3);
      map.set("all", Number.isFinite(fallback) && fallback > 0 ? Math.floor(fallback) : 3);
    }
    return map;
  }, [intelStatuses, intelMeta.refresh_days]);

  const currentResourceRefreshDays = useMemo(() => {
    const direct = refreshDaysByTarget.get(resourceTargetType);
    if (direct && direct > 0) {
      return direct;
    }
    const shared = refreshDaysByTarget.get("all");
    return shared && shared > 0 ? shared : 3;
  }, [refreshDaysByTarget, resourceTargetType]);

  const updateModeOptions = useMemo(
    () => buildUpdateModeOptions(currentResourceRefreshDays),
    [currentResourceRefreshDays],
  );

  function resetResourceForm() {
    setEditingResourceId(null);
    setResourceName("");
    setResourceUrl("");
    setResourceTargetType("all");
    setResourceContentType("strategies");
    setResourceUpdateMode("every_3_days");
  }

  function startEditResource(resource: IntelResource) {
    if (resource.source_kind !== "custom") {
      return;
    }
    setEditingResourceId(resource.id);
    setResourceName(resource.name);
    setResourceUrl(resource.url);
    setResourceTargetType(resource.target_type || "all");
    setResourceContentType(resource.content_type || "strategies");
    setResourceUpdateMode(resource.update_mode === "static" ? "static" : "every_3_days");
  }

  async function handleSaveResource() {
    const cleanName = resourceName.trim();
    const cleanUrl = resourceUrl.trim();
    if (!cleanName || !cleanUrl) {
      setResourceSaveError("Resource name and URL are required.");
      return;
    }

    setResourceSaveLoading(true);
    setResourceSaveError("");
    setResourceSaveSuccess("");
    try {
      if (editingResourceId) {
        await updateIntelResourceFromDesktop(editingResourceId, {
          name: cleanName,
          url: cleanUrl,
          target_type: resourceTargetType,
          content_type: resourceContentType,
          update_mode: resourceUpdateMode,
        });
        setResourceSaveSuccess("Resource updated successfully.");
      } else {
        await addIntelResourceFromDesktop({
          name: cleanName,
          url: cleanUrl,
          target_type: resourceTargetType,
          content_type: resourceContentType,
          update_mode: resourceUpdateMode,
          enabled: true,
        });
        setResourceSaveSuccess("Resource saved and will be included in Intel source planning.");
      }
      resetResourceForm();
      await loadIntelData();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to add resource";
      setResourceSaveError(message);
    } finally {
      setResourceSaveLoading(false);
    }
  }

  async function handleRemoveResource(resource: IntelResource) {
    if (resource.source_kind !== "custom") {
      return;
    }
    const confirmDelete = window.confirm(`Delete resource "${resource.name}"?`);
    if (!confirmDelete) {
      return;
    }
    setResourceSaveLoading(true);
    setResourceSaveError("");
    setResourceSaveSuccess("");
    try {
      await deleteIntelResourceFromDesktop(resource.id);
      if (editingResourceId === resource.id) {
        resetResourceForm();
      }
      setResourceSaveSuccess("Resource removed.");
      await loadIntelData();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to remove resource";
      setResourceSaveError(message);
    } finally {
      setResourceSaveLoading(false);
    }
  }

  async function handleSaveSchedule() {
    const value = Number(scheduleRefreshDays);
    if (!Number.isFinite(value) || value < 1 || value > 3650) {
      setScheduleSaveError("Refresh days must be between 1 and 3650.");
      setScheduleSaveSuccess("");
      return;
    }
    setScheduleSaving(true);
    setScheduleSaveError("");
    setScheduleSaveSuccess("");
    try {
      await setIntelUpdateScheduleFromDesktop({
        target_type: scheduleTargetType,
        refresh_days: Math.floor(value),
      });
      setScheduleSaveSuccess("Intel update schedule saved.");
      await loadIntelData();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to save schedule";
      setScheduleSaveError(message);
    } finally {
      setScheduleSaving(false);
    }
  }

  async function handleForceUpdateNow() {
    setForceUpdateLoading(true);
    setForceUpdateError("");
    setForceUpdateSuccess("");
    setShowForceUpdatePanel(true);
    try {
      const response = await forceIntelUpdateFromDesktop({
        target_type: scheduleTargetType,
        info: "Manual force update from Settings",
      });
      if (!response.started) {
        setForceUpdateSuccess("Force update already running for this target.");
      } else {
        setForceUpdateSuccess("Force update started in background.");
      }
      await loadForceUpdateStatus();
      await loadIntelData();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to force update";
      setForceUpdateError(message);
    } finally {
      setForceUpdateLoading(false);
    }
  }

  async function handleCancelForceUpdate() {
    setForceUpdateCancelLoading(true);
    setForceUpdateError("");
    setForceUpdateSuccess("");
    try {
      const response = await cancelForceIntelUpdateFromDesktop(scheduleTargetType);
      if (response.cancelled) {
        setForceUpdateSuccess("Force update cancellation requested.");
        setForceUpdateStatus((current) => {
          if (!current) {
            return current;
          }
          return {
            ...current,
            status: "cancelled",
            message: "Cancellation requested by user.",
            updated_at: new Date().toISOString(),
          };
        });
      } else {
        setForceUpdateSuccess(
          response.reason
            ? `Cannot cancel now: ${response.reason}.`
            : "No running force update to cancel.",
        );
      }
      await loadForceUpdateStatus();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to cancel force update";
      setForceUpdateError(message);
    } finally {
      setForceUpdateCancelLoading(false);
    }
  }

  async function handleForceUpdateAction() {
    if (forceUpdateIsActive) {
      await handleCancelForceUpdate();
      return;
    }
    await handleForceUpdateNow();
  }

  return (
    <div className="mx-auto flex h-full min-h-0 max-w-5xl flex-col gap-4">
      <h1 className="text-lg font-bold text-text-primary">Settings</h1>
      <Tabs
        className="min-h-0 flex-1"
        contentClassName="min-h-0 flex-1 overflow-y-auto pr-1"
        tabs={[
          {
            id: "runtime",
            label: "Runtime",
            content: (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Server size={14} />
                    Backend Runtime
                  </CardTitle>
                </CardHeader>
                <div className="space-y-3">
                  <Input
                    label="Server URL"
                    value={config.serverUrl}
                    onChange={(event) =>
                      config.updateConfig({ serverUrl: event.target.value })
                    }
                  />
                  <Input
                    label="Server Port"
                    type="number"
                    value={String(config.serverPort)}
                    onChange={(event) =>
                      config.updateConfig({
                        serverPort: Number(event.target.value) || 8000
                      })
                    }
                  />
                </div>
              </Card>
            )
          },
          {
            id: "llm",
            label: "LLM",
            content: (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Cpu size={14} />
                    LLM Provider
                  </CardTitle>
                </CardHeader>
                <div className="space-y-3">
                  <Select
                    label="Active model"
                    value={config.activeLLM}
                    onChange={(event) => config.setActiveLLM(event.target.value)}
                    options={config.llmConfigs.map((item) => ({
                      value: item.id,
                      label: item.name
                    }))}
                  />
                  <Select
                    label="Mode"
                    value={activeLLM?.mode ?? "public"}
                    onChange={(event) => {
                      if (!activeLLM) {
                        return;
                      }
                      config.updateLLM(activeLLM.id, {
                        mode: event.target.value as "public" | "local"
                      });
                    }}
                    options={[
                      { value: "public", label: "Public LLM" },
                      { value: "local", label: "Local LLM" }
                    ]}
                  />
                </div>
              </Card>
            )
          },
          {
            id: "safety",
            label: "Safety",
            content: (
              <Card className="space-y-3">
                <Toggle
                  checked={config.autoApprove}
                  onChange={(next) => config.updateConfig({ autoApprove: next })}
                  label="Auto-approve low-risk actions"
                />
                <Toggle
                  checked={config.stealthMode}
                  onChange={(next) => config.updateConfig({ stealthMode: next })}
                  label="Stealth mode"
                />
              </Card>
            )
          },
          {
            id: "appearance",
            label: "Appearance",
            content: (
              <Card className="space-y-3">
                <div className="mb-1 flex items-center gap-2 text-sm font-semibold">
                  <Palette size={14} />
                  Theme
                </div>
                <Toggle
                  checked={isDark}
                  onChange={setDark}
                  label={`Enable ${isDark ? "light" : "dark"} mode`}
                />
              </Card>
            )
          },
          {
            id: "intel-rag",
            label: "Intel / RAG",
            content: (
              <div className="space-y-4">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Bot size={14} />
                      RAG Resources
                    </CardTitle>
                  </CardHeader>
                  <div className="space-y-3">
                    <div className="grid grid-cols-1 gap-3 md:grid-cols-5">
                      <Input
                        label="Resource Name"
                        placeholder="My Security Notes"
                        value={resourceName}
                        onChange={(event) => setResourceName(event.target.value)}
                      />
                      <Input
                        label="Resource URL"
                        placeholder="https://..."
                        value={resourceUrl}
                        onChange={(event) => setResourceUrl(event.target.value)}
                      />
                      <Select
                        label="Resource Type"
                        value={resourceContentType}
                        onChange={(event) => setResourceContentType(event.target.value)}
                        options={RESOURCE_TYPE_OPTIONS}
                      />
                      <Select
                        label="Intel Update"
                        value={resourceUpdateMode}
                        onChange={(event) => {
                          const nextMode = event.target.value === "static" ? "static" : "every_3_days";
                          setResourceUpdateMode(nextMode);
                        }}
                        options={updateModeOptions}
                      />
                      <Select
                        label="Target Type"
                        value={resourceTargetType}
                        onChange={(event) => setResourceTargetType(event.target.value)}
                        options={intelTargetOptions}
                      />
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <Button size="sm" onClick={handleSaveResource} loading={resourceSaveLoading}>
                        <Plus size={12} />
                        {editingResourceId ? "Save Changes" : "Add Resource"}
                      </Button>
                      {editingResourceId && (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={resetResourceForm}
                          disabled={resourceSaveLoading}
                        >
                          Cancel Edit
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => {
                          void loadIntelData();
                        }}
                        disabled={intelLoading}
                      >
                        <RefreshCcw size={12} />
                        Refresh
                      </Button>
                    </div>
                    {resourceSaveError && (
                      <p className="rounded-md border border-red-500/30 bg-red-500/10 px-2 py-1 text-xs text-red-300">
                        {resourceSaveError}
                      </p>
                    )}
                    {resourceSaveSuccess && (
                      <p className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-300">
                        {resourceSaveSuccess}
                      </p>
                    )}

                    <div className="grid grid-cols-1 gap-2 md:grid-cols-12">
                      <div className="md:col-span-6">
                        <Input
                          label={`Search Resources (${intelResources.length} loaded)`}
                          placeholder="Search by name, URL, type..."
                          value={resourceSearch}
                          onChange={(event) => setResourceSearch(event.target.value)}
                        />
                      </div>
                      <div className="md:col-span-2">
                      <Select
                        label="Filter Type"
                        value={resourceTypeFilter}
                        onChange={(event) => {
                          const next = event.target.value;
                          setResourceTypeFilter(next);
                          // Avoid accidental empty results when switching type
                          // while another narrow filter remains active.
                          if (next === "payload") {
                            setResourceUpdateFilter("all");
                          }
                        }}
                        options={typeFilterOptions}
                      />
                      </div>
                      <div className="md:col-span-2">
                      <Select
                        label="Filter Target"
                        value={resourceTargetFilter}
                        onChange={(event) => setResourceTargetFilter(event.target.value)}
                        options={targetFilterOptions}
                      />
                      </div>
                      <div className="md:col-span-2">
                      <Select
                        label="Filter Update"
                        value={resourceUpdateFilter}
                        onChange={(event) => setResourceUpdateFilter(event.target.value)}
                        options={updateFilterOptions}
                      />
                      </div>
                    </div>
                    <div className="flex justify-end">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => {
                          setResourceSearch("");
                          setResourceTypeFilter("all");
                          setResourceTargetFilter("all");
                          setResourceUpdateFilter("all");
                        }}
                      >
                        Reset Filters
                      </Button>
                    </div>

                    <div className="max-h-72 space-y-2 overflow-y-auto pr-1">
                      {filteredIntelResources.length === 0 ? (
                        <p className="text-xs text-text-muted">No resources found.</p>
                      ) : (
                        filteredIntelResources.map((resource) => (
                          (() => {
                            const canModify = resource.source_kind === "custom";
                            const changeDisabled = !canModify || resourceSaveLoading;
                            const removeDisabled = !canModify || resourceSaveLoading;
                            const disabledTitle = "Built-in resource is managed by config and cannot be changed here.";
                            return (
                          <div
                            key={`${resource.source_kind}-${resource.id}`}
                            className="rounded-md border border-border bg-surface-0/35 p-2"
                          >
                            <div className="flex items-start justify-between gap-2">
                              <div className="min-w-0">
                                <p className="truncate text-sm font-semibold text-text-primary">{resource.name}</p>
                                <p className="text-[11px] text-text-muted">
                                  {formatTargetTypeLabel(resourceDisplayTarget(resource.target_type, resourceTargetFilter))}
                                  {" • "}
                                  {resource.content_type || "unknown"}
                                  {" • "}
                                  {formatResourceCadence(resource)}
                                  {" • "}
                                  Last update: {formatTimestamp(resource.intel_last_update)}
                                </p>
                              </div>
                              <div className="flex items-center gap-1">
                                <span className="rounded border border-border px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-text-secondary">
                                  {resourceSourceLabel(resource)}
                                </span>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  title={canModify ? "Edit resource" : disabledTitle}
                                  onClick={() => startEditResource(resource)}
                                  disabled={changeDisabled}
                                >
                                  <Pencil size={12} />
                                  Change
                                </Button>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  title={canModify ? "Remove resource from registry and RAG data" : disabledTitle}
                                  onClick={() => {
                                    void handleRemoveResource(resource);
                                  }}
                                  disabled={removeDisabled}
                                >
                                  <Trash2 size={12} />
                                  Remove
                                </Button>
                              </div>
                            </div>
                            <p className="mt-1 break-all font-mono text-[11px] text-text-secondary">
                              {resource.url || "No URL"}
                            </p>
                          </div>
                            );
                          })()
                        ))
                      )}
                    </div>
                  </div>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Clock3 size={14} />
                      Intel Update Schedule
                    </CardTitle>
                  </CardHeader>
                  <div className="mb-3 grid grid-cols-1 gap-3 md:grid-cols-4">
                    <Select
                      label="RAG Target Type"
                      value={scheduleTargetType}
                      onChange={(event) => setScheduleTargetType(event.target.value)}
                      options={intelTargetOptions}
                    />
                    <Input
                      label="Refresh Every (Days)"
                      type="number"
                      min={1}
                      max={3650}
                      value={scheduleRefreshDays}
                      onChange={(event) => setScheduleRefreshDays(event.target.value)}
                    />
                    <div className="flex items-end">
                      <Button
                        size="sm"
                        onClick={handleSaveSchedule}
                        loading={scheduleSaving}
                        className="w-full"
                      >
                        Save Schedule
                      </Button>
                    </div>
                    <div className="flex items-end">
                      <Button
                        size="sm"
                        variant={forceUpdateIsActive ? "danger" : "ghost"}
                        onClick={handleForceUpdateAction}
                        loading={forceUpdateIsActive ? forceUpdateCancelLoading : forceUpdateLoading}
                        className="w-full"
                      >
                        {forceUpdateIsActive
                          ? (forceUpdateCancelLoading ? "Cancelling..." : "Cancel Force Update")
                          : "Force Update Now"}
                      </Button>
                    </div>
                  </div>
                  {(scheduleSaveError || scheduleSaveSuccess || forceUpdateError || forceUpdateSuccess) && (
                    <div className="mb-3 space-y-1 text-xs">
                      {scheduleSaveError && (
                        <p className="rounded-md border border-red-500/30 bg-red-500/10 px-2 py-1 text-red-300">
                          {scheduleSaveError}
                        </p>
                      )}
                      {scheduleSaveSuccess && (
                        <p className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-emerald-300">
                          {scheduleSaveSuccess}
                        </p>
                      )}
                      {forceUpdateError && (
                        <p className="rounded-md border border-red-500/30 bg-red-500/10 px-2 py-1 text-red-300">
                          {forceUpdateError}
                        </p>
                      )}
                      {forceUpdateSuccess && (
                        <p className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-emerald-300">
                          {forceUpdateSuccess}
                        </p>
                      )}
                    </div>
                  )}
                  {showForceUpdatePanel && forceUpdateStatus && (
                    <div className="mt-2 rounded-md border border-border bg-surface-0/35 p-2">
                      <p className="text-xs font-semibold text-text-primary">
                        Force Update Status • {formatTargetTypeLabel(forceUpdateStatus.target_type)}
                      </p>
                      <p className="mt-1 text-[11px] text-text-secondary">
                        {forceUpdateStatus.status.toUpperCase()} • {Math.max(0, Math.min(100, forceUpdateStatus.progress))}%
                      </p>
                      <div className="mt-2 h-2 w-full overflow-hidden rounded bg-surface-0">
                        <div
                          className={`h-full transition-all ${
                            forceUpdateStatus.status === "error"
                              ? "bg-red-500/70"
                              : forceUpdateStatus.status === "completed"
                                ? "bg-emerald-500/70"
                                : "bg-blue-500/70"
                          }`}
                          style={{ width: `${Math.max(0, Math.min(100, forceUpdateStatus.progress))}%` }}
                        />
                      </div>
                      <p className="mt-2 text-[11px] text-text-muted">
                        {forceUpdateStatus.message || "Waiting..."}
                      </p>
                    </div>
                  )}
                </Card>

                {(intelLoading || intelError) && (
                  <div className="text-xs">
                    {intelLoading && <p className="text-text-muted">Loading Intel/RAG settings...</p>}
                    {intelError && (
                      <p className="rounded-md border border-red-500/30 bg-red-500/10 px-2 py-1 text-red-300">
                        {intelError}
                      </p>
                    )}
                  </div>
                )}
              </div>
            )
          }
        ]}
        defaultTab="runtime"
      />
    </div>
  );
}
