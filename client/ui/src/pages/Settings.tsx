import { useCallback, useEffect, useMemo, useState } from "react";
import { Bot, CheckCircle2, Clock3, Cpu, ListTree, Palette, Pencil, Plus, RefreshCcw, Trash2 } from "lucide-react";
import clsx from "clsx";

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
  fetchSystemSettingsFromDesktop,
  updateSystemSettingsFromDesktop,
  resetSystemSettingsToDefaultsFromDesktop,
  testLLMConfigFromDesktop,
  type IntelForceUpdateStatus,
  type IntelResource,
  type IntelTargetTypeOption,
  type IntelUpdateStatusPayload,
  type LLMProfile,
  type SystemSettings,
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
  cloud: new Set(["cloud"]),
  container: new Set(["container", "cloud"]),
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
  "cloud",
  "container",
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
  const [llmProfiles, setLlmProfiles] = useState<LLMProfile[]>([]);
  const [fallbackProfiles, setFallbackProfiles] = useState<LLMProfile[]>([]);
  const [llmMode, setLlmMode] = useState("public");
  const [editingProfileId, setEditingProfileId] = useState<string | null>(null);
  const [profileName, setProfileName] = useState("");
  const [profileProvider, setProfileProvider] = useState("cerebras");
  const [profileModel, setProfileModel] = useState("");
  const [profileUrl, setProfileUrl] = useState("");
  const [profileKey, setProfileKey] = useState("");
  const [llmTestingId, setLlmTestingId] = useState<string | null>(null);
  const [llmTestResult, setLlmTestResult] = useState<{ id: string; ok: boolean; message: string } | null>(null);
  const [llmSaveLoading, setLlmSaveLoading] = useState(false);

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

  // Synchronize system settings with backend
  const loadSystemSettings = useCallback(async () => {
    try {
      const remote = await fetchSystemSettingsFromDesktop();
      setLlmProfiles(remote.llm_profiles || []);
      setFallbackProfiles(remote.fallback_profiles || []);
      setLlmMode(remote.llm_mode || "public");
      if (remote.privacy_gate !== config.privacyGate) {
        config.updateConfig({ privacyGate: remote.privacy_gate });
      }
    } catch (err) {
      console.error("Failed to sync system settings:", err);
    }
  }, [config]);

  useEffect(() => {
    void loadSystemSettings();
  }, [loadSystemSettings]);

  const handleTogglePrivacyGate = useCallback(async (next: boolean) => {
    config.updateConfig({ privacyGate: next });
    try {
      await updateSystemSettingsFromDesktop({
        privacy_gate: next,
        llm_profiles: llmProfiles,
        llm_mode: llmMode
      });
    } catch (err) {
      console.error("Failed to update backend privacy gate setting:", err);
    }
  }, [config, llmProfiles, llmMode]);
  
  const redistributeLLMRoles = (profiles: LLMProfile[]): LLMProfile[] => {
    if (profiles.length === 0) return [];
    // Simple: first = primary (handles everything), second = backup (failover only)
    return profiles.map((p, idx) => ({
      ...p,
      roles: idx === 0 ? ["primary"] : ["backup"],
    }));
  };

  const handleEditProfile = (id: string) => {
    const p = llmProfiles.find(x => x.id === id);
    if (!p) return;
    setProfileName(p.name);
    setProfileProvider(p.provider);
    setProfileModel(p.model);
    setProfileUrl(p.api_url || "");
    setProfileKey(p.api_key || "");
    setEditingProfileId(id);
  };

  const handleSaveLLMSettings = async (profiles: LLMProfile[], mode: string) => {
    // Automatically redistribute roles before saving
    const balanced = redistributeLLMRoles(profiles);
    setLlmProfiles(balanced);
    
    try {
      setLlmSaveLoading(true);
      await updateSystemSettingsFromDesktop({
        privacy_gate: config.privacyGate,
        llm_profiles: balanced,
        llm_mode: mode
      });
    } catch (err) {
      console.error("Failed to save LLM settings:", err);
    } finally {
      setLlmSaveLoading(false);
    }
  };

  const handleResetToDefaults = async () => {
    const confirmed = window.confirm(
      "This will remove all saved LLM profiles. PentaForge will block scans until a profile is added again. Continue?"
    );
    if (!confirmed) return;

    try {
      setLlmSaveLoading(true);
      const remote = await resetSystemSettingsToDefaultsFromDesktop();
      setLlmProfiles(remote.llm_profiles || []);
      setFallbackProfiles(remote.fallback_profiles || []);
      setLlmMode(remote.llm_mode || "public");
      if (remote.privacy_gate !== config.privacyGate) {
        config.updateConfig({ privacyGate: remote.privacy_gate });
      }
      alert("LLM profiles cleared.");
    } catch (err) {
      console.error("Failed to reset settings:", err);
      alert("Failed to reset settings: " + (err instanceof Error ? err.message : String(err)));
    } finally {
      setLlmSaveLoading(false);
    }
  };

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
    <div className="mx-auto flex h-screen max-h-screen flex-col gap-4 overflow-hidden p-4">
      <h1 className="text-lg font-bold text-text-primary">Settings</h1>
      <Tabs
        className="min-h-0 flex-1"
        contentClassName="min-h-0 flex-1 overflow-y-auto pr-2"
        tabs={[
          {
            id: "llm",
            label: "LLM Configuration",
            content: (
              <div className="space-y-6">
                {/* Profiles List */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  <div className="lg:col-span-2 space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-bold text-text-primary flex items-center gap-2 uppercase tracking-wider">
                        <Cpu size={16} className="text-pf-400" />
                        Active Profiles
                      </h3>
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={handleResetToDefaults}
                        loading={llmSaveLoading}
                        className="h-8 text-[10px] font-black uppercase tracking-widest px-3"
                      >
                        <RefreshCcw size={12} className="mr-2" />
                        Clear Profiles
                      </Button>
                    </div>

                    <div className="space-y-3">
                      {llmProfiles.length === 0 ? (
                        fallbackProfiles.map((profile, idx) => (
                          <Card key="fallback" className="relative overflow-hidden border-border bg-surface-1/50 opacity-80 border-dashed">
                            <div className="absolute top-0 right-0 px-2 py-1 bg-surface-2 text-[8px] font-bold text-text-muted rounded-bl-lg uppercase tracking-widest">Environment Fallback</div>
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-3">
                                <div className="w-8 h-8 rounded-lg bg-pf-500/10 flex items-center justify-center">
                                  <RefreshCcw size={14} className="text-pf-400" />
                                </div>
                                <div>
                                  <div className="flex items-center gap-2">
                                    <h4 className="text-sm font-bold text-text-primary">{profile.name}</h4>
                                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface-2 text-text-muted font-mono uppercase">
                                      {profile.provider}
                                    </span>
                                  </div>
                                  <p className="text-[11px] text-text-muted mt-0.5 font-mono">
                                    {profile.model}
                                  </p>
                                </div>
                              </div>
                              <div className="text-right">
                                <span className="text-[9px] font-black text-text-muted uppercase tracking-widest block mb-1">Assigned Tasks</span>
                                <div className="inline-flex items-center px-2 py-0.5 rounded-full bg-surface-2 border border-border text-[10px] font-bold text-text-muted whitespace-nowrap">
                                  UNIVERSAL (All Roles)
                                </div>
                              </div>
                            </div>
                          </Card>
                        ))
                      ) : (
                        llmProfiles.map((profile, idx) => (
                          <Card key={profile.id} className={clsx(
                            "relative overflow-hidden border-border hover:border-pf-500/30 transition-all p-3",
                            !profile.is_active && "opacity-50"
                          )}>
                            <div className="flex items-center justify-between gap-4">
                              <div className="flex items-start gap-3 flex-1 min-w-0">
                                <div className="w-10 h-10 rounded-xl bg-surface-2 flex items-center justify-center flex-shrink-0 border border-border">
                                  <Cpu size={18} className="text-pf-400" />
                                </div>
                                <div className="min-w-0 flex-1">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <h4 className="text-sm font-black text-text-primary truncate">{profile.name}</h4>
                                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-surface-2 text-text-muted font-mono uppercase border border-border">
                                      {profile.provider}
                                    </span>
                                  </div>
                                  <p className="text-[11px] text-text-muted mt-0.5 font-mono truncate">
                                    {profile.model}
                                  </p>
                                  <div className="flex flex-wrap gap-1 mt-2">
                                    <span className={`text-[9px] px-2.5 py-0.5 rounded-full font-black uppercase tracking-wider ${
                                      idx === 0
                                        ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/25'
                                        : 'bg-amber-500/15 text-amber-400 border border-amber-500/25'
                                    }`}>
                                      {idx === 0 ? '⚡ Primary' : '🛡 Backup'}
                                    </span>
                                    {idx === 0 && (
                                      <span className="text-[9px] px-2 py-0.5 rounded-full bg-surface-2 text-text-muted border border-border">
                                        All agents
                                      </span>
                                    )}
                                    {idx === 1 && (
                                      <span className="text-[9px] px-2 py-0.5 rounded-full bg-surface-2 text-text-muted border border-border">
                                        Failover only
                                      </span>
                                    )}
                                  </div>
                                </div>
                              </div>

                              <div className="flex flex-col items-end gap-2 shrink-0">
                                 <div className="flex items-center gap-4">
                                   <div className="text-right hidden sm:block">
                                     <span className="text-[9px] font-black text-text-muted uppercase tracking-widest block mb-0.5">Status</span>
                                     <div className="inline-flex items-center px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-[10px] font-bold text-emerald-400 whitespace-nowrap">
                                       READY
                                     </div>
                                   </div>

                                   <div className="flex items-center gap-1 bg-surface-2 p-1 rounded-lg border border-border">
                                     <Button
                                       size="xs"
                                       variant="ghost"
                                       onClick={async () => {
                                         setLlmTestingId(profile.id);
                                         setLlmTestResult(null);
                                         try {
                                           const res = await testLLMConfigFromDesktop(profile);
                                           setLlmTestResult({ id: profile.id, ...res });
                                         } catch (err) {
                                           setLlmTestResult({ id: profile.id, ok: false, message: String(err) });
                                         } finally {
                                           setLlmTestingId(null);
                                         }
                                       }}
                                       loading={llmTestingId === profile.id}
                                       className="h-7 w-7 p-0 text-text-muted hover:text-pf-400"
                                     >
                                       <RefreshCcw size={12} />
                                     </Button>
                                     <Button
                                       size="xs"
                                       variant="ghost"
                                       onClick={() => handleEditProfile(profile.id)}
                                       className="h-7 w-7 p-0 text-text-muted hover:text-pf-400"
                                     >
                                       <Pencil size={12} />
                                     </Button>
                                     <Button
                                       size="xs"
                                       variant="ghost"
                                       onClick={() => {
                                         const next = llmProfiles.filter(p => p.id !== profile.id);
                                         setLlmProfiles(next);
                                         handleSaveLLMSettings(next, llmMode);
                                       }}
                                       className="h-7 w-7 p-0 text-text-muted hover:text-red-400"
                                     >
                                       <Trash2 size={12} />
                                     </Button>
                                   </div>
                                 </div>
                              </div>
                            </div>

                            {llmTestResult?.id === profile.id && (
                              <div className={clsx(
                                "mt-3 px-3 py-2 rounded-lg text-[10px] font-medium flex items-center gap-2",
                                llmTestResult.ok ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" : "bg-red-500/10 text-red-400 border border-red-500/20"
                              )}>
                                <div className={clsx("w-1.5 h-1.5 rounded-full animate-pulse", llmTestResult.ok ? "bg-emerald-400" : "bg-red-400")} />
                                {llmTestResult.message}
                              </div>
                            )}
                          </Card>
                        ))
                      )}
                    </div>
                  </div>

                  {/* Add/Edit Form */}
                  <div className="space-y-4">
                    <Card className="border-pf-500/20 bg-gradient-to-br from-pf-600/5 to-surface-1">
                      <CardHeader>
                        <CardTitle className="text-xs uppercase tracking-widest text-text-muted flex items-center gap-2">
                          {editingProfileId ? <Pencil size={12} /> : <Plus size={12} />}
                          {editingProfileId ? "Edit Profile" : "Add New Profile"}
                        </CardTitle>
                      </CardHeader>
                      <div className="space-y-3">
                        <Input
                          label="Friendly Name"
                          placeholder="e.g. Brain (Gemini 2.0)"
                          value={profileName}
                          onChange={(e) => setProfileName(e.target.value)}
                        />
                        <div className="grid grid-cols-2 gap-2">
                          <Select
                            label="Provider"
                            value={profileProvider}
                            onChange={(e) => setProfileProvider(e.target.value)}
                            options={[
                              { value: "cerebras", label: "Cerebras" },
                              { value: "openai", label: "OpenAI" },
                              { value: "gemini", label: "Gemini" },
                              { value: "groq", label: "Groq" },
                              { value: "mistral", label: "Mistral" },
                              { value: "ollama", label: "Ollama (Local)" },
                              { value: "custom", label: "Custom OpenAI-compatible" },
                            ]}
                          />
                          <Input
                            label="Model"
                            placeholder="gpt-4o / gemini-2.5-flash"
                            value={profileModel}
                            onChange={(e) => setProfileModel(e.target.value)}
                          />
                        </div>
                        <Input
                          label="API URL (Optional)"
                          placeholder="https://..."
                          value={profileUrl}
                          onChange={(e) => setProfileUrl(e.target.value)}
                        />
                        <Input
                          label="API Key"
                          type="password"
                          placeholder="••••••••••••"
                          value={profileKey}
                          onChange={(e) => setProfileKey(e.target.value)}
                        />
                        

                        <div className="flex gap-2 pt-2">
                          <Button
                            className="flex-1"
                            onClick={async () => {
                              if (!editingProfileId && llmProfiles.length >= 2) {
                                alert("You can only add a maximum of two LLM profiles (Primary and Backup).");
                                return;
                              }

                              const newProfile: LLMProfile = {
                                id: editingProfileId || `profile_${Date.now()}`,
                                name: profileName || `${profileProvider} - ${profileModel}`,
                                provider: profileProvider,
                                model: profileModel,
                                api_url: profileUrl || null,
                                api_key: profileKey || null,
                                is_active: true,
                                roles: [], // Roles will be auto-assigned on save
                              };

                              // Test before adding/saving
                              setLlmSaveLoading(true);
                              try {
                                const test = await testLLMConfigFromDesktop(newProfile);
                                if (!test.ok) {
                                  alert(`Profile is not valid: ${test.message}`);
                                  return;
                                }

                                const exists = llmProfiles.some(p => p.id !== newProfile.id && p.provider === newProfile.provider && p.model === newProfile.model && p.api_url === newProfile.api_url);
                                if (exists) {
                                  alert("A similar profile already exists.");
                                  return;
                                }

                                const next = editingProfileId
                                  ? llmProfiles.map(p => p.id === editingProfileId ? newProfile : p)
                                  : [...llmProfiles, newProfile];

                                setLlmProfiles(next);
                                await handleSaveLLMSettings(next, llmMode);

                                // Reset form
                                setEditingProfileId(null);
                                setProfileName("");
                                setProfileModel("");
                                setProfileUrl("");
                                setProfileKey("");
                                setLlmTestResult(null);
                              } catch (err) {
                                alert(String(err));
                              } finally {
                                setLlmSaveLoading(false);
                              }
                            }}
                            loading={llmSaveLoading}
                          >
                            {llmSaveLoading ? "Testing..." : (editingProfileId ? "Update Profile" : "Add Profile")}
                          </Button>
                          {editingProfileId && (
                            <Button variant="ghost" onClick={() => setEditingProfileId(null)}>Cancel</Button>
                          )}
                        </div>
                      </div>
                    </Card>

                    <Card className="bg-surface-2/50 border-pf-500/10 p-4">
                      <h4 className="text-[10px] font-bold text-pf-400 uppercase tracking-widest mb-3 flex items-center gap-2">
                        <Bot size={12} />
                        Failover Strategy
                      </h4>
                      <div className="space-y-3">
                        {llmProfiles.length === 0 && (
                          <p className="text-[11px] text-text-muted italic">Add a profile to get started.</p>
                        )}
                        {llmProfiles.length === 1 && (
                          <div className="p-2.5 rounded-lg bg-pf-500/5 border border-pf-500/10">
                            <p className="text-[11px] text-text-secondary font-bold">⚡ Single LLM Mode</p>
                            <p className="text-[10px] text-text-muted mt-1">This model handles all agents: planning, recon, exploit, analysis, and reporting.</p>
                            <p className="text-[10px] text-text-muted mt-1">On failure: retry at <span className="font-mono text-pf-400">10s → 30s → 60s</span>, then stop with error.</p>
                          </div>
                        )}
                        {llmProfiles.length === 2 && (
                          <div className="space-y-2">
                            <div className="p-2.5 rounded-lg bg-emerald-500/5 border border-emerald-500/15">
                              <p className="text-[11px] text-text-secondary font-bold">⚡ Primary — All Agents</p>
                              <p className="text-[10px] text-text-muted mt-1">Handles every task. If it fails, instantly switches to backup.</p>
                            </div>
                            <div className="p-2.5 rounded-lg bg-amber-500/5 border border-amber-500/15">
                              <p className="text-[11px] text-text-secondary font-bold">🛡 Backup — Failover Only</p>
                              <p className="text-[10px] text-text-muted mt-1">Used only when primary is unreachable or rate-limited. Retries at <span className="font-mono text-pf-400">10s → 60s</span>, then stops.</p>
                            </div>
                          </div>
                        )}
                      </div>
                    </Card>
                  </div>
                </div>
              </div>
            )
          },
          {
            id: "safety",
            label: "Safety",
            content: (
              <Card className="space-y-3">
                <Toggle
                  checked={config.privacyGate}
                  onChange={handleTogglePrivacyGate}
                  label="PrivacyGate (LLM Anonymization)"
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
                                    <p className="text-xs text-text-muted">
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
                                    <span className="rounded border border-border px-1.5 py-0.5 text-xs uppercase tracking-wide text-text-secondary">
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
                                <p className="mt-1 break-all font-mono text-xs text-text-secondary">
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
                      <p className="mt-1 text-xs text-text-secondary">
                        {forceUpdateStatus.status.toUpperCase()} • {Math.max(0, Math.min(100, forceUpdateStatus.progress))}%
                      </p>
                      <div className="mt-2 h-2 w-full overflow-hidden rounded bg-surface-0">
                        <div
                          className={`h-full transition-all ${forceUpdateStatus.status === "error"
                              ? "bg-red-500/70"
                              : forceUpdateStatus.status === "completed"
                                ? "bg-emerald-500/70"
                                : "bg-blue-500/70"
                            }`}
                          style={{ width: `${Math.max(0, Math.min(100, forceUpdateStatus.progress))}%` }}
                        />
                      </div>
                      <p className="mt-2 text-xs text-text-muted">
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
        defaultTab="llm"
      />
    </div>
  );
}
