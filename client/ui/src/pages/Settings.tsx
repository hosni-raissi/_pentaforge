import { useCallback, useEffect, useMemo, useState } from "react";
import { Bot, Clock3, Cpu, Palette, Plus, RefreshCcw, Server } from "lucide-react";

import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { Select } from "@/components/ui/Select";
import { Tabs } from "@/components/ui/Tabs";
import { Toggle } from "@/components/ui/Toggle";
import {
  addIntelResourceFromDesktop,
  listIntelResourcesFromDesktop,
  listIntelUpdateStatusFromDesktop,
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
  const [resourceTargetType, setResourceTargetType] = useState("all");
  const [resourceSaveLoading, setResourceSaveLoading] = useState(false);
  const [resourceSaveError, setResourceSaveError] = useState("");
  const [resourceSaveSuccess, setResourceSaveSuccess] = useState("");
  const [resourceSearch, setResourceSearch] = useState("");

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
    void loadIntelData();
  }, [loadIntelData]);

  const filteredIntelResources = useMemo(() => {
    const needle = resourceSearch.trim().toLowerCase();
    if (!needle) {
      return intelResources;
    }
    return intelResources.filter((resource) => {
      const text = `${resource.name} ${resource.url} ${resource.target_type} ${resource.source_kind}`.toLowerCase();
      return text.includes(needle);
    });
  }, [intelResources, resourceSearch]);

  async function handleAddResource() {
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
      await addIntelResourceFromDesktop({
        name: cleanName,
        url: cleanUrl,
        target_type: resourceTargetType,
        enabled: true,
      });
      setResourceName("");
      setResourceUrl("");
      setResourceSaveSuccess("Resource saved and will be included in Intel source planning.");
      await loadIntelData();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to add resource";
      setResourceSaveError(message);
    } finally {
      setResourceSaveLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-5xl space-y-4">
      <h1 className="text-lg font-bold text-text-primary">Settings</h1>
      <Tabs
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
                    <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
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
                        label="Target Type"
                        value={resourceTargetType}
                        onChange={(event) => setResourceTargetType(event.target.value)}
                        options={intelTargetOptions}
                      />
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <Button size="sm" onClick={handleAddResource} loading={resourceSaveLoading}>
                        <Plus size={12} />
                        Add Resource
                      </Button>
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

                    <Input
                      label="Search Resources"
                      placeholder="Search by name, URL, type..."
                      value={resourceSearch}
                      onChange={(event) => setResourceSearch(event.target.value)}
                    />

                    <div className="max-h-72 space-y-2 overflow-y-auto pr-1">
                      {filteredIntelResources.length === 0 ? (
                        <p className="text-xs text-text-muted">No resources found.</p>
                      ) : (
                        filteredIntelResources.map((resource) => (
                          <div
                            key={`${resource.source_kind}-${resource.id}`}
                            className="rounded-md border border-border bg-surface-0/35 p-2"
                          >
                            <div className="flex items-start justify-between gap-2">
                              <div className="min-w-0">
                                <p className="truncate text-sm font-semibold text-text-primary">{resource.name}</p>
                                <p className="text-[11px] text-text-muted">
                                  {formatTargetTypeLabel(resource.target_type)}
                                  {" • "}
                                  {resource.content_type || "unknown"}
                                  {" • "}
                                  {resource.updatable ? "updatable" : "read-only"}
                                </p>
                              </div>
                              <span className="rounded border border-border px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-text-secondary">
                                {resource.source_kind}
                              </span>
                            </div>
                            <p className="mt-1 break-all font-mono text-[11px] text-text-secondary">
                              {resource.url || "No URL"}
                            </p>
                          </div>
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
                  <div className="space-y-2 text-xs text-text-secondary">
                    <p>
                      Intel checks cooldown every run and refreshes every
                      {" "}
                      <span className="font-semibold text-text-primary">{intelMeta.refresh_days}</span>
                      {" "}
                      day(s).
                    </p>
                    <p>
                      Update window:
                      {" "}
                      <span className="font-semibold text-text-primary">last {intelMeta.update_days_back} days</span>
                      {" "}
                      • max
                      {" "}
                      <span className="font-semibold text-text-primary">{intelMeta.update_max_results}</span>
                      {" "}
                      result(s) per fetch
                    </p>
                    <p>
                      Pipeline writes:
                      {" "}
                      <span className="font-semibold text-text-primary">
                        {intelMeta.pipeline_outputs.join(", ")}
                      </span>
                    </p>
                    <p>
                      Last checked:
                      {" "}
                      <span className="font-semibold text-text-primary">
                        {formatTimestamp(intelMeta.checked_at || null)}
                      </span>
                    </p>
                  </div>

                  <div className="mt-3 max-h-80 space-y-2 overflow-y-auto pr-1">
                    {intelStatuses.length === 0 ? (
                      <p className="text-xs text-text-muted">No Intel update records yet.</p>
                    ) : (
                      intelStatuses.map((status) => {
                        const hoursRemaining = Math.ceil(status.seconds_until_next_update / 3600);
                        const sourcePreview = status.will_update.verify_sources.slice(0, 8);
                        return (
                          <div
                            key={status.target_type}
                            className="rounded-md border border-border bg-surface-0/35 p-2"
                          >
                            <div className="flex items-start justify-between gap-2">
                              <div>
                                <p className="text-sm font-semibold text-text-primary">
                                  {formatTargetTypeLabel(status.target_type)}
                                </p>
                                <p className="text-[11px] text-text-muted">
                                  Last: {formatTimestamp(status.last_update)}
                                  {" • "}
                                  Next: {formatTimestamp(status.next_update)}
                                </p>
                              </div>
                              <span
                                className={`rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wide ${
                                  status.due_now
                                    ? "border-amber-500/50 text-amber-300"
                                    : "border-emerald-500/50 text-emerald-300"
                                }`}
                              >
                                {status.due_now ? "Due Now" : `In ${hoursRemaining}h`}
                              </span>
                            </div>
                            <p className="mt-1 text-[11px] text-text-secondary">
                              Will update:
                              {" "}
                              {status.will_update.fetch_streams.join(", ")}
                              {" → "}
                              {status.will_update.embed_content_types.join(", ")}
                            </p>
                            <p className="mt-1 text-[11px] text-text-muted">
                              Sources ({status.sources.length}):
                              {" "}
                              {sourcePreview.join(", ")}
                              {status.will_update.verify_sources.length > sourcePreview.length ? " ..." : ""}
                            </p>
                          </div>
                        );
                      })
                    )}
                  </div>
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
