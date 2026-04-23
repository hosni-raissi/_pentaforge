import { useCallback, useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, ListTree, Plus, RefreshCcw, RotateCcw, Save, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { Select } from "@/components/ui/Select";
import {
  getStaticReconPlanFromDesktop,
  listProjectTargetTypesFromDesktop,
  listStaticReconPlansFromDesktop,
  resetStaticReconPlanFromDesktop,
  saveStaticReconPlanFromDesktop,
  type ProjectTargetTypeOption,
  type StaticReconPlan,
  type StaticReconScenario,
} from "@/lib/projectBridge";

function formatTargetTypeLabel(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function normalizeMethods(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function createEmptyScenario(): StaticReconScenario {
  return {
    task: "",
    agent: "recon",
    priority: 3,
    details: "",
    methods: [],
    done: false,
    status: "not yet",
  };
}

export function StaticReconPlanSettings() {
  const [targetOptions, setTargetOptions] = useState<ProjectTargetTypeOption[]>([]);
  const [plans, setPlans] = useState<StaticReconPlan[]>([]);
  const [selectedTargetType, setSelectedTargetType] = useState("web_app");
  const [editingPlan, setEditingPlan] = useState<StaticReconPlan | null>(null);
  const [expandedScenarioIndex, setExpandedScenarioIndex] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const loadPlans = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [nextTargetOptions, nextPlans] = await Promise.all([
        listProjectTargetTypesFromDesktop(),
        listStaticReconPlansFromDesktop(),
      ]);
      const normalizedTargetOptions = nextTargetOptions.length > 0
        ? nextTargetOptions
        : [{ value: "web_app", label: "Web Application" }];
      setTargetOptions(normalizedTargetOptions);
      setPlans(nextPlans);
      setSelectedTargetType((current) => {
        const preferred = current || normalizedTargetOptions[0]?.value || "web_app";
        const exists = normalizedTargetOptions.some((item) => item.value === preferred);
        return exists ? preferred : normalizedTargetOptions[0]?.value || "web_app";
      });
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Failed to load static recon plans");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadPlans();
  }, [loadPlans]);

  useEffect(() => {
    const matched = plans.find((item) => item.target_type === selectedTargetType) ?? null;
    setEditingPlan(matched ? JSON.parse(JSON.stringify(matched)) as StaticReconPlan : null);
  }, [plans, selectedTargetType]);

  const selectedPlanSummary = useMemo(() => {
    if (!editingPlan) {
      return null;
    }
    return {
      total: editingPlan.scenarios.length,
      highPriority: editingPlan.scenarios.filter((item) => Number(item.priority) <= 2).length,
    };
  }, [editingPlan]);

  function updateScenario(index: number, patch: Partial<StaticReconScenario>) {
    setEditingPlan((current) => {
      if (!current) {
        return current;
      }
      const nextScenarios = current.scenarios.map((scenario, scenarioIndex) => (
        scenarioIndex === index ? { ...scenario, ...patch } : scenario
      ));
      return { ...current, scenarios: nextScenarios };
    });
  }

  function addScenario() {
    setEditingPlan((current) => {
      if (!current) {
        return current;
      }
      return {
        ...current,
        scenarios: [...current.scenarios, createEmptyScenario()],
      };
    });
  }

  function removeScenario(index: number) {
    setEditingPlan((current) => {
      if (!current) {
        return current;
      }
      return {
        ...current,
        scenarios: current.scenarios.filter((_, scenarioIndex) => scenarioIndex !== index),
      };
    });
  }

  async function handleReloadSelected() {
    setError("");
    setSuccess("");
    setLoading(true);
    try {
      const plan = await getStaticReconPlanFromDesktop(selectedTargetType);
      setPlans((current) => {
        const others = current.filter((item) => item.target_type !== plan.target_type);
        return [...others, plan].sort((a, b) => a.target_type.localeCompare(b.target_type));
      });
      setEditingPlan(JSON.parse(JSON.stringify(plan)) as StaticReconPlan);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Failed to reload plan");
    } finally {
      setLoading(false);
    }
  }

  async function handleSave() {
    if (!editingPlan) {
      return;
    }
    setSaving(true);
    setError("");
    setSuccess("");
    try {
      const payload: StaticReconPlan = {
        ...editingPlan,
        target_type: selectedTargetType,
        generated_from: "ui_settings",
        scenarios: editingPlan.scenarios.map((scenario) => ({
          ...scenario,
          task: scenario.task.trim(),
          details: scenario.details.trim(),
          methods: scenario.methods.map((method) => method.trim()).filter(Boolean),
          agent: "recon",
          priority: Number(scenario.priority) || 3,
        })),
      };
      const saved = await saveStaticReconPlanFromDesktop(selectedTargetType, payload);
      setPlans((current) => {
        const others = current.filter((item) => item.target_type !== saved.target_type);
        return [...others, saved].sort((a, b) => a.target_type.localeCompare(b.target_type));
      });
      setEditingPlan(JSON.parse(JSON.stringify(saved)) as StaticReconPlan);
      setSuccess("Static recon plan saved.");
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : "Failed to save plan");
    } finally {
      setSaving(false);
    }
  }

  async function handleReset() {
    const confirmed = window.confirm(`Reset the static recon plan for ${formatTargetTypeLabel(selectedTargetType)}?`);
    if (!confirmed) {
      return;
    }
    setSaving(true);
    setError("");
    setSuccess("");
    try {
      const restored = await resetStaticReconPlanFromDesktop(selectedTargetType);
      setPlans((current) => {
        const others = current.filter((item) => item.target_type !== restored.target_type);
        return [...others, restored].sort((a, b) => a.target_type.localeCompare(b.target_type));
      });
      setEditingPlan(JSON.parse(JSON.stringify(restored)) as StaticReconPlan);
      setSuccess("Static recon plan reset to default.");
    } catch (resetError) {
      setError(resetError instanceof Error ? resetError.message : "Failed to reset plan");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ListTree size={14} />
            Static Recon Plans
          </CardTitle>
        </CardHeader>
        <div className="space-y-3">
          <p className="text-sm text-text-secondary">
            Each target type has a saved recon baseline in the database. You can update, add, or remove scenarios here,
            and the planner warmup will use that saved version.
          </p>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
            <Select
              label="Target Type"
              value={selectedTargetType}
              onChange={(event) => setSelectedTargetType(event.target.value)}
              options={targetOptions.map((option) => ({
                value: option.value,
                label: option.label,
              }))}
            />
            <Input
              label="Max Items"
              type="number"
              min={1}
              max={50}
              value={String(editingPlan?.max_items ?? 20)}
              onChange={(event) => {
                const nextValue = Math.max(1, Math.min(50, Number(event.target.value) || 20));
                setEditingPlan((current) => (current ? { ...current, max_items: nextValue } : current));
              }}
            />
            <Input
              label="Saved Scenarios"
              value={String(selectedPlanSummary?.total ?? 0)}
              readOnly
            />
            <Input
              label="High Priority (P1-P2)"
              value={String(selectedPlanSummary?.highPriority ?? 0)}
              readOnly
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" onClick={handleSave} loading={saving} disabled={!editingPlan}>
              <Save size={12} />
              Save Plan
            </Button>
            <Button size="sm" variant="ghost" onClick={() => void handleReloadSelected()} disabled={loading || saving}>
              <RefreshCcw size={12} />
              Reload
            </Button>
            <Button size="sm" variant="ghost" onClick={handleReset} disabled={!editingPlan || saving}>
              <RotateCcw size={12} />
              Reset Default
            </Button>
            <Button size="sm" variant="ghost" onClick={addScenario} disabled={!editingPlan || saving}>
              <Plus size={12} />
              Add Scenario
            </Button>
          </div>
          {error && (
            <p className="rounded-md border border-red-500/30 bg-red-500/10 px-2 py-1 text-xs text-red-300">
              {error}
            </p>
          )}
          {success && (
            <p className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-300">
              {success}
            </p>
          )}
        </div>
      </Card>

      <div className="space-y-3">
        {loading && <p className="text-sm text-text-muted">Loading static recon plans...</p>}
        {!loading && editingPlan && editingPlan.scenarios.length === 0 && (
          <Card>
            <p className="text-sm text-text-muted">No scenarios saved for this target type yet.</p>
          </Card>
        )}
        {!loading && editingPlan?.scenarios.map((scenario, index) => {
          const isExpanded = expandedScenarioIndex === index;
          return (
            <Card key={`${selectedTargetType}-${index}`} className="overflow-hidden">
              <div 
                className="flex items-center justify-between p-3 cursor-pointer hover:bg-surface-0/50 transition-colors"
                onClick={() => setExpandedScenarioIndex(isExpanded ? null : index)}
              >
                <div className="flex items-center gap-3">
                  {isExpanded ? <ChevronDown size={14} className="text-text-secondary" /> : <ChevronRight size={14} className="text-text-secondary" />}
                  <div className="flex flex-col">
                    <span className="text-sm font-medium">Scenario {index + 1}: {scenario.task || "Untitled Scenario"}</span>
                    <span className="text-xs text-text-secondary">Priority P{scenario.priority} • {scenario.methods.length} methods</span>
                  </div>
                </div>
              </div>
              
              {isExpanded && (
                <div className="p-4 border-t border-border space-y-4 bg-surface-0/20">
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-medium text-text-primary">Update Scenario</h4>
                    <Button size="sm" variant="ghost" onClick={() => removeScenario(index)} disabled={saving} className="text-red-400 hover:text-red-300 hover:bg-red-500/10">
                      <Trash2 size={12} />
                      Remove
                    </Button>
                  </div>
                  
                  <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                    <Input
                      label="Task"
                      value={scenario.task}
                      onChange={(event) => updateScenario(index, { task: event.target.value })}
                    />
                    <Select
                      label="Agent"
                      value="recon"
                      onChange={() => undefined}
                      options={[{ value: "recon", label: "Recon" }]}
                    />
                    <Input
                      label="Priority"
                      type="number"
                      min={1}
                      max={5}
                      value={String(scenario.priority)}
                      onChange={(event) => updateScenario(index, { priority: Math.max(1, Math.min(5, Number(event.target.value) || 3)) })}
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="block text-xs font-medium text-text-secondary">Details</label>
                    <textarea
                      className="min-h-24 w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary transition-colors duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-pf-500/50"
                      value={scenario.details}
                      onChange={(event) => updateScenario(index, { details: event.target.value })}
                    />
                  </div>
                  <Input
                    label="Methods"
                    hint="Comma-separated technique descriptions"
                    value={scenario.methods.join(", ")}
                    onChange={(event) => updateScenario(index, { methods: normalizeMethods(event.target.value) })}
                  />
                </div>
              )}
            </Card>
          );
        })}
      </div>
    </div>
  );
}
