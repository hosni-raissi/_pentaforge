import { useCallback, useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, ListTree, Plus, RefreshCcw, RotateCcw, Save, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { Select } from "@/components/ui/Select";
import {
  getInformationGatheringProfileFromDesktop,
  listInformationGatheringProfilesFromDesktop,
  listProjectTargetTypesFromDesktop,
  resetInformationGatheringProfileFromDesktop,
  saveInformationGatheringProfileFromDesktop,
  type InformationGatheringProfile,
  type InformationGatheringProfileBlock,
  type ProjectTargetTypeOption,
} from "@/lib/projectBridge";

function formatTargetTypeLabel(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function normalizeList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function slugifyBlockId(value: string): string {
  const clean = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return clean || "new_block";
}

function createEmptyBlock(): InformationGatheringProfileBlock {
  return {
    id: "new_block",
    name: "",
    interaction: "active_safe",
    goal: "",
    tools: [],
  };
}

export function StaticReconPlanSettings() {
  const [targetOptions, setTargetOptions] = useState<ProjectTargetTypeOption[]>([]);
  const [profiles, setProfiles] = useState<InformationGatheringProfile[]>([]);
  const [selectedTargetType, setSelectedTargetType] = useState("web_app");
  const [editingProfile, setEditingProfile] = useState<InformationGatheringProfile | null>(null);
  const [expandedBlockIndex, setExpandedBlockIndex] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const loadProfiles = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [nextTargetOptions, nextProfiles] = await Promise.all([
        listProjectTargetTypesFromDesktop(),
        listInformationGatheringProfilesFromDesktop(),
      ]);
      const normalizedTargetOptions = nextTargetOptions.length > 0
        ? nextTargetOptions
        : [{ value: "web_app", label: "Web Application" }];
      setTargetOptions(normalizedTargetOptions);
      setProfiles(nextProfiles);
      setSelectedTargetType((current) => {
        const preferred = current || normalizedTargetOptions[0]?.value || "web_app";
        const exists = normalizedTargetOptions.some((item) => item.value === preferred);
        return exists ? preferred : normalizedTargetOptions[0]?.value || "web_app";
      });
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Failed to load information gathering profiles");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadProfiles();
  }, [loadProfiles]);

  useEffect(() => {
    const matched = profiles.find((item) => item.target_type === selectedTargetType) ?? null;
    setEditingProfile(matched ? JSON.parse(JSON.stringify(matched)) as InformationGatheringProfile : null);
    setExpandedBlockIndex(null);
  }, [profiles, selectedTargetType]);

  const selectedProfileSummary = useMemo(() => {
    if (!editingProfile) {
      return null;
    }
    const toolCount = editingProfile.blocks.reduce((count, block) => count + block.tools.length, 0);
    return {
      totalBlocks: editingProfile.blocks.length,
      totalTools: toolCount,
    };
  }, [editingProfile]);

  function updateBlock(index: number, patch: Partial<InformationGatheringProfileBlock>) {
    setEditingProfile((current) => {
      if (!current) {
        return current;
      }
      const nextBlocks = current.blocks.map((block, blockIndex) => {
        if (blockIndex !== index) {
          return block;
        }
        const nextBlock = { ...block, ...patch };
        if ("name" in patch && (!patch.id || patch.id === block.id)) {
          nextBlock.id = slugifyBlockId(String(nextBlock.name || block.name));
        }
        return nextBlock;
      });
      return { ...current, max_blocks: nextBlocks.length, blocks: nextBlocks };
    });
  }

  function addBlock() {
    setEditingProfile((current) => {
      if (!current) {
        return current;
      }
      const nextBlocks = [...current.blocks, createEmptyBlock()];
      return {
        ...current,
        max_blocks: nextBlocks.length,
        blocks: nextBlocks,
      };
    });
    setExpandedBlockIndex(editingProfile?.blocks.length ?? 0);
  }

  function removeBlock(index: number) {
    setEditingProfile((current) => {
      if (!current) {
        return current;
      }
      const nextBlocks = current.blocks.filter((_, blockIndex) => blockIndex !== index);
      return {
        ...current,
        max_blocks: Math.max(1, nextBlocks.length),
        blocks: nextBlocks,
      };
    });
    setExpandedBlockIndex((current) => (current === index ? null : current));
  }

  async function handleReloadSelected() {
    setError("");
    setSuccess("");
    setLoading(true);
    try {
      const profile = await getInformationGatheringProfileFromDesktop(selectedTargetType);
      setProfiles((current) => {
        const others = current.filter((item) => item.target_type !== profile.target_type);
        return [...others, profile].sort((a, b) => a.target_type.localeCompare(b.target_type));
      });
      setEditingProfile(JSON.parse(JSON.stringify(profile)) as InformationGatheringProfile);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Failed to reload profile");
    } finally {
      setLoading(false);
    }
  }

  async function handleSave() {
    if (!editingProfile) {
      return;
    }
    setSaving(true);
    setError("");
    setSuccess("");
    try {
      const payload: InformationGatheringProfile = {
        ...editingProfile,
        target_type: selectedTargetType,
        version: editingProfile.version || "1.0",
        generated_from: "ui_settings",
        max_blocks: editingProfile.blocks.length,
        blocks: editingProfile.blocks.map((block) => ({
          ...block,
          id: slugifyBlockId(block.id || block.name),
          name: block.name.trim(),
          goal: block.goal.trim(),
          interaction: block.interaction.trim() || "active_safe",
          tools: block.tools.map((tool) => tool.trim()).filter(Boolean),
        })),
      };
      const saved = await saveInformationGatheringProfileFromDesktop(selectedTargetType, payload);
      setProfiles((current) => {
        const others = current.filter((item) => item.target_type !== saved.target_type);
        return [...others, saved].sort((a, b) => a.target_type.localeCompare(b.target_type));
      });
      setEditingProfile(JSON.parse(JSON.stringify(saved)) as InformationGatheringProfile);
      setSuccess("Information Gathering profile saved.");
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : "Failed to save profile");
    } finally {
      setSaving(false);
    }
  }

  async function handleReset() {
    const confirmed = window.confirm(`Reset the Information Gathering profile for ${formatTargetTypeLabel(selectedTargetType)}?`);
    if (!confirmed) {
      return;
    }
    setSaving(true);
    setError("");
    setSuccess("");
    try {
      const restored = await resetInformationGatheringProfileFromDesktop(selectedTargetType);
      setProfiles((current) => {
        const others = current.filter((item) => item.target_type !== restored.target_type);
        return [...others, restored].sort((a, b) => a.target_type.localeCompare(b.target_type));
      });
      setEditingProfile(JSON.parse(JSON.stringify(restored)) as InformationGatheringProfile);
      setSuccess("Information Gathering profile reset to JSON default.");
    } catch (resetError) {
      setError(resetError instanceof Error ? resetError.message : "Failed to reset profile");
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
            Static Information Gathering
          </CardTitle>
        </CardHeader>
        <div className="space-y-3">
          <p className="text-sm text-text-secondary">
            Edit the JSON-backed Information Gathering baseline for each target type. This is the exact block profile
            loaded before the Information Gathering LLM organizes the first static scan.
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
              label="Version"
              value={editingProfile?.version ?? "1.0"}
              readOnly
            />
            <Input
              label="Saved Blocks"
              value={String(selectedProfileSummary?.totalBlocks ?? 0)}
              readOnly
            />
            <Input
              label="Total Tools"
              value={String(selectedProfileSummary?.totalTools ?? 0)}
              readOnly
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" onClick={handleSave} loading={saving} disabled={!editingProfile}>
              <Save size={12} />
              Save Profile
            </Button>
            <Button size="sm" variant="ghost" onClick={() => void handleReloadSelected()} disabled={loading || saving}>
              <RefreshCcw size={12} />
              Reload
            </Button>
            <Button size="sm" variant="ghost" onClick={handleReset} disabled={!editingProfile || saving}>
              <RotateCcw size={12} />
              Reset Default
            </Button>
            <Button size="sm" variant="ghost" onClick={addBlock} disabled={!editingProfile || saving}>
              <Plus size={12} />
              Add Block
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
        {loading && <p className="text-sm text-text-muted">Loading Information Gathering profiles...</p>}
        {!loading && editingProfile && editingProfile.blocks.length === 0 && (
          <Card>
            <p className="text-sm text-text-muted">No blocks saved for this target type yet.</p>
          </Card>
        )}
        {!loading && editingProfile?.blocks.map((block, index) => {
          const isExpanded = expandedBlockIndex === index;
          return (
            <Card key={`${selectedTargetType}-${index}`} className="overflow-hidden">
              <div
                className="flex cursor-pointer items-center justify-between p-3 transition-colors hover:bg-surface-0/50"
                onClick={() => setExpandedBlockIndex(isExpanded ? null : index)}
              >
                <div className="flex items-center gap-3">
                  {isExpanded ? <ChevronDown size={14} className="text-text-secondary" /> : <ChevronRight size={14} className="text-text-secondary" />}
                  <div className="flex flex-col">
                    <span className="text-sm font-medium">Block {index + 1}: {block.name || "Untitled Block"}</span>
                    <span className="text-xs text-text-secondary">{block.id || "no_id"} • {block.interaction} • {block.tools.length} tools</span>
                  </div>
                </div>
              </div>

              {isExpanded && (
                <div className="space-y-4 border-t border-border bg-surface-0/20 p-4">
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-medium text-text-primary">Update Block</h4>
                    <Button size="sm" variant="ghost" onClick={() => removeBlock(index)} disabled={saving} className="text-red-400 hover:bg-red-500/10 hover:text-red-300">
                      <Trash2 size={12} />
                      Remove
                    </Button>
                  </div>

                  <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                    <Input
                      label="Name"
                      value={block.name}
                      onChange={(event) => updateBlock(index, { name: event.target.value })}
                    />
                    <Input
                      label="Block ID"
                      value={block.id}
                      onChange={(event) => updateBlock(index, { id: slugifyBlockId(event.target.value) })}
                    />
                    <Select
                      label="Interaction"
                      value={block.interaction}
                      onChange={(event) => updateBlock(index, { interaction: event.target.value })}
                      options={[
                        { value: "passive", label: "Passive" },
                        { value: "active_safe", label: "Active Safe" },
                        { value: "active", label: "Active" },
                      ]}
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="block text-xs font-medium text-text-secondary">Goal</label>
                    <textarea
                      className="min-h-24 w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary transition-colors duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-pf-500/50"
                      value={block.goal}
                      onChange={(event) => updateBlock(index, { goal: event.target.value })}
                    />
                  </div>
                  <Input
                    label="Tools"
                    hint="Comma-separated baseline tools from the Information Gathering JSON profile"
                    value={block.tools.join(", ")}
                    onChange={(event) => updateBlock(index, { tools: normalizeList(event.target.value) })}
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
