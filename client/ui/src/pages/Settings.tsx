import { Cpu, Palette, Server } from "lucide-react";

import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { Select } from "@/components/ui/Select";
import { Tabs } from "@/components/ui/Tabs";
import { Toggle } from "@/components/ui/Toggle";
import { useConfig } from "@/stores/config";
import { useTheme } from "@/stores/theme";

export default function Settings() {
  const config = useConfig();
  const { isDark, setDark } = useTheme();
  const activeLLM = config.llmConfigs.find(
    (item) => item.id === config.activeLLM
  );

  return (
    <div className="mx-auto max-w-3xl space-y-4">
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
          }
        ]}
        defaultTab="runtime"
      />
    </div>
  );
}
