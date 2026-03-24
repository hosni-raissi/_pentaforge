import { useNavigate } from "react-router-dom";
import { FolderOpen } from "lucide-react";

import { AgentStatus } from "@/components/dashboard/AgentStatus";
import { FindingsTable } from "@/components/dashboard/FindingsTable";
import { PhaseTimeline } from "@/components/dashboard/PhaseTimeline";
import { ScanProgress } from "@/components/dashboard/ScanProgress";
import { StatsGrid } from "@/components/dashboard/StatsGrid";
import { Button } from "@/components/ui/Button";
import { useProjects } from "@/stores/projects";

export default function Dashboard() {
  const navigate = useNavigate();
  const activeProject = useProjects((state) => state.getActive());

  if (!activeProject) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3">
        <FolderOpen size={48} className="text-text-muted" />
        <p className="text-sm text-text-secondary">No project selected.</p>
        <Button onClick={() => navigate("/projects")}>Open Projects</Button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold">{activeProject.name}</h1>
        <p className="text-sm text-text-secondary">{activeProject.target}</p>
      </div>

      <StatsGrid findings={activeProject.findings} />

      <div className="grid gap-4 xl:grid-cols-2">
        <PhaseTimeline />
        <ScanProgress
          phases={activeProject.phases}
          progress={activeProject.scanProgress}
        />
      </div>

      <AgentStatus agents={activeProject.agents} />
      <FindingsTable findings={activeProject.findings} />
    </div>
  );
}
