import { useMemo } from "react";

import { useProjects } from "@/stores/projects";
import type { ProjectStatus } from "@/types";

export function useProject() {
  const {
    projects,
    activeProjectId,
    setActive,
    addProject,
    updateProject
  } = useProjects();

  const activeProject = useMemo(
    () => projects.find((project) => project.id === activeProjectId) ?? null,
    [projects, activeProjectId]
  );

  return {
    projects,
    activeProject,
    setActiveProject: setActive,
    addProject,
    updateStatus: (id: string, status: ProjectStatus) =>
      updateProject(id, { status })
  };
}
