import { ProjectCard } from "@/components/projects/ProjectCard";
import type { Project } from "@/types";

export function ProjectList({
  projects,
  onOpen
}: {
  projects: Project[];
  onOpen: (id: string) => void;
}) {
  return (
    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
      {projects.map((project) => (
        <ProjectCard key={project.id} project={project} onOpen={onOpen} />
      ))}
    </div>
  );
}
