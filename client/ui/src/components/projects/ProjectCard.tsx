import { Badge } from "@/components/ui/Badge";
import type { Project } from "@/types";

export function ProjectCard({
  project,
  onOpen
}: {
  project: Project;
  onOpen: (id: string) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onOpen(project.id)}
      className="w-full rounded-xl border border-border bg-surface-1 p-4 text-left hover:bg-surface-2"
    >
      <div className="mb-2 flex items-center justify-between">
        <h3 className="font-semibold">{project.name}</h3>
        <Badge variant={project.status}>{project.status}</Badge>
      </div>
      <p className="text-sm text-text-secondary">{project.target}</p>
      <p className="mt-1 text-xs text-text-muted">Type: {project.targetType}</p>
    </button>
  );
}
