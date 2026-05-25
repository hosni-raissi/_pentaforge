import type { Project } from "@/types";

export interface MobileRuntimeNotice {
  tone: "success" | "warning" | "info";
  title: string;
  detail: string;
}

export function getProjectMobileRuntimeNotice(project: Project | null | undefined): MobileRuntimeNotice | null {
  if (!project || String(project.targetType || "").trim().toLowerCase() !== "mobile") {
    return null;
  }

  return null;
}
