import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { Project, ProjectStatus } from '../types';

interface ProjectStore {
  projects: Project[];
  activeProjectId: string | null;
  runningProjectId: string | null;

  // Actions
  addProject: (project: Project) => void;
  removeProject: (id: string) => void;
  setActive: (id: string | null) => void;
  setRunning: (id: string | null) => void;
  updateProject: (id: string, updates: Partial<Project>) => void;
  getActive: () => Project | null;
  getRunning: () => Project | null;
}

export const useProjects = create<ProjectStore>()(
  persist(
    (set, get) => ({
      projects: [],
      activeProjectId: null,
      runningProjectId: null,

      addProject: (project) =>
        set((s) => ({
          projects: [project, ...s.projects],
          activeProjectId: project.id,
        })),

      removeProject: (id) =>
        set((s) => ({
          projects: s.projects.filter((p) => p.id !== id),
          activeProjectId: s.activeProjectId === id ? null : s.activeProjectId,
          runningProjectId: s.runningProjectId === id ? null : s.runningProjectId,
        })),

      setActive: (id) => set({ activeProjectId: id }),

      setRunning: (id) =>
        set((s) => {
          // Only one project can run at a time
          const updated = s.projects.map((p) => {
            if (p.id === id) return { ...p, status: 'running' as ProjectStatus };
            if (p.status === 'running') return { ...p, status: 'paused' as ProjectStatus };
            return p;
          });
          return { projects: updated, runningProjectId: id };
        }),

      updateProject: (id, updates) =>
        set((s) => ({
          projects: s.projects.map((p) =>
            p.id === id ? { ...p, ...updates, updatedAt: new Date().toISOString() } : p
          ),
        })),

      getActive: () => {
        const { projects, activeProjectId } = get();
        return projects.find((p) => p.id === activeProjectId) ?? null;
      },

      getRunning: () => {
        const { projects, runningProjectId } = get();
        return projects.find((p) => p.id === runningProjectId) ?? null;
      },
    }),
    { name: 'pf-projects' }
  )
);