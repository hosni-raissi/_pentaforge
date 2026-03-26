import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { Project, ProjectStatus } from '../types';
import {
  deleteProjectFromDesktop,
  listProjectsFromDesktop,
  saveProjectToDesktop,
  supportsDesktopProjectBridge,
} from '../lib/projectBridge';

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
  hydrateFromDatabase: () => Promise<void>;
}

export const useProjects = create<ProjectStore>()(
  persist(
    (set, get) => ({
      projects: [],
      activeProjectId: null,
      runningProjectId: null,

      addProject: (project) =>
        set((s) => {
          const nextProjects = [project, ...s.projects];
          void saveProjectToDesktop(project).catch((error) => {
            console.error('Failed to persist project:', error);
          });
          return {
            projects: nextProjects,
            activeProjectId: project.id,
          };
        }),

      removeProject: (id) =>
        set((s) => {
          void deleteProjectFromDesktop(id).catch((error) => {
            console.error('Failed to delete project from desktop DB:', error);
          });

          return {
            projects: s.projects.filter((p) => p.id !== id),
            activeProjectId: s.activeProjectId === id ? null : s.activeProjectId,
            runningProjectId: s.runningProjectId === id ? null : s.runningProjectId,
          };
        }),

      setActive: (id) => set({ activeProjectId: id }),

      setRunning: (id) =>
        set((s) => {
          // Only one project can run at a time
          const updated = s.projects.map((p) => {
            if (p.id === id) return { ...p, status: 'running' as ProjectStatus };
            if (p.status === 'running') return { ...p, status: 'paused' as ProjectStatus };
            return p;
          });

          if (supportsDesktopProjectBridge()) {
            for (const project of updated) {
              void saveProjectToDesktop(project).catch((error) => {
                console.error('Failed to sync running project state:', error);
              });
            }
          }

          return { projects: updated, runningProjectId: id };
        }),

      updateProject: (id, updates) =>
        set((s) => {
          let updatedProject: Project | null = null;
          const projects = s.projects.map((p) => {
            if (p.id !== id) {
              return p;
            }
            updatedProject = { ...p, ...updates, updatedAt: new Date().toISOString() };
            return updatedProject;
          });

          if (updatedProject) {
            void saveProjectToDesktop(updatedProject).catch((error) => {
              console.error('Failed to update project in desktop DB:', error);
            });
          }

          return { projects };
        }),

      getActive: () => {
        const { projects, activeProjectId } = get();
        return projects.find((p) => p.id === activeProjectId) ?? null;
      },

      getRunning: () => {
        const { projects, runningProjectId } = get();
        return projects.find((p) => p.id === runningProjectId) ?? null;
      },

      hydrateFromDatabase: async () => {
        if (!supportsDesktopProjectBridge()) {
          return;
        }

        try {
          const remoteProjects = await listProjectsFromDesktop();
          const localProjects = get().projects;

          if (remoteProjects.length === 0 && localProjects.length > 0) {
            for (const project of localProjects) {
              await saveProjectToDesktop(project);
            }
            return;
          }

          set((state) => {
            const activeStillExists = state.activeProjectId
              ? remoteProjects.some((p) => p.id === state.activeProjectId)
              : false;
            const runningStillExists = state.runningProjectId
              ? remoteProjects.some((p) => p.id === state.runningProjectId)
              : false;

            return {
              projects: remoteProjects,
              activeProjectId: activeStillExists
                ? state.activeProjectId
                : remoteProjects[0]?.id ?? null,
              runningProjectId: runningStillExists
                ? state.runningProjectId
                : remoteProjects.find((p) => p.status === 'running')?.id ?? null,
            };
          });
        } catch (error) {
          console.error('Failed to hydrate projects from desktop DB:', error);
        }
      },
    }),
    { name: 'pf-projects' }
  )
);
