import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { Project, ProjectStatus } from '../types';
import {
  deleteProjectFromDesktop,
  listProjectsFromDesktop,
  saveProjectToDesktop,
  startProjectScanFromDesktop,
  stopProjectScanFromDesktop,
  supportsDesktopProjectBridge,
} from '../lib/projectBridge';

interface ProjectStore {
  projects: Project[];
  activeProjectId: string | null;
  runningProjectId: string | null;
  startingProjectId: string | null;

  // Actions
  addProject: (project: Project, opts?: { persist?: boolean }) => void;
  removeProject: (id: string) => Promise<void>;
  setActive: (id: string | null) => void;
  setRunning: (id: string | null, opts?: { triggerScan?: boolean; resume?: boolean; force?: boolean }) => void;
  stopScan: (id: string, mode: "stop" | "pause" | "cancel") => Promise<void>;
  updateProject: (id: string, updates: Partial<Project>, opts?: { persist?: boolean }) => void;
  getActive: () => Project | null;
  getRunning: () => Project | null;
  hydrateFromDatabase: () => Promise<void>;
}

type PersistedProjectStore = Pick<ProjectStore, 'activeProjectId'>;

export const useProjects = create<ProjectStore>()(
  persist(
    (set, get) => ({
      projects: [],
      activeProjectId: null,
      runningProjectId: null,
      startingProjectId: null,

      addProject: (project, opts) =>
        set((s) => {
          const nextProjects = [project, ...s.projects];
          const shouldPersist = opts?.persist !== false;
          if (shouldPersist) {
            void saveProjectToDesktop(project).catch((error) => {
              console.error('Failed to persist project:', error);
            });
          }
          return {
            projects: nextProjects,
            activeProjectId: project.id,
          };
        }),

      removeProject: async (id) => {
        try {
          await deleteProjectFromDesktop(id);
        } catch (error) {
          console.error('Failed to delete project from desktop DB:', error);
          // We still remove it from local state for responsiveness, 
          // but we could also throw here if we wanted to block the UI.
        }

        set((s) => ({
          projects: s.projects.filter((p) => p.id !== id),
          activeProjectId: s.activeProjectId === id ? null : s.activeProjectId,
          runningProjectId: s.runningProjectId === id ? null : s.runningProjectId,
          startingProjectId: s.startingProjectId === id ? null : s.startingProjectId,
        }));
      },

      setActive: (id) => set({ activeProjectId: id }),

      setRunning: (id, opts) => {
        const state = get();
        const shouldTriggerScan = opts?.triggerScan === true;
        const shouldResume = opts?.resume === true;
        const shouldForce = opts?.force === true;

        if (id) {
          const targetProject = state.projects.find((project) => project.id === id);
          const targetIsRunning = targetProject?.status === 'running';
          const otherProjectRunning = state.projects.some(
            (project) => project.id !== id && project.status === 'running',
          );

          if (state.startingProjectId === id || targetIsRunning) {
            return;
          }
          if (state.startingProjectId && state.startingProjectId !== id) {
            return;
          }
          if (otherProjectRunning) {
            return;
          }
        }

        let updated = state.projects;
        const changedProjectIds = new Set<string>();

        if (!shouldTriggerScan) {
          updated = state.projects.map((p) => {
            if (p.id === id) {
              if (p.status !== 'running') {
                changedProjectIds.add(p.id);
              }
              return { ...p, status: 'running' as ProjectStatus };
            }
            if (p.status === 'running') {
              changedProjectIds.add(p.id);
              return { ...p, status: 'stopped' as ProjectStatus };
            }
            return p;
          });

          set({
            projects: updated,
            runningProjectId: id,
            startingProjectId: id,
            activeProjectId: id,
          });

          if (supportsDesktopProjectBridge()) {
            for (const project of updated) {
              if (!changedProjectIds.has(project.id) || project.id === id) {
                continue;
              }
              void saveProjectToDesktop(project).catch((error) => {
                console.error('Failed to sync running project state:', error);
              });
            }
          }
        } else {
          const nowIso = new Date().toISOString();
          updated = state.projects.map((project) => {
            if (project.id !== id) {
              return project;
            }
            const previousLastScan = project.lastScan ?? {};
            return {
              ...project,
              status: 'running',
              scanProgress: Math.max(project.scanProgress ?? 0, 5),
              updatedAt: nowIso,
              lastScan: {
                ...previousLastScan,
                status: 'running',
                startedAt: previousLastScan.startedAt || nowIso,
                finishedAt: undefined,
                elapsedSeconds: shouldResume
                  ? (
                    typeof previousLastScan.elapsedSeconds === 'number'
                    && Number.isFinite(previousLastScan.elapsedSeconds)
                      ? previousLastScan.elapsedSeconds
                      : 0
                  )
                  : 0,
                durationSeconds: undefined,
                error: '',
                // Fresh runs clear prior result; resume keeps it.
                result: shouldResume ? previousLastScan.result : undefined,
              },
            };
          });

          set({
            projects: updated,
            runningProjectId: id,
            startingProjectId: id,
            activeProjectId: id,
          });
        }

        if (!id || !supportsDesktopProjectBridge() || !shouldTriggerScan) {
          set((inner) => ({
            startingProjectId: inner.startingProjectId === id ? null : inner.startingProjectId,
          }));
          return;
        }

        const runningProject = updated.find((project) => project.id === id);
        if (!runningProject) {
          set((inner) => ({
            runningProjectId: inner.runningProjectId === id ? null : inner.runningProjectId,
            startingProjectId: inner.startingProjectId === id ? null : inner.startingProjectId,
          }));
          return;
        }

        void (async () => {
          try {
            await saveProjectToDesktop(runningProject);
          } catch (error) {
            console.error('Failed to persist running project before scan start:', error);
          }

          try {
            const response = await startProjectScanFromDesktop({
              projectId: id,
              target: runningProject.target,
              targetConfig: runningProject.targetConfig,
              scope: runningProject.description ?? '',
              resume: shouldResume,
              force: shouldForce,
            });
            set((inner) => {
              if (inner.startingProjectId !== id) {
                return {};
              }

              const nowIso = new Date().toISOString();
              const responseStatus = String(response.status || '').toLowerCase();
              const nextStatus: ProjectStatus = (
                responseStatus === 'completed'
                || responseStatus === 'stopped'
                || responseStatus === 'idle'
                || responseStatus === 'error'
              )
                ? responseStatus
                : 'running';
              return {
                projects: inner.projects.map((project) => (
                  project.id === id
                    ? {
                      ...project,
                      status: nextStatus,
                      updatedAt: nowIso,
                      scanProgress: nextStatus === 'running'
                        ? Math.max(project.scanProgress ?? 0, 5)
                        : project.scanProgress,
                      lastScan: nextStatus === 'running'
                        ? {
                          scanId: response.scan_id || project.lastScan?.scanId || '',
                          status: 'running',
                          startedAt: response.started_at ?? nowIso,
                          finishedAt: undefined,
                          elapsedSeconds: 0,
                          durationSeconds: undefined,
                          error: '',
                        }
                        : project.lastScan,
                    }
                    : project
                )),
                activeProjectId: id,
                runningProjectId: nextStatus === 'running'
                  ? id
                  : (inner.runningProjectId === id ? null : inner.runningProjectId),
                startingProjectId: null,
              };
            });
          } catch (error) {
            console.error('Failed to start orchestrator scan:', error);
            const nowIso = new Date().toISOString();
            const errorMessage = error instanceof Error
              ? error.message
              : 'Failed to start orchestrator scan';
            set((inner) => ({
              projects: inner.projects.map((project) => (
                project.id === id
                  ? {
                    ...project,
                    status: 'error' as ProjectStatus,
                    updatedAt: nowIso,
                    lastScan: {
                      ...(project.lastScan ?? {}),
                      status: 'error',
                      finishedAt: nowIso,
                      durationSeconds:
                        typeof project.lastScan?.elapsedSeconds === 'number'
                        && Number.isFinite(project.lastScan.elapsedSeconds)
                          ? project.lastScan.elapsedSeconds
                          : undefined,
                      error: errorMessage,
                    },
                  }
                  : project
              )),
              activeProjectId: id,
              runningProjectId: inner.runningProjectId === id ? null : inner.runningProjectId,
              startingProjectId: inner.startingProjectId === id ? null : inner.startingProjectId,
            }));
          }
        })();
      },

      stopScan: async (id, mode) => {
        const state = get();
        const target = state.projects.find((project) => project.id === id);
        if (!target) {
          return;
        }

        try {
          await stopProjectScanFromDesktop({ projectId: id, mode });
        } catch (error) {
          console.error('Failed to stop scan:', error);
        }

        if (mode === 'cancel') {
          const resetProject: Project = {
            ...target,
            status: 'idle',
            scanProgress: 0,
            lastScan: undefined,
            agents: target.agents.map((agent) => ({
              ...agent,
              state: 'idle',
              progress: 0,
              currentTask: '',
              lastUpdate: '',
            })),
            phases: target.phases.map((phase) => ({
              ...phase,
              status: 'pending',
              progress: 0,
              startedAt: '',
              completedAt: '',
            })),
            updatedAt: new Date().toISOString(),
          };
          set((inner) => ({
            projects: inner.projects.map((project) => (
              project.id === id ? resetProject : project
            )),
            runningProjectId: inner.runningProjectId === id ? null : inner.runningProjectId,
            startingProjectId: inner.startingProjectId === id ? null : inner.startingProjectId,
          }));
          void saveProjectToDesktop(resetProject).catch((error) => {
            console.error('Failed to persist cancelled project reset:', error);
          });
          return;
        }

        const nowIso = new Date().toISOString();
        const stoppedProject: Project = {
          ...target,
          status: 'stopped',
          updatedAt: nowIso,
          lastScan: {
            ...(target.lastScan ?? {}),
            status: 'stopped',
            finishedAt: nowIso,
            durationSeconds:
              typeof target.lastScan?.elapsedSeconds === 'number'
              && Number.isFinite(target.lastScan.elapsedSeconds)
                ? target.lastScan.elapsedSeconds
                : target.lastScan?.durationSeconds,
          },
        };
        set((inner) => ({
          projects: inner.projects.map((project) => (
            project.id === id ? stoppedProject : project
          )),
          runningProjectId: inner.runningProjectId === id ? null : inner.runningProjectId,
          startingProjectId: inner.startingProjectId === id ? null : inner.startingProjectId,
        }));
      },

      updateProject: (id, updates, opts) =>
        set((s) => {
          let updatedProject: Project | null = null;
          const projects = s.projects.map((p) => {
            if (p.id !== id) {
              return p;
            }
            const nextProject: Project = { ...p, ...updates, updatedAt: new Date().toISOString() };
            updatedProject = nextProject;
            return nextProject;
          });

          const shouldPersist = opts?.persist !== false;
          if (updatedProject && shouldPersist) {
            void saveProjectToDesktop(updatedProject).catch((error) => {
              console.error('Failed to update project in desktop DB:', error);
            });
          }

          let nextRunningProjectId = s.runningProjectId;
          let nextStartingProjectId = s.startingProjectId;
          const nextStatus = updates.status;

          if (nextStatus === 'running') {
            nextRunningProjectId = id;
          } else if (nextStatus) {
            if (nextRunningProjectId === id) {
              nextRunningProjectId = null;
            }
            if (nextStartingProjectId === id) {
              nextStartingProjectId = null;
            }
          }

          return {
            projects,
            runningProjectId: nextRunningProjectId,
            startingProjectId: nextStartingProjectId,
          };
        }),

      getActive: () => {
        const { projects, activeProjectId } = get();
        const safeProjects = Array.isArray(projects) ? projects : [];
        return safeProjects.find((p) => p.id === activeProjectId) ?? null;
      },

      getRunning: () => {
        const { projects, runningProjectId } = get();
        const safeProjects = Array.isArray(projects) ? projects : [];
        return safeProjects.find((p) => p.id === runningProjectId) ?? null;
      },

      hydrateFromDatabase: async () => {
        if (!supportsDesktopProjectBridge()) {
          return;
        }

        try {
          const remoteProjects = await listProjectsFromDesktop();

          set((state) => {
            const nextProjects: Project[] = [...remoteProjects];

            // Preserve optimistic in-flight start state. Without this, periodic
            // hydrate can overwrite local "running" back to stale remote state
            // before the start-scan response is applied.
            if (state.startingProjectId) {
              const startingId = state.startingProjectId;
              const localStarting = state.projects.find((project) => project.id === startingId);
              if (localStarting) {
                const remoteIndex = nextProjects.findIndex((project) => project.id === startingId);
                if (remoteIndex >= 0) {
                  const remoteStarting = nextProjects[remoteIndex];
                  if (remoteStarting.status !== 'running') {
                    nextProjects[remoteIndex] = {
                      ...remoteStarting,
                      ...localStarting,
                    };
                  }
                } else {
                  nextProjects.unshift(localStarting);
                }
              }
            }

            const activeStillExists = state.activeProjectId
              ? nextProjects.some((p) => p.id === state.activeProjectId)
              : false;
            const runningProject = nextProjects.find((p) => p.status === 'running');

            return {
              projects: nextProjects,
              activeProjectId: activeStillExists
                ? state.activeProjectId
                : nextProjects[0]?.id ?? null,
              runningProjectId: runningProject?.id ?? null,
              startingProjectId: state.startingProjectId,
            };
          });
        } catch (error) {
          console.error('Failed to hydrate projects from desktop DB:', error);
        }
      },
    }),
    {
      name: 'pf-projects',
      version: 2,
      partialize: (state): PersistedProjectStore => ({
        activeProjectId: state.activeProjectId,
      }),
      migrate: (persistedState, version) => {
        const state = (persistedState ?? {}) as Partial<ProjectStore>;
        if (version < 2) {
          return {
            activeProjectId: typeof state.activeProjectId === 'string' ? state.activeProjectId : null,
          };
        }
        return {
          activeProjectId: typeof state.activeProjectId === 'string' ? state.activeProjectId : null,
        };
      },
      merge: (persisted, current) => {
        const state = (persisted ?? {}) as Partial<PersistedProjectStore>;
        const activeProjectId = (
          typeof state.activeProjectId === 'string' || state.activeProjectId === null
        )
          ? state.activeProjectId
          : current.activeProjectId;

        return {
          ...current,
          activeProjectId,
        };
      },
    }
  )
);
