import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, Trash2, Play, Square, FolderOpen, Share2, RefreshCcw } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Dialog } from '../components/ui/Dialog';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { useProjects } from '../stores/projects';
import { format } from 'date-fns';
import type { Project } from '../types';
import {
  listProjectTargetFieldsFromDesktop,
  listProjectTargetTypesFromDesktop,
  type ProjectTargetField,
  type ProjectTargetTypeOption,
} from '../lib/projectBridge';

const FALLBACK_TARGET_TYPES: ProjectTargetTypeOption[] = [
  { value: 'web_app', label: 'Web Application' },
  { value: 'api', label: 'API' },
  { value: 'mobile', label: 'Mobile App' },
  { value: 'infra', label: 'Infrastructure' },
  { value: 'network', label: 'Network' },
  { value: 'iot', label: 'IoT' },
  { value: 'linux_server', label: 'Linux Server' },
  { value: 'desktop', label: 'Desktop App' },
  { value: 'cloud', label: 'Cloud' },
  { value: 'container', label: 'Container' },
  { value: 'database', label: 'Database' },
  { value: 'repository', label: 'Repository' },
];

const FALLBACK_FIELD: ProjectTargetField = {
  key: 'target',
  label: 'Target',
  required: true,
  data_type: 'string',
  options: [],
};

const PRIMARY_TARGET_KEYS = [
  'url',
  'base_url',
  'host',
  'target_ip',
  'gateway',
  'cidr',
  'repo_url',
  'targets.ip_address',
];

export default function Projects() {
  const navigate = useNavigate();
  const {
    projects,
    addProject,
    removeProject,
    setActive,
    setRunning,
    runningProjectId,
    startingProjectId,
    stopScan,
    hydrateFromDatabase,
  } = useProjects();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [form, setForm] = useState({ name: '', targetType: '', description: '' });
  const [targetTypes, setTargetTypes] = useState<ProjectTargetTypeOption[]>([]);
  const [targetFields, setTargetFields] = useState<ProjectTargetField[]>([]);
  const [targetInfo, setTargetInfo] = useState<Record<string, string>>({});
  const [typesLoading, setTypesLoading] = useState(false);
  const [fieldsLoading, setFieldsLoading] = useState(false);
  const [typesError, setTypesError] = useState<string>('');
  const [fieldsError, setFieldsError] = useState<string>('');
  const [searchTerm, setSearchTerm] = useState('');
  const [creatingProject, setCreatingProject] = useState(false);
  const [stopDialogOpen, setStopDialogOpen] = useState(false);
  const [stopProjectId, setStopProjectId] = useState<string | null>(null);

  function formatShortDate(value: string): string {
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      return '--';
    }
    return format(parsed, 'MMM d');
  }

  useEffect(() => {
    if (!dialogOpen) {
      return;
    }

    let cancelled = false;
    async function loadTypes() {
      setTypesLoading(true);
      setTypesError('');
      try {
        const remote = await listProjectTargetTypesFromDesktop();
        const nextTypes = remote.length > 0 ? remote : FALLBACK_TARGET_TYPES;
        if (cancelled) {
          return;
        }
        setTargetTypes(nextTypes);
        setForm((previous) => {
          const hasCurrent = nextTypes.some((item) => item.value === previous.targetType);
          return {
            ...previous,
            targetType: hasCurrent ? previous.targetType : (nextTypes[0]?.value ?? ''),
          };
        });
      } catch {
        if (cancelled) {
          return;
        }
        setTypesError('Using fallback target types (server metadata unavailable).');
        setTargetTypes(FALLBACK_TARGET_TYPES);
        setForm((previous) => ({
          ...previous,
          targetType: previous.targetType || FALLBACK_TARGET_TYPES[0].value,
        }));
      } finally {
        if (!cancelled) {
          setTypesLoading(false);
        }
      }
    }

    void loadTypes();
    return () => {
      cancelled = true;
    };
  }, [dialogOpen]);

  useEffect(() => {
    if (!dialogOpen || !form.targetType) {
      return;
    }

    let cancelled = false;
    async function loadFields() {
      setFieldsLoading(true);
      setFieldsError('');
      try {
        const remote = await listProjectTargetFieldsFromDesktop(form.targetType);
        const nextFields = remote.length > 0 ? remote : [FALLBACK_FIELD];
        if (cancelled) {
          return;
        }
        setTargetFields(nextFields);
        setTargetInfo((previous) => {
          const next: Record<string, string> = {};
          for (const field of nextFields) {
            const value = previous[field.key];
            if (typeof value === 'string') {
              next[field.key] = value;
            }
          }
          return next;
        });
      } catch {
        if (cancelled) {
          return;
        }
        setFieldsError('Using fallback fields (schema metadata unavailable).');
        setTargetFields([FALLBACK_FIELD]);
        setTargetInfo((previous) => ({ target: previous.target ?? '' }));
      } finally {
        if (!cancelled) {
          setFieldsLoading(false);
        }
      }
    }

    void loadFields();
    return () => {
      cancelled = true;
    };
  }, [dialogOpen, form.targetType]);

  const missingRequiredField = targetFields.some((field) => {
    if (!field.required) {
      return false;
    }
    return !(targetInfo[field.key] ?? '').trim();
  });

  const filteredProjects = useMemo(() => {
    const needle = searchTerm.trim().toLowerCase();
    if (!needle) {
      return projects;
    }
    return projects.filter((project) => {
      const haystack = `${project.name} ${project.target} ${project.targetType}`.toLowerCase();
      return haystack.includes(needle);
    });
  }, [projects, searchTerm]);

  function handleCreate() {
    if (creatingProject) {
      return;
    }
    setCreatingProject(true);

    const cleanedTargetInfo = Object.fromEntries(
      Object.entries(targetInfo).filter(([, value]) => value.trim().length > 0),
    );

    const primaryTarget =
      PRIMARY_TARGET_KEYS.map((key) => cleanedTargetInfo[key]).find((value) => typeof value === 'string' && value.length > 0)
      || targetFields.map((field) => cleanedTargetInfo[field.key]).find((value) => typeof value === 'string' && value.length > 0)
      || '';

    const project: Project = {
      id: crypto.randomUUID(),
      name: form.name,
      target: primaryTarget,
      targetType: form.targetType,
      targetConfig: cleanedTargetInfo,
      status: 'idle',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      description: form.description,
      findings: [],
      agents: [
        { name: 'planner', state: 'idle' },
        { name: 'recon', state: 'idle' },
        { name: 'exploit', state: 'idle' },
        { name: 'verify', state: 'idle' },
        { name: 'report', state: 'idle' },
        { name: 'retest', state: 'idle' },
      ],
      phases: [
        { name: 'Reconnaissance', status: 'pending', progress: 0 },
        { name: 'Enumeration', status: 'pending', progress: 0 },
        { name: 'Exploitation', status: 'pending', progress: 0 },
        { name: 'Post-Exploitation', status: 'pending', progress: 0 },
        { name: 'Reporting', status: 'pending', progress: 0 },
      ],
      scanProgress: 0,
    };
    addProject(project);
    setDialogOpen(false);
    setForm({
      name: '',
      targetType: targetTypes[0]?.value ?? '',
      description: '',
    });
    setTargetInfo({});
    navigate('/dashboard');
    setCreatingProject(false);
  }

  function openProject(id: string) {
    setActive(id);
    navigate('/dashboard');
  }

  function openClientShare(projectId: string) {
    setActive(projectId);
    navigate('/client-share');
  }

  return (
    <div className="max-w-4xl mx-auto space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-text-primary">Projects</h1>
          <p className="text-xs text-text-muted">
            {filteredProjects.length}
            {' '}
            of
            {' '}
            {projects.length}
            {' '}
            engagement{projects.length !== 1 ? 's' : ''}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => hydrateFromDatabase()}
            title="Reload projects from server"
          >
            <RefreshCcw size={14} />
            Reload
          </Button>
          <Button onClick={() => setDialogOpen(true)} size="sm">
            <Plus size={14} /> New Project
          </Button>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <Input
          value={searchTerm}
          onChange={(event) => setSearchTerm(event.target.value)}
          placeholder="Search projects by name, target, or type..."
          className="max-w-lg"
        />
        {searchTerm.trim() && (
          <Button variant="ghost" size="sm" onClick={() => setSearchTerm('')}>
            Clear
          </Button>
        )}
      </div>

      {/* Project list */}
      <AnimatePresence>
        {projects.length === 0 ? (
          <Card className="flex flex-col items-center justify-center py-16">
            <FolderOpen size={40} className="text-text-muted mb-3" />
            <p className="text-sm text-text-secondary mb-1">No projects yet</p>
            <p className="text-xs text-text-muted mb-4">Create a new engagement to get started.</p>
            <Button onClick={() => setDialogOpen(true)} size="sm">
              <Plus size={14} /> Create Project
            </Button>
          </Card>
        ) : filteredProjects.length === 0 ? (
          <Card className="flex flex-col items-center justify-center py-16">
            <FolderOpen size={40} className="text-text-muted mb-3" />
            <p className="text-sm text-text-secondary mb-1">No matching projects</p>
            <p className="text-xs text-text-muted mb-4">Try a different search keyword.</p>
            <Button variant="secondary" size="sm" onClick={() => setSearchTerm('')}>
              Clear Search
            </Button>
          </Card>
        ) : (
          <div className="space-y-2">
            {filteredProjects.map((project) => (
              <motion.div
                key={project.id}
                layout
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
              >
                <Card hover onClick={() => openProject(project.id)} className="flex items-center justify-between">
                  <div className="flex items-center gap-3 min-w-0 flex-1">
                    <div className="w-8 h-8 rounded-md bg-pf-600/15 flex items-center justify-center shrink-0">
                      <FolderOpen size={16} className="text-pf-400" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-text-primary truncate">{project.name}</p>
                      <p className="text-[11px] text-text-muted font-mono truncate">{project.target}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0 ml-4">
                    <Badge variant={project.status} dot>{project.status}</Badge>
                    {startingProjectId === project.id && (
                      <span className="text-[10px] text-text-muted">starting...</span>
                    )}
                    <span className="text-[10px] text-text-muted w-16 text-right">
                      {formatShortDate(project.updatedAt)}
                    </span>
                    <div className="flex items-center gap-1 ml-2" onClick={(e) => e.stopPropagation()}>
                      {(() => {
                        const isStartingThisProject = startingProjectId === project.id;
                        const anotherProjectBusy = (
                          (!!runningProjectId && runningProjectId !== project.id)
                          || (!!startingProjectId && startingProjectId !== project.id)
                        );
                        const canStartProject = !anotherProjectBusy && !isStartingThisProject;

                        return (
                          <>
                            {project.status !== 'running' && (
                              <Button
                                variant="ghost" size="sm"
                                onClick={() => {
                                  if (project.status === 'completed') {
                                    const confirmed = window.confirm('This scan already completed. Start a new scan and clear previous results?');
                                    if (!confirmed) {
                                      return;
                                    }
                                    setRunning(project.id, { triggerScan: true, force: true });
                                    return;
                                  }
                                  if (project.status === 'paused') {
                                    const confirmed = window.confirm('Resume will start a new scan and keep previous history visible. Continue?');
                                    if (!confirmed) {
                                      return;
                                    }
                                    setRunning(project.id, { triggerScan: true, resume: true });
                                    return;
                                  }
                                  setRunning(project.id, { triggerScan: true });
                                }}
                                disabled={!canStartProject}
                                title={!canStartProject ? 'Another scan is already running' : 'Start scan'}
                              >
                                <Play size={12} />
                              </Button>
                            )}
                            {project.status === 'running' && (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => {
                                  setStopProjectId(project.id);
                                  setStopDialogOpen(true);
                                }}
                                title="Stop scan"
                              >
                                <Square size={12} />
                              </Button>
                            )}
                          </>
                        );
                      })()}
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => openClientShare(project.id)}
                        title="Share scan result"
                      >
                        <Share2 size={12} />
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => removeProject(project.id)} title="Delete">
                        <Trash2 size={12} />
                      </Button>
                    </div>
                  </div>
                </Card>
              </motion.div>
            ))}
          </div>
        )}
      </AnimatePresence>

      {/* New Project Dialog */}
      <Dialog
        open={dialogOpen}
        onClose={() => {
          setDialogOpen(false);
          setCreatingProject(false);
        }}
        title="New Project"
        width="max-w-3xl"
      >
        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <Input
              label="Project Name"
              placeholder="ACME Corp — Web Assessment 2026"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
            <Select
              label="Target Type"
              options={targetTypes}
              value={form.targetType}
              onChange={(e) => {
                setForm({ ...form, targetType: e.target.value });
                setTargetInfo({});
              }}
            />
          </div>

          {typesLoading && <p className="text-[11px] text-text-muted">Loading target types...</p>}
          {typesError && <p className="text-[11px] text-yellow-400">{typesError}</p>}

          <div className="rounded-lg border border-border bg-surface-0/35 p-3">
            <div className="mb-3 flex items-center justify-between">
              <p className="text-xs font-semibold tracking-wide text-text-secondary">Target Information</p>
              <p className="text-[11px] text-text-muted">
                {targetFields.length} field{targetFields.length === 1 ? '' : 's'}
              </p>
            </div>
            {fieldsLoading ? (
              <p className="text-[11px] text-text-muted">Loading target info fields from schema...</p>
            ) : (
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                {targetFields.map((field) => {
                  const isWideField = (
                    field.data_type === 'array'
                    || field.key.includes('headers')
                    || field.key.includes('params')
                    || field.key.includes('body')
                    || field.key.includes('description')
                    || field.key.startsWith('endpoints.')
                    || field.key.startsWith('credentials.two_factor')
                  );

                  if (field.data_type === 'enum') {
                    return (
                      <div key={field.key} className={isWideField ? 'md:col-span-2' : ''}>
                        <Select
                          label={`${field.label}${field.required ? ' *' : ''}`}
                          options={(field.options.length > 0 ? field.options : ['']).map((value) => ({
                            value,
                            label: value || 'Unknown',
                          }))}
                          value={targetInfo[field.key] ?? ''}
                          onChange={(event) => {
                            setTargetInfo((previous) => ({
                              ...previous,
                              [field.key]: event.target.value,
                            }));
                          }}
                        />
                      </div>
                    );
                  }

                  if (field.data_type === 'boolean') {
                    return (
                      <div key={field.key} className={isWideField ? 'md:col-span-2' : ''}>
                        <Select
                          label={`${field.label}${field.required ? ' *' : ''}`}
                          options={[
                            { value: 'true', label: 'True' },
                            { value: 'false', label: 'False' },
                          ]}
                          value={targetInfo[field.key] ?? 'false'}
                          onChange={(event) => {
                            setTargetInfo((previous) => ({
                              ...previous,
                              [field.key]: event.target.value,
                            }));
                          }}
                        />
                      </div>
                    );
                  }

                  const inputType = field.data_type === 'integer' || field.data_type === 'number' ? 'number' : 'text';
                  return (
                    <div key={field.key} className={isWideField ? 'md:col-span-2' : ''}>
                      <Input
                        label={`${field.label}${field.required ? ' *' : ''}`}
                        placeholder={field.key}
                        type={inputType}
                        value={targetInfo[field.key] ?? ''}
                        onChange={(event) => {
                          setTargetInfo((previous) => ({
                            ...previous,
                            [field.key]: event.target.value,
                          }));
                        }}
                      />
                    </div>
                  );
                })}
              </div>
            )}
            {fieldsError && <p className="mt-2 text-[11px] text-yellow-400">{fieldsError}</p>}
          </div>

          <Input
            label="Description (optional)"
            placeholder="Black-box web application assessment"
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
          />
          <div className="flex justify-end gap-2 pt-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                setDialogOpen(false);
                setCreatingProject(false);
              }}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              loading={creatingProject}
              onClick={(event) => {
                event.preventDefault();
                event.stopPropagation();
                handleCreate();
              }}
              disabled={
                creatingProject
                || !form.name.trim()
                || !form.targetType
                || missingRequiredField
                || typesLoading
                || fieldsLoading
              }
            >
              Create
            </Button>
          </div>
        </div>
      </Dialog>

      <Dialog
        open={stopDialogOpen}
        onClose={() => setStopDialogOpen(false)}
        title="Stop Scan"
        description="Choose whether to pause or cancel the current scan."
      >
        <div className="space-y-3 text-xs text-text-secondary">
          <p>
            Pause will keep current logs and results so you can review them. Cancel will clear logs,
            agent results, and reset status to idle.
          </p>
          <div className="flex flex-col gap-2 sm:flex-row sm:justify-end">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setStopDialogOpen(false)}
            >
              Back
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                if (!stopProjectId) {
                  return;
                }
                setStopDialogOpen(false);
                void stopScan(stopProjectId, 'pause');
              }}
            >
              Pause Scan
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={() => {
                if (!stopProjectId) {
                  return;
                }
                setStopDialogOpen(false);
                void stopScan(stopProjectId, 'cancel');
              }}
            >
              Cancel Scan
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}
