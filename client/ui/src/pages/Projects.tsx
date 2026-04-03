import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, Trash2, Play, Square, FolderOpen, Share2, RefreshCcw, Pencil } from 'lucide-react';
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function getNestedValue(payload: Record<string, unknown>, dottedKey: string): unknown {
  const parts = dottedKey.split('.');
  let cursor: unknown = payload;
  for (const part of parts) {
    if (!isRecord(cursor)) {
      return undefined;
    }
    cursor = cursor[part];
  }
  return cursor;
}

function setNestedValue(payload: Record<string, unknown>, dottedKey: string, value: unknown): void {
  const parts = dottedKey.split('.');
  let cursor: Record<string, unknown> = payload;
  for (let i = 0; i < parts.length; i += 1) {
    const part = parts[i];
    const isLast = i === parts.length - 1;
    if (isLast) {
      cursor[part] = value;
      return;
    }
    const next = cursor[part];
    if (!isRecord(next)) {
      const created: Record<string, unknown> = {};
      cursor[part] = created;
      cursor = created;
      continue;
    }
    cursor = next;
  }
}

export default function Projects() {
  const navigate = useNavigate();
  const {
    projects,
    addProject,
    updateProject,
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
  const [credentialProfiles, setCredentialProfiles] = useState<Array<Record<string, string>>>([{}]);
  const [typesLoading, setTypesLoading] = useState(false);
  const [fieldsLoading, setFieldsLoading] = useState(false);
  const [typesError, setTypesError] = useState<string>('');
  const [fieldsError, setFieldsError] = useState<string>('');
  const [searchTerm, setSearchTerm] = useState('');
  const [creatingProject, setCreatingProject] = useState(false);
  const [editingProjectId, setEditingProjectId] = useState<string | null>(null);
  const [pendingEditProject, setPendingEditProject] = useState<Project | null>(null);
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

  const credentialFields = useMemo(
    () => targetFields.filter((field) => field.key.startsWith('credentials.')),
    [targetFields],
  );

  const nonCredentialFields = useMemo(
    () => targetFields.filter((field) => !field.key.startsWith('credentials.')),
    [targetFields],
  );

  useEffect(() => {
    if (!dialogOpen || credentialFields.length === 0) {
      return;
    }
    setCredentialProfiles((previous) => (
      previous.length > 0 ? previous : [{}]
    ));
  }, [dialogOpen, credentialFields.length]);

  useEffect(() => {
    if (!dialogOpen || !pendingEditProject) {
      return;
    }
    const config = isRecord(pendingEditProject.targetConfig) ? pendingEditProject.targetConfig : {};
    const nextTargetInfo: Record<string, string> = {};

    for (const field of nonCredentialFields) {
      const value = getNestedValue(config, field.key);
      nextTargetInfo[field.key] = typeof value === 'string' ? value : '';
    }

    const credentialSource = Array.isArray(config.credentials)
      ? config.credentials
      : [];
    const nextProfiles: Array<Record<string, string>> = credentialSource
      .filter((profile): profile is Record<string, unknown> => isRecord(profile))
      .map((profile) => {
        const next: Record<string, string> = {};
        for (const field of credentialFields) {
          const suffix = field.key.slice('credentials.'.length);
          const value = getNestedValue(profile, suffix);
          next[suffix] = typeof value === 'string' ? value : '';
        }
        return next;
      });

    if (nextProfiles.length === 0 && credentialFields.length > 0) {
      const fallbackProfile: Record<string, string> = {};
      for (const field of credentialFields) {
        const suffix = field.key.slice('credentials.'.length);
        const value = getNestedValue(config, field.key);
        fallbackProfile[suffix] = typeof value === 'string' ? value : '';
      }
      if (Object.values(fallbackProfile).some((value) => value.trim().length > 0)) {
        nextProfiles.push(fallbackProfile);
      }
    }

    setTargetInfo(nextTargetInfo);
    setCredentialProfiles(nextProfiles.length > 0 ? nextProfiles : [{}]);
    setPendingEditProject(null);
  }, [dialogOpen, pendingEditProject, nonCredentialFields, credentialFields]);

  const missingRequiredField = targetFields.some((field) => {
    if (!field.required) {
      return false;
    }
    if (field.key.startsWith('credentials.')) {
      const suffix = field.key.slice('credentials.'.length);
      return !credentialProfiles.some((profile) => (profile[suffix] ?? '').trim().length > 0);
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

  function resetProjectFormState() {
    setEditingProjectId(null);
    setPendingEditProject(null);
    setForm({
      name: '',
      targetType: targetTypes[0]?.value ?? '',
      description: '',
    });
    setTargetInfo({});
    setCredentialProfiles([{}]);
    setCreatingProject(false);
  }

  function handleOpenCreateDialog() {
    resetProjectFormState();
    setDialogOpen(true);
  }

  function handleOpenEditDialog(project: Project) {
    setEditingProjectId(project.id);
    setForm({
      name: project.name,
      targetType: project.targetType,
      description: project.description ?? '',
    });
    setTargetInfo({});
    setCredentialProfiles([{}]);
    setPendingEditProject(project);
    setDialogOpen(true);
  }

  function buildTargetConfigPayload(): { primaryTarget: string; payload: Record<string, unknown> } {
    const cleanedTargetInfo: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(targetInfo)) {
      if (value.trim().length > 0) {
        setNestedValue(cleanedTargetInfo, key, value.trim());
      }
    }

    const cleanedProfiles = credentialProfiles
      .map((profile) => {
        const next: Record<string, unknown> = {};
        for (const [suffix, value] of Object.entries(profile)) {
          const clean = value.trim();
          if (!clean) {
            continue;
          }
          setNestedValue(next, suffix, clean);
        }
        return next;
      })
      .filter((profile) => Object.keys(profile).length > 0);

    if (cleanedProfiles.length > 0) {
      cleanedTargetInfo.credentials = cleanedProfiles;
    }

    const primaryTargetFromPreferred = PRIMARY_TARGET_KEYS
      .map((key) => getNestedValue(cleanedTargetInfo, key))
      .find((value): value is string => typeof value === 'string' && value.length > 0);
    const primaryTargetFromFields = nonCredentialFields
      .map((field) => getNestedValue(cleanedTargetInfo, field.key))
      .find((value): value is string => typeof value === 'string' && value.length > 0);
    const primaryTarget = primaryTargetFromPreferred || primaryTargetFromFields || '';

    return { primaryTarget, payload: cleanedTargetInfo };
  }

  function handleCreateOrUpdate() {
    if (creatingProject) {
      return;
    }
    setCreatingProject(true);

    const { primaryTarget, payload } = buildTargetConfigPayload();

    if (editingProjectId) {
      updateProject(editingProjectId, {
        name: form.name,
        targetType: form.targetType,
        target: primaryTarget,
        targetConfig: payload,
        description: form.description,
      });
      setDialogOpen(false);
      resetProjectFormState();
      return;
    }

    const project: Project = {
      id: crypto.randomUUID(),
      name: form.name,
      target: primaryTarget,
      targetType: form.targetType,
      targetConfig: payload,
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
    resetProjectFormState();
    navigate('/dashboard');
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
          <p className="text-sm text-text-muted">
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
          <Button onClick={handleOpenCreateDialog} size="sm">
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
            <p className="text-sm text-text-muted mb-4">Create a new engagement to get started.</p>
            <Button onClick={handleOpenCreateDialog} size="sm">
              <Plus size={14} /> Create Project
            </Button>
          </Card>
        ) : filteredProjects.length === 0 ? (
          <Card className="flex flex-col items-center justify-center py-16">
            <FolderOpen size={40} className="text-text-muted mb-3" />
            <p className="text-sm text-text-secondary mb-1">No matching projects</p>
            <p className="text-sm text-text-muted mb-4">Try a different search keyword.</p>
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
                      <p className="text-sm text-text-muted font-mono truncate">{project.target}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0 ml-4">
                    <Badge variant={project.status} dot>{project.status}</Badge>
                    {startingProjectId === project.id && (
                      <span className="text-sm text-text-muted">starting...</span>
                    )}
                    <span className="text-sm text-text-muted w-16 text-right">
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
                        onClick={() => handleOpenEditDialog(project)}
                        title="Edit project"
                      >
                        <Pencil size={12} />
                      </Button>
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
          resetProjectFormState();
        }}
        title={editingProjectId ? "Edit Project" : "New Project"}
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
                setCredentialProfiles([{}]);
              }}
            />
          </div>

          {typesLoading && <p className="text-sm text-text-muted">Loading target types...</p>}
          {typesError && <p className="text-sm text-yellow-400">{typesError}</p>}

          <div className="rounded-lg border border-border bg-surface-0/35 p-3">
            <div className="mb-3 flex items-center justify-between">
              <p className="text-sm font-semibold tracking-wide text-text-secondary">Target Information</p>
              <p className="text-sm text-text-muted">
                {targetFields.length} field{targetFields.length === 1 ? '' : 's'}
              </p>
            </div>
            {fieldsLoading ? (
              <p className="text-sm text-text-muted">Loading target info fields from schema...</p>
            ) : (
              <div className="space-y-3">
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  {nonCredentialFields.map((field) => {
                    const isWideField = (
                      field.data_type === 'array'
                      || field.key.includes('headers')
                      || field.key.includes('params')
                      || field.key.includes('body')
                      || field.key.includes('description')
                      || field.key.startsWith('endpoints.')
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

                {credentialFields.length > 0 && (
                  <div className="rounded-md border border-border bg-surface-1/35 p-2">
                    <div className="mb-2 flex items-center justify-between">
                      <p className="text-sm font-semibold tracking-wide text-text-secondary">
                        Credential Profiles
                      </p>
                      <Button
                        variant="secondary"
                        size="xs"
                        onClick={() => {
                          setCredentialProfiles((previous) => [...previous, {}]);
                        }}
                        title="Add credential profile"
                      >
                        <Plus size={12} />
                      </Button>
                    </div>
                    <div className="space-y-2">
                      {credentialProfiles.map((profile, profileIndex) => (
                        <div key={`credential-profile-${profileIndex}`} className="rounded-md border border-border bg-surface-0/35 p-2">
                          <div className="mb-2 flex items-center justify-between">
                            <p className="text-sm font-semibold text-text-primary">
                              Profile {profileIndex + 1}
                            </p>
                            <Button
                              variant="ghost"
                              size="xs"
                              onClick={() => {
                                setCredentialProfiles((previous) => (
                                  previous.filter((_, idx) => idx !== profileIndex).length > 0
                                    ? previous.filter((_, idx) => idx !== profileIndex)
                                    : [{}]
                                ));
                              }}
                              title="Remove profile"
                            >
                              <Trash2 size={12} />
                            </Button>
                          </div>
                          <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                            {credentialFields.map((field) => {
                              const suffix = field.key.slice('credentials.'.length);
                              const labelBase = field.label.startsWith('Credentials ')
                                ? field.label.slice('Credentials '.length)
                                : field.label;
                              if (field.data_type === 'enum') {
                                return (
                                  <Select
                                    key={`credential-${profileIndex}-${suffix}`}
                                    label={`${labelBase}${field.required ? ' *' : ''}`}
                                    options={(field.options.length > 0 ? field.options : ['']).map((value) => ({
                                      value,
                                      label: value || 'Unknown',
                                    }))}
                                    value={profile[suffix] ?? ''}
                                    onChange={(event) => {
                                      setCredentialProfiles((previous) => previous.map((entry, idx) => (
                                        idx === profileIndex
                                          ? { ...entry, [suffix]: event.target.value }
                                          : entry
                                      )));
                                    }}
                                  />
                                );
                              }

                              if (field.data_type === 'boolean') {
                                return (
                                  <Select
                                    key={`credential-${profileIndex}-${suffix}`}
                                    label={`${labelBase}${field.required ? ' *' : ''}`}
                                    options={[
                                      { value: 'true', label: 'True' },
                                      { value: 'false', label: 'False' },
                                    ]}
                                    value={profile[suffix] ?? 'false'}
                                    onChange={(event) => {
                                      setCredentialProfiles((previous) => previous.map((entry, idx) => (
                                        idx === profileIndex
                                          ? { ...entry, [suffix]: event.target.value }
                                          : entry
                                      )));
                                    }}
                                  />
                                );
                              }

                              return (
                                <Input
                                  key={`credential-${profileIndex}-${suffix}`}
                                  label={`${labelBase}${field.required ? ' *' : ''}`}
                                  placeholder={suffix}
                                  type={suffix.toLowerCase().includes('password') ? 'password' : 'text'}
                                  value={profile[suffix] ?? ''}
                                  onChange={(event) => {
                                    setCredentialProfiles((previous) => previous.map((entry, idx) => (
                                      idx === profileIndex
                                        ? { ...entry, [suffix]: event.target.value }
                                        : entry
                                    )));
                                  }}
                                />
                              );
                            })}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
            {fieldsError && <p className="mt-2 text-sm text-yellow-400">{fieldsError}</p>}
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
                resetProjectFormState();
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
                handleCreateOrUpdate();
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
              {editingProjectId ? 'Save' : 'Create'}
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
        <div className="space-y-3 text-sm text-text-secondary">
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
