import { type ChangeEvent, type DragEvent, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Dialog } from '../components/ui/Dialog';
import { Input } from '../components/ui/Input';
import { Textarea } from '../components/ui/Textarea';
import { Select } from '../components/ui/Select';
import { useProjects } from '../stores/projects';
import { clsx } from 'clsx';
import { 
  Plus, Trash2, Play, Square, FolderOpen, Share2, RefreshCcw, Pencil,
  Globe, Database, Shield, Network, Cpu, Smartphone, Cloud, Box, Code, Monitor, Server,
  AlertCircle, CheckCircle2, Upload
} from 'lucide-react';
import { format } from 'date-fns';
import type { Project } from '../types';
import {
  listProjectTargetFieldsFromDesktop,
  listProjectTargetTypesFromDesktop,
  saveProjectToDesktop,
  uploadMobileArtifactToDesktop,
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
  { value: 'cloud', label: 'Cloud' },
  { value: 'container', label: 'Container' },
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
  'file_path',
  'url',
  'base_url',
  'host',
  'target_ip',
  'gateway',
  'cidr',
  'package_name',
  'repo_url',
  'targets.ip_address',
];

const MOBILE_ARTIFACT_ACCEPT = '.apk,.aab,.ipa';

function basenameFromPath(value: string): string {
  const normalized = value.replace(/\\/g, '/');
  const parts = normalized.split('/');
  return parts[parts.length - 1] ?? value;
}

function inferMobileArtifactMetadata(filename: string): {
  inputType?: string;
  platform?: string;
} {
  const lower = filename.toLowerCase();
  if (lower.endsWith('.ipa')) {
    return { inputType: 'ipa', platform: 'ios' };
  }
  if (lower.endsWith('.apk') || lower.endsWith('.aab')) {
    return { inputType: 'apk', platform: 'android' };
  }
  return {};
}

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

function getFieldDefaultValue(field: ProjectTargetField): string {
  if (field.data_type === 'boolean') {
    return 'false';
  }
  if (field.data_type === 'enum' && field.options.length > 0) {
    return field.options[0] ?? '';
  }
  return '';
}

function formatProjectSaveError(error: unknown): string {
  const fallback = 'Failed to save project. Please check the target fields and try again.';
  const message = error instanceof Error ? error.message : String(error ?? '');
  const jsonStart = message.indexOf('{');
  if (jsonStart >= 0) {
    try {
      const parsed = JSON.parse(message.slice(jsonStart)) as {
        detail?: string;
        errors?: Array<{ field?: string; reason?: string; value?: string }>;
      };
      if (Array.isArray(parsed.errors) && parsed.errors.length > 0) {
        const formatted = parsed.errors
          .map((entry) => {
            const field = String(entry.field || 'target');
            const reason = String(entry.reason || 'invalid value');
            return `${field}: ${reason}`;
          })
          .join(' | ');
        return parsed.detail ? `${parsed.detail}: ${formatted}` : formatted;
      }
      if (typeof parsed.detail === 'string' && parsed.detail.trim()) {
        return parsed.detail.trim();
      }
    } catch {
      return message || fallback;
    }
  }
  return message || fallback;
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
    startingProjectMessage,
    stoppingProjectId,
    stoppingProjectMessage,
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
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [projectToDelete, setProjectToDelete] = useState<Project | null>(null);
  const [deleteError, setDeleteError] = useState('');
  const [customChecklistText, setCustomChecklistText] = useState('');
  const [customChecklistName, setCustomChecklistName] = useState('');
  const [customChecklistError, setCustomChecklistError] = useState('');
  const [submitError, setSubmitError] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [creatingProject, setCreatingProject] = useState(false);
  const [editingProjectId, setEditingProjectId] = useState<string | null>(null);
  const [pendingEditProject, setPendingEditProject] = useState<Project | null>(null);
  const [stopDialogOpen, setStopDialogOpen] = useState(false);
  const [stopProjectId, setStopProjectId] = useState<string | null>(null);
  const [deletingProjectId, setDeletingProjectId] = useState<string | null>(null);
  const [draftProjectId, setDraftProjectId] = useState<string>(() => crypto.randomUUID());
  const [mobileArtifactUploading, setMobileArtifactUploading] = useState(false);
  const [mobileArtifactError, setMobileArtifactError] = useState('');
  const [mobileArtifactDragActive, setMobileArtifactDragActive] = useState(false);
  const mobileArtifactInputRef = useRef<HTMLInputElement | null>(null);

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
        const nextTypes = (remote.length > 0 ? remote : FALLBACK_TARGET_TYPES).map((type) => ({
          ...type,
          disabled: false,
        }));

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
            if (typeof value === 'string' && value.length > 0) {
              next[field.key] = value;
              continue;
            }
            const fallback = getFieldDefaultValue(field);
            if (fallback) {
              next[field.key] = fallback;
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
    setCredentialProfiles((previous) => {
      const baseProfiles = previous.length > 0 ? previous : [{}];
      return baseProfiles.map((profile) => {
        const next = { ...profile };
        for (const field of credentialFields) {
          const suffix = field.key.slice('credentials.'.length);
          if ((next[suffix] ?? '').trim().length > 0) {
            continue;
          }
          const fallback = getFieldDefaultValue(field);
          if (fallback) {
            next[suffix] = fallback;
          }
        }
        return next;
      });
    });
  }, [dialogOpen, credentialFields]);

  useEffect(() => {
    if (!dialogOpen || !pendingEditProject) {
      return;
    }
    const config = isRecord(pendingEditProject.targetConfig) ? pendingEditProject.targetConfig : {};
    const nextTargetInfo: Record<string, string> = {};

    for (const field of nonCredentialFields) {
      const value = getNestedValue(config, field.key);
      if (typeof value === 'string' && value.length > 0) {
        nextTargetInfo[field.key] = value;
        continue;
      }
      const fallback = getFieldDefaultValue(field);
      if (fallback) {
        nextTargetInfo[field.key] = fallback;
      }
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
          if (typeof value === 'string' && value.length > 0) {
            next[suffix] = value;
            continue;
          }
          const fallback = getFieldDefaultValue(field);
          if (fallback) {
            next[suffix] = fallback;
          }
        }
        return next;
      });

    if (nextProfiles.length === 0 && credentialFields.length > 0) {
      const fallbackProfile: Record<string, string> = {};
      for (const field of credentialFields) {
        const suffix = field.key.slice('credentials.'.length);
        const value = getNestedValue(config, field.key);
        if (typeof value === 'string' && value.length > 0) {
          fallbackProfile[suffix] = value;
          continue;
        }
        const fallback = getFieldDefaultValue(field);
        if (fallback) {
          fallbackProfile[suffix] = fallback;
        }
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
    setDraftProjectId(crypto.randomUUID());
    setForm({
      name: '',
      targetType: targetTypes[0]?.value ?? '',
      description: '',
    });
    setTargetInfo({});
    setCredentialProfiles([{}]);
    setCustomChecklistText('');
    setCustomChecklistName('');
    setCustomChecklistError('');
    setSubmitError('');
    setCreatingProject(false);
    setMobileArtifactUploading(false);
    setMobileArtifactError('');
    setMobileArtifactDragActive(false);
  }

  function handleOpenCreateDialog() {
    resetProjectFormState();
    setDialogOpen(true);
  }

  function handleOpenEditDialog(project: Project) {
    setEditingProjectId(project.id);
    setDraftProjectId(project.id);
    setForm({
      name: project.name,
      targetType: project.targetType,
      description: project.description ?? '',
    });
    setTargetInfo({});
    setCredentialProfiles([{}]);
    setCustomChecklistText(project.customChecklistText ?? '');
    setCustomChecklistName(project.customChecklistName ?? '');
    setCustomChecklistError('');
    setMobileArtifactUploading(false);
    setMobileArtifactError('');
    setMobileArtifactDragActive(false);
    setPendingEditProject(project);
    setDialogOpen(true);
  }

  async function handleMobileArtifactSelected(file: File | null) {
    if (!file || form.targetType !== 'mobile') {
      return;
    }

    const lower = file.name.toLowerCase();
    if (!lower.endsWith('.apk') && !lower.endsWith('.aab') && !lower.endsWith('.ipa')) {
      setMobileArtifactError('Only .apk, .aab, or .ipa files are supported for mobile targets.');
      return;
    }

    const projectId = editingProjectId ?? draftProjectId ?? crypto.randomUUID();
    if (!editingProjectId && !draftProjectId) {
      setDraftProjectId(projectId);
    }

    setMobileArtifactUploading(true);
    setMobileArtifactError('');
    try {
      const uploaded = await uploadMobileArtifactToDesktop(projectId, file);
      const inferred = inferMobileArtifactMetadata(file.name);
      setTargetInfo((previous) => ({
        ...previous,
        file_path: uploaded.path,
        ...(inferred.inputType ? { input_type: inferred.inputType } : {}),
        ...(inferred.platform ? { platform: inferred.platform } : {}),
      }));
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to upload mobile artifact.';
      setMobileArtifactError(message);
    } finally {
      setMobileArtifactUploading(false);
      setMobileArtifactDragActive(false);
    }
  }

  function handleMobileArtifactInputChange(event: ChangeEvent<HTMLInputElement>) {
    const nextFile = event.target.files?.[0] ?? null;
    void handleMobileArtifactSelected(nextFile);
    event.currentTarget.value = '';
  }

  function handleMobileArtifactDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setMobileArtifactDragActive(false);
    const nextFile = event.dataTransfer.files?.[0] ?? null;
    void handleMobileArtifactSelected(nextFile);
  }

  async function handleChecklistFileSelected(file: File | null) {
    if (!file) {
      return;
    }
    if (!file.name.toLowerCase().endsWith('.txt')) {
      setCustomChecklistError('Only .txt checklist files are supported.');
      return;
    }
    try {
      const text = await file.text();
      if (!text.trim()) {
        setCustomChecklistError('Checklist file is empty.');
        return;
      }
      setCustomChecklistText(text);
      setCustomChecklistName(file.name);
      setCustomChecklistError('');
    } catch {
      setCustomChecklistError('Failed to read checklist file.');
    }
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

  async function handleCreateOrUpdate() {
    if (creatingProject) {
      return;
    }
    setCreatingProject(true);
    setSubmitError('');

    const { primaryTarget, payload } = buildTargetConfigPayload();
    const projectId = editingProjectId ?? draftProjectId ?? crypto.randomUUID();

    const projectPayload: Project = {
      id: projectId,
      name: form.name,
      target: primaryTarget,
      targetType: form.targetType,
      targetConfig: payload,
      customChecklistText: customChecklistText.trim() || undefined,
      customChecklistName: customChecklistText.trim()
        ? (customChecklistName || 'custom-checklist.txt')
        : undefined,
      status: 'idle',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      description: form.description,
      findings: [],
      agents: [
        { name: 'planner', state: 'idle' },
        { name: 'executer', state: 'idle' },
        { name: 'analyzer', state: 'idle' },
      ],
      phases: [
        { name: 'Reconnaissance', status: 'pending', progress: 0 },
        { name: 'Enumeration', status: 'pending', progress: 0 },
        { name: 'Exploitation', status: 'pending', progress: 0 },
        { name: 'Post-Exploitation', status: 'pending', progress: 0 },
        { name: 'Reporting', status: 'pending', progress: 0 },
      ],
      scanProgress: 0,
      approval_mode: 'custom',
    };

    if (editingProjectId) {
      const existingProject = projects.find((project) => project.id === editingProjectId);
      if (!existingProject) {
        setSubmitError('Project no longer exists. Please reload and try again.');
        setCreatingProject(false);
        return;
      }

      const updatedProject: Project = {
        ...existingProject,
        name: form.name,
        targetType: form.targetType,
        target: primaryTarget,
        targetConfig: payload,
        customChecklistText: customChecklistText.trim() || undefined,
        customChecklistName: customChecklistText.trim()
          ? (customChecklistName || 'custom-checklist.txt')
          : undefined,
        description: form.description,
        updatedAt: new Date().toISOString(),
      };

      try {
        await saveProjectToDesktop(updatedProject);
        updateProject(editingProjectId, updatedProject, { persist: false });
        setDialogOpen(false);
        resetProjectFormState();
      } catch (error) {
        setSubmitError(formatProjectSaveError(error));
      } finally {
        setCreatingProject(false);
      }
      return;
    }

    try {
      await saveProjectToDesktop(projectPayload);
      addProject(projectPayload, { persist: false });
      setDialogOpen(false);
      resetProjectFormState();
      navigate('/dashboard');
    } catch (error) {
      setSubmitError(formatProjectSaveError(error));
    } finally {
      setCreatingProject(false);
    }
  }

  function openProject(id: string) {
    setActive(id);
    navigate('/dashboard');
  }

  function openClientShare(projectId: string) {
    setActive(projectId);
    navigate('/reports');
  }

  return (
    <div className="h-full overflow-auto p-4">
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
                      <span className="text-sm text-text-muted">
                        {startingProjectMessage || 'starting...'}
                      </span>
                    )}
                    {stoppingProjectId === project.id && (
                      <span className="text-sm text-text-muted">
                        {stoppingProjectMessage || 'stopping...'}
                      </span>
                    )}
                    <span className="text-sm text-text-muted w-16 text-right">
                      {formatShortDate(project.updatedAt)}
                    </span>
                    <div className="flex items-center gap-1 ml-2" onClick={(e) => e.stopPropagation()}>
                      {(() => {
                        const isStartingThisProject = startingProjectId === project.id;
                        const isStoppingThisProject = stoppingProjectId === project.id;
                        const anotherProjectBusy = (
                          (!!runningProjectId && runningProjectId !== project.id)
                          || (!!startingProjectId && startingProjectId !== project.id)
                          || (!!stoppingProjectId && stoppingProjectId !== project.id)
                        );
                        const canStartProject = !anotherProjectBusy && !isStartingThisProject && !isStoppingThisProject;

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
                                  if (project.status === 'stopped') {
                                    const confirmed = window.confirm('This scan was stopped. Restart will begin a fresh analysis. Continue?');
                                    if (!confirmed) {
                                      return;
                                    }
                                    setRunning(project.id, { triggerScan: true });
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
                                loading={stoppingProjectId === project.id}
                                disabled={stoppingProjectId === project.id}
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
                        title="Open reports and share delivery"
                      >
                        <Share2 size={12} />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={(e) => {
                          e.preventDefault();
                          e.stopPropagation();
                          setProjectToDelete(project);
                          setDeleteDialogOpen(true);
                        }}
                        title="Delete"
                      >
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
          <div className="grid grid-cols-1 gap-4">
            <Input
              label="Project Name *"
              placeholder="ACME Corp — Web Assessment 2026"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <label className="text-[10px] font-bold text-text-muted uppercase tracking-widest">Select Target Vector</label>
            </div>
            <div className="grid grid-cols-3 md:grid-cols-5 gap-2">
              {targetTypes.map((type) => {
                const Icon = {
                  'web_app': Globe,
                  'api': Database,
                  'mobile': Smartphone,
                  'infra': Shield,
                  'network': Network,
                  'iot': Cpu,
                  'linux_server': Server,
                  'cloud': Cloud,
                  'container': Box,
                  'repository': Code,
                }[type.value] || Globe;

                const isActive = form.targetType === type.value;

                return (
                  <motion.button
                    key={type.value}
                    type="button"
                    whileHover={{ scale: 1.02, translateY: -1 }}
                    whileTap={{ scale: 0.98 }}
                    onClick={() => {
                      setForm({ ...form, targetType: type.value });
                      setTargetInfo({});
                      setCredentialProfiles([{}]);
                      setMobileArtifactError('');
                      setMobileArtifactDragActive(false);
                    }}
                    className={clsx(
                      "group relative flex flex-col items-center justify-center p-2 rounded-xl border transition-all text-center gap-1.5 overflow-hidden",
                      isActive
                        ? "bg-pf-500/10 border-pf-500/60 shadow-[0_0_15px_-5px_rgba(var(--pf-500-rgb),0.3)]"
                        : "bg-surface-2/50 border-border/60 text-text-muted hover:border-pf-500/30 hover:bg-surface-2 hover:text-text-primary"
                    )}
                  >
                    {/* Background Glow for Active State */}
                    {isActive && (
                      <motion.div 
                        layoutId="active-glow"
                        className="absolute inset-0 bg-gradient-to-br from-pf-500/5 to-transparent pointer-events-none"
                      />
                    )}

                    <div className={clsx(
                      "p-1.5 rounded-lg transition-colors",
                      isActive ? "bg-pf-500/20 text-pf-400" : "bg-surface-3/50 text-text-muted group-hover:text-pf-500/70"
                    )}>
                      <Icon size={16} />
                    </div>

                    <div className="flex flex-col">
                      <span className={clsx(
                        "text-[9px] font-black uppercase tracking-tight transition-colors",
                        isActive ? "text-pf-400" : "text-text-muted group-hover:text-text-primary"
                      )}>
                        {type.label}
                      </span>
                    </div>
                  </motion.button>
                );
              })}
            </div>
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

                    if (form.targetType === 'mobile' && field.key === 'file_path') {
                      const artifactPath = targetInfo[field.key] ?? '';
                      const artifactName = artifactPath ? basenameFromPath(artifactPath) : '';
                      return (
                        <div key={field.key} className="md:col-span-2">
                          <div className="space-y-2">
                            <label className="text-[10px] font-bold text-text-muted uppercase tracking-widest">
                              {field.label}{field.required ? ' *' : ''}
                            </label>
                            <div
                              onDragOver={(event) => {
                                event.preventDefault();
                                if (!mobileArtifactUploading) {
                                  setMobileArtifactDragActive(true);
                                }
                              }}
                              onDragLeave={(event) => {
                                event.preventDefault();
                                setMobileArtifactDragActive(false);
                              }}
                              onDrop={handleMobileArtifactDrop}
                              className={clsx(
                                'rounded-2xl border border-dashed p-4 transition-all',
                                mobileArtifactDragActive
                                  ? 'border-pf-500 bg-pf-500/8 shadow-[0_0_0_1px_rgba(var(--pf-500-rgb),0.2)]'
                                  : 'border-border bg-surface-1/40 hover:border-pf-500/30 hover:bg-surface-1/70',
                                mobileArtifactUploading && 'opacity-70',
                              )}
                            >
                              <input
                                ref={mobileArtifactInputRef}
                                type="file"
                                accept={MOBILE_ARTIFACT_ACCEPT}
                                className="hidden"
                                onChange={handleMobileArtifactInputChange}
                              />
                              <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                                <div className="flex items-start gap-3">
                                  <div className="mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl bg-pf-500/12 text-pf-400">
                                    <Upload size={18} />
                                  </div>
                                  <div className="space-y-1.5">
                                    <p className="text-sm font-semibold text-text-primary">
                                      Drop an APK, AAB, or IPA here
                                    </p>
                                    <p className="text-sm text-text-muted">
                                    The file is uploaded into the project sandbox and used directly during mobile scans.
                                    </p>
                                    {artifactName ? (
                                      <div className="inline-flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-sm text-emerald-300">
                                        <CheckCircle2 size={14} />
                                        <span>Uploaded:</span>
                                        <span className="font-mono text-emerald-200">{artifactName}</span>
                                      </div>
                                    ) : (
                                      <p className="text-sm text-text-muted">
                                        No mobile artifact uploaded yet.
                                      </p>
                                    )}
                                  </div>
                                </div>
                                <Button
                                  type="button"
                                  variant="outline"
                                  size="md"
                                  className="min-w-[140px] self-start whitespace-nowrap rounded-xl border-pf-500/30 bg-pf-500/8 px-4 font-semibold text-pf-300 hover:bg-pf-500/14 md:self-center"
                                  disabled={mobileArtifactUploading}
                                  onClick={() => mobileArtifactInputRef.current?.click()}
                                >
                                  <Upload size={15} />
                                  {mobileArtifactUploading ? 'Uploading...' : 'Browse Artifact'}
                                </Button>
                              </div>
                            </div>
                            {artifactPath ? (
                              <p className="text-sm text-text-muted break-all">
                                Sandbox path: <span className="font-mono">{artifactPath}</span>
                              </p>
                            ) : null}
                          </div>
                        </div>
                      );
                    }

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
            {mobileArtifactError ? (
              <p className="mt-2 text-sm text-red-400">{mobileArtifactError}</p>
            ) : null}
          </div>

          <Textarea
            label="Description (optional)"
            placeholder="Black-box web application assessment"
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
            rows={4}
          />

          <div className="rounded-lg border border-border bg-surface-0/35 p-3">
            <div className="mb-2 flex items-center justify-between gap-3">
              <div>
                <p className="text-sm font-semibold tracking-wide text-text-secondary">
                  Custom Checklist Upload
                </p>
                <p className="text-sm text-text-muted">
                  Optional `.txt` checklist. If present, Intel skips checklist generation and formats this file into the project checklist JSON.
                </p>
              </div>
              {customChecklistText.trim() ? (
                <Button
                  variant="ghost"
                  size="xs"
                  onClick={() => {
                    setCustomChecklistText('');
                    setCustomChecklistName('');
                    setCustomChecklistError('');
                  }}
                  title="Remove uploaded checklist"
                >
                  <Trash2 size={12} />
                </Button>
              ) : null}
            </div>
            <div className="space-y-2">
              <input
                type="file"
                accept=".txt,text/plain"
                className="block w-full rounded-md border border-border bg-surface-1 px-3 py-2 text-sm text-text-primary file:mr-3 file:rounded-md file:border-0 file:bg-pf-600/15 file:px-3 file:py-1.5 file:text-sm file:font-medium file:text-pf-300"
                onChange={(event) => {
                  const nextFile = event.target.files?.[0] ?? null;
                  void handleChecklistFileSelected(nextFile);
                  event.currentTarget.value = '';
                }}
              />
              {customChecklistName ? (
                <p className="text-sm text-text-secondary">
                  Loaded: {customChecklistName} ({customChecklistText.split(/\r?\n/).filter((line) => line.trim().length > 0).length} lines)
                </p>
              ) : (
                <p className="text-sm text-text-muted">
                  No custom checklist uploaded. Default Intel checklist generation will be used.
                </p>
              )}
              {customChecklistError ? (
                <p className="text-sm text-yellow-400">{customChecklistError}</p>
              ) : null}
            </div>
          </div>
          {submitError ? (
            <p className="text-sm text-red-400">{submitError}</p>
          ) : null}
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
                || mobileArtifactUploading
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
        description="Choose whether to stop or cancel the current scan."
      >
        <div className="space-y-3 text-sm text-text-secondary">
          <p>
            Stop will keep current logs and results so you can review them. Cancel will clear logs,
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
                void stopScan(stopProjectId, 'stop');
              }}
              loading={stoppingProjectId === stopProjectId}
              disabled={stoppingProjectId === stopProjectId}
            >
              Stop Scan
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
              loading={stoppingProjectId === stopProjectId}
              disabled={stoppingProjectId === stopProjectId}
            >
              Cancel Scan
            </Button>
          </div>
        </div>
      </Dialog>
      <Dialog
        open={deleteDialogOpen}
        onClose={() => {
          if (deletingProjectId) {
            return;
          }
          setDeleteDialogOpen(false);
          setDeleteError('');
        }}
        title="Delete Project"
        description={`Are you sure you want to delete project "${projectToDelete?.name}"? This will permanently remove all findings and scan history.`}
      >
        <div className="space-y-3 pt-2">
          {deleteError ? (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">
              {deleteError}
            </div>
          ) : null}
          <div className="flex justify-end gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              setDeleteDialogOpen(false);
              setDeleteError('');
            }}
            disabled={Boolean(deletingProjectId)}
          >
            Cancel
          </Button>
          <Button
            variant="danger"
            size="sm"
            loading={deletingProjectId === projectToDelete?.id}
            onClick={async () => {
              if (projectToDelete) {
                setDeleteError('');
                setDeletingProjectId(projectToDelete.id);
                try {
                  await removeProject(projectToDelete.id);
                  setDeleteDialogOpen(false);
                  setProjectToDelete(null);
                  setDeleteError('');
                } catch (error) {
                  setDeleteError(
                    error instanceof Error
                      ? error.message
                      : 'Failed to delete project. Please try again.',
                  );
                } finally {
                  setDeletingProjectId(null);
                }
              }
            }}
          >
            Delete
          </Button>
          </div>
        </div>
      </Dialog>
      </div>
    </div>
  );
}
