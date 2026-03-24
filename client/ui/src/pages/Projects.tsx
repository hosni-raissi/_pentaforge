import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, Trash2, Play, Square, FolderOpen } from 'lucide-react';
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

const targetTypes = [
  { value: 'web', label: 'Web Application' },
  { value: 'api', label: 'REST / GraphQL API' },
  { value: 'network', label: 'Network Infrastructure' },
  { value: 'linux_server', label: 'Linux Server' },
  { value: 'cloud', label: 'Cloud (AWS/Azure/GCP)' },
  { value: 'container', label: 'Container / Kubernetes' },
  { value: 'database', label: 'Database' },
  { value: 'iot', label: 'IoT Device' },
  { value: 'mobile', label: 'Mobile App' },
  { value: 'desktop', label: 'Desktop App' },
  { value: 'active_directory', label: 'Active Directory' },
  { value: 'repository', label: 'Source Code Repository' },
];

export default function Projects() {
  const navigate = useNavigate();
  const { projects, addProject, removeProject, setActive, setRunning, runningProjectId } = useProjects();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [form, setForm] = useState({ name: '', target: '', targetType: 'web', description: '' });

  function handleCreate() {
    const project: Project = {
      id: crypto.randomUUID(),
      name: form.name,
      target: form.target,
      targetType: form.targetType,
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
    setForm({ name: '', target: '', targetType: 'web', description: '' });
    navigate('/dashboard');
  }

  function openProject(id: string) {
    setActive(id);
    navigate('/dashboard');
  }

  return (
    <div className="max-w-4xl mx-auto space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-text-primary">Projects</h1>
          <p className="text-xs text-text-muted">{projects.length} engagement{projects.length !== 1 ? 's' : ''}</p>
        </div>
        <Button onClick={() => setDialogOpen(true)} size="sm">
          <Plus size={14} /> New Project
        </Button>
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
        ) : (
          <div className="space-y-2">
            {projects.map((project) => (
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
                    <span className="text-[10px] text-text-muted w-16 text-right">
                      {format(new Date(project.updatedAt), 'MMM d')}
                    </span>
                    <div className="flex items-center gap-1 ml-2" onClick={(e) => e.stopPropagation()}>
                      {project.status !== 'running' && (
                        <Button
                          variant="ghost" size="sm"
                          onClick={() => setRunning(project.id)}
                          disabled={!!runningProjectId && runningProjectId !== project.id}
                          title="Start scan"
                        >
                          <Play size={12} />
                        </Button>
                      )}
                      {project.status === 'running' && (
                        <Button variant="ghost" size="sm" onClick={() => setRunning(null)} title="Stop scan">
                          <Square size={12} />
                        </Button>
                      )}
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
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} title="New Project">
        <div className="space-y-3">
          <Input
            label="Project Name"
            placeholder="ACME Corp — Web Assessment 2026"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
          />
          <Input
            label="Target"
            placeholder="https://target.example.com"
            value={form.target}
            onChange={(e) => setForm({ ...form, target: e.target.value })}
          />
          <Select
            label="Target Type"
            options={targetTypes}
            value={form.targetType}
            onChange={(e) => setForm({ ...form, targetType: e.target.value })}
          />
          <Input
            label="Description (optional)"
            placeholder="Black-box web application assessment"
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
          />
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" size="sm" onClick={() => setDialogOpen(false)}>Cancel</Button>
            <Button size="sm" onClick={handleCreate} disabled={!form.name || !form.target}>Create</Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}