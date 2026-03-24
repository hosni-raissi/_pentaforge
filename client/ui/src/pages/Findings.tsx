// src/pages/Findings.tsx
import { useProjects } from '../stores/projects';
import { FindingsTable } from '../components/dashboard/FindingsTable';
import { useNavigate } from 'react-router-dom';
import { Button } from '../components/ui/Button';

export default function Findings() {
  const project = useProjects((s) => s.getActive());
  const navigate = useNavigate();

  if (!project) {
    return (
      <div className="flex items-center justify-center h-full">
        <Button onClick={() => navigate('/projects')}>Select a Project</Button>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto space-y-4">
      <h1 className="text-lg font-bold text-text-primary">Findings — {project.name}</h1>
      <FindingsTable findings={project.findings} limit={100} />
    </div>
  );
}