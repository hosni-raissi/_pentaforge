import { useProjects } from '../stores/projects';
import { Card, CardHeader, CardTitle } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Play, Square, RotateCcw } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export default function Scan() {
  const project = useProjects((s) => s.getActive());
  const { setRunning, runningProjectId } = useProjects();
  const navigate = useNavigate();

  if (!project) {
    return (
      <div className="flex items-center justify-center h-full">
        <Button onClick={() => navigate('/projects')}>Select a Project</Button>
      </div>
    );
  }

  const isRunning = runningProjectId === project.id;
  const canRun = !runningProjectId || runningProjectId === project.id;

  return (
    <div className="max-w-3xl mx-auto space-y-4">
      <h1 className="text-lg font-bold text-text-primary">Scan Control</h1>

      <Card>
        <CardHeader>
          <CardTitle>{project.name}</CardTitle>
          <Badge variant={project.status} dot>{project.status}</Badge>
        </CardHeader>

        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="p-2.5 rounded bg-surface-2">
              <span className="text-text-muted">Target</span>
              <p className="font-mono text-text-primary mt-0.5">{project.target}</p>
            </div>
            <div className="p-2.5 rounded bg-surface-2">
              <span className="text-text-muted">Type</span>
              <p className="text-text-primary mt-0.5 capitalize">{project.targetType.replace('_', ' ')}</p>
            </div>
          </div>

          {/* Controls */}
          <div className="flex items-center gap-2 pt-2">
            {!isRunning ? (
              <Button onClick={() => setRunning(project.id)} disabled={!canRun}>
                <Play size={14} /> Start Scan
              </Button>
            ) : (
              <>
                <Button variant="danger" onClick={() => setRunning(null)}>
                  <Square size={14} /> Stop Scan
                </Button>
                <Button variant="secondary">
                  <RotateCcw size={14} /> Restart
                </Button>
              </>
            )}
          </div>

          {!canRun && (
            <p className="text-[11px] text-yellow-400">
              Another project is currently running. Stop it first.
            </p>
          )}
        </div>
      </Card>
    </div>
  );
}