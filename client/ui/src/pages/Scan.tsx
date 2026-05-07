import { useProjects } from '../stores/projects';
import { Card, CardHeader, CardTitle } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Play, Square, RotateCcw } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { Dialog } from '../components/ui/Dialog';
import { useState } from 'react';

export default function Scan() {
  const project = useProjects((s) => s.getActive());
  const { setRunning, runningProjectId, startingProjectId, stopScan } = useProjects();
  const navigate = useNavigate();
  const [stopDialogOpen, setStopDialogOpen] = useState(false);

  if (!project) {
    return (
      <div className="flex items-center justify-center h-full">
        <Button onClick={() => navigate('/projects')}>Select a Project</Button>
      </div>
    );
  }

  const isRunning = runningProjectId === project.id;
  const isStarting = startingProjectId === project.id;
  const canRun = (!runningProjectId && !startingProjectId) || runningProjectId === project.id;

  return (
    <div className="max-w-3xl mx-auto space-y-4">
      <h1 className="text-lg font-bold text-text-primary">Scan Control</h1>

      <Card>
        <CardHeader>
          <CardTitle>{project.name}</CardTitle>
          <Badge variant={project.status} dot>{project.status}</Badge>
        </CardHeader>

        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3 text-sm">
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
              <Button
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
                    const confirmed = window.confirm('Resume will start a new scan and keep previous history visible. Continue?');
                    if (!confirmed) {
                      return;
                    }
                    setRunning(project.id, { triggerScan: true, resume: true });
                    return;
                  }
                  setRunning(project.id, { triggerScan: true });
                }}
                disabled={!canRun || isStarting}
                loading={isStarting}
              >
                <Play size={14} /> Start Scan
              </Button>
            ) : (
              <>
                <Button variant="danger" onClick={() => setStopDialogOpen(true)}>
                  <Square size={14} /> Stop Scan
                </Button>
                <Button variant="secondary">
                  <RotateCcw size={14} /> Restart
                </Button>
              </>
            )}
          </div>

          {!canRun && (
            <p className="text-sm text-yellow-400">
              Another project is currently running. Stop it first.
            </p>
          )}
          {isStarting && (
            <p className="text-sm text-text-muted">
              Starting scan...
            </p>
          )}
        </div>
      </Card>

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
                setStopDialogOpen(false);
                void stopScan(project.id, 'pause');
              }}
            >
              Pause Scan
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={() => {
                setStopDialogOpen(false);
                void stopScan(project.id, 'cancel');
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
