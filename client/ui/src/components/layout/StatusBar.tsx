import { useProjects } from '../../stores/projects';
import { useConfig } from '../../stores/config';
import { Badge } from '../ui/Badge';
import { Cpu, Database, Wifi } from 'lucide-react';

export function StatusBar() {
  const running = useProjects((s) => s.getRunning());
  const { activeLLM, llmConfigs, serverUrl, serverPort } = useConfig();
  const llm = llmConfigs.find((c) => c.id === activeLLM);

  return (
    <div className="h-6 bg-surface-1 border-t border-border flex items-center justify-between px-3 text-[10px] text-text-muted">
      <div className="flex items-center gap-3">
        <span className="flex items-center gap-1">
          <Wifi size={10} />
          {serverUrl}:{serverPort}
        </span>
        <span className="flex items-center gap-1">
          <Cpu size={10} />
          {llm?.name ?? 'No LLM'}
        </span>
        <span className="flex items-center gap-1">
          <Database size={10} />
          {llm?.mode === 'local' ? 'Local' : 'Cloud'}
        </span>
      </div>
      <div className="flex items-center gap-2">
        {running ? (
          <Badge variant="running" dot>{running.name}</Badge>
        ) : (
          <span>Ready</span>
        )}
      </div>
    </div>
  );
}