import { useProjects } from '../../stores/projects';
import { useConfig } from '../../stores/config';
import { Badge } from '../ui/Badge';
import { Cpu, Database, Wifi } from 'lucide-react';

export function StatusBar() {
  const running = useProjects((s) => s.getRunning());
  const { activeLLM, llmConfigs, serverUrl, serverPort } = useConfig();
  const safeLlmConfigs = Array.isArray(llmConfigs) ? llmConfigs : [];
  const llm = safeLlmConfigs.find((c) => c.id === activeLLM);
  const safeServerUrl = typeof serverUrl === 'string' ? serverUrl : 'http://localhost';
  const safeServerPort = typeof serverPort === 'number' ? serverPort : 8000;

  return (
    <div className="h-6 bg-surface-1 border-t border-border flex items-center justify-between px-3 text-sm text-text-muted">
      <div className="flex items-center gap-3">
        <span className="flex items-center gap-1">
          <Wifi size={10} />
          {safeServerUrl}:{safeServerPort}
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
