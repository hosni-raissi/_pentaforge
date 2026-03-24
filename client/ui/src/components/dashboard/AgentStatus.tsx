import { motion } from 'framer-motion';
import { Card, CardHeader, CardTitle } from '../ui/Card';
import { Badge } from '../ui/Badge';
import type { AgentInfo } from '../../types';
import { Bot, Search, Crosshair, CheckCircle, FileText, RotateCcw } from 'lucide-react';

const agentIcons = {
  planner: Bot,
  recon: Search,
  exploit: Crosshair,
  verify: CheckCircle,
  report: FileText,
  retest: RotateCcw,
};

interface AgentStatusProps {
  agents: AgentInfo[];
}

export function AgentStatus({ agents }: AgentStatusProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Agent Status</CardTitle>
      </CardHeader>
      <div className="space-y-2">
        {agents.map((agent) => {
          const Icon = agentIcons[agent.name] ?? Bot;
          return (
            <motion.div
              key={agent.name}
              layout
              className="flex items-center justify-between py-1.5 px-2 rounded-md bg-surface-2"
            >
              <div className="flex items-center gap-2">
                <Icon size={14} className="text-text-muted" />
                <span className="text-xs font-medium text-text-primary capitalize">{agent.name}</span>
              </div>
              <div className="flex items-center gap-2">
                {agent.currentTask && (
                  <span className="text-[10px] text-text-muted max-w-[140px] truncate">
                    {agent.currentTask}
                  </span>
                )}
                <Badge variant={agent.state} dot>{agent.state}</Badge>
              </div>
            </motion.div>
          );
        })}
      </div>
    </Card>
  );
}