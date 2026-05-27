import React, { useEffect, useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronDown, ChevronRight, CheckCircle2, AlertCircle, Loader2, Copy, Check } from 'lucide-react';
import { cn } from '@/lib/utils';

export type OrchestratorStage = 'planner' | 'executer' | 'analyzer';
export type OrchestratorStatus = 'idle' | 'waiting' | 'thinking' | 'running' | 'completed' | 'error';

export interface ActivityEntry {
  type: 'thinking' | 'command' | 'result' | 'info';
  message: string;
  at?: string;
}

export interface NodeData {
  stage: OrchestratorStage;
  status: OrchestratorStatus;
  label: string;
  subtext?: string;
  icon: React.ElementType;
  progress?: number;
  recentActivity?: ActivityEntry[];
  actionPanel?: {
    title: string;
    detail: string;
    tone?: 'info' | 'warn' | 'danger';
    controls?: React.ReactNode;
  } | null;
}

interface OrchestratorPipelineProps {
  stages: Record<OrchestratorStage, NodeData>;
  className?: string;
}

const STAGE_COLORS = {
  planner: 'text-blue-400 border-blue-500/20',
  executer: 'text-amber-400 border-amber-500/20',
  analyzer: 'text-emerald-400 border-emerald-500/20',
};

const GLOW_COLORS = {
  planner: 'rgba(59, 130, 246, 0.3)',
  executer: 'rgba(245, 158, 11, 0.3)',
  analyzer: 'rgba(16, 185, 129, 0.3)',
};

export const OrchestratorPipeline: React.FC<OrchestratorPipelineProps> = ({ stages, className }) => {
  const stageOrder: OrchestratorStage[] = ['planner', 'executer', 'analyzer'];
  const labels: Record<OrchestratorStage, string> = {
    planner: 'PLANNER',
    executer: 'EXECUTER',
    analyzer: 'ANALYSER',
  };

  const activeStageIndex = [...stageOrder].reverse().findIndex(key => {
    const s = stages[key]?.status;
    return s === 'running' || s === 'thinking';
  });
  const currentActiveKey = activeStageIndex !== -1 ? stageOrder[stageOrder.length - 1 - activeStageIndex] : null;

  return (
    <div className={cn("flex h-full w-full flex-col items-center mx-auto", className)}>
      {stageOrder.map((stageKey, index) => {
        const node = stages[stageKey];
        const isLast = index === stageOrder.length - 1;
        const isActive = node.status === 'thinking' || node.status === 'running';
        const isCompleted = node.status === 'completed';

        return (
          <div key={stageKey} className="w-full flex flex-col items-start relative">
            {!isLast && (
              <div className="absolute left-[1.25rem] top-[1.25rem] bottom-[-0.15rem] w-[2px]">
                <PipelineConnector
                  active={isActive || isCompleted}
                  pulse={isActive && currentActiveKey === stageKey}
                  color={GLOW_COLORS[stageKey]}
                />
              </div>
            )}
            <PipelineNode
              node={{ ...node, label: labels[stageKey] }}
              isCurrentActive={currentActiveKey === stageKey}
            />
          </div>
        );
      })}
    </div>
  );
};

const CodeCopyButton: React.FC<{ text: string }> = ({ text }) => {
  const [copied, setCopied] = useState(false);
  const handleCopy = useCallback(() => {
    void navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [text]);

  return (
    <button
      onClick={handleCopy}
      className="flex items-center gap-1 text-[10px] text-pf-400 hover:text-pf-300 transition-colors"
    >
      {copied ? <Check size={10} /> : <Copy size={10} />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
};

function renderMarkdown(text: string) {
  if (!text) return null;

  const renderLineContent = (line: string) => {
    // Handle Bold (**), Italics (*), and Inline Code (`)
    const boldParts = line.split(/(\*\*.*?\*\*)/g);
    return boldParts.map((bp, bpIdx) => {
      if (bp.startsWith('**') && bp.endsWith('**')) {
        return <strong key={bpIdx} className="font-bold text-text-primary">{bp.slice(2, -2)}</strong>;
      }

      // Sub-split for inline code (`)
      const codeParts = bp.split(/(`.*?`)/g);
      return codeParts.map((cp, cpIdx) => {
        if (cp.startsWith('`') && cp.endsWith('`')) {
          return (
            <code key={cpIdx} className="px-1 py-0.5 rounded bg-zinc-800 text-pf-300 font-mono text-[10px] border border-white/5 mx-0.5">
              {cp.slice(1, -1)}
            </code>
          );
        }

        // Sub-split for italics (*)
        const italicParts = cp.split(/(\*.*?\*)/g);
        return italicParts.map((ip, ipIdx) => {
          if (ip.startsWith('*') && ip.endsWith('*')) {
            return <em key={ipIdx} className="italic opacity-80">{ip.slice(1, -1)}</em>;
          }
          return ip;
        });
      });
    });
  };

  const parts = text.split(/(```[\s\S]*?```)/g);
  return parts.map((part, i) => {
    if (part.startsWith('```') && part.endsWith('```')) {
      const match = part.match(/```(\w+)?\n?([\s\S]*?)```/);
      if (match) {
        const lang = (match[1] || '').toLowerCase();
        const code = match[2].trim();
        return (
          <div key={i} className="my-3 max-w-full rounded-lg border border-pf-500/20 bg-surface-2/50 overflow-hidden shadow-lg">
            <div className="px-3 py-1.5 flex items-center justify-between bg-surface-3/50 border-b border-pf-500/10">
              <span className="text-[10px] uppercase font-bold text-text-muted">{lang || 'code'}</span>
              <CodeCopyButton text={code} />
            </div>
            <pre className="p-3 text-[11px] overflow-x-auto font-mono scrollbar-pf text-pf-100">
              <code>{code}</code>
            </pre>
          </div>
        );
      }
    }

    return (
      <div key={i} className="space-y-1">
        {part.split('\n').map((line, lineIdx) => (
          <p key={lineIdx} className={cn("text-[11px] leading-relaxed text-text-secondary min-h-[1.2em]", line.startsWith('---') && "opacity-40 my-2")}>
            {renderLineContent(line)}
          </p>
        ))}
      </div>
    );
  });
}

const PipelineNode: React.FC<{ node: NodeData; isCurrentActive: boolean }> = ({ node, isCurrentActive }) => {
  const Icon = node.icon;
  const hasActionPanel = Boolean(node.actionPanel);
  const effectiveStatus: OrchestratorStatus = hasActionPanel && node.status === 'completed'
    ? 'running'
    : node.status;
  const isWorking = (effectiveStatus === 'thinking' || effectiveStatus === 'running') && (isCurrentActive || hasActionPanel);
  const recentActivity = node.recentActivity || [];
  const filteredActivities = recentActivity.filter((activity) => {
    if (effectiveStatus === 'running' || effectiveStatus === 'thinking') {
      return activity.type !== 'result';
    }
    return true;
  });
  const visibleActivities = filteredActivities
    .map((activity) => ({
      ...activity,
      message: activity.message?.trim() || '',
    }))
    .filter((activity) => activity.message.length > 0)
    .slice(-3);
  const renderedActivities = node.stage === 'planner'
    ? visibleActivities
    : [...visibleActivities].reverse();
  const actionTone = node.actionPanel?.tone || 'warn';
  const [isCollapsed, setIsCollapsed] = useState(effectiveStatus === 'completed');
  const shouldHideActivityFeed = Boolean(node.actionPanel);

  useEffect(() => {
    if (effectiveStatus === 'completed') {
      setIsCollapsed(true);
      return;
    }
    setIsCollapsed(false);
  }, [effectiveStatus]);

  const analyzerThinkingContext = () => {
    const haystack = recentActivity.map((activity) => activity.message.toLowerCase()).join(' ');
    if (
      haystack.includes('vuln') ||
      haystack.includes('vulnerability') ||
      haystack.includes('[verify]') ||
      haystack.includes('[retest]') ||
      haystack.includes('confirmed')
    ) {
      return 'vuln...';
    }
    return 'info...';
  };

  const primaryStatusLine = () => {
    if (effectiveStatus === 'thinking') {
      if (node.stage === 'analyzer') {
        return `thinking... ${analyzerThinkingContext()}`;
      }
      return 'thinking...';
    }
    if (effectiveStatus === 'running') {
      if (hasActionPanel) {
        return 'awaiting approval...';
      }
      return 'working...';
    }
    if (effectiveStatus === 'completed') {
      return 'completed';
    }
    if (effectiveStatus === 'waiting') {
      return 'waiting...';
    }
    if (effectiveStatus === 'error') {
      return 'error';
    }
    return 'idle';
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn(
        "relative flex items-start gap-3 w-full transition-all duration-500 py-1.5",
        STAGE_COLORS[node.stage]
      )}
    >
      {/* Icon Hexagon/Circle */}
      <div className="relative z-10">
        <div className={cn(
          "flex items-center justify-center w-10 h-10 rounded-xl border bg-surface-0",
          isWorking ? "animate-pulse border-current" : "border-border"
        )}>
          {node.status === 'thinking' ? (
            <Loader2 className="w-5 h-5 animate-spin text-blue-400" />
          ) : (
            <Icon className="w-5 h-5" />
          )}
        </div>

        {/* Status Mini-Badge */}
        <div className="absolute -top-1 -right-1">
          <StatusBadge status={node.status} />
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between gap-2 h-10">
          <h3 className="font-bold text-xl tracking-tight uppercase">{node.label}</h3>
          {node.progress !== undefined && (
            <span className="font-mono text-sm font-bold opacity-60">{node.progress}%</span>
          )}
        </div>

        <div className="mt-1 relative min-h-[48px] pl-4 group">
          {/* Vertical accent line - FIXED */}
          <div className="absolute left-0 top-1 bottom-1 w-[1.5px] bg-blue-500/30 rounded-full z-10" />

          <div className="space-y-1 py-0.5">
            <div className="flex items-center gap-2">
              <div className={cn(
                "h-2 w-2 rounded-full shrink-0",
                effectiveStatus === 'running' ? "bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.4)]" :
                  effectiveStatus === 'thinking' ? "bg-blue-400 shadow-[0_0_8px_rgba(96,165,250,0.35)]" :
                    effectiveStatus === 'completed' ? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.35)]" :
                      effectiveStatus === 'error' ? "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.35)]" :
                        "bg-text-muted/30",
                (isCurrentActive || hasActionPanel) && (effectiveStatus === 'running' || effectiveStatus === 'thinking') && "animate-pulse"
              )} />
              <span className={cn(
                "text-[12px] font-medium",
                effectiveStatus === 'thinking' ? "text-sky-400 italic" :
                  effectiveStatus === 'running' ? "text-orange-300" :
                    effectiveStatus === 'completed' ? "text-emerald-400" :
                      effectiveStatus === 'error' ? "text-red-400" :
                        "text-text-secondary"
              )}>
                {primaryStatusLine()}
              </span>
              {effectiveStatus === 'completed' ? (
                <button
                  type="button"
                  onClick={() => setIsCollapsed((value) => !value)}
                  className="inline-flex items-center rounded-md p-0.5 text-emerald-400/80 transition hover:bg-emerald-500/10 hover:text-emerald-300"
                  title={isCollapsed ? 'Show completed details' : 'Hide completed details'}
                  aria-label={isCollapsed ? 'Show completed details' : 'Hide completed details'}
                  aria-expanded={!isCollapsed}
                >
                  {isCollapsed ? <ChevronRight size={14} /> : <ChevronDown size={14} />}
                </button>
              ) : null}
            </div>

            {node.actionPanel ? (
              <div
                className={cn(
                  "mt-2 max-h-[150px] overflow-hidden rounded-xl border px-3 py-3 shadow-sm backdrop-blur-sm",
                  actionTone === 'warn' && "border-amber-500/30 bg-amber-500/10",
                  actionTone === 'info' && "border-sky-500/30 bg-sky-500/10",
                  actionTone === 'danger' && "border-red-500/30 bg-red-500/10",
                )}
              >
                <div className="flex items-start gap-2.5">
                  <div
                    className={cn(
                      "mt-0.5 h-2.5 w-2.5 shrink-0 rounded-full",
                      actionTone === 'warn' && "bg-amber-400 shadow-[0_0_10px_rgba(251,191,36,0.45)]",
                      actionTone === 'info' && "bg-sky-400 shadow-[0_0_10px_rgba(56,189,248,0.45)]",
                      actionTone === 'danger' && "bg-red-400 shadow-[0_0_10px_rgba(248,113,113,0.45)]",
                    )}
                  />
                  <div className="min-w-0 flex-1 space-y-1.5">
                    <div className="space-y-1">
                      <p className="text-sm font-semibold text-text-primary">
                        {node.actionPanel.title}
                      </p>
                      <p
                        title={node.actionPanel.detail}
                        className="overflow-hidden text-ellipsis whitespace-nowrap text-[12px] leading-5 text-text-secondary"
                      >
                        {node.actionPanel.detail}
                      </p>
                    </div>
                    {node.actionPanel.controls ? (
                      <div className="flex flex-col items-stretch gap-1.5 pt-0.5 sm:items-end">
                        {node.actionPanel.controls}
                      </div>
                    ) : null}
                  </div>
                </div>
              </div>
            ) : null}

            <AnimatePresence initial={false}>
              {!isCollapsed ? (
                <motion.div
                  key="pipeline-node-body"
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.18, ease: 'easeInOut' }}
                  className="overflow-hidden"
                >
                  <div className="space-y-1 pt-1">
                    {!shouldHideActivityFeed && visibleActivities.length > 0 ? (
                      <div className="space-y-1">
                        {renderedActivities.map((activity, index) => {
                          const isCommand = activity.type === 'command';
                          return isCommand ? (
                            <code
                              title={activity.message}
                              key={`${activity.type}-${activity.at || index}-${activity.message}`}
                              className="block overflow-hidden text-ellipsis whitespace-nowrap rounded-md border border-border/40 dark:border-border bg-surface-2/40 px-2.5 py-1.5 font-mono text-[11px] text-text-secondary"
                            >
                              {activity.message}
                            </code>
                          ) : (
                            <p
                              key={`${activity.type}-${activity.at || index}-${activity.message}`}
                              title={activity.message}
                              className={cn(
                                "overflow-hidden text-ellipsis whitespace-nowrap text-[11px] leading-5",
                                activity.type === 'result'
                                  ? "text-emerald-300"
                                  : activity.type === 'thinking'
                                    ? "text-sky-300"
                                    : "text-text-secondary"
                              )}
                            >
                              {activity.message}
                            </p>
                          );
                        })}
                      </div>
                    ) : null}

                    {!shouldHideActivityFeed && visibleActivities.length === 0 && node.subtext ? (
                      <div className="mt-1">
                        {renderMarkdown(node.subtext)}
                      </div>
                    ) : null}
                  </div>
                </motion.div>
              ) : null}
            </AnimatePresence>
          </div>
        </div>
      </div>

      {/* Decorative Glow */}
      {isWorking && (
        <div
          className="absolute inset-0 rounded-2xl opacity-10 pointer-events-none"
          style={{
            background: `radial-gradient(circle at center, ${GLOW_COLORS[node.stage]} 0%, transparent 70%)`
          }}
        />
      )}
    </motion.div>
  );
};

const PipelineConnector: React.FC<{ active: boolean; pulse: boolean; color: string }> = ({ active, pulse, color }) => {
  return (
    <div className="relative w-full h-full">
      <div className="absolute left-0 w-[2px] h-full bg-border" />
      {active && (
        <motion.div
          initial={{ height: 0 }}
          animate={{ height: '100%' }}
          className="absolute left-0 w-[2.5px] origin-top"
          style={{ backgroundColor: color }}
        />
      )}
      {pulse && (
        <div className="absolute left-0 w-[2px] h-full overflow-hidden">
          <motion.div
            animate={{ y: ['-100%', '100%'] }}
            transition={{ repeat: Infinity, duration: 2, ease: "linear" }}
            className="w-full h-8 bg-gradient-to-b from-transparent via-current to-transparent opacity-100"
            style={{ color }}
          />
        </div>
      )}
    </div>
  );
};

const StatusBadge: React.FC<{ status: OrchestratorStatus }> = ({ status }) => {
  if (status === 'completed') {
    return <div className="p-0.5 rounded-full bg-emerald-500 text-white shadow-lg shadow-emerald-500/20"><CheckCircle2 size={14} /></div>;
  }
  if (status === 'error') {
    return <div className="p-0.5 rounded-full bg-red-500 text-white shadow-lg shadow-red-500/20"><AlertCircle size={14} /></div>;
  }
  if (status === 'thinking' || status === 'running') {
    return (
      <div className="relative flex h-3.5 w-3.5">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-current opacity-75"></span>
        <span className="relative inline-flex rounded-full h-3.5 w-3.5 bg-current"></span>
      </div>
    );
  }
  if (status === 'waiting') {
    return <div className="h-3 w-3 rounded-full border-2 border-text-muted/40 bg-surface-1"></div>;
  }
  return null;
};
