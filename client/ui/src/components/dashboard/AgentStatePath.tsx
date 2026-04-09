import { useCallback, useMemo, useState } from 'react';
import ReactFlow, {
  Background,
  EdgeLabelRenderer,
  BaseEdge,
  Handle,
  Position,
  useReactFlow,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeTypes,
  type EdgeTypes,
} from 'reactflow';
import {
  Activity,
  Bot,
  CheckCircle,
  Crosshair,
  Eye,
  FileText,
  RotateCcw,
  Search,
  X,
} from 'lucide-react';

import 'reactflow/dist/style.css';
import type { AgentInfo } from '../../types';
import { cn } from '../../lib/utils';
import { Badge } from '../ui/Badge';
import { Card, CardHeader, CardTitle } from '../ui/Card';

// ─── Types ────────────────────────────────────────────────────────────────────

interface AgentStatePathProps {
  agents: AgentInfo[];
  showHeader?: boolean;
  className?: string;
  graphHeightClassName?: string;
  subtitle?: string;
  agentInsights?: Partial<Record<AgentGraphRole, AgentInsightPanelData>>;
}

type AgentName = AgentInfo['name'];
type AgentState = AgentInfo['state'];
export type AgentGraphRole = AgentName | 'intel' | 'perceptor';

export interface AgentHistoryEntry {
  id: string;
  at: string;
  level: 'info' | 'success' | 'warn' | 'error';
  message: string;
  event?: string;
}

export interface AgentInsightPanelData {
  result?: string;
  resultLabel?: string;
  history: AgentHistoryEntry[];
}

interface AgentNodeData {
  role: AgentGraphRole;
  label: string;
  state: AgentState;
  currentTask?: string;
  progress?: number;
}

interface ExecutorLayerData {
  label: string;
  subtitle: string;
}

interface FeedbackEdgeData {
  color: string;
  animated: boolean;
  // absolute X coordinate the path travels along (right side rail)
  railX: number;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const EXECUTOR_AGENTS: AgentName[] = ['recon', 'exploit', 'verify', 'report', 'retest'];
const AGENT_ROLES: AgentGraphRole[] = ['intel', 'planner', 'recon', 'exploit', 'verify', 'report', 'retest', 'perceptor'];

const AGENT_ICONS = {
  intel:     Activity,
  planner:   Bot,
  recon:     Search,
  exploit:   Crosshair,
  verify:    CheckCircle,
  report:    FileText,
  retest:    RotateCcw,
  perceptor: Eye,
} as const;

const STATE_RING: Record<AgentState, string> = {
  idle:    'border-slate-500/50    bg-slate-500/10',
  running: 'border-pf-500/70      bg-pf-500/15',
  success: 'border-emerald-500/70 bg-emerald-500/15',
  error:   'border-red-500/70     bg-red-500/15',
  waiting: 'border-yellow-500/70  bg-yellow-500/15',
};

const EDGE_COLOR: Record<AgentState, string> = {
  idle:    '#64748b',
  running: '#3b82f6',
  success: '#10b981',
  error:   '#ef4444',
  waiting: '#f59e0b',
};

// ─── Vertical Layout Constants ────────────────────────────────────────────────
// Flow: Intel (top) → Planner → Executor Layer (horizontal) → Perceptor (bottom)

const CENTER_X = 400;

// Y positions for the main vertical flow
const INTEL_Y    = 20;
const PLANNER_Y  = 155;
const LAYER_Y    = 275;
const PERCEPTOR_Y = 500;

// Executor layer dimensions (wide horizontal band)
const LAYER_X      = 60;
const LAYER_WIDTH  = 680;
const LAYER_HEIGHT = 155;

// Executor agents spread horizontally inside the layer
const EXECUTOR_Y        = LAYER_Y + 48;  // inside the layer
const EXECUTOR_X_START  = 110;
const EXECUTOR_X_GAP    = 130;

// Circle is h-16 = 64px
const CIRCLE_HALF = 32;

// Feedback loop rail on the right side
const FEEDBACK_RAIL_X = LAYER_X + LAYER_WIDTH + 65;

// ─── Custom feedback loop edge ────────────────────────────────────────────────
// Draws a path along the right side:
//   Perceptor (right) → right to rail → up along rail → left into Planner (right)

function FeedbackLoopEdge({
  sourceX, sourceY,
  targetX, targetY,
  data,
  markerEnd,
}: EdgeProps<FeedbackEdgeData>) {
  const railX  = data?.railX  ?? sourceX + 80;
  const color  = data?.color  ?? '#f59e0b';
  const radius = 10;

  // Path: right from source → corner → up rail → corner → left to target
  const edgePath = [
    `M ${sourceX} ${sourceY}`,
    `L ${railX - radius} ${sourceY}`,
    `Q ${railX} ${sourceY} ${railX} ${sourceY - radius}`,
    `L ${railX} ${targetY + radius}`,
    `Q ${railX} ${targetY} ${railX - radius} ${targetY}`,
    `L ${targetX} ${targetY}`,
  ].join(' ');

  const labelX = railX + 14;
  const labelY = (sourceY + targetY) / 2;

  return (
    <>
      <BaseEdge
        path={edgePath}
        markerEnd={markerEnd}
        style={{
          stroke:          color,
          strokeWidth:     1.8,
          strokeDasharray: '6 4',
          fill:            'none',
        }}
      />
      {data?.animated && (
        <path
          d={edgePath}
          fill="none"
          stroke={color}
          strokeWidth={1.8}
          strokeDasharray="6 4"
          opacity={0.6}
          style={{ animation: 'dashmove 1s linear infinite' }}
        />
      )}
      <EdgeLabelRenderer>
        <div
          style={{
            position:  'absolute',
            transform: `translate(0, -50%) translate(${labelX}px, ${labelY}px)`,
            pointerEvents: 'none',
            fontSize:  10,
            color:     '#94a3b8',
            fontWeight: 600,
            whiteSpace: 'nowrap',
            writingMode: 'vertical-rl',
            textOrientation: 'mixed',
          }}
          className="nodrag nopan"
        >
          feedback loop
        </div>
      </EdgeLabelRenderer>
    </>
  );
}

// ─── Node components ──────────────────────────────────────────────────────────

function AgentNode({ data }: { data: AgentNodeData }) {
  const Icon = AGENT_ICONS[data.role] ?? Bot;

  return (
    <div className="flex flex-col items-center gap-1" style={{ minWidth: 110 }}>
      {/* Top/Bottom handles for vertical flow */}
      <Handle type="target"   position={Position.Top}    id="top"           className="!h-2 !w-2 !border-0 !bg-pf-500" />
      <Handle type="target"   position={Position.Left}   id="left-target"   className="!h-2 !w-2 !border-0 !bg-pf-500" style={{ top: CIRCLE_HALF }} />

      <div
        className={cn(
          'flex h-16 w-16 flex-col items-center justify-center rounded-full border-2 shadow-sm',
          STATE_RING[data.state],
        )}
      >
        <Icon size={14} className="text-text-primary" />
        <span className="mt-0.5 text-[9px] font-semibold uppercase tracking-wider text-text-primary">
          {data.label}
        </span>
      </div>

      <Badge variant={data.state} dot className="text-[9px]">
        {data.state}
      </Badge>

      {data.currentTask
        ? <p className="max-w-[108px] truncate text-[9px] text-text-secondary">{data.currentTask}</p>
        : <p className="text-[9px] text-text-muted">idle</p>
      }

      {typeof data.progress === 'number' && (
        <div className="w-[96px]">
          <div className="h-1 overflow-hidden rounded-full bg-surface-3">
            <div
              className="h-full rounded-full bg-pf-500 transition-all duration-300"
              style={{ width: `${Math.min(Math.max(data.progress, 0), 100)}%` }}
            />
          </div>
          <p className="mt-0.5 text-center text-[9px] text-text-muted">{data.progress}%</p>
        </div>
      )}

      <Handle type="source" position={Position.Bottom} id="bottom"       className="!h-2 !w-2 !border-0 !bg-pf-500" />
      <Handle type="source" position={Position.Right}  id="right-source" className="!h-2 !w-2 !border-0 !bg-pf-500" style={{ top: CIRCLE_HALF }} />
    </div>
  );
}

function ExecutorLayerNode({ data }: { data: ExecutorLayerData }) {
  return (
    <div
      className="rounded-2xl border border-pf-500/20 bg-pf-500/5 px-4 pt-3 shadow-inner"
      style={{ width: LAYER_WIDTH, height: LAYER_HEIGHT }}
    >
      <p className="text-center text-xs font-semibold uppercase tracking-widest text-pf-300">
        {data.label}
      </p>
      <p className="mt-1 text-center text-xs leading-snug text-text-secondary">
        {data.subtitle}
      </p>
    </div>
  );
}

const nodeTypes: NodeTypes = {
  agent:         AgentNode,
  executorLayer: ExecutorLayerNode,
};

const edgeTypes: EdgeTypes = {
  feedbackLoop: FeedbackLoopEdge,
};

function formatNodeTime(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return '--:--:--';
  }
  return parsed.toLocaleTimeString();
}

function levelClass(level: AgentHistoryEntry['level']): string {
  if (level === 'error' || level === 'warn') {
    return 'text-red-300';
  }
  if (level === 'success') {
    return 'text-emerald-300';
  }
  return 'text-text-secondary';
}

// ─── Main component ───────────────────────────────────────────────────────────

export function AgentStatePath({
  agents,
  showHeader = true,
  className,
  graphHeightClassName = 'h-[580px]',
  subtitle = 'Intel → Planner → Executor Layer (parallel) → Perceptor (feedback loop)',
  agentInsights,
}: AgentStatePathProps) {
  const { nodes, edges } = useMemo(() => {
    const byName = new Map(agents.map((a) => [a.name, a]));
    const intelHistory = agentInsights?.intel?.history ?? [];
    const latestIntelEntry = intelHistory.length > 0
      ? intelHistory[intelHistory.length - 1]
      : undefined;
    const hasIntelError = intelHistory.some(
      (entry) => entry.level === 'error' || entry.event === 'intel_crashed',
    );
    const hasIntelComplete = intelHistory.some(
      (entry) => entry.event === 'intel_complete',
    );
    const hasIntelActivity = intelHistory.length > 0;

    // ── Derived states ─────────────────────────────────────────────────────

    const planner      = byName.get('planner');
    const plannerState = planner?.state ?? 'waiting';

    const intelState: AgentState =
      hasIntelError                               ? 'error'
      : hasIntelComplete                          ? 'success'
      : hasIntelActivity                          ? 'running'
      : plannerState === 'error'                 ? 'error'
      : plannerState === 'running'               ? 'running'
      : plannerState === 'success'               ? 'success'
      : 'waiting';

    const executorStates  = EXECUTOR_AGENTS.map((n) => byName.get(n)?.state ?? 'waiting');
    const runningExecutor = EXECUTOR_AGENTS.find((n) => byName.get(n)?.state === 'running');

    const perceptorState: AgentState =
      executorStates.includes('error')               ? 'error'
      : executorStates.includes('running')           ? 'running'
      : executorStates.every((s) => s === 'success') ? 'success'
      : 'waiting';

    const progressNums = EXECUTOR_AGENTS
      .map((n) => byName.get(n)?.progress)
      .filter((v): v is number => typeof v === 'number');

    const perceptorProgress = progressNums.length
      ? Math.round(progressNums.reduce((s, v) => s + v, 0) / progressNums.length)
      : undefined;

    // ── Nodes (vertical layout) ───────────────────────────────────────────

    const graphNodes: Node[] = [
      // Executor layer background — wide horizontal band
      {
        id:         'executor-layer',
        type:       'executorLayer',
        position:   { x: LAYER_X, y: LAYER_Y },
        selectable: false,
        draggable:  false,
        data:       { label: 'Executor Layer', subtitle: 'Parallel agents' } satisfies ExecutorLayerData,
        style:      { zIndex: 0 },
      },
      // Intel — top center
      {
        id:       'intel',
        type:     'agent',
        position: { x: CENTER_X - 55, y: INTEL_Y },
        data: {
          role: 'intel',
          label: 'Intel',
          state: intelState,
          currentTask: latestIntelEntry?.message || 'Context → Planner',
        } satisfies AgentNodeData,
      },
      // Planner — below Intel
      {
        id:       'planner',
        type:     'agent',
        position: { x: CENTER_X - 55, y: PLANNER_Y },
        data: {
          role: 'planner', label: 'Planner', state: plannerState,
          currentTask: planner?.currentTask, progress: planner?.progress,
        } satisfies AgentNodeData,
      },
      // 5 executor agents — horizontal row inside the layer
      ...EXECUTOR_AGENTS.map((name, i) => ({
        id:       name,
        type:     'agent',
        position: { x: EXECUTOR_X_START + i * EXECUTOR_X_GAP, y: EXECUTOR_Y },
        data: {
          role:        name,
          label:       name.charAt(0).toUpperCase() + name.slice(1),
          state:       byName.get(name)?.state ?? 'waiting',
          currentTask: byName.get(name)?.currentTask,
          progress:    byName.get(name)?.progress,
        } satisfies AgentNodeData,
        style: { zIndex: 1 },
      })),
      // Perceptor — bottom center
      {
        id:       'perceptor',
        type:     'agent',
        position: { x: CENTER_X - 55, y: PERCEPTOR_Y },
        data: {
          role: 'perceptor', label: 'Perceptor', state: perceptorState,
          currentTask: runningExecutor ? `Reading ${runningExecutor}` : 'Aggregating output',
          progress:    perceptorProgress,
        } satisfies AgentNodeData,
      },
    ];

    // ── Edges (vertical flow) ─────────────────────────────────────────────

    const mkEdge = (
      id: string,
      source: string,
      target: string,
      state: AgentState,
      opts: Partial<Edge> = {},
    ): Edge => ({
      id, source, target,
      type:     'smoothstep',
      animated: state === 'running',
      style:    { stroke: EDGE_COLOR[state], strokeWidth: 1.8 },
      ...opts,
    });

    const graphEdges: Edge[] = [
      // Intel → Planner (vertical)
      mkEdge('intel-planner', 'intel', 'planner', plannerState, {
        sourceHandle: 'bottom',
        targetHandle: 'top',
      }),

      // Planner → each executor (fan out from bottom to top of each executor)
      ...EXECUTOR_AGENTS.map((name) =>
        mkEdge(`planner-${name}`, 'planner', name, byName.get(name)?.state ?? 'waiting', {
          sourceHandle: 'bottom',
          targetHandle: 'top',
        }),
      ),

      // Each executor → Perceptor (fan in from bottom to top)
      ...EXECUTOR_AGENTS.map((name) =>
        mkEdge(`${name}-perceptor`, name, 'perceptor', byName.get(name)?.state ?? 'waiting', {
          sourceHandle: 'bottom',
          targetHandle: 'top',
        }),
      ),

      // Feedback loop — custom edge arcing along the right side
      // Perceptor (right) → up the right rail → into Planner (right)
      {
        id:           'perceptor-planner-loop',
        source:       'perceptor',
        target:       'planner',
        sourceHandle: 'right-source',
        targetHandle: 'right-source', // using right handle as target too
        type:         'feedbackLoop',
        data: {
          color:    EDGE_COLOR[perceptorState],
          animated: perceptorState === 'running',
          railX:    FEEDBACK_RAIL_X,
        } satisfies FeedbackEdgeData,
      },
    ];

    return { nodes: graphNodes, edges: graphEdges };
  }, [agents, agentInsights]);

  const [locked, setLocked] = useState(true);
  const [selectedRole, setSelectedRole] = useState<AgentGraphRole | null>(null);

  const selectedNodeData = useMemo(() => {
    if (!selectedRole) {
      return null;
    }
    const matching = nodes.find((node) => node.type === 'agent' && node.id === selectedRole);
    if (!matching) {
      return null;
    }
    return matching.data as AgentNodeData;
  }, [nodes, selectedRole]);

  const selectedInsight = selectedRole ? agentInsights?.[selectedRole] : undefined;
  const selectedHistory = selectedInsight?.history ?? [];
  const selectedResult = selectedInsight?.result?.trim() ?? '';
  const selectedResultLabel = selectedInsight?.resultLabel ?? 'Latest Result';

  return (
    <Card className={cn('overflow-hidden p-0', className)}>
      <style>{`
        @keyframes dashmove { to { stroke-dashoffset: -20; } }
        .pf-controls button {
          display: flex;
          align-items: center;
          justify-content: center;
          width: 28px;
          height: 28px;
          border-radius: 6px;
          border: 1px solid rgba(255,255,255,0.12);
          background: rgba(255,255,255,0.08);
          color: #fff;
          cursor: pointer;
          transition: background 0.15s;
        }
        .pf-controls button:hover { background: rgba(255,255,255,0.16); }
        .pf-controls button.active { background: rgba(255,255,255,0.22); }
        .pf-controls button svg { width: 13px; height: 13px; stroke: #fff; fill: none; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; }
        .pf-controls button svg.filled { fill: #fff; stroke: none; }
      `}</style>

      {showHeader && (
        <CardHeader className="border-b border-border px-4 py-3">
          <CardTitle>Agent State Path</CardTitle>
          <p className="mt-1 text-sm text-text-secondary">{subtitle}</p>
        </CardHeader>
      )}

      {selectedRole && selectedNodeData ? (
        <div className={cn('flex flex-col gap-3 bg-surface-0/60 p-3', graphHeightClassName)}>
          <div className="flex items-start justify-between rounded-md border border-border bg-surface-1/80 px-3 py-2">
            <div>
              <p className="text-sm font-semibold text-text-primary">{selectedNodeData.label} Agent Details</p>
              <div className="mt-1 flex flex-wrap items-center gap-2">
                <Badge variant={selectedNodeData.state} dot className="text-xs">
                  {selectedNodeData.state}
                </Badge>
                {typeof selectedNodeData.progress === 'number' && (
                  <span className="text-xs font-mono text-text-muted">
                    Progress: {selectedNodeData.progress}%
                  </span>
                )}
              </div>
              <p className="mt-1 text-xs text-text-secondary">
                {selectedNodeData.currentTask?.trim() || 'No active task for this agent.'}
              </p>
            </div>

            <button
              type="button"
              onClick={() => setSelectedRole(null)}
              className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs text-text-secondary transition-colors hover:bg-surface-2 hover:text-text-primary"
              title="Back to graph"
            >
              <X size={12} />
              Back
            </button>
          </div>

          <div className="grid min-h-0 flex-1 gap-3 xl:grid-cols-[1.15fr_0.85fr]">
            <div className="min-h-0 rounded-md border border-border bg-surface-1/70 p-3">
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-text-muted">
                {selectedResultLabel}
              </p>
              <div className="h-full max-h-full overflow-y-auto rounded-md border border-border/70 bg-surface-0/40 p-2">
                <p className="whitespace-pre-wrap break-words text-sm leading-relaxed text-text-primary">
                  {selectedResult || 'No returned result recorded for this agent yet.'}
                </p>
              </div>
            </div>

            <div className="min-h-0 rounded-md border border-border bg-surface-1/70 p-3">
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-text-muted">
                Full History
              </p>
              {selectedHistory.length === 0 ? (
                <div className="rounded-md border border-border/70 bg-surface-0/40 p-2">
                  <p className="text-sm text-text-muted">No historical logs for this agent yet.</p>
                </div>
              ) : (
                <div className="h-full max-h-full space-y-1.5 overflow-y-auto rounded-md border border-border/70 bg-surface-0/40 p-2">
                  {selectedHistory.map((entry) => (
                    <div key={entry.id} className="rounded-md border border-border/70 bg-surface-1/40 p-1.5">
                      <div className="flex items-center justify-between text-xs text-text-muted">
                        <span className={cn('font-semibold uppercase tracking-wide', levelClass(entry.level))}>
                          {entry.level}
                        </span>
                        <span className="font-mono">{formatNodeTime(entry.at)}</span>
                      </div>
                      <p className="mt-1 text-sm text-text-primary">{entry.message}</p>
                      {entry.event && (
                        <p className="mt-0.5 text-sm text-text-muted">event: {entry.event}</p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      ) : (
        <div className={cn('relative bg-surface-0/60', graphHeightClassName)}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            onNodeClick={(_, node) => {
              if (node.type !== 'agent') {
                return;
              }
              if (!AGENT_ROLES.includes(node.id as AgentGraphRole)) {
                return;
              }
              setSelectedRole(node.id as AgentGraphRole);
            }}
            onInit={(instance) => instance.fitView({ padding: 0.18 })}
            fitView
            fitViewOptions={{ padding: 0.18 }}
            minZoom={0.25}
            maxZoom={1.6}
            nodesDraggable={!locked}
            panOnDrag={!locked}
            zoomOnScroll={!locked}
            zoomOnPinch={!locked}
            zoomOnDoubleClick={!locked}
            preventScrolling={!locked}
            proOptions={{ hideAttribution: true }}
          >
            <Background color="var(--border)" gap={28} size={1} />
            <CustomControls locked={locked} onToggleLock={() => setLocked(l => !l)} />
          </ReactFlow>

          <div className="pointer-events-none absolute right-3 top-3 z-20 rounded-md border border-border bg-surface-1/90 px-2.5 py-1.5 text-xs text-text-secondary shadow">
            Click any agent node to inspect logs, result, and history
          </div>
        </div>
      )}
    </Card>
  );
}

function CustomControls({
  locked,
  onToggleLock,
}: {
  locked: boolean;
  onToggleLock: () => void;
}) {
  const { zoomIn, zoomOut, fitView } = useReactFlow();

  return (
    <div
      className="pf-controls absolute bottom-3 left-3 z-10 flex flex-col gap-1"
    >
      {/* Zoom in */}
      <button onClick={() => zoomIn({ duration: 200 })} title="Zoom in">
        <svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
      </button>

      {/* Zoom out */}
      <button onClick={() => zoomOut({ duration: 200 })} title="Zoom out">
        <svg viewBox="0 0 24 24"><line x1="5" y1="12" x2="19" y2="12"/></svg>
      </button>

      {/* Fit view */}
      <button onClick={() => fitView({ padding: 0.18, duration: 300 })} title="Fit view">
        <svg viewBox="0 0 24 24">
          <polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/>
          <line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/>
        </svg>
      </button>

      {/* Lock / unlock */}
      <button onClick={onToggleLock} className={locked ? 'active' : ''} title={locked ? 'Unlock' : 'Lock'}>
        {locked ? (
          <svg viewBox="0 0 24 24" className="filled">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4" fill="none" stroke="#fff" strokeWidth="2"/>
          </svg>
        ) : (
          <svg viewBox="0 0 24 24">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 9.9-1"/>
          </svg>
        )}
      </button>
    </div>
  );
}
