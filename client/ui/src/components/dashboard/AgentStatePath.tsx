import { useMemo, useState, useCallback } from 'react';
import ReactFlow, {
  Background,
  Controls,
  EdgeLabelRenderer,
  BaseEdge,
  Handle,
  Position,
  useReactFlow,
  useStore,
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
} from 'lucide-react';

import 'reactflow/dist/style.css';
import type { AgentInfo } from '../../types';
import { cn } from '../../lib/utils';
import { Badge } from '../ui/Badge';
import { Card, CardHeader, CardTitle } from '../ui/Card';

// ─── Types ────────────────────────────────────────────────────────────────────

interface AgentStatePathProps {
  agents: AgentInfo[];
}

type AgentName = AgentInfo['name'];
type AgentState = AgentInfo['state'];

interface AgentNodeData {
  role: AgentName | 'intel' | 'perceptor';
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
  // absolute Y coordinate the path should travel along (below executor layer)
  belowY: number;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const EXECUTOR_AGENTS: AgentName[] = ['recon', 'exploit', 'verify', 'report', 'retest'];

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

// ─── Layout ───────────────────────────────────────────────────────────────────

const LAYER_X      = 490;
const LAYER_Y      = 10;
const LAYER_HEIGHT = 610; // 5 agents × 100px + 10px gap + 60/30 padding

const EXECUTOR_X       = 530;
const EXECUTOR_Y_START = 55;
const EXECUTOR_Y_GAP   = 100; // 100px node height + ~0px gap (tight but spaced)

// Circle is h-16 = 64px. Handles must be at its vertical centre (32px)
// so edges connect to the middle of the circle, not the node wrapper edge.
const CIRCLE_HALF = 32;

// The feedback loop horizontal rail sits this many px below the layer bottom
const FEEDBACK_RAIL_OFFSET = 55;
const FEEDBACK_RAIL_Y      = LAYER_Y + LAYER_HEIGHT + FEEDBACK_RAIL_OFFSET;

// ─── Custom feedback loop edge ────────────────────────────────────────────────
// Draws an explicit L-shaped path:
//   Perceptor (bottom) → down to rail → left across → up into Planner (bottom)
// This guarantees the path travels below the executor layer regardless of
// how ReactFlow's router wants to place it.

function FeedbackLoopEdge({
  sourceX, sourceY,
  targetX, targetY,
  data,
  markerEnd,
}: EdgeProps<FeedbackEdgeData>) {
  const railY  = data?.belowY ?? sourceY + 80;
  const color  = data?.color  ?? '#f59e0b';
  const radius = 10;

  // Path: down from source → corner → left rail → corner → up to target
  const edgePath = [
    `M ${sourceX} ${sourceY}`,
    `L ${sourceX} ${railY - radius}`,
    `Q ${sourceX} ${railY} ${sourceX - radius} ${railY}`,
    `L ${targetX + radius} ${railY}`,
    `Q ${targetX} ${railY} ${targetX} ${railY - radius}`,
    `L ${targetX} ${targetY}`,
  ].join(' ');

  const labelX = (sourceX + targetX) / 2;
  const labelY = railY + 14;

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
            transform: `translate(-50%, 0) translate(${labelX}px, ${labelY}px)`,
            pointerEvents: 'none',
            fontSize:  10,
            color:     '#94a3b8',
            fontWeight: 600,
            whiteSpace: 'nowrap',
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
      {/* Left/Right handles pinned to circle vertical centre */}
      <Handle type="target"   position={Position.Left}               style={{ top: CIRCLE_HALF }} className="!h-2 !w-2 !border-0 !bg-pf-500" />
      <Handle type="target"   position={Position.Top}    id="top"    className="!h-2 !w-2 !border-0 !bg-pf-500" />
      <Handle type="target"   position={Position.Bottom} id="bottom-target" className="!h-2 !w-2 !border-0 !bg-pf-500" />

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

      <Handle type="source" position={Position.Right}  id="right"         style={{ top: CIRCLE_HALF }} className="!h-2 !w-2 !border-0 !bg-pf-500" />
      <Handle type="source" position={Position.Bottom} id="bottom-source" className="!h-2 !w-2 !border-0 !bg-pf-500" />
    </div>
  );
}

function ExecutorLayerNode({ data }: { data: ExecutorLayerData }) {
  return (
    <div
      className="rounded-2xl border border-pf-500/20 bg-pf-500/5 px-3 pt-3 shadow-inner"
      style={{ width: 200, height: LAYER_HEIGHT }}
    >
      <p className="text-center text-[10px] font-semibold uppercase tracking-widest text-pf-300">
        {data.label}
      </p>
      <p className="mt-1 text-center text-[10px] leading-snug text-text-secondary">
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

// ─── Main component ───────────────────────────────────────────────────────────

export function AgentStatePath({ agents }: AgentStatePathProps) {
  const { nodes, edges } = useMemo(() => {
    const byName = new Map(agents.map((a) => [a.name, a]));

    // ── Derived states ─────────────────────────────────────────────────────

    const planner      = byName.get('planner');
    const plannerState = planner?.state ?? 'waiting';

    const intelState: AgentState =
      plannerState === 'error'                                    ? 'error'
      : plannerState === 'running' || plannerState === 'success'  ? 'success'
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

    // ── Nodes ──────────────────────────────────────────────────────────────

    const graphNodes: Node[] = [
      {
        id:         'executor-layer',
        type:       'executorLayer',
        position:   { x: LAYER_X, y: LAYER_Y },
        selectable: false,
        draggable:  false,
        data:       { label: 'Executor Layer', subtitle: 'Parallel agents' } satisfies ExecutorLayerData,
        style:      { zIndex: 0 },
      },
      {
        id:       'intel',
        type:     'agent',
        position: { x: 40, y: 273 },
        data: { role: 'intel', label: 'Intel', state: intelState, currentTask: 'Context → Planner' } satisfies AgentNodeData,
      },
      {
        id:       'planner',
        type:     'agent',
        position: { x: 260, y: 273 },
        data: {
          role: 'planner', label: 'Planner', state: plannerState,
          currentTask: planner?.currentTask, progress: planner?.progress,
        } satisfies AgentNodeData,
      },
      ...EXECUTOR_AGENTS.map((name, i) => ({
        id:       name,
        type:     'agent',
        position: { x: EXECUTOR_X, y: EXECUTOR_Y_START + i * EXECUTOR_Y_GAP },
        data: {
          role:        name,
          label:       name.charAt(0).toUpperCase() + name.slice(1),
          state:       byName.get(name)?.state ?? 'waiting',
          currentTask: byName.get(name)?.currentTask,
          progress:    byName.get(name)?.progress,
        } satisfies AgentNodeData,
        style: { zIndex: 1 },
      })),
      {
        id:       'perceptor',
        type:     'agent',
        position: { x: 780, y: 273 },
        data: {
          role: 'perceptor', label: 'Perceptor', state: perceptorState,
          currentTask: runningExecutor ? `Reading ${runningExecutor}` : 'Aggregating output',
          progress:    perceptorProgress,
        } satisfies AgentNodeData,
      },
    ];

    // ── Edges ──────────────────────────────────────────────────────────────

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
      mkEdge('intel-planner', 'intel', 'planner', plannerState, { sourceHandle: 'right' }),

      ...EXECUTOR_AGENTS.map((name) =>
        mkEdge(`planner-${name}`, 'planner', name, byName.get(name)?.state ?? 'waiting', {
          sourceHandle: 'right',
        }),
      ),

      ...EXECUTOR_AGENTS.map((name) =>
        mkEdge(`${name}-perceptor`, name, 'perceptor', byName.get(name)?.state ?? 'waiting', {
          sourceHandle: 'right',
        }),
      ),

      // Feedback loop — custom edge type draws an explicit path below the
      // executor layer. The `belowY` value is passed as data so the edge
      // component knows exactly where to draw the horizontal rail.
      {
        id:           'perceptor-planner-loop',
        source:       'perceptor',
        target:       'planner',
        sourceHandle: 'bottom-source',
        targetHandle: 'bottom-target',
        type:         'feedbackLoop',
        data: {
          color:    EDGE_COLOR[perceptorState],
          animated: perceptorState === 'running',
          belowY:   FEEDBACK_RAIL_Y,
        } satisfies FeedbackEdgeData,
      },
    ];

    return { nodes: graphNodes, edges: graphEdges };
  }, [agents]);

  const [locked, setLocked] = useState(true);

  return (
    <Card className="overflow-hidden p-0">
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

      <CardHeader className="border-b border-border px-4 py-3">
        <CardTitle>Agent State Path</CardTitle>
        <p className="mt-1 text-xs text-text-secondary">
          Intel → Planner → Executor Layer (parallel) → Perceptor → Planner (feedback loop)
        </p>
      </CardHeader>

      <div className="relative h-[480px] bg-surface-0/60">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          fitView
          fitViewOptions={{ padding: 0.15 }}
          defaultViewport={{ x: 0, y: 0, zoom: 0.7 }}
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
      </div>
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
      <button onClick={() => fitView({ padding: 0.15, duration: 300 })} title="Fit view">
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