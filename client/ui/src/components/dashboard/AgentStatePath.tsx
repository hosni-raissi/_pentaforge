import { useEffect, useMemo, useState } from "react";
import ReactFlow, {
  Background,
  BaseEdge,
  EdgeLabelRenderer,
  Handle,
  Position,
  useReactFlow,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeTypes,
  type EdgeTypes,
} from "reactflow";
import { Bot, Crosshair, Eye, X } from "lucide-react";

import "reactflow/dist/style.css";
import type { AgentInfo } from "../../types";
import { cn } from "../../lib/utils";
import { Badge } from "../ui/Badge";
import { Card, CardHeader, CardTitle } from "../ui/Card";

interface AgentStatePathProps {
  agents: AgentInfo[];
  showHeader?: boolean;
  className?: string;
  graphHeightClassName?: string;
  subtitle?: string;
  agentInsights?: Partial<Record<AgentGraphRole, AgentInsightPanelData>>;
}

export type AgentGraphRole = "planner" | "executer" | "analyzer";
type AgentState = AgentInfo["state"];

export interface AgentHistoryEntry {
  id: string;
  at: string;
  level: "info" | "success" | "warn" | "error";
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
  detail: string;
  state: AgentState;
  currentTask?: string;
  progress?: number;
}

interface FeedbackEdgeData {
  color: string;
  animated: boolean;
  railX: number;
}

const AGENT_ROLES: AgentGraphRole[] = ["planner", "executer", "analyzer"];
const AGENT_LABELS: Record<AgentGraphRole, string> = {
  planner: "Planner",
  executer: "Executer",
  analyzer: "Analyzer",
};
const AGENT_DETAILS: Record<AgentGraphRole, string> = {
  planner: "Checklist + plan + 2 active slots",
  executer: "Recon + exploit in parallel",
  analyzer: "Classify + filter + verify + persist",
};
const AGENT_ICONS = {
  planner: Bot,
  executer: Crosshair,
  analyzer: Eye,
} as const;

const STATE_RING: Record<AgentState, string> = {
  idle: "border-slate-500/50 bg-slate-500/10",
  running: "border-pf-500/70 bg-pf-500/15",
  success: "border-emerald-500/70 bg-emerald-500/15",
  error: "border-red-500/70 bg-red-500/15",
  waiting: "border-yellow-500/70 bg-yellow-500/15",
};

const EDGE_COLOR: Record<AgentState, string> = {
  idle: "#64748b",
  running: "#3b82f6",
  success: "#10b981",
  error: "#ef4444",
  waiting: "#f59e0b",
};

const CENTER_X = 240;
const PLANNER_Y = 44;
const EXECUTER_Y = 228;
const ANALYZER_Y = 412;
const FEEDBACK_RAIL_X = 510;
const NODE_HALF = 34;

function FeedbackLoopEdge({
  sourceX,
  sourceY,
  targetX,
  targetY,
  data,
  markerEnd,
}: EdgeProps<FeedbackEdgeData>) {
  const railX = data?.railX ?? sourceX + 100;
  const color = data?.color ?? "#f59e0b";
  const radius = 10;
  const path = [
    `M ${sourceX} ${sourceY}`,
    `L ${railX - radius} ${sourceY}`,
    `Q ${railX} ${sourceY} ${railX} ${sourceY - radius}`,
    `L ${railX} ${targetY + radius}`,
    `Q ${railX} ${targetY} ${railX - radius} ${targetY}`,
    `L ${targetX} ${targetY}`,
  ].join(" ");
  const labelX = railX + 14;
  const labelY = (sourceY + targetY) / 2;

  return (
    <>
      <BaseEdge
        path={path}
        markerEnd={markerEnd}
        style={{
          stroke: color,
          strokeWidth: 1.8,
          strokeDasharray: "6 4",
          fill: "none",
        }}
      />
      {data?.animated ? (
        <path
          d={path}
          fill="none"
          stroke={color}
          strokeWidth={1.8}
          strokeDasharray="6 4"
          opacity={0.6}
          style={{ animation: "dashmove 1s linear infinite" }}
        />
      ) : null}
      <EdgeLabelRenderer>
        <div
          style={{
            position: "absolute",
            transform: `translate(0, -50%) translate(${labelX}px, ${labelY}px)`,
            pointerEvents: "none",
            fontSize: 10,
            color: "#94a3b8",
            fontWeight: 600,
            whiteSpace: "nowrap",
            writingMode: "vertical-rl",
            textOrientation: "mixed",
          }}
          className="nodrag nopan"
        >
          planner rereads state
        </div>
      </EdgeLabelRenderer>
    </>
  );
}

function AgentNode({ data }: { data: AgentNodeData }) {
  const Icon = AGENT_ICONS[data.role] ?? Bot;

  return (
    <div className="flex flex-col items-center gap-1" style={{ minWidth: 180 }}>
      <Handle type="target" position={Position.Top} id="top" className="!h-2 !w-2 !border-0 !bg-pf-500" />
      <Handle
        type="target"
        position={Position.Left}
        id="left-target"
        className="!h-2 !w-2 !border-0 !bg-pf-500"
        style={{ top: NODE_HALF }}
      />
      <div
        className={cn(
          "flex h-20 w-20 flex-col items-center justify-center rounded-full border-2 shadow-sm",
          STATE_RING[data.state],
        )}
      >
        <Icon size={16} className="text-text-primary" />
        <span className="mt-1 text-[10px] font-semibold uppercase tracking-wider text-text-primary">
          {data.label}
        </span>
      </div>
      <Badge variant={data.state} dot className="text-[10px]">
        {data.state}
      </Badge>
      <p className="max-w-[180px] text-center text-[10px] text-text-secondary">
        {data.detail}
      </p>
      <p className="max-w-[180px] truncate text-[10px] text-text-muted">
        {data.currentTask?.trim() || "No active task"}
      </p>
      {typeof data.progress === "number" ? (
        <div className="w-[132px]">
          <div className="h-1 overflow-hidden rounded-full bg-surface-3">
            <div
              className="h-full rounded-full bg-pf-500 transition-all duration-300"
              style={{ width: `${Math.min(Math.max(data.progress, 0), 100)}%` }}
            />
          </div>
          <p className="mt-0.5 text-center text-[9px] text-text-muted">{data.progress}%</p>
        </div>
      ) : null}
      <Handle type="source" position={Position.Bottom} id="bottom" className="!h-2 !w-2 !border-0 !bg-pf-500" />
      <Handle
        type="source"
        position={Position.Right}
        id="right-source"
        className="!h-2 !w-2 !border-0 !bg-pf-500"
        style={{ top: NODE_HALF }}
      />
    </div>
  );
}

const nodeTypes: NodeTypes = {
  agent: AgentNode,
};

const edgeTypes: EdgeTypes = {
  feedbackLoop: FeedbackLoopEdge,
};

function formatNodeTime(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return "--:--:--";
  }
  return parsed.toLocaleTimeString();
}

function levelClass(level: AgentHistoryEntry["level"]): string {
  if (level === "error" || level === "warn") {
    return "text-red-300";
  }
  if (level === "success") {
    return "text-emerald-300";
  }
  return "text-text-secondary";
}

export function AgentStatePath({
  agents,
  showHeader = true,
  className,
  graphHeightClassName = "h-[560px]",
  subtitle = "Planner -> Executer -> Analyzer -> Planner",
  agentInsights,
}: AgentStatePathProps) {
  const { nodes, edges } = useMemo(() => {
    const byName = new Map(agents.map((agent) => [agent.name, agent]));
    const planner = byName.get("planner");
    const executer = byName.get("executer");
    const analyzer = byName.get("analyzer");

    const graphNodes: Node[] = [
      {
        id: "planner",
        type: "agent",
        position: { x: CENTER_X, y: PLANNER_Y },
        data: {
          role: "planner",
          label: AGENT_LABELS.planner,
          detail: AGENT_DETAILS.planner,
          state: planner?.state ?? "waiting",
          currentTask: planner?.currentTask,
          progress: planner?.progress,
        } satisfies AgentNodeData,
      },
      {
        id: "executer",
        type: "agent",
        position: { x: CENTER_X, y: EXECUTER_Y },
        data: {
          role: "executer",
          label: AGENT_LABELS.executer,
          detail: AGENT_DETAILS.executer,
          state: executer?.state ?? "waiting",
          currentTask: executer?.currentTask,
          progress: executer?.progress,
        } satisfies AgentNodeData,
      },
      {
        id: "analyzer",
        type: "agent",
        position: { x: CENTER_X, y: ANALYZER_Y },
        data: {
          role: "analyzer",
          label: AGENT_LABELS.analyzer,
          detail: AGENT_DETAILS.analyzer,
          state: analyzer?.state ?? "waiting",
          currentTask: analyzer?.currentTask,
          progress: analyzer?.progress,
        } satisfies AgentNodeData,
      },
    ];

    const mkEdge = (
      id: string,
      source: string,
      target: string,
      state: AgentState,
      opts: Partial<Edge> = {},
    ): Edge => ({
      id,
      source,
      target,
      type: "smoothstep",
      animated: state === "running",
      style: { stroke: EDGE_COLOR[state], strokeWidth: 1.8 },
      ...opts,
    });

    const graphEdges: Edge[] = [
      mkEdge("planner-executer", "planner", "executer", executer?.state ?? "waiting", {
        sourceHandle: "bottom",
        targetHandle: "top",
      }),
      mkEdge("executer-analyzer", "executer", "analyzer", analyzer?.state ?? "waiting", {
        sourceHandle: "bottom",
        targetHandle: "top",
      }),
      {
        id: "analyzer-planner-loop",
        source: "analyzer",
        target: "planner",
        sourceHandle: "right-source",
        targetHandle: "right-source",
        type: "feedbackLoop",
        data: {
          color: EDGE_COLOR[analyzer?.state ?? "waiting"],
          animated: analyzer?.state === "running",
          railX: FEEDBACK_RAIL_X,
        } satisfies FeedbackEdgeData,
      },
    ];

    return { nodes: graphNodes, edges: graphEdges };
  }, [agents]);

  const [locked, setLocked] = useState(true);
  const [selectedRole, setSelectedRole] = useState<AgentGraphRole | null>(null);

  useEffect(() => {
    if (!selectedRole) {
      return;
    }
    const roleStillPresent = nodes.some((entry) => entry.id === selectedRole && entry.type === "agent");
    if (!roleStillPresent) {
      setSelectedRole(null);
    }
  }, [nodes, selectedRole]);

  const selectedNodeData = useMemo(() => {
    if (!selectedRole) {
      return null;
    }
    const node = nodes.find((entry) => entry.id === selectedRole && entry.type === "agent");
    return node ? (node.data as AgentNodeData) : null;
  }, [nodes, selectedRole]);

  const selectedInsight = selectedRole ? agentInsights?.[selectedRole] : undefined;
  const selectedHistory = selectedInsight?.history ?? [];
  const selectedResult = selectedInsight?.result?.trim() ?? "";
  const selectedResultLabel = selectedInsight?.resultLabel ?? "Latest Result";

  return (
    <Card className={cn("overflow-hidden p-0", className)}>
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

      {showHeader ? (
        <CardHeader className="border-b border-border px-4 py-3">
          <CardTitle>Agent State Path</CardTitle>
          <p className="mt-1 text-sm text-text-secondary">{subtitle}</p>
        </CardHeader>
      ) : null}

      {selectedRole && selectedNodeData ? (
        <div className={cn("flex min-h-[560px] flex-col gap-3 bg-surface-0/60 p-3", graphHeightClassName)}>
          <div className="flex items-start justify-between rounded-md border border-border bg-surface-1/80 px-3 py-2">
            <div>
              <p className="text-sm font-semibold text-text-primary">{selectedNodeData.label} Details</p>
              <div className="mt-1 flex flex-wrap items-center gap-2">
                <Badge variant={selectedNodeData.state} dot className="text-xs">
                  {selectedNodeData.state}
                </Badge>
                {typeof selectedNodeData.progress === "number" ? (
                  <span className="text-xs font-mono text-text-muted">
                    Progress: {selectedNodeData.progress}%
                  </span>
                ) : null}
              </div>
              <p className="mt-1 text-xs text-text-secondary">{selectedNodeData.detail}</p>
              <p className="mt-1 text-xs text-text-secondary">
                {selectedNodeData.currentTask?.trim() || "No active task for this role."}
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
                  {selectedResult || "No returned result recorded for this role yet."}
                </p>
              </div>
            </div>

            <div className="min-h-0 rounded-md border border-border bg-surface-1/70 p-3">
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-text-muted">
                Full History
              </p>
              {selectedHistory.length === 0 ? (
                <div className="rounded-md border border-border/70 bg-surface-0/40 p-2">
                  <p className="text-sm text-text-muted">No historical logs for this role yet.</p>
                </div>
              ) : (
                <div className="h-full max-h-full space-y-1.5 overflow-y-auto rounded-md border border-border/70 bg-surface-0/40 p-2">
                  {selectedHistory.map((entry) => (
                    <div key={entry.id} className="rounded-md border border-border/70 bg-surface-1/40 p-1.5">
                      <div className="flex items-center justify-between text-xs text-text-muted">
                        <span className={cn("font-semibold uppercase tracking-wide", levelClass(entry.level))}>
                          {entry.level}
                        </span>
                        <span className="font-mono">{formatNodeTime(entry.at)}</span>
                      </div>
                      <p className="mt-1 text-sm text-text-primary">{entry.message}</p>
                      {entry.event ? (
                        <p className="mt-0.5 text-sm text-text-muted">event: {entry.event}</p>
                      ) : null}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      ) : (
        <div className={cn("relative min-h-[560px] bg-surface-0/60", graphHeightClassName)}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            onNodeClick={(_, node) => {
              if (node.type !== "agent" || !AGENT_ROLES.includes(node.id as AgentGraphRole)) {
                return;
              }
              setSelectedRole(node.id as AgentGraphRole);
            }}
            onInit={(instance) => instance.fitView({ padding: 0.2 })}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            minZoom={0.35}
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
            <CustomControls locked={locked} onToggleLock={() => setLocked((value) => !value)} />
          </ReactFlow>

          <div className="pointer-events-none absolute right-3 top-3 z-20 rounded-md border border-border bg-surface-1/90 px-2.5 py-1.5 text-xs text-text-secondary shadow">
            Click a role to inspect logs, results, and history
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
    <div className="pf-controls absolute bottom-3 left-3 z-10 flex flex-col gap-1">
      <button onClick={() => zoomIn({ duration: 200 })} title="Zoom in">
        <svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>
      </button>
      <button onClick={() => zoomOut({ duration: 200 })} title="Zoom out">
        <svg viewBox="0 0 24 24"><line x1="5" y1="12" x2="19" y2="12" /></svg>
      </button>
      <button onClick={() => fitView({ padding: 0.2, duration: 300 })} title="Fit view">
        <svg viewBox="0 0 24 24">
          <polyline points="15 3 21 3 21 9" /><polyline points="9 21 3 21 3 15" />
          <line x1="21" y1="3" x2="14" y2="10" /><line x1="3" y1="21" x2="10" y2="14" />
        </svg>
      </button>
      <button onClick={onToggleLock} className={locked ? "active" : ""} title={locked ? "Unlock" : "Lock"}>
        {locked ? (
          <svg viewBox="0 0 24 24" className="filled">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" fill="none" stroke="#fff" strokeWidth="2" />
          </svg>
        ) : (
          <svg viewBox="0 0 24 24">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 9.9-1" />
          </svg>
        )}
      </button>
    </div>
  );
}
