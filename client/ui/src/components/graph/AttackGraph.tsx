import { useCallback, useMemo } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  type Node,
  type Edge,
  type NodeTypes,
  Position,
  Handle,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { cn } from '../../lib/utils';
import { Card, CardHeader, CardTitle } from '../ui/Card';
import type { Finding } from '../../types';
import { Shield, Bug, Server, Globe } from 'lucide-react';

// ── Custom Node ──────────────────────────────────────────

interface AttackNodeData {
  label: string;
  type: 'target' | 'service' | 'vulnerability' | 'exploit';
  severity?: string;
}

function AttackNode({ data }: { data: AttackNodeData }) {
  const icons = {
    target: Globe,
    service: Server,
    vulnerability: Bug,
    exploit: Shield,
  };
  const colors = {
    target: 'border-pf-500 bg-pf-500/10',
    service: 'border-slate-500 bg-slate-500/10',
    vulnerability: 'border-orange-500 bg-orange-500/10',
    exploit: 'border-red-500 bg-red-500/10',
  };
  const Icon = icons[data.type];

  return (
    <div className={cn(
      'px-3 py-2 rounded-lg border-2 bg-surface-1 min-w-[120px]',
      'shadow-lg text-center',
      colors[data.type]
    )}>
      <Handle type="target" position={Position.Top} className="!bg-pf-500 !w-2 !h-2 !border-0" />
      <div className="flex items-center gap-1.5 justify-center">
        <Icon size={12} />
        <span className="text-[11px] font-medium text-text-primary">{data.label}</span>
      </div>
      {data.severity && (
        <span className="text-[9px] text-text-muted capitalize mt-0.5 block">{data.severity}</span>
      )}
      <Handle type="source" position={Position.Bottom} className="!bg-pf-500 !w-2 !h-2 !border-0" />
    </div>
  );
}

const nodeTypes: NodeTypes = {
  attack: AttackNode,
};

// ── Main Component ───────────────────────────────────────

interface AttackGraphProps {
  target: string;
  findings: Finding[];
  className?: string;
}

export function AttackGraph({ target, findings, className }: AttackGraphProps) {
  const { nodes, edges } = useMemo(() => {
    const n: Node<AttackNodeData>[] = [];
    const e: Edge[] = [];

    // Root target node
    n.push({
      id: 'target',
      type: 'attack',
      position: { x: 250, y: 0 },
      data: { label: target, type: 'target' },
    });

    // Group findings by category to create service nodes
    const categories = new Map<string, Finding[]>();
    findings.forEach((f) => {
      const existing = categories.get(f.category) ?? [];
      existing.push(f);
      categories.set(f.category, existing);
    });

    let serviceX = 0;
    const serviceSpacing = 200;

    categories.forEach((categoryFindings, category) => {
      const serviceId = `svc-${category}`;
      n.push({
        id: serviceId,
        type: 'attack',
        position: { x: serviceX, y: 120 },
        data: { label: category, type: 'service' },
      });
      e.push({
        id: `e-target-${serviceId}`,
        source: 'target',
        target: serviceId,
        animated: true,
        style: { stroke: '#3b82f6', strokeWidth: 1.5 },
      });

      categoryFindings.forEach((finding, i) => {
        const findingId = `f-${finding.id}`;
        n.push({
          id: findingId,
          type: 'attack',
          position: { x: serviceX - 40 + i * 80, y: 240 },
          data: {
            label: finding.title.slice(0, 20),
            type: finding.status === 'verified' ? 'exploit' : 'vulnerability',
            severity: finding.severity,
          },
        });
        e.push({
          id: `e-${serviceId}-${findingId}`,
          source: serviceId,
          target: findingId,
          style: {
            stroke: finding.severity === 'critical' ? '#ef4444' :
                    finding.severity === 'high' ? '#f97316' : '#64748b',
            strokeWidth: 1.5,
          },
        });
      });

      serviceX += serviceSpacing;
    });

    return { nodes: n, edges: e };
  }, [target, findings]);

  return (
    <Card className={cn('p-0 overflow-hidden', className)}>
      <CardHeader className="px-4 pt-3 pb-0">
        <CardTitle>Attack Graph</CardTitle>
      </CardHeader>
      <div className="h-80">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          minZoom={0.3}
          maxZoom={1.5}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="var(--border)" gap={20} size={1} />
          <Controls
            className="!bg-surface-2 !border-border !rounded-lg !shadow-lg [&>button]:!bg-surface-1 [&>button]:!border-border [&>button]:!text-text-muted [&>button:hover]:!bg-surface-3"
          />
          <MiniMap
            className="!bg-surface-2 !border-border !rounded-lg"
            nodeColor={(node) => {
              const d = node.data as AttackNodeData;
              return d.type === 'exploit' ? '#ef4444' :
                     d.type === 'vulnerability' ? '#f97316' :
                     d.type === 'service' ? '#64748b' : '#3b82f6';
            }}
          />
        </ReactFlow>
      </div>
    </Card>
  );
}