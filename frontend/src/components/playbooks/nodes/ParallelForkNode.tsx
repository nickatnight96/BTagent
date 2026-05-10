import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { GitBranch } from "lucide-react";
import type { ParallelForkNodeData } from "@/types/playbook";

function ParallelForkNodeComponent({ id, data, selected }: NodeProps) {
  const nodeData = data as unknown as ParallelForkNodeData;
  const branchCount = nodeData.branchCount || 2;

  // Generate output handles based on branch count
  const outputHandles = Array.from({ length: branchCount }, (_, i) => ({
    id: `branch-${i}`,
    label: nodeData.branchLabels?.[i] ?? `Branch ${i + 1}`,
  }));

  return (
    <div
      data-testid={`playbook-builder-node-${id}`}
      data-node-type="parallel_fork"
      className={`
        relative min-w-[220px] rounded-lg border-l-4 border-purple-500
        bg-slate-800 shadow-lg transition-all duration-150
        ${selected ? "ring-2 ring-purple-400/60 shadow-purple-500/20" : "hover:shadow-xl"}
      `}
    >
      {/* Input handle */}
      <Handle
        type="target"
        position={Position.Top}
        className="!w-3 !h-3 !bg-purple-500 !border-2 !border-slate-800"
      />

      <div className="flex items-center gap-2.5 px-3 py-2.5">
        <div className="flex items-center justify-center w-7 h-7 rounded-md bg-purple-500/20 shrink-0">
          <GitBranch className="w-4 h-4 text-purple-400" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-xs font-semibold text-purple-400 uppercase tracking-wider">
            Parallel Fork
          </div>
          <div className="text-sm font-medium text-slate-100 truncate">
            {nodeData.label || "Parallel Execution"}
          </div>
          <div className="text-xs text-slate-400">
            {branchCount} branches
          </div>
        </div>
      </div>

      {/* Multiple output handles */}
      <div className="flex justify-around px-4 pb-1">
        {outputHandles.map((handle, idx) => (
          <div key={handle.id} className="relative">
            <Handle
              type="source"
              position={Position.Bottom}
              id={handle.id}
              className="!w-3 !h-3 !bg-purple-400 !border-2 !border-slate-800"
              style={{
                left: `${((idx + 1) / (branchCount + 1)) * 100}%`,
              }}
            />
            <span className="absolute -bottom-4 left-1/2 -translate-x-1/2 text-[9px] font-medium text-purple-400 whitespace-nowrap">
              {handle.label}
            </span>
          </div>
        ))}
      </div>

      <div className="h-4" /> {/* Spacer for labels */}
    </div>
  );
}

export const ParallelForkNode = memo(ParallelForkNodeComponent);
