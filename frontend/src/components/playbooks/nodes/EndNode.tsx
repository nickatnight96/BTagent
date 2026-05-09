import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { CircleCheckBig } from "lucide-react";
import type { EndNodeData } from "@/types/playbook";

function EndNodeComponent({ id, data, selected }: NodeProps) {
  const nodeData = data as unknown as EndNodeData;

  return (
    <div
      data-testid={`playbook-builder-node-${id}`}
      data-node-type="end"
      className={`
        relative min-w-[180px] rounded-lg border-l-4 border-slate-500
        bg-slate-800 shadow-lg transition-all duration-150
        ${selected ? "ring-2 ring-slate-400/60 shadow-slate-500/20" : "hover:shadow-xl"}
      `}
    >
      {/* Input handle only */}
      <Handle
        type="target"
        position={Position.Top}
        className="!w-3 !h-3 !bg-slate-500 !border-2 !border-slate-800"
      />

      <div className="flex items-center gap-2.5 px-3 py-2.5">
        <div className="flex items-center justify-center w-7 h-7 rounded-md bg-slate-500/20 shrink-0">
          <CircleCheckBig className="w-4 h-4 text-slate-400" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            End
          </div>
          <div className="text-sm font-medium text-slate-100 truncate">
            {nodeData.label || "End"}
          </div>
        </div>
      </div>
    </div>
  );
}

export const EndNode = memo(EndNodeComponent);
