import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { Diamond } from "lucide-react";
import type { DecisionNodeData } from "@/types/playbook";

function DecisionNodeComponent({ data, selected }: NodeProps) {
  const nodeData = data as unknown as DecisionNodeData;

  return (
    <div
      className={`
        relative min-w-[220px] rounded-lg border-l-4 border-amber-500
        bg-slate-800 shadow-lg transition-all duration-150
        ${selected ? "ring-2 ring-amber-400/60 shadow-amber-500/20" : "hover:shadow-xl"}
      `}
    >
      {/* Input handle */}
      <Handle
        type="target"
        position={Position.Top}
        className="!w-3 !h-3 !bg-amber-500 !border-2 !border-slate-800"
      />

      <div className="flex items-center gap-2.5 px-3 py-2.5">
        <div className="flex items-center justify-center w-7 h-7 rounded-md bg-amber-500/20 shrink-0">
          <Diamond className="w-4 h-4 text-amber-400" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-xs font-semibold text-amber-400 uppercase tracking-wider">
            Decision
          </div>
          <div className="text-sm font-medium text-slate-100 truncate">
            {nodeData.label || "Untitled Decision"}
          </div>
          <div className="text-xs text-slate-400 truncate">
            {nodeData.condition || "No condition set"}
          </div>
        </div>
      </div>

      {/* Diamond shape indicator */}
      <div className="absolute -top-1 left-1/2 -translate-x-1/2 w-2 h-2 rotate-45 bg-amber-500" />

      {/* Two output handles: Yes and No */}
      <div className="flex justify-between px-6 pb-1">
        <div className="relative">
          <Handle
            type="source"
            position={Position.Bottom}
            id="yes"
            className="!w-3 !h-3 !bg-green-500 !border-2 !border-slate-800 !left-0"
            style={{ left: 0, right: "auto" }}
          />
          <span className="absolute -bottom-4 left-1/2 -translate-x-1/2 text-[10px] font-medium text-green-400">
            Yes
          </span>
        </div>
        <div className="relative">
          <Handle
            type="source"
            position={Position.Bottom}
            id="no"
            className="!w-3 !h-3 !bg-red-500 !border-2 !border-slate-800 !right-0"
            style={{ right: 0, left: "auto" }}
          />
          <span className="absolute -bottom-4 left-1/2 -translate-x-1/2 text-[10px] font-medium text-red-400">
            No
          </span>
        </div>
      </div>

      <div className="h-4" /> {/* Spacer for handle labels */}
    </div>
  );
}

export const DecisionNode = memo(DecisionNodeComponent);
