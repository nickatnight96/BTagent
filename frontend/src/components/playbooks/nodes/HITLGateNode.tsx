import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { ShieldAlert } from "lucide-react";
import type { HITLGateNodeData } from "@/types/playbook";

function HITLGateNodeComponent({ data, selected }: NodeProps) {
  const nodeData = data as unknown as HITLGateNodeData;

  return (
    <div
      className={`
        relative min-w-[220px] rounded-lg border-l-4 border-red-500
        bg-slate-800 shadow-lg transition-all duration-150
        ${selected ? "ring-2 ring-red-400/60 shadow-red-500/20" : "hover:shadow-xl"}
      `}
    >
      {/* Input handle */}
      <Handle
        type="target"
        position={Position.Top}
        className="!w-3 !h-3 !bg-red-500 !border-2 !border-slate-800"
      />

      <div className="flex items-center gap-2.5 px-3 py-2.5">
        <div className="flex items-center justify-center w-7 h-7 rounded-md bg-red-500/20 shrink-0">
          <ShieldAlert className="w-4 h-4 text-red-400" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-xs font-semibold text-red-400 uppercase tracking-wider">
            HITL Gate
          </div>
          <div className="text-sm font-medium text-slate-100 truncate">
            {nodeData.label || "Approval Required"}
          </div>
          <div className="text-xs text-slate-400 truncate">
            {nodeData.prompt || "Awaiting human approval"}
          </div>
          <div className="text-xs text-slate-500 mt-0.5">
            Role: {nodeData.requiredRole || "senior_analyst"}
          </div>
        </div>
      </div>

      {/* Output handle */}
      <Handle
        type="source"
        position={Position.Bottom}
        className="!w-3 !h-3 !bg-red-500 !border-2 !border-slate-800"
      />
    </div>
  );
}

export const HITLGateNode = memo(HITLGateNodeComponent);
