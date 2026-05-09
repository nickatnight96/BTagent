import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { Wrench } from "lucide-react";
import type { ActionNodeData } from "@/types/playbook";

function ActionNodeComponent({ id, data, selected }: NodeProps) {
  const nodeData = data as unknown as ActionNodeData;
  const argCount = nodeData.arguments ? Object.keys(nodeData.arguments).length : 0;

  return (
    <div
      data-testid={`playbook-builder-node-${id}`}
      data-node-type="action"
      className={`
        relative min-w-[220px] rounded-lg border-l-4 border-blue-500
        bg-slate-800 shadow-lg transition-all duration-150
        ${selected ? "ring-2 ring-blue-400/60 shadow-blue-500/20" : "hover:shadow-xl"}
      `}
    >
      {/* Input handle */}
      <Handle
        type="target"
        position={Position.Top}
        className="!w-3 !h-3 !bg-blue-500 !border-2 !border-slate-800"
      />

      <div className="flex items-center gap-2.5 px-3 py-2.5">
        <div className="flex items-center justify-center w-7 h-7 rounded-md bg-blue-500/20 shrink-0">
          <Wrench className="w-4 h-4 text-blue-400" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-xs font-semibold text-blue-400 uppercase tracking-wider">
            Action
          </div>
          <div className="text-sm font-medium text-slate-100 truncate">
            {nodeData.label || "Untitled Action"}
          </div>
          <div className="text-xs text-slate-400 truncate">
            {nodeData.toolName || "No tool selected"}
            {argCount > 0 ? ` (${argCount} args)` : ""}
          </div>
        </div>
      </div>

      {/* Output handle */}
      <Handle
        type="source"
        position={Position.Bottom}
        className="!w-3 !h-3 !bg-blue-500 !border-2 !border-slate-800"
      />
    </div>
  );
}

export const ActionNode = memo(ActionNodeComponent);
