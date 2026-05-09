import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { Zap } from "lucide-react";
import type { TriggerNodeData } from "@/types/playbook";

const TRIGGER_LABELS: Record<string, string> = {
  alert_severity: "Alert Severity",
  ioc_type: "IOC Type",
  manual: "Manual",
  webhook: "Webhook",
  schedule: "Schedule",
};

function TriggerNodeComponent({ id, data, selected }: NodeProps) {
  const nodeData = data as unknown as TriggerNodeData;
  const triggerLabel = TRIGGER_LABELS[nodeData.triggerType] ?? nodeData.triggerType;

  return (
    <div
      data-testid={`playbook-builder-node-${id}`}
      data-node-type="trigger"
      className={`
        relative min-w-[220px] rounded-lg border-l-4 border-green-500
        bg-slate-800 shadow-lg transition-all duration-150
        ${selected ? "ring-2 ring-green-400/60 shadow-green-500/20" : "hover:shadow-xl"}
      `}
    >
      <div className="flex items-center gap-2.5 px-3 py-2.5">
        <div className="flex items-center justify-center w-7 h-7 rounded-md bg-green-500/20 shrink-0">
          <Zap className="w-4 h-4 text-green-400" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-xs font-semibold text-green-400 uppercase tracking-wider">
            Trigger
          </div>
          <div className="text-sm font-medium text-slate-100 truncate">
            {nodeData.label || "Untitled"}
          </div>
          <div className="text-xs text-slate-400 truncate">
            {triggerLabel}
            {nodeData.parameters && Object.keys(nodeData.parameters).length > 0
              ? ` (${Object.keys(nodeData.parameters).length} conditions)`
              : ""}
          </div>
        </div>
      </div>

      {/* Output handle only */}
      <Handle
        type="source"
        position={Position.Bottom}
        className="!w-3 !h-3 !bg-green-500 !border-2 !border-slate-800"
      />
    </div>
  );
}

export const TriggerNode = memo(TriggerNodeComponent);
