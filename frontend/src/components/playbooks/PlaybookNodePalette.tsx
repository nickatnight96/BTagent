import { Zap, Wrench, Diamond, ShieldAlert, GitBranch, CircleCheckBig } from "lucide-react";
import type { DragEvent } from "react";

interface PaletteItem {
  type: string;
  label: string;
  description: string;
  icon: React.ReactNode;
  accentColor: string;
}

const PALETTE_ITEMS: PaletteItem[] = [
  {
    type: "trigger",
    label: "Trigger",
    description: "Starting condition for playbook",
    icon: <Zap className="w-4 h-4" />,
    accentColor: "text-green-400 bg-green-500/20 border-green-500/30",
  },
  {
    type: "action",
    label: "Action",
    description: "Execute a tool or MCP action",
    icon: <Wrench className="w-4 h-4" />,
    accentColor: "text-blue-400 bg-blue-500/20 border-blue-500/30",
  },
  {
    type: "decision",
    label: "Decision",
    description: "Branch on a condition (Yes/No)",
    icon: <Diamond className="w-4 h-4" />,
    accentColor: "text-amber-400 bg-amber-500/20 border-amber-500/30",
  },
  {
    type: "hitlGate",
    label: "HITL Gate",
    description: "Require human approval to proceed",
    icon: <ShieldAlert className="w-4 h-4" />,
    accentColor: "text-red-400 bg-red-500/20 border-red-500/30",
  },
  {
    type: "parallelFork",
    label: "Parallel Fork",
    description: "Fan-out to parallel branches",
    icon: <GitBranch className="w-4 h-4" />,
    accentColor: "text-purple-400 bg-purple-500/20 border-purple-500/30",
  },
  {
    type: "end",
    label: "End",
    description: "Terminal node, no further steps",
    icon: <CircleCheckBig className="w-4 h-4" />,
    accentColor: "text-slate-400 bg-slate-500/20 border-slate-500/30",
  },
];

export function PlaybookNodePalette() {
  const onDragStart = (event: DragEvent<HTMLDivElement>, nodeType: string) => {
    event.dataTransfer.setData("application/reactflow", nodeType);
    event.dataTransfer.effectAllowed = "move";
  };

  return (
    <div className="w-56 bg-slate-900 border-r border-slate-700/50 flex flex-col h-full">
      <div className="px-3 py-3 border-b border-slate-700/50">
        <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
          Node Palette
        </h3>
        <p className="text-xs text-slate-500 mt-1">
          Drag nodes onto the canvas
        </p>
      </div>

      <div className="flex-1 overflow-y-auto p-2 space-y-1.5">
        {PALETTE_ITEMS.map((item) => (
          <div
            key={item.type}
            draggable
            onDragStart={(e) => onDragStart(e, item.type)}
            className="flex items-start gap-2.5 p-2.5 rounded-lg border border-slate-700/50 bg-slate-800/50 cursor-grab active:cursor-grabbing hover:bg-slate-800 hover:border-slate-600/50 transition-all duration-150 select-none"
          >
            <div
              className={`flex items-center justify-center w-7 h-7 rounded-md border shrink-0 ${item.accentColor}`}
            >
              {item.icon}
            </div>
            <div className="min-w-0">
              <div className="text-sm font-medium text-slate-200">
                {item.label}
              </div>
              <div className="text-xs text-slate-500 leading-tight">
                {item.description}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
