import { useCallback } from "react";
import { X } from "lucide-react";
import { usePlaybookStore } from "@/stores/playbookStore";
import { TriggerType, OnFailure } from "@/types/playbook";
import type {
  TriggerNodeData,
  ActionNodeData,
  DecisionNodeData,
  HITLGateNodeData,
  ParallelForkNodeData,
} from "@/types/playbook";

const TOOL_CATALOG = [
  "siem_query",
  "edr_isolate_host",
  "edr_get_process_tree",
  "cti_lookup_ioc",
  "cti_enrich_ip",
  "cti_enrich_domain",
  "cti_enrich_hash",
  "ticket_create",
  "ticket_update",
  "email_notify",
  "run_osquery",
  "block_ip",
  "disable_account",
  "quarantine_file",
];

const ROLE_OPTIONS = [
  "analyst",
  "senior_analyst",
  "incident_commander",
  "admin",
];

export function PlaybookConfigPanel() {
  const { builderNodes, selectedNodeId, updateNode, removeNode, setSelectedNode } =
    usePlaybookStore();

  const selectedNode = builderNodes.find((n) => n.id === selectedNodeId);

  const handleUpdate = useCallback(
    (field: string, value: unknown) => {
      if (!selectedNodeId) return;
      updateNode(selectedNodeId, { [field]: value });
    },
    [selectedNodeId, updateNode],
  );

  const handleClose = useCallback(() => {
    setSelectedNode(null);
  }, [setSelectedNode]);

  const handleDelete = useCallback(() => {
    if (!selectedNodeId) return;
    removeNode(selectedNodeId);
  }, [selectedNodeId, removeNode]);

  if (!selectedNode) {
    return (
      <div className="w-72 bg-slate-900 border-l border-slate-700/50 flex flex-col items-center justify-center text-center p-6">
        <p className="text-sm text-slate-500">
          Select a node on the canvas to configure its properties.
        </p>
      </div>
    );
  }

  const nodeType = selectedNode.type;
  const nodeData = selectedNode.data as Record<string, unknown>;

  return (
    <div className="w-72 bg-slate-900 border-l border-slate-700/50 flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-3 border-b border-slate-700/50">
        <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
          Node Config
        </h3>
        <button
          onClick={handleClose}
          className="p-1 rounded text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Config form */}
      <div className="flex-1 overflow-y-auto p-3 space-y-4">
        {/* Common: Label */}
        <FieldGroup label="Name">
          <input
            type="text"
            value={String(nodeData.label ?? "")}
            onChange={(e) => handleUpdate("label", e.target.value)}
            className="w-full px-2.5 py-1.5 text-sm bg-slate-800 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500 transition-colors"
            placeholder="Node name"
          />
        </FieldGroup>

        {/* Type-specific config */}
        {nodeType === "trigger" && (
          <TriggerConfig
            data={nodeData as unknown as TriggerNodeData}
            onUpdate={handleUpdate}
          />
        )}
        {nodeType === "action" && (
          <ActionConfig
            data={nodeData as unknown as ActionNodeData}
            onUpdate={handleUpdate}
          />
        )}
        {nodeType === "decision" && (
          <DecisionConfig
            data={nodeData as unknown as DecisionNodeData}
            onUpdate={handleUpdate}
          />
        )}
        {nodeType === "hitlGate" && (
          <HITLGateConfig
            data={nodeData as unknown as HITLGateNodeData}
            onUpdate={handleUpdate}
          />
        )}
        {nodeType === "parallelFork" && (
          <ParallelConfig
            data={nodeData as unknown as ParallelForkNodeData}
            onUpdate={handleUpdate}
          />
        )}

        {/* Node ID (read-only) */}
        <FieldGroup label="Node ID">
          <input
            type="text"
            value={selectedNode.id}
            readOnly
            className="w-full px-2.5 py-1.5 text-xs bg-slate-800/50 border border-slate-700/50 rounded-md text-slate-500 font-mono cursor-default"
          />
        </FieldGroup>
      </div>

      {/* Actions */}
      <div className="p-3 border-t border-slate-700/50">
        <button
          onClick={handleDelete}
          className="w-full px-3 py-1.5 text-sm font-medium text-red-400 bg-red-500/10 border border-red-500/20 rounded-md hover:bg-red-500/20 transition-colors"
        >
          Delete Node
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-config components
// ---------------------------------------------------------------------------

function FieldGroup({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-xs font-medium text-slate-400 mb-1">{label}</label>
      {children}
    </div>
  );
}

function TriggerConfig({
  data,
  onUpdate,
}: {
  data: TriggerNodeData;
  onUpdate: (field: string, value: unknown) => void;
}) {
  return (
    <>
      <FieldGroup label="Trigger Type">
        <select
          value={data.triggerType ?? TriggerType.MANUAL}
          onChange={(e) => onUpdate("triggerType", e.target.value)}
          className="w-full px-2.5 py-1.5 text-sm bg-slate-800 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
        >
          {Object.values(TriggerType).map((t) => (
            <option key={t} value={t}>
              {t.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
            </option>
          ))}
        </select>
      </FieldGroup>

      <FieldGroup label="Condition Parameters (JSON)">
        <textarea
          value={JSON.stringify(data.parameters ?? {}, null, 2)}
          onChange={(e) => {
            try {
              const parsed = JSON.parse(e.target.value) as Record<string, unknown>;
              onUpdate("parameters", parsed);
            } catch {
              // Don't update on invalid JSON
            }
          }}
          rows={4}
          className="w-full px-2.5 py-1.5 text-xs font-mono bg-slate-800 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500 resize-none"
          placeholder='{"severity": "critical"}'
        />
      </FieldGroup>
    </>
  );
}

function ActionConfig({
  data,
  onUpdate,
}: {
  data: ActionNodeData;
  onUpdate: (field: string, value: unknown) => void;
}) {
  return (
    <>
      <FieldGroup label="Tool Name">
        <select
          value={data.toolName ?? ""}
          onChange={(e) => onUpdate("toolName", e.target.value)}
          className="w-full px-2.5 py-1.5 text-sm bg-slate-800 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
        >
          <option value="">Select a tool...</option>
          {TOOL_CATALOG.map((tool) => (
            <option key={tool} value={tool}>
              {tool}
            </option>
          ))}
        </select>
      </FieldGroup>

      <FieldGroup label="Arguments (JSON)">
        <textarea
          value={JSON.stringify(data.arguments ?? {}, null, 2)}
          onChange={(e) => {
            try {
              const parsed = JSON.parse(e.target.value) as Record<string, unknown>;
              onUpdate("arguments", parsed);
            } catch {
              // Don't update on invalid JSON
            }
          }}
          rows={5}
          className="w-full px-2.5 py-1.5 text-xs font-mono bg-slate-800 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500 resize-none"
          placeholder='{"query": "..."}'
        />
      </FieldGroup>

      <FieldGroup label="Timeout (seconds)">
        <input
          type="number"
          value={data.timeoutSeconds ?? 300}
          onChange={(e) => onUpdate("timeoutSeconds", parseInt(e.target.value, 10) || 300)}
          min={1}
          max={86400}
          className="w-full px-2.5 py-1.5 text-sm bg-slate-800 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
        />
      </FieldGroup>

      <FieldGroup label="On Failure">
        <select
          value={data.onFailure ?? OnFailure.ABORT}
          onChange={(e) => onUpdate("onFailure", e.target.value)}
          className="w-full px-2.5 py-1.5 text-sm bg-slate-800 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
        >
          {Object.values(OnFailure).map((f) => (
            <option key={f} value={f}>
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </option>
          ))}
        </select>
      </FieldGroup>
    </>
  );
}

function DecisionConfig({
  data,
  onUpdate,
}: {
  data: DecisionNodeData;
  onUpdate: (field: string, value: unknown) => void;
}) {
  return (
    <FieldGroup label="Condition Expression">
      <textarea
        value={data.condition ?? ""}
        onChange={(e) => onUpdate("condition", e.target.value)}
        rows={3}
        className="w-full px-2.5 py-1.5 text-sm bg-slate-800 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500 resize-none"
        placeholder='e.g., result.severity == "critical"'
      />
      <p className="text-xs text-slate-500 mt-1">
        Key-path comparison. True branch goes to &quot;Yes&quot; output, false branch to &quot;No&quot;.
      </p>
    </FieldGroup>
  );
}

function HITLGateConfig({
  data,
  onUpdate,
}: {
  data: HITLGateNodeData;
  onUpdate: (field: string, value: unknown) => void;
}) {
  return (
    <>
      <FieldGroup label="Approval Prompt">
        <textarea
          value={data.prompt ?? ""}
          onChange={(e) => onUpdate("prompt", e.target.value)}
          rows={3}
          className="w-full px-2.5 py-1.5 text-sm bg-slate-800 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500 resize-none"
          placeholder="Approve containment action?"
        />
      </FieldGroup>

      <FieldGroup label="Timeout (seconds)">
        <input
          type="number"
          value={data.timeoutSeconds ?? 3600}
          onChange={(e) => onUpdate("timeoutSeconds", parseInt(e.target.value, 10) || 3600)}
          min={60}
          max={86400}
          className="w-full px-2.5 py-1.5 text-sm bg-slate-800 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
        />
      </FieldGroup>

      <FieldGroup label="Required Role">
        <select
          value={data.requiredRole ?? "senior_analyst"}
          onChange={(e) => onUpdate("requiredRole", e.target.value)}
          className="w-full px-2.5 py-1.5 text-sm bg-slate-800 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
        >
          {ROLE_OPTIONS.map((role) => (
            <option key={role} value={role}>
              {role.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
            </option>
          ))}
        </select>
      </FieldGroup>
    </>
  );
}

function ParallelConfig({
  data,
  onUpdate,
}: {
  data: ParallelForkNodeData;
  onUpdate: (field: string, value: unknown) => void;
}) {
  const handleBranchCount = (count: number) => {
    const clamped = Math.max(2, Math.min(8, count));
    onUpdate("branchCount", clamped);
    // Extend labels array if needed
    const labels = [...(data.branchLabels ?? [])];
    while (labels.length < clamped) {
      labels.push(`Branch ${labels.length + 1}`);
    }
    onUpdate("branchLabels", labels.slice(0, clamped));
  };

  const handleLabelChange = (index: number, value: string) => {
    const labels = [...(data.branchLabels ?? [])];
    labels[index] = value;
    onUpdate("branchLabels", labels);
  };

  const branchCount = data.branchCount ?? 2;
  const labels = data.branchLabels ?? [];

  return (
    <>
      <FieldGroup label="Branch Count">
        <input
          type="number"
          value={branchCount}
          onChange={(e) => handleBranchCount(parseInt(e.target.value, 10) || 2)}
          min={2}
          max={8}
          className="w-full px-2.5 py-1.5 text-sm bg-slate-800 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
        />
      </FieldGroup>

      <FieldGroup label="Branch Labels">
        <div className="space-y-1.5">
          {Array.from({ length: branchCount }, (_, i) => (
            <input
              key={i}
              type="text"
              value={labels[i] ?? `Branch ${i + 1}`}
              onChange={(e) => handleLabelChange(i, e.target.value)}
              className="w-full px-2.5 py-1.5 text-xs bg-slate-800 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
              placeholder={`Branch ${i + 1}`}
            />
          ))}
        </div>
      </FieldGroup>
    </>
  );
}
