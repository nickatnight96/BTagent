/**
 * Bidirectional conversion between React Flow graph and playbook YAML,
 * plus dagre-based auto-layout.
 */

import type { Node, Edge } from "@xyflow/react";
import {
  TriggerType,
  OnFailure,
  type TriggerNodeData,
  type ActionNodeData,
  type DecisionNodeData,
  type HITLGateNodeData,
  type ParallelForkNodeData,
} from "@/types/playbook";

// ---------------------------------------------------------------------------
// Dagre-like auto-layout (simple top-to-bottom without external dependency)
// ---------------------------------------------------------------------------

const NODE_WIDTH = 260;
const NODE_HEIGHT = 80;
const HORIZONTAL_SPACING = 80;
const VERTICAL_SPACING = 100;

function buildAdjacency(nodes: Node[], edges: Edge[]): Map<string, string[]> {
  const adj = new Map<string, string[]>();
  for (const n of nodes) {
    adj.set(n.id, []);
  }
  for (const e of edges) {
    const children = adj.get(e.source) ?? [];
    children.push(e.target);
    adj.set(e.source, children);
  }
  return adj;
}

function computeDepths(adj: Map<string, string[]>, roots: string[]): Map<string, number> {
  const depths = new Map<string, number>();
  const queue = [...roots];
  for (const r of roots) depths.set(r, 0);

  while (queue.length > 0) {
    const current = queue.shift()!;
    const depth = depths.get(current) ?? 0;
    for (const child of adj.get(current) ?? []) {
      const existing = depths.get(child);
      if (existing === undefined || existing < depth + 1) {
        depths.set(child, depth + 1);
        queue.push(child);
      }
    }
  }
  return depths;
}

export function autoLayout(nodes: Node[], edges: Edge[]): Node[] {
  if (nodes.length === 0) return nodes;

  const adj = buildAdjacency(nodes, edges);
  const hasIncoming = new Set<string>();
  for (const e of edges) hasIncoming.add(e.target);
  const roots = nodes.filter((n) => !hasIncoming.has(n.id)).map((n) => n.id);
  if (roots.length === 0) roots.push(nodes[0]!.id);

  const depths = computeDepths(adj, roots);

  // Group nodes by depth level
  const levels = new Map<number, string[]>();
  for (const [id, depth] of depths) {
    const level = levels.get(depth) ?? [];
    level.push(id);
    levels.set(depth, level);
  }

  // Also handle any unvisited nodes
  for (const n of nodes) {
    if (!depths.has(n.id)) {
      const maxDepth = Math.max(0, ...depths.values());
      const fallback = levels.get(maxDepth + 1) ?? [];
      fallback.push(n.id);
      levels.set(maxDepth + 1, fallback);
    }
  }

  const positions = new Map<string, { x: number; y: number }>();
  const sortedLevels = [...levels.keys()].sort((a, b) => a - b);

  for (const depth of sortedLevels) {
    const ids = levels.get(depth) ?? [];
    const totalWidth = ids.length * NODE_WIDTH + (ids.length - 1) * HORIZONTAL_SPACING;
    const startX = -totalWidth / 2;

    ids.forEach((id, index) => {
      positions.set(id, {
        x: startX + index * (NODE_WIDTH + HORIZONTAL_SPACING),
        y: depth * (NODE_HEIGHT + VERTICAL_SPACING),
      });
    });
  }

  return nodes.map((n) => {
    const pos = positions.get(n.id);
    return pos ? { ...n, position: { x: pos.x, y: pos.y } } : n;
  });
}

// ---------------------------------------------------------------------------
// Nodes/Edges -> YAML string
// ---------------------------------------------------------------------------

function yamlEscape(value: string): string {
  if (
    value.includes(":") ||
    value.includes("#") ||
    value.includes("'") ||
    value.includes('"') ||
    value.includes("\n") ||
    value.startsWith(" ") ||
    value.endsWith(" ")
  ) {
    return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
  }
  return value;
}

function objectToYaml(obj: Record<string, unknown>, level: number): string {
  const lines: string[] = [];
  for (const [key, value] of Object.entries(obj)) {
    if (value === null || value === undefined) continue;
    if (typeof value === "object" && !Array.isArray(value)) {
      lines.push(`${"  ".repeat(level)}${key}:`);
      lines.push(objectToYaml(value as Record<string, unknown>, level + 1));
    } else if (Array.isArray(value)) {
      lines.push(`${"  ".repeat(level)}${key}:`);
      for (const item of value) {
        if (typeof item === "object") {
          lines.push(`${"  ".repeat(level + 1)}-`);
          lines.push(objectToYaml(item as Record<string, unknown>, level + 2));
        } else {
          lines.push(`${"  ".repeat(level + 1)}- ${String(item)}`);
        }
      }
    } else if (typeof value === "string") {
      lines.push(`${"  ".repeat(level)}${key}: ${yamlEscape(value)}`);
    } else {
      lines.push(`${"  ".repeat(level)}${key}: ${String(value)}`);
    }
  }
  return lines.join("\n");
}

export function nodesToYAML(nodes: Node[], edges: Edge[]): string {
  const triggerNode = nodes.find((n) => n.type === "trigger");
  const stepNodes = nodes.filter((n) => n.type !== "trigger");

  // Build edge map for next_step resolution
  const edgeMap = new Map<string, Edge[]>();
  for (const e of edges) {
    const list = edgeMap.get(e.source) ?? [];
    list.push(e);
    edgeMap.set(e.source, list);
  }

  const lines: string[] = [];

  // Header
  const triggerData = triggerNode?.data as TriggerNodeData | undefined;
  lines.push(`name: ${yamlEscape(triggerData?.label ?? "Untitled Playbook")}`);
  lines.push("version: \"1.0\"");
  lines.push(`description: ${yamlEscape("Playbook created with visual builder")}`);
  lines.push("");

  // Trigger
  lines.push("trigger:");
  lines.push(`  type: ${triggerData?.triggerType ?? TriggerType.MANUAL}`);
  if (triggerData?.parameters && Object.keys(triggerData.parameters).length > 0) {
    lines.push("  parameters:");
    lines.push(objectToYaml(triggerData.parameters, 2));
  } else {
    lines.push("  parameters: {}");
  }
  lines.push("");

  // Steps
  lines.push("steps:");
  for (const node of stepNodes) {
    const outEdges = edgeMap.get(node.id) ?? [];
    const data = node.data as Record<string, unknown>;

    lines.push(`  - id: ${yamlEscape(node.id)}`);
    lines.push(`    type: ${node.type === "hitlGate" ? "hitl_gate" : node.type === "parallelFork" ? "parallel_fork" : node.type ?? "action"}`);
    lines.push(`    name: ${yamlEscape(String(data.label ?? node.id))}`);

    if (node.type === "action") {
      const actionData = data as unknown as ActionNodeData;
      if (actionData.toolName) {
        lines.push(`    tool_name: ${yamlEscape(actionData.toolName)}`);
      }
      if (actionData.arguments && Object.keys(actionData.arguments).length > 0) {
        lines.push("    arguments:");
        lines.push(objectToYaml(actionData.arguments, 3));
      }
      if (actionData.timeoutSeconds && actionData.timeoutSeconds !== 300) {
        lines.push(`    timeout_seconds: ${actionData.timeoutSeconds}`);
      }
      if (actionData.onFailure && actionData.onFailure !== OnFailure.ABORT) {
        lines.push(`    on_failure: ${actionData.onFailure}`);
      }
      const nextEdge = outEdges[0];
      if (nextEdge) lines.push(`    next_step: ${yamlEscape(nextEdge.target)}`);
    } else if (node.type === "decision") {
      const decData = data as unknown as DecisionNodeData;
      if (decData.condition) {
        lines.push(`    condition: ${yamlEscape(decData.condition)}`);
      }
      const trueEdge = outEdges.find((e) => e.sourceHandle === "yes");
      const falseEdge = outEdges.find((e) => e.sourceHandle === "no");
      if (trueEdge) lines.push(`    true_branch: ${yamlEscape(trueEdge.target)}`);
      if (falseEdge) lines.push(`    false_branch: ${yamlEscape(falseEdge.target)}`);
    } else if (node.type === "hitlGate") {
      const hitlData = data as unknown as HITLGateNodeData;
      if (hitlData.prompt) lines.push(`    prompt: ${yamlEscape(hitlData.prompt)}`);
      if (hitlData.timeoutSeconds) lines.push(`    timeout_seconds: ${hitlData.timeoutSeconds}`);
      if (hitlData.requiredRole) lines.push(`    required_role: ${yamlEscape(hitlData.requiredRole)}`);
      const nextEdge = outEdges[0];
      if (nextEdge) lines.push(`    next_step: ${yamlEscape(nextEdge.target)}`);
    } else if (node.type === "parallelFork") {
      const pfData = data as unknown as ParallelForkNodeData;
      if (outEdges.length > 0) {
        lines.push("    branches:");
        for (const e of outEdges) {
          lines.push(`      - [${yamlEscape(e.target)}]`);
        }
      }
      if (pfData.branchLabels && pfData.branchLabels.length > 0) {
        lines.push(`    # branch_labels: ${pfData.branchLabels.join(", ")}`);
      }
    } else if (node.type === "end") {
      // End nodes have no special config
    }

    lines.push("");
  }

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// YAML string -> Nodes/Edges
// ---------------------------------------------------------------------------

/** Minimal YAML-like parser for playbook structure. */
function parseSimpleYaml(yaml: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  const lines = yaml.split("\n");

  let i = 0;
  while (i < lines.length) {
    const line = lines[i]!;
    const trimmed = line.trimStart();

    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith("#")) {
      i++;
      continue;
    }

    const colonIdx = trimmed.indexOf(":");
    if (colonIdx === -1) {
      i++;
      continue;
    }

    const key = trimmed.substring(0, colonIdx).trim();
    const value = trimmed.substring(colonIdx + 1).trim();

    if (value === "" || value === "{}") {
      // Could be a nested object - for simplicity store as string
      result[key] = value === "{}" ? {} : "";
    } else {
      // Remove quotes if present
      const unquoted = value.replace(/^["']|["']$/g, "");
      result[key] = unquoted;
    }

    i++;
  }

  return result;
}

interface ParsedStep {
  id: string;
  type: string;
  name: string;
  tool_name?: string;
  condition?: string;
  true_branch?: string;
  false_branch?: string;
  next_step?: string;
  prompt?: string;
  timeout_seconds?: number;
  required_role?: string;
  on_failure?: string;
  arguments?: Record<string, unknown>;
  branches?: string[][];
}

function parseStepsFromYaml(yaml: string): { header: Record<string, string>; trigger: Record<string, string>; steps: ParsedStep[] } {
  const lines = yaml.split("\n");
  const header: Record<string, string> = {};
  const trigger: Record<string, string> = {};
  const steps: ParsedStep[] = [];

  let section: "header" | "trigger" | "steps" = "header";
  let currentStep: Partial<ParsedStep> | null = null;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    if (trimmed === "trigger:") {
      section = "trigger";
      continue;
    }
    if (trimmed === "steps:") {
      section = "steps";
      continue;
    }

    if (section === "header") {
      const colonIdx = trimmed.indexOf(":");
      if (colonIdx > 0) {
        const key = trimmed.substring(0, colonIdx).trim();
        const value = trimmed.substring(colonIdx + 1).trim().replace(/^["']|["']$/g, "");
        header[key] = value;
      }
    } else if (section === "trigger") {
      const colonIdx = trimmed.indexOf(":");
      if (colonIdx > 0) {
        const key = trimmed.substring(0, colonIdx).trim();
        const value = trimmed.substring(colonIdx + 1).trim().replace(/^["']|["']$/g, "");
        trigger[key] = value;
      }
    } else if (section === "steps") {
      if (trimmed.startsWith("- id:")) {
        // Save previous step
        if (currentStep?.id) {
          steps.push(currentStep as ParsedStep);
        }
        const id = trimmed.replace("- id:", "").trim().replace(/^["']|["']$/g, "");
        currentStep = { id };
      } else if (currentStep) {
        const colonIdx = trimmed.indexOf(":");
        if (colonIdx > 0) {
          const key = trimmed.substring(0, colonIdx).trim().replace("- ", "");
          const value = trimmed.substring(colonIdx + 1).trim().replace(/^["']|["']$/g, "");
          if (key === "timeout_seconds") {
            currentStep.timeout_seconds = parseInt(value, 10) || 300;
          } else {
            (currentStep as Record<string, unknown>)[key] = value;
          }
        }
      }
    }
  }

  // Don't forget the last step
  if (currentStep?.id) {
    steps.push(currentStep as ParsedStep);
  }

  return { header, trigger, steps };
}

function mapStepTypeToNodeType(stepType: string): string {
  switch (stepType) {
    case "hitl_gate":
      return "hitlGate";
    case "parallel_fork":
      return "parallelFork";
    case "action":
    case "decision":
    case "end":
      return stepType;
    default:
      return "action";
  }
}

function buildNodeData(step: ParsedStep, nodeType: string): Record<string, unknown> {
  const base = { label: step.name || step.id };

  switch (nodeType) {
    case "action":
      return {
        ...base,
        toolName: step.tool_name ?? "",
        arguments: step.arguments ?? {},
        timeoutSeconds: step.timeout_seconds ?? 300,
        onFailure: step.on_failure ?? OnFailure.ABORT,
      };
    case "decision":
      return {
        ...base,
        condition: step.condition ?? "",
      };
    case "hitlGate":
      return {
        ...base,
        prompt: step.prompt ?? "",
        timeoutSeconds: step.timeout_seconds ?? 3600,
        requiredRole: step.required_role ?? "senior_analyst",
      };
    case "parallelFork":
      return {
        ...base,
        branchCount: step.branches?.length ?? 2,
        branchLabels: [],
      };
    case "end":
      return base;
    default:
      return base;
  }
}

export function yamlToNodes(yaml: string): { nodes: Node[]; edges: Edge[] } {
  const { header, trigger, steps } = parseStepsFromYaml(yaml);

  const nodes: Node[] = [];
  const edges: Edge[] = [];

  // Create trigger node
  const triggerNode: Node = {
    id: "trigger-1",
    type: "trigger",
    position: { x: 0, y: 0 },
    data: {
      label: header.name ?? "Untitled Playbook",
      triggerType: (trigger.type as TriggerType) ?? TriggerType.MANUAL,
      parameters: {},
    } satisfies TriggerNodeData,
  };
  nodes.push(triggerNode);

  // Connect trigger to first step
  if (steps.length > 0) {
    edges.push({
      id: `e-trigger-1-${steps[0]!.id}`,
      source: "trigger-1",
      target: steps[0]!.id,
      type: "smoothstep",
    });
  }

  // Create step nodes
  for (const step of steps) {
    const nodeType = mapStepTypeToNodeType(step.type ?? "action");
    const data = buildNodeData(step, nodeType);

    nodes.push({
      id: step.id,
      type: nodeType,
      position: { x: 0, y: 0 },
      data,
    });

    // Create edges
    if (nodeType === "decision") {
      if (step.true_branch) {
        edges.push({
          id: `e-${step.id}-${step.true_branch}-yes`,
          source: step.id,
          target: step.true_branch,
          sourceHandle: "yes",
          label: "Yes",
          type: "smoothstep",
        });
      }
      if (step.false_branch) {
        edges.push({
          id: `e-${step.id}-${step.false_branch}-no`,
          source: step.id,
          target: step.false_branch,
          sourceHandle: "no",
          label: "No",
          type: "smoothstep",
        });
      }
    } else if (nodeType === "parallelFork" && step.branches) {
      for (const branch of step.branches) {
        for (const targetId of branch) {
          edges.push({
            id: `e-${step.id}-${targetId}`,
            source: step.id,
            target: targetId,
            type: "smoothstep",
          });
        }
      }
    } else if (step.next_step) {
      edges.push({
        id: `e-${step.id}-${step.next_step}`,
        source: step.id,
        target: step.next_step,
        type: "smoothstep",
      });
    }
  }

  // Auto-layout
  const layoutedNodes = autoLayout(nodes, edges);
  return { nodes: layoutedNodes, edges };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let _nodeCounter = 0;

export function generateNodeId(type: string): string {
  _nodeCounter++;
  return `${type}-${Date.now()}-${_nodeCounter}`;
}

export function resetNodeCounter(): void {
  _nodeCounter = 0;
}
