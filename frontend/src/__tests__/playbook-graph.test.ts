import { describe, it, expect } from "vitest";
import type { Edge, Node } from "@xyflow/react";

import { autoLayout } from "@/utils/playbook-graph";

function makeNode(id: string): Node {
  return { id, position: { x: 0, y: 0 }, data: {}, type: "default" };
}

function makeEdge(source: string, target: string): Edge {
  return { id: `${source}->${target}`, source, target };
}

describe("autoLayout — cycle guard (regression for codex P1 on #188)", () => {
  it("terminates on a 2-node back-edge cycle", () => {
    const nodes = ["A", "B"].map(makeNode);
    // A -> B -> A
    const edges = [makeEdge("A", "B"), makeEdge("B", "A")];

    const started = Date.now();
    const result = autoLayout(nodes, edges);
    const elapsed = Date.now() - started;

    // Returned every input node, positioned, in <100ms (was: infinite loop).
    expect(result).toHaveLength(2);
    expect(result.every((n) => typeof n.position.x === "number")).toBe(true);
    expect(result.every((n) => typeof n.position.y === "number")).toBe(true);
    expect(elapsed).toBeLessThan(100);
  });

  it("terminates on a 3-node cycle (A -> B -> C -> A)", () => {
    const nodes = ["A", "B", "C"].map(makeNode);
    const edges = [makeEdge("A", "B"), makeEdge("B", "C"), makeEdge("C", "A")];

    const started = Date.now();
    const result = autoLayout(nodes, edges);
    const elapsed = Date.now() - started;

    expect(result).toHaveLength(3);
    expect(elapsed).toBeLessThan(100);
  });

  it("terminates on a self-loop (A -> A)", () => {
    const nodes = [makeNode("A")];
    const edges = [makeEdge("A", "A")];

    const result = autoLayout(nodes, edges);

    expect(result).toHaveLength(1);
    expect(result[0]!.position.x).toBeDefined();
  });

  it("still produces a valid top-to-bottom layout for an acyclic DAG", () => {
    const nodes = ["A", "B", "C", "D"].map(makeNode);
    // A -> B -> D ; A -> C -> D
    const edges = [
      makeEdge("A", "B"),
      makeEdge("A", "C"),
      makeEdge("B", "D"),
      makeEdge("C", "D"),
    ];

    const result = autoLayout(nodes, edges);
    const byId = Object.fromEntries(result.map((n) => [n.id, n]));

    // A is the root (y=0); D is the leaf (deepest); B and C share a row.
    expect(byId["A"]!.position.y).toBe(0);
    expect(byId["B"]!.position.y).toBe(byId["C"]!.position.y);
    expect(byId["D"]!.position.y).toBeGreaterThan(byId["B"]!.position.y);
  });
});
