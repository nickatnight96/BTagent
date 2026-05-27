import { describe, it, expect } from "vitest";
import { groupFindingsByCluster } from "@/stores/huntStore";
import type { HuntFinding } from "@/types/hunt";

function finding(id: string, clusterId: string | null): HuntFinding {
  return {
    id,
    org_id: "org_default",
    source: "hunt_pack",
    domain: "sigma",
    title: id,
    description: "",
    severity: "medium",
    confidence: 0.5,
    technique_ids: [],
    entities: [],
    observables: [],
    state: "clustered",
    cluster_id: clusterId,
    suppressed_by: null,
    investigation_id: null,
    evidence: {},
    created_at: "2026-05-26T00:00:00Z",
    updated_at: "2026-05-26T00:00:00Z",
  };
}

describe("groupFindingsByCluster", () => {
  it("groups findings by their cluster id", () => {
    const grouped = groupFindingsByCluster([
      finding("a", "hclu_1"),
      finding("b", "hclu_1"),
      finding("c", "hclu_2"),
    ]);
    expect(grouped["hclu_1"]).toHaveLength(2);
    expect(grouped["hclu_2"]).toHaveLength(1);
  });

  it("buckets clusterless findings under the empty key", () => {
    const grouped = groupFindingsByCluster([finding("a", null)]);
    expect(grouped[""]).toHaveLength(1);
  });

  it("returns an empty object for no findings", () => {
    expect(groupFindingsByCluster([])).toEqual({});
  });
});
