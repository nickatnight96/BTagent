/**
 * Unit tests for the hunt API client shape mapping.
 * Verifies that the TypeScript types mirror the backend Pydantic models exactly.
 */
import { describe, it, expect } from "vitest";
import type {
  HuntFinding,
  HuntFindingCluster,
  HuntFindingClusterListResponse,
  SuppressionRule,
  SuppressionMatch,
  HuntEntity,
  HuntObservable,
  PromoteFindingsResponse,
  CreateSuppressionRequest,
  SuppressClusterRequest,
  PromoteClusterRequest,
  SuppressionState,
  HuntFindingState,
  HuntDomain,
  HuntSource,
  Severity,
} from "@/types/hunt";

// --- Type-level shape mapping tests ---

describe("HuntFinding shape mirrors backend HuntFinding Pydantic model", () => {
  it("accepts a fully-populated finding", () => {
    const f: HuntFinding = {
      id: "hfnd_01",
      org_id: "org_default",
      source: "hunt_pack" as HuntSource,
      domain: "sigma" as HuntDomain,
      title: "Suspicious PowerShell",
      description: "Base64-encoded command observed",
      severity: "high" as Severity,
      confidence: 0.85,
      technique_ids: ["T1059.001"],
      entities: [{ kind: "host", value: "dc01.corp" } as HuntEntity],
      observables: [
        { type: "ip", value: "10.0.0.1" } as HuntObservable,
      ],
      state: "new" as HuntFindingState,
      cluster_id: null,
      suppressed_by: null,
      investigation_id: null,
      evidence: { run_id: "hrun_01" },
      created_at: "2026-06-01T12:00:00Z",
      updated_at: "2026-06-01T12:00:00Z",
    };
    expect(f.id).toBe("hfnd_01");
    expect(f.source).toBe("hunt_pack");
    expect(f.technique_ids).toHaveLength(1);
  });

  it("accepts optional nullable fields as null", () => {
    const f: HuntFinding = {
      id: "hfnd_02",
      org_id: "org_default",
      source: "behavioral",
      domain: "behavioral",
      title: "Outlier login",
      description: "",
      severity: "medium",
      confidence: 0.5,
      technique_ids: [],
      entities: [],
      observables: [],
      state: "clustered",
      cluster_id: "hclu_01",
      suppressed_by: null,
      investigation_id: null,
      evidence: {},
      created_at: "2026-06-01T12:00:00Z",
      updated_at: "2026-06-01T12:00:00Z",
    };
    expect(f.cluster_id).toBe("hclu_01");
    expect(f.suppressed_by).toBeNull();
  });
});

describe("HuntFindingCluster shape mirrors backend HuntFindingCluster Pydantic model", () => {
  it("accepts a cluster with all fields", () => {
    const c: HuntFindingCluster = {
      id: "hclu_01",
      org_id: "org_default",
      signature: "sigma/T1059.001",
      title: "Encoded PS on DC",
      domain: "sigma",
      severity: "high",
      technique_ids: ["T1059.001"],
      finding_count: 3,
      state: "clustered",
      representative_finding_id: "hfnd_01",
      created_at: "2026-06-01T12:00:00Z",
      updated_at: "2026-06-01T12:00:00Z",
    };
    expect(c.finding_count).toBe(3);
    expect(c.representative_finding_id).toBe("hfnd_01");
  });
});

describe("HuntFindingClusterListResponse shape", () => {
  it("matches the GET /hunt/findings response envelope", () => {
    const resp: HuntFindingClusterListResponse = {
      clusters: [],
      findings: [],
      total_clusters: 0,
      total_findings: 0,
    };
    expect(resp.total_clusters).toBe(0);
    expect(resp.total_findings).toBe(0);
    expect(Array.isArray(resp.clusters)).toBe(true);
    expect(Array.isArray(resp.findings)).toBe(true);
  });
});

describe("SuppressionRule shape mirrors backend SuppressionRule Pydantic model", () => {
  it("accepts a full suppression rule", () => {
    const match: SuppressionMatch = {
      source: "hunt_pack",
      domain: null,
      technique_ids: ["T1059.001"],
      entity_values: [],
      observable_values: [],
    };
    const rule: SuppressionRule = {
      id: "supp_01",
      org_id: "org_default",
      name: "Approved PS on DC",
      reason: "Approved admin task",
      match,
      state: "active" as SuppressionState,
      match_count: 2,
      created_by: "usr_01",
      created_at: "2026-06-01T12:00:00Z",
      expires_at: null,
      reconfirm_at: "2026-09-01T12:00:00Z",
    };
    expect(rule.match.technique_ids).toContain("T1059.001");
    expect(rule.expires_at).toBeNull();
    expect(rule.reconfirm_at).toBe("2026-09-01T12:00:00Z");
  });
});

describe("CreateSuppressionRequest shape", () => {
  it("requires name + reason + match", () => {
    const req: CreateSuppressionRequest = {
      name: "Approved admin PS",
      reason: "Change ticket #1234",
      match: {
        source: null,
        domain: "sigma",
        technique_ids: ["T1059.001"],
        entity_values: [],
        observable_values: [],
      },
    };
    expect(req.name).toBeTruthy();
    expect(req.reason).toBeTruthy();
  });

  it("accepts optional expiry + reconfirm fields", () => {
    const req: CreateSuppressionRequest = {
      name: "Test",
      reason: "Test",
      match: {
        technique_ids: [],
        entity_values: [],
        observable_values: [],
      },
      expires_in_hours: 720,
      reconfirm_in_hours: 2160,
    };
    expect(req.expires_in_hours).toBe(720);
    expect(req.reconfirm_in_hours).toBe(2160);
  });
});

describe("SuppressClusterRequest shape", () => {
  it("accepts omitted match (service derives from cluster pattern)", () => {
    const req: SuppressClusterRequest = {
      name: "Cluster rule",
      reason: "Bulk suppress approved cluster",
    };
    expect(req.match).toBeUndefined();
  });
});

describe("PromoteClusterRequest shape", () => {
  it("accepts optional title", () => {
    const req1: PromoteClusterRequest = {};
    const req2: PromoteClusterRequest = { title: "Suspicious activity cluster" };
    expect(req1.title).toBeUndefined();
    expect(req2.title).toBeTruthy();
  });
});

describe("PromoteFindingsResponse shape", () => {
  it("carries investigation_id and promoted finding ids", () => {
    const resp: PromoteFindingsResponse = {
      investigation_id: "inv_01",
      promoted_finding_ids: ["hfnd_01", "hfnd_02"],
    };
    expect(resp.investigation_id).toBe("inv_01");
    expect(resp.promoted_finding_ids).toHaveLength(2);
  });
});
