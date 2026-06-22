/**
 * Unit tests for cloud store helpers and Zustand store (#117 Phase B).
 *
 * Tests cover:
 *  1. ``buildTimeline``         — sorting and field extraction
 *  2. ``buildIAMLinks``         — assume_chain → IAMRelationship derivation
 *  3. ``buildWorkloadMatrix``   — managed vs shadow cell tallying
 *  4. ``buildShadowList``       — risk_score ordering
 *  5. ``buildTamperGroups``     — technique_family grouping
 *  6. ``useCloudStore``         — fetch, error, suppress, promote (mocked API)
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  buildTimeline,
  buildIAMLinks,
  buildWorkloadMatrix,
  buildShadowList,
  buildTamperGroups,
} from "@/stores/cloudStore";
import type { HuntFinding } from "@/types/hunt";

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

function cloudFinding(
  overrides: Partial<HuntFinding> & { id: string },
): HuntFinding {
  return {
    org_id: "org_default",
    source: "cloud",
    domain: "cloud",
    title: "Cloud finding " + overrides.id,
    description: "",
    severity: "medium",
    confidence: 0.8,
    technique_ids: [],
    entities: [],
    observables: [],
    state: "new",
    cluster_id: null,
    suppressed_by: null,
    investigation_id: null,
    evidence: {},
    created_at: "2026-06-01T12:00:00Z",
    updated_at: "2026-06-01T12:00:00Z",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// buildTimeline
// ---------------------------------------------------------------------------

describe("buildTimeline", () => {
  it("returns empty array for no findings", () => {
    expect(buildTimeline([])).toEqual([]);
  });

  it("extracts provider, account_id, actor, target from evidence", () => {
    const f = cloudFinding({
      id: "f1",
      evidence: {
        provider: "aws",
        account_id: "123456789012",
        actor_arn: "arn:aws:iam::123456789012:role/BadRole",
        target_arn: "arn:aws:s3:::sensitive-bucket",
      },
    });
    const [entry] = buildTimeline([f]);
    expect(entry?.provider).toBe("aws");
    expect(entry?.account_id).toBe("123456789012");
    expect(entry?.actor).toBe("arn:aws:iam::123456789012:role/BadRole");
    expect(entry?.target).toBe("arn:aws:s3:::sensitive-bucket");
  });

  it("defaults missing evidence fields to 'unknown'", () => {
    const f = cloudFinding({ id: "f2", evidence: {} });
    const [entry] = buildTimeline([f]);
    expect(entry?.provider).toBe("aws");
    expect(entry?.account_id).toBe("unknown");
    expect(entry?.actor).toBe("unknown");
    expect(entry?.target).toBe("unknown");
  });

  it("sorts findings chronologically (oldest first)", () => {
    const findings = [
      cloudFinding({ id: "f_late", created_at: "2026-06-03T00:00:00Z", evidence: {} }),
      cloudFinding({ id: "f_early", created_at: "2026-06-01T00:00:00Z", evidence: {} }),
      cloudFinding({ id: "f_mid", created_at: "2026-06-02T00:00:00Z", evidence: {} }),
    ];
    const timeline = buildTimeline(findings);
    expect(timeline.map((e) => e.finding_id)).toEqual(["f_early", "f_mid", "f_late"]);
  });

  it("preserves technique_ids from the finding", () => {
    const f = cloudFinding({ id: "f3", technique_ids: ["T1078", "T1550"], evidence: {} });
    const [entry] = buildTimeline([f]);
    expect(entry?.technique_ids).toEqual(["T1078", "T1550"]);
  });
});

// ---------------------------------------------------------------------------
// buildIAMLinks
// ---------------------------------------------------------------------------

describe("buildIAMLinks", () => {
  it("returns empty array for findings without assume_chain", () => {
    const f = cloudFinding({ id: "f1", evidence: {} });
    expect(buildIAMLinks([f])).toEqual([]);
  });

  it("returns empty array when assume_chain has fewer than 2 elements", () => {
    const f = cloudFinding({ id: "f1", evidence: { assume_chain: ["arn:aws:iam::111:role/A"] } });
    expect(buildIAMLinks([f])).toEqual([]);
  });

  it("emits one relationship per consecutive pair in the chain", () => {
    const f = cloudFinding({
      id: "f1",
      evidence: {
        assume_chain: [
          "arn:aws:iam::111:role/A",
          "arn:aws:iam::111:role/B",
          "arn:aws:iam::111:role/C",
        ],
      },
    });
    const links = buildIAMLinks([f]);
    expect(links).toHaveLength(2);
    expect(links[0]).toMatchObject({
      source_role: "arn:aws:iam::111:role/A",
      trustee: "arn:aws:iam::111:role/B",
      finding_id: "f1",
    });
    expect(links[1]).toMatchObject({
      source_role: "arn:aws:iam::111:role/B",
      trustee: "arn:aws:iam::111:role/C",
      finding_id: "f1",
    });
  });

  it("deduplicates identical source+trustee pairs across findings", () => {
    const chain = ["arn:aws:iam::111:role/A", "arn:aws:iam::111:role/B"];
    const findings = [
      cloudFinding({ id: "f1", evidence: { assume_chain: chain } }),
      cloudFinding({ id: "f2", evidence: { assume_chain: chain } }),
    ];
    const links = buildIAMLinks(findings);
    // Only one relationship despite two findings with the same chain.
    expect(links).toHaveLength(1);
  });

  it("flags cross-account relationships via ARN account-ID segment", () => {
    const f = cloudFinding({
      id: "f1",
      evidence: {
        assume_chain: [
          "arn:aws:iam::111111111111:role/Source",
          "arn:aws:iam::999999999999:role/Target",
        ],
      },
    });
    const [link] = buildIAMLinks([f]);
    expect(link?.is_cross_account).toBe(true);
  });

  it("does not flag same-account relationships as cross-account", () => {
    const f = cloudFinding({
      id: "f1",
      evidence: {
        assume_chain: [
          "arn:aws:iam::111111111111:role/Source",
          "arn:aws:iam::111111111111:role/Target",
        ],
      },
    });
    const [link] = buildIAMLinks([f]);
    expect(link?.is_cross_account).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// buildWorkloadMatrix
// ---------------------------------------------------------------------------

describe("buildWorkloadMatrix", () => {
  it("returns 15 cells (3 providers × 5 workload kinds) for no findings", () => {
    const matrix = buildWorkloadMatrix([]);
    // All cells should be zero.
    expect(matrix).toHaveLength(15);
    for (const cell of matrix) {
      expect(cell.managed_count).toBe(0);
      expect(cell.shadow_count).toBe(0);
    }
  });

  it("increments managed_count for non-shadow workload findings", () => {
    const f = cloudFinding({
      id: "f1",
      evidence: { provider: "aws", workload_kind: "bedrock_agentcore", shadow_workload: false },
    });
    const matrix = buildWorkloadMatrix([f]);
    const cell = matrix.find((c) => c.provider === "aws" && c.kind === "bedrock_agentcore");
    expect(cell?.managed_count).toBe(1);
    expect(cell?.shadow_count).toBe(0);
  });

  it("increments shadow_count for shadow workload findings", () => {
    const f = cloudFinding({
      id: "f1",
      evidence: { provider: "gcp", workload_kind: "cloud_run_mcp", shadow_workload: true },
    });
    const matrix = buildWorkloadMatrix([f]);
    const cell = matrix.find((c) => c.provider === "gcp" && c.kind === "cloud_run_mcp");
    expect(cell?.managed_count).toBe(0);
    expect(cell?.shadow_count).toBe(1);
  });

  it("tallies multiple findings into the correct cells", () => {
    const findings = [
      cloudFinding({
        id: "f1",
        evidence: { provider: "azure", workload_kind: "unmanaged", shadow_workload: true },
      }),
      cloudFinding({
        id: "f2",
        evidence: { provider: "azure", workload_kind: "unmanaged", shadow_workload: true },
      }),
      cloudFinding({
        id: "f3",
        evidence: { provider: "azure", workload_kind: "unmanaged", shadow_workload: false },
      }),
    ];
    const matrix = buildWorkloadMatrix(findings);
    const cell = matrix.find((c) => c.provider === "azure" && c.kind === "unmanaged");
    expect(cell?.shadow_count).toBe(2);
    expect(cell?.managed_count).toBe(1);
  });

  it("ignores findings without provider or workload_kind evidence", () => {
    const f = cloudFinding({ id: "f1", evidence: { shadow_workload: true } });
    const matrix = buildWorkloadMatrix([f]);
    // All counts stay zero.
    for (const cell of matrix) {
      expect(cell.managed_count + cell.shadow_count).toBe(0);
    }
  });
});

// ---------------------------------------------------------------------------
// buildShadowList
// ---------------------------------------------------------------------------

describe("buildShadowList", () => {
  it("returns only shadow findings", () => {
    const findings = [
      cloudFinding({ id: "shadow", evidence: { shadow_workload: true, risk_score: 0.8 } }),
      cloudFinding({ id: "managed", evidence: { shadow_workload: false, risk_score: 0.9 } }),
      cloudFinding({ id: "no-flag", evidence: {} }),
    ];
    const list = buildShadowList(findings);
    expect(list).toHaveLength(1);
    expect(list[0]!.id).toBe("shadow");
  });

  it("sorts by risk_score descending", () => {
    const findings = [
      cloudFinding({ id: "low", evidence: { shadow_workload: true, risk_score: 0.2 } }),
      cloudFinding({ id: "high", evidence: { shadow_workload: true, risk_score: 0.9 } }),
      cloudFinding({ id: "mid", evidence: { shadow_workload: true, risk_score: 0.5 } }),
    ];
    const list = buildShadowList(findings);
    expect(list.map((f) => f.id)).toEqual(["high", "mid", "low"]);
  });

  it("defaults missing risk_score to 0", () => {
    const findings = [
      cloudFinding({ id: "a", evidence: { shadow_workload: true } }),
      cloudFinding({ id: "b", evidence: { shadow_workload: true, risk_score: 0.5 } }),
    ];
    const list = buildShadowList(findings);
    // "b" (0.5) should come before "a" (defaulted to 0).
    expect(list[0]!.id).toBe("b");
  });
});

// ---------------------------------------------------------------------------
// buildTamperGroups
// ---------------------------------------------------------------------------

describe("buildTamperGroups", () => {
  it("returns an empty map for no findings", () => {
    expect(buildTamperGroups([])).toEqual(new Map());
  });

  it("groups findings by evidence.technique_family", () => {
    const findings = [
      cloudFinding({ id: "f1", evidence: { technique_family: "Privilege Escalation" } }),
      cloudFinding({ id: "f2", evidence: { technique_family: "Privilege Escalation" } }),
      cloudFinding({ id: "f3", evidence: { technique_family: "Defense Evasion" } }),
    ];
    const groups = buildTamperGroups(findings);
    expect(groups.get("Privilege Escalation")).toHaveLength(2);
    expect(groups.get("Defense Evasion")).toHaveLength(1);
  });

  it("puts findings without technique_family under 'Other'", () => {
    const f = cloudFinding({ id: "f1", evidence: {} });
    const groups = buildTamperGroups([f]);
    expect(groups.get("Other")).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// useCloudStore — light integration (mocked API)
// ---------------------------------------------------------------------------

const mockListCloudFindings = vi.fn();
const mockSuppressCloudFinding = vi.fn();
const mockPromoteCloudFindings = vi.fn();

vi.mock("@/api/cloud", () => ({
  listCloudFindings: (...a: unknown[]) => mockListCloudFindings(...a),
  suppressCloudFinding: (...a: unknown[]) => mockSuppressCloudFinding(...a),
  promoteCloudFindings: (...a: unknown[]) => mockPromoteCloudFindings(...a),
  getCloudFinding: vi.fn(),
}));

import { useCloudStore } from "@/stores/cloudStore";

beforeEach(() => {
  vi.clearAllMocks();
  useCloudStore.setState({
    findings: [],
    total: 0,
    page: 1,
    pageSize: 50,
    activeTab: "timeline",
    isLoading: false,
    isMutating: false,
    error: null,
  });
});

describe("useCloudStore.fetchFindings", () => {
  it("populates findings after client-side domain filter", async () => {
    const cloudFindingItem = cloudFinding({ id: "cloud-1" });
    const nonCloudFinding: HuntFinding = {
      ...cloudFinding({ id: "other-1" }),
      domain: "behavioral",
    };
    mockListCloudFindings.mockResolvedValueOnce({
      clusters: [],
      findings: [cloudFindingItem, nonCloudFinding],
      total_clusters: 0,
      total_findings: 2,
    });

    await useCloudStore.getState().fetchFindings();

    const { findings, isLoading, error } = useCloudStore.getState();
    // Client-side filter keeps only domain=cloud.
    expect(findings).toHaveLength(1);
    expect(findings[0]!.id).toBe("cloud-1");
    expect(isLoading).toBe(false);
    expect(error).toBeNull();
  });

  it("sets error on API failure", async () => {
    mockListCloudFindings.mockRejectedValueOnce(new Error("timeout"));
    await useCloudStore.getState().fetchFindings();
    expect(useCloudStore.getState().error).toBeTruthy();
    expect(useCloudStore.getState().isLoading).toBe(false);
  });
});

describe("useCloudStore.promote", () => {
  it("returns investigation_id and re-fetches on success", async () => {
    mockPromoteCloudFindings.mockResolvedValueOnce({
      investigation_id: "inv_abc",
      promoted_finding_ids: ["cloud-1"],
    });
    mockListCloudFindings.mockResolvedValueOnce({
      clusters: [],
      findings: [],
      total_clusters: 0,
      total_findings: 0,
    });

    const invId = await useCloudStore.getState().promote(["cloud-1"], "Test investigation");
    expect(invId).toBe("inv_abc");
    expect(mockListCloudFindings).toHaveBeenCalledTimes(1);
  });

  it("surfaces error and re-throws on failure", async () => {
    mockPromoteCloudFindings.mockRejectedValueOnce(new Error("forbidden"));
    await expect(useCloudStore.getState().promote(["cloud-1"])).rejects.toBeTruthy();
    expect(useCloudStore.getState().error).toBeTruthy();
    expect(useCloudStore.getState().isMutating).toBe(false);
  });
});

describe("useCloudStore.suppress", () => {
  it("calls suppressCloudFinding and re-fetches inbox on success", async () => {
    mockSuppressCloudFinding.mockResolvedValueOnce({ id: "sup_1" });
    mockListCloudFindings.mockResolvedValueOnce({
      clusters: [],
      findings: [],
      total_clusters: 0,
      total_findings: 0,
    });

    await useCloudStore.getState().suppress("cloud-1", {
      name: "suppress-test",
      reason: "test",
      match: { technique_ids: [], entity_values: [], observable_values: [] },
    });

    expect(mockSuppressCloudFinding).toHaveBeenCalledWith(
      "cloud-1",
      expect.objectContaining({ name: "suppress-test" }),
    );
    expect(mockListCloudFindings).toHaveBeenCalledTimes(1);
  });
});

describe("useCloudStore.setTab", () => {
  it("updates activeTab", () => {
    useCloudStore.getState().setTab("iam");
    expect(useCloudStore.getState().activeTab).toBe("iam");
  });
});
