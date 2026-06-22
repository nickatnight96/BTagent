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
  it("trusts the server-side domain=cloud filter and uses total_findings", async () => {
    // Codex #216 P1: the backend's list_findings now honours ``domain=cloud``
    // server-side, so the store passes whatever it gets straight through —
    // no client-side re-filter — and uses ``total_findings`` from the
    // response so pagination reflects the real cloud total (not the current
    // page length, which was the pre-fix bug).
    const cloudA = cloudFinding({ id: "cloud-1" });
    const cloudB = cloudFinding({ id: "cloud-2" });
    mockListCloudFindings.mockResolvedValueOnce({
      clusters: [],
      findings: [cloudA, cloudB],
      total_clusters: 0,
      total_findings: 142, // server-side total across all pages
    });

    await useCloudStore.getState().fetchFindings();

    const { findings, total, isLoading, error } = useCloudStore.getState();
    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.id)).toEqual(["cloud-1", "cloud-2"]);
    expect(total).toBe(142);
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


// ---------------------------------------------------------------------------
// Codex #216 regression — read REAL detector evidence keys
// ---------------------------------------------------------------------------

describe("Codex #216 regression — real-detector evidence keys", () => {
  it("buildIAMLinks reads evidence.path (the real detect_sts_chaining key)", () => {
    // Real Phase-A emitter writes ``evidence.path`` + ``evidence.detection`` ===
    // "sts_chaining" (not the legacy ``assume_chain`` we originally read).
    const f = cloudFinding({
      id: "f-codex-216-sts",
      evidence: {
        detection: "sts_chaining",
        path: [
          "arn:aws:iam::111111111111:role/A",
          "arn:aws:iam::222222222222:role/B",
          "arn:aws:iam::222222222222:role/C",
        ],
      },
    });
    const links = buildIAMLinks([f]);
    expect(links).toHaveLength(2);
    expect(links[0]!.source_role).toBe("arn:aws:iam::111111111111:role/A");
    expect(links[0]!.trustee).toBe("arn:aws:iam::222222222222:role/B");
    expect(links[0]!.is_cross_account).toBe(true); // 111… → 222…
    expect(links[1]!.source_role).toBe("arn:aws:iam::222222222222:role/B");
    expect(links[1]!.trustee).toBe("arn:aws:iam::222222222222:role/C");
  });

  it("buildWorkloadMatrix reads evidence.kind (the real shadow-workload key)", () => {
    // Real ``detect_shadow_workloads`` emits ``evidence.kind`` + ``provider`` +
    // ``shadow_workload: True`` — not the legacy ``workload_kind``.
    const f = cloudFinding({
      id: "f-codex-216-shadow",
      evidence: {
        provider: "aws",
        kind: "bedrock_agentcore",
        shadow_workload: true,
        detection: "shadow_workload",
      },
    });
    const cells = buildWorkloadMatrix([f]);
    const cell = cells.find((c) => c.provider === "aws" && c.kind === "bedrock_agentcore");
    expect(cell).toBeDefined();
    expect(cell!.shadow_count).toBe(1);
    expect(cell!.managed_count).toBe(0);
  });
});
