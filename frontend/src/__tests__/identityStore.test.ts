/**
 * Unit tests for identityStore helpers and Zustand store (#116 Phase B).
 *
 * Tests cover:
 * - ``buildPrincipalSummaries``: per-principal grouping, severity aggregation,
 *   consent-finding extraction, chronological timeline sort.
 * - ``buildGrantTableRows``: grant dedup by (principal, app), severity precedence.
 * - Store integration: fetchFindings, suppress, promote mutations.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  buildPrincipalSummaries,
  buildGrantTableRows,
  buildGrantGraph,
  useIdentityStore,
  CONSENT_TECHNIQUE_IDS,
} from "@/stores/identityStore";
import type { HuntFinding } from "@/types/hunt";

// --------------------------------------------------------------------------- //
// Fixture helpers
// --------------------------------------------------------------------------- //

function finding(
  overrides: Partial<HuntFinding> & { id: string },
): HuntFinding {
  return {
    org_id: "org_test",
    source: "identity",
    domain: "identity",
    title: `Finding ${overrides.id}`,
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
    created_at: "2026-06-22T12:00:00Z",
    updated_at: "2026-06-22T12:00:00Z",
    ...overrides,
  };
}

// --------------------------------------------------------------------------- //
// CONSENT_TECHNIQUE_IDS
// --------------------------------------------------------------------------- //

describe("CONSENT_TECHNIQUE_IDS", () => {
  it("includes T1078.004 and T1098.001", () => {
    expect(CONSENT_TECHNIQUE_IDS.has("T1078.004")).toBe(true);
    expect(CONSENT_TECHNIQUE_IDS.has("T1098.001")).toBe(true);
  });

  it("does not include unrelated techniques", () => {
    expect(CONSENT_TECHNIQUE_IDS.has("T1059.001")).toBe(false);
  });
});

// --------------------------------------------------------------------------- //
// buildPrincipalSummaries
// --------------------------------------------------------------------------- //

describe("buildPrincipalSummaries", () => {
  it("returns empty array for no findings", () => {
    expect(buildPrincipalSummaries([])).toEqual([]);
  });

  it("groups findings by principal_id from evidence", () => {
    const summaries = buildPrincipalSummaries([
      finding({ id: "f1", evidence: { principal_id: "alice@corp" } }),
      finding({ id: "f2", evidence: { principal_id: "alice@corp" } }),
      finding({ id: "f3", evidence: { principal_id: "bob@corp" } }),
    ]);
    expect(summaries).toHaveLength(2);
    const alice = summaries.find((s) => s.principal_id === "alice@corp");
    expect(alice?.finding_count).toBe(2);
    const bob = summaries.find((s) => s.principal_id === "bob@corp");
    expect(bob?.finding_count).toBe(1);
  });

  it("falls back to entity value when evidence.principal_id is absent", () => {
    const summaries = buildPrincipalSummaries([
      finding({
        id: "f1",
        evidence: {},
        entities: [{ kind: "user", value: "svc-account@corp" }],
      }),
    ]);
    expect(summaries[0]?.principal_id).toBe("svc-account@corp");
  });

  it("falls back to finding.id when no entity or evidence principal", () => {
    const summaries = buildPrincipalSummaries([
      finding({ id: "f_fallback", evidence: {}, entities: [] }),
    ]);
    expect(summaries[0]?.principal_id).toBe("f_fallback");
  });

  it("computes max_severity across findings for the same principal", () => {
    const summaries = buildPrincipalSummaries([
      finding({ id: "f1", evidence: { principal_id: "p1" }, severity: "low" }),
      finding({ id: "f2", evidence: { principal_id: "p1" }, severity: "critical" }),
      finding({ id: "f3", evidence: { principal_id: "p1" }, severity: "medium" }),
    ]);
    expect(summaries[0]?.max_severity).toBe("critical");
  });

  it("sorts by finding_count descending", () => {
    const summaries = buildPrincipalSummaries([
      finding({ id: "f1", evidence: { principal_id: "p_low" } }),
      finding({ id: "f2", evidence: { principal_id: "p_high" } }),
      finding({ id: "f3", evidence: { principal_id: "p_high" } }),
      finding({ id: "f4", evidence: { principal_id: "p_high" } }),
    ]);
    expect(summaries[0]?.principal_id).toBe("p_high");
    expect(summaries[1]?.principal_id).toBe("p_low");
  });

  it("sorts timeline entries chronologically by timestamp", () => {
    const summaries = buildPrincipalSummaries([
      finding({
        id: "f_later",
        evidence: { principal_id: "p1", window_end: "2026-06-22T14:00:00Z" },
        created_at: "2026-06-22T14:00:00Z",
      }),
      finding({
        id: "f_earlier",
        evidence: { principal_id: "p1", window_end: "2026-06-22T10:00:00Z" },
        created_at: "2026-06-22T10:00:00Z",
      }),
    ]);
    const timeline = summaries[0]?.timeline ?? [];
    expect(timeline[0]?.finding_id).toBe("f_earlier");
    expect(timeline[1]?.finding_id).toBe("f_later");
  });

  it("extracts consent_findings for T1078.004 technique", () => {
    const summaries = buildPrincipalSummaries([
      finding({
        id: "f_consent",
        evidence: { principal_id: "p1" },
        technique_ids: ["T1078.004"],
      }),
      finding({
        id: "f_other",
        evidence: { principal_id: "p1" },
        technique_ids: ["T1059.001"],
      }),
    ]);
    expect(summaries[0]?.consent_findings).toHaveLength(1);
    expect(summaries[0]?.consent_findings[0]?.finding_id).toBe("f_consent");
  });

  it("extracts consent_findings for T1098.001 technique", () => {
    const summaries = buildPrincipalSummaries([
      finding({
        id: "f_sp_cred",
        evidence: { principal_id: "p1" },
        technique_ids: ["T1098.001"],
      }),
    ]);
    expect(summaries[0]?.consent_findings).toHaveLength(1);
  });

  it("uses evidence.window_end as timeline entry timestamp when present", () => {
    const summaries = buildPrincipalSummaries([
      finding({
        id: "f1",
        evidence: { principal_id: "p1", window_end: "2026-06-01T08:00:00Z" },
        created_at: "2026-06-22T12:00:00Z",
      }),
    ]);
    expect(summaries[0]?.timeline[0]?.timestamp).toBe("2026-06-01T08:00:00Z");
  });

  it("falls back to created_at when evidence.window_end is absent", () => {
    const summaries = buildPrincipalSummaries([
      finding({
        id: "f1",
        evidence: { principal_id: "p1" },
        created_at: "2026-06-22T12:00:00Z",
      }),
    ]);
    expect(summaries[0]?.timeline[0]?.timestamp).toBe("2026-06-22T12:00:00Z");
  });
});

// --------------------------------------------------------------------------- //
// buildGrantTableRows
// --------------------------------------------------------------------------- //

describe("buildGrantTableRows", () => {
  it("returns empty array for findings with no app_id", () => {
    const rows = buildGrantTableRows([
      finding({ id: "f1", evidence: { principal_id: "p1" } }),
    ]);
    expect(rows).toHaveLength(0);
  });

  it("creates one row per unique (principal, app) pair", () => {
    const rows = buildGrantTableRows([
      finding({ id: "f1", evidence: { principal_id: "p1", app_id: "app_A" } }),
      finding({ id: "f2", evidence: { principal_id: "p1", app_id: "app_A" } }),
      finding({ id: "f3", evidence: { principal_id: "p2", app_id: "app_A" } }),
    ]);
    expect(rows).toHaveLength(2);
  });

  it("keeps the highest-severity finding for each (principal, app) key", () => {
    const rows = buildGrantTableRows([
      finding({
        id: "f_low",
        severity: "low",
        evidence: { principal_id: "p1", app_id: "app_A" },
      }),
      finding({
        id: "f_high",
        severity: "high",
        evidence: { principal_id: "p1", app_id: "app_A" },
      }),
    ]);
    expect(rows[0]?.severity).toBe("high");
    expect(rows[0]?.finding_id).toBe("f_high");
  });

  it("populates scopes and consent_type from evidence", () => {
    const rows = buildGrantTableRows([
      finding({
        id: "f1",
        evidence: {
          principal_id: "p1",
          app_id: "app_A",
          scopes: ["Mail.Read", "offline_access"],
          consent_type: "admin",
        },
      }),
    ]);
    expect(rows[0]?.scopes).toEqual(["Mail.Read", "offline_access"]);
    expect(rows[0]?.consent_type).toBe("admin");
  });

  it("uses app_id as app_display_name fallback", () => {
    const rows = buildGrantTableRows([
      finding({
        id: "f1",
        evidence: { principal_id: "p1", app_id: "client_abc123" },
      }),
    ]);
    expect(rows[0]?.app_display_name).toBe("client_abc123");
  });

  it("uses app_display_name from evidence when present", () => {
    const rows = buildGrantTableRows([
      finding({
        id: "f1",
        evidence: {
          principal_id: "p1",
          app_id: "client_abc123",
          app_display_name: "My OAuth App",
        },
      }),
    ]);
    expect(rows[0]?.app_display_name).toBe("My OAuth App");
  });

  it("defaults consent_type to 'unknown' when absent", () => {
    const rows = buildGrantTableRows([
      finding({
        id: "f1",
        evidence: { principal_id: "p1", app_id: "app_A" },
      }),
    ]);
    expect(rows[0]?.consent_type).toBe("unknown");
  });

  it("sorts rows by severity descending", () => {
    const rows = buildGrantTableRows([
      finding({
        id: "f_low",
        severity: "low",
        evidence: { principal_id: "p1", app_id: "app_A" },
      }),
      finding({
        id: "f_crit",
        severity: "critical",
        evidence: { principal_id: "p2", app_id: "app_B" },
      }),
      finding({
        id: "f_med",
        severity: "medium",
        evidence: { principal_id: "p3", app_id: "app_C" },
      }),
    ]);
    expect(rows[0]?.severity).toBe("critical");
    expect(rows[1]?.severity).toBe("medium");
    expect(rows[2]?.severity).toBe("low");
  });
});

// --------------------------------------------------------------------------- //
// Store integration
// --------------------------------------------------------------------------- //

const mockListIdentityFindings = vi.fn();
const mockSuppressIdentityFinding = vi.fn();
const mockPromoteIdentityFindings = vi.fn();

vi.mock("@/api/identity", () => ({
  listIdentityFindings: (...a: unknown[]) => mockListIdentityFindings(...a),
  getIdentityFinding: vi.fn(),
  suppressIdentityFinding: (...a: unknown[]) => mockSuppressIdentityFinding(...a),
  promoteIdentityFindings: (...a: unknown[]) => mockPromoteIdentityFindings(...a),
}));

beforeEach(() => {
  vi.clearAllMocks();
  useIdentityStore.setState({
    findings: [],
    totalFindings: 0,
    page: 1,
    pageSize: 50,
    stateFilter: "active",
    isLoading: false,
    isMutating: false,
    error: null,
    selectedFindingIds: [],
  });
});

describe("useIdentityStore.fetchFindings", () => {
  it("populates findings and totalFindings from the API response", async () => {
    const items = [
      finding({ id: "f1", evidence: { principal_id: "p1" } }),
    ];
    mockListIdentityFindings.mockResolvedValueOnce({
      clusters: [],
      findings: items,
      total_clusters: 0,
      total_findings: 1,
    });

    await useIdentityStore.getState().fetchFindings();

    const { findings, totalFindings, isLoading, error } = useIdentityStore.getState();
    expect(findings).toEqual(items);
    expect(totalFindings).toBe(1);
    expect(isLoading).toBe(false);
    expect(error).toBeNull();
  });

  it("sets error on API failure", async () => {
    mockListIdentityFindings.mockRejectedValueOnce(new Error("network error"));

    await useIdentityStore.getState().fetchFindings();

    expect(useIdentityStore.getState().error).toBeTruthy();
    expect(useIdentityStore.getState().isLoading).toBe(false);
  });

  it("passes the stateFilter as the state param", async () => {
    mockListIdentityFindings.mockResolvedValueOnce({
      clusters: [],
      findings: [],
      total_clusters: 0,
      total_findings: 0,
    });
    useIdentityStore.setState({ stateFilter: "suppressed" });

    await useIdentityStore.getState().fetchFindings();

    expect(mockListIdentityFindings).toHaveBeenCalledWith(
      expect.objectContaining({ state: "suppressed" }),
    );
  });
});

describe("useIdentityStore.suppress", () => {
  it("calls suppressIdentityFinding and re-fetches on success", async () => {
    mockSuppressIdentityFinding.mockResolvedValueOnce({ id: "rule_1" });
    mockListIdentityFindings.mockResolvedValueOnce({
      clusters: [],
      findings: [],
      total_clusters: 0,
      total_findings: 0,
    });

    await useIdentityStore.getState().suppress("f1", {
      name: "Test",
      reason: "Testing",
      match: { technique_ids: [], entity_values: [], observable_values: [] },
    });

    expect(mockSuppressIdentityFinding).toHaveBeenCalledWith("f1", expect.any(Object));
    expect(mockListIdentityFindings).toHaveBeenCalledTimes(1);
    expect(useIdentityStore.getState().isMutating).toBe(false);
  });

  it("sets error and re-throws on API failure", async () => {
    mockSuppressIdentityFinding.mockRejectedValueOnce(new Error("500"));

    await expect(
      useIdentityStore.getState().suppress("f1", {
        name: "Test",
        reason: "Testing",
        match: { technique_ids: [], entity_values: [], observable_values: [] },
      }),
    ).rejects.toBeTruthy();

    expect(useIdentityStore.getState().error).toBeTruthy();
    expect(useIdentityStore.getState().isMutating).toBe(false);
  });
});

describe("useIdentityStore.promote", () => {
  it("returns investigation_id and re-fetches on success", async () => {
    mockPromoteIdentityFindings.mockResolvedValueOnce({
      investigation_id: "inv_abc",
      promoted_finding_ids: ["f1"],
    });
    mockListIdentityFindings.mockResolvedValueOnce({
      clusters: [],
      findings: [],
      total_clusters: 0,
      total_findings: 0,
    });

    const invId = await useIdentityStore.getState().promote(["f1"], "Test investigation");

    expect(invId).toBe("inv_abc");
    expect(mockListIdentityFindings).toHaveBeenCalledTimes(1);
    expect(useIdentityStore.getState().selectedFindingIds).toHaveLength(0);
  });
});

describe("useIdentityStore.toggleSelected", () => {
  it("adds a finding id when not already selected", () => {
    useIdentityStore.getState().toggleSelected("f1");
    expect(useIdentityStore.getState().selectedFindingIds).toContain("f1");
  });

  it("removes a finding id when already selected", () => {
    useIdentityStore.setState({ selectedFindingIds: ["f1"] });
    useIdentityStore.getState().toggleSelected("f1");
    expect(useIdentityStore.getState().selectedFindingIds).not.toContain("f1");
  });
});

describe("useIdentityStore.setStateFilter", () => {
  it("updates stateFilter and resets page to 1", () => {
    useIdentityStore.setState({ page: 3 });
    useIdentityStore.getState().setStateFilter("promoted");
    const { stateFilter, page } = useIdentityStore.getState();
    expect(stateFilter).toBe("promoted");
    expect(page).toBe(1);
  });
});

// --------------------------------------------------------------------------- //
// buildGrantGraph (#116 Phase C — live grant graph)
// --------------------------------------------------------------------------- //

import type { OAuthGrant } from "@/types/identity_hunt";

function grant(overrides: Partial<OAuthGrant> & { id: string }): OAuthGrant {
  return {
    org_id: "org_test",
    app_id: "app_slack",
    app_display_name: "Slack",
    principal_id: "alice@example.com",
    provider: "okta",
    scopes: ["openid", "profile"],
    consent_type: "user",
    granted_at: "2026-06-20T00:00:00Z",
    last_used: null,
    revoked_at: null,
    raw: {},
    ...overrides,
  };
}

describe("buildGrantGraph", () => {
  it("returns empty nodes/edges for no grants", () => {
    const g = buildGrantGraph([]);
    expect(g.nodes).toEqual([]);
    expect(g.edges).toEqual([]);
  });

  it("creates one node per distinct principal and app, namespaced by kind", () => {
    const g = buildGrantGraph([
      grant({ id: "g1", principal_id: "alice", app_id: "slack" }),
      grant({ id: "g2", principal_id: "alice", app_id: "zoom" }),
      grant({ id: "g3", principal_id: "bob", app_id: "slack" }),
    ]);
    const principalNodes = g.nodes.filter((n) => n.kind === "principal");
    const appNodes = g.nodes.filter((n) => n.kind === "app");
    expect(principalNodes.map((n) => n.id).sort()).toEqual(["p:alice", "p:bob"]);
    expect(appNodes.map((n) => n.id).sort()).toEqual(["a:slack", "a:zoom"]);
  });

  it("lays principals in the left column and apps in the right column", () => {
    const g = buildGrantGraph([
      grant({ id: "g1", principal_id: "alice", app_id: "slack" }),
      grant({ id: "g2", principal_id: "bob", app_id: "zoom" }),
    ]);
    const principals = g.nodes.filter((n) => n.kind === "principal");
    const apps = g.nodes.filter((n) => n.kind === "app");
    expect(new Set(principals.map((n) => n.position.x))).toEqual(new Set([0]));
    // Apps share a single x > principals' x; rows stack vertically.
    expect(apps.every((n) => n.position.x > 0)).toBe(true);
    expect(principals.map((n) => n.position.y)).toEqual([0, 90]);
  });

  it("emits one edge per grant carrying consent_type, scope_count and revoked", () => {
    const g = buildGrantGraph([
      grant({ id: "g1", scopes: ["a", "b", "c"], consent_type: "admin" }),
      grant({
        id: "g2",
        principal_id: "bob",
        app_id: "legacy",
        revoked_at: "2026-06-25T00:00:00Z",
        scopes: [],
      }),
    ]);
    expect(g.edges).toHaveLength(2);
    const e1 = g.edges.find((e) => e.id === "e:g1")!;
    expect(e1.source).toBe("p:alice@example.com");
    expect(e1.target).toBe("a:app_slack");
    expect(e1.consent_type).toBe("admin");
    expect(e1.scope_count).toBe(3);
    expect(e1.revoked).toBe(false);
    const e2 = g.edges.find((e) => e.id === "e:g2")!;
    expect(e2.revoked).toBe(true);
    expect(e2.scope_count).toBe(0);
  });

  it("prefers a non-empty app display name for the app node label", () => {
    const g = buildGrantGraph([
      grant({ id: "g1", app_id: "app_x", app_display_name: "" }),
      grant({ id: "g2", app_id: "app_x", app_display_name: "Acme App" }),
    ]);
    const appNode = g.nodes.find((n) => n.id === "a:app_x")!;
    expect(appNode.label).toBe("Acme App");
  });

  it("does not collide a principal and an app that share a raw id", () => {
    const g = buildGrantGraph([
      grant({ id: "g1", principal_id: "shared", app_id: "shared" }),
    ]);
    expect(g.nodes.map((n) => n.id).sort()).toEqual(["a:shared", "p:shared"]);
  });
});
