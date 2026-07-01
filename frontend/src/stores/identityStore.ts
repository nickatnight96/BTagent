/**
 * Identity Hunt Zustand store (#116 Phase B).
 *
 * State shape mirrors ``huntStore`` and ``behavioralStore``:
 * - Paginated identity finding list (domain=identity) with 30s polling.
 * - State-filter tabs (active / suppressed / promoted).
 * - Per-principal grouping: findings are aggregated client-side into
 *   ``PrincipalSummary`` objects sorted by finding count desc.
 * - Suppress / promote mutations delegating to the existing hunt endpoints.
 *
 * TODO (Phase C): Subscribe to ``HUNT_FINDING_*`` WebSocket events for
 * domain=identity to replace the polling fallback, same as HuntTriagePage.
 */

import { create } from "zustand";
import { ApiError } from "@/api/client";
import {
  listIdentityFindings,
  suppressIdentityFinding,
  promoteIdentityFindings,
  listIdentityGrants,
  getRevocationProposal,
  acceptRevocationProposal,
  rejectRevocationProposal,
} from "@/api/identity";
import type { HuntFinding, CreateSuppressionRequest } from "@/types/hunt";
import type {
  IdentityFindingEvidence,
  IdentityTimelineEntry,
  PrincipalSummary,
  GrantTableRow,
  OAuthGrant,
  GrantGraph,
  RevocationProposal,
} from "@/types/identity_hunt";

// Vertical spacing between rows in each column of the grant graph layout.
const GRAPH_ROW_GAP = 90;
const GRAPH_COL_X = { principal: 0, app: 360 } as const;

// --------------------------------------------------------------------------- //
// Consent / credential technique IDs (anomalous-consent panel filter)
// --------------------------------------------------------------------------- //

/**
 * MITRE ATT&CK technique IDs that indicate anomalous consent or SP credential
 * manipulation.  Findings whose ``technique_ids`` overlap this set are surfaced
 * in the dedicated consent panel.
 *
 * T1078.004 — Valid Accounts: Cloud Accounts (OAuth/OIDC grant abuse)
 * T1098.001 — Account Manipulation: Additional Cloud Credentials (SP secrets)
 */
export const CONSENT_TECHNIQUE_IDS = new Set(["T1078.004", "T1098.001"]);

// --------------------------------------------------------------------------- //
// Client-side aggregation helpers
// --------------------------------------------------------------------------- //

/** Severity sort order (higher index = higher priority). */
const SEVERITY_RANK: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function maxSeverity(a: string, b: string): string {
  return (SEVERITY_RANK[a] ?? 0) >= (SEVERITY_RANK[b] ?? 0) ? a : b;
}

/**
 * Extract ``principal_id`` from a finding's evidence dict.
 *
 * Falls back to the first entity value of kind "user" or "service_principal",
 * then to the finding id, so every finding can be grouped even when the
 * evidence is sparse.
 */
function extractPrincipalId(finding: HuntFinding): string {
  const ev = finding.evidence as IdentityFindingEvidence;
  if (ev?.principal_id) return ev.principal_id;
  const identityEntity = finding.entities.find(
    (e) => e.kind === "user" || e.kind === "service_principal",
  );
  if (identityEntity) return identityEntity.value;
  return finding.id;
}

/** Convert a HuntFinding into an IdentityTimelineEntry. */
function toTimelineEntry(finding: HuntFinding): IdentityTimelineEntry {
  const ev = finding.evidence as IdentityFindingEvidence;
  return {
    finding_id: finding.id,
    timestamp: (ev?.window_end as string | undefined) ?? finding.created_at,
    severity: finding.severity,
    label: finding.title,
    technique_ids: finding.technique_ids,
    evidence: ev ?? {},
    state: finding.state,
    cluster_id: finding.cluster_id,
  };
}

/** Returns true when a timeline entry is consent- or credential-related. */
function isConsentEntry(entry: IdentityTimelineEntry): boolean {
  return entry.technique_ids.some((t) => CONSENT_TECHNIQUE_IDS.has(t));
}

/**
 * Build per-principal summaries from a flat finding list.
 *
 * Sorted descending by ``finding_count`` so the most-active principal
 * appears first.  Ties are broken by ``max_severity`` descending.
 */
export function buildPrincipalSummaries(findings: HuntFinding[]): PrincipalSummary[] {
  const byPrincipal = new Map<
    string,
    { entries: IdentityTimelineEntry[]; max_severity: string }
  >();

  for (const f of findings) {
    const pid = extractPrincipalId(f);
    const entry = toTimelineEntry(f);
    const existing = byPrincipal.get(pid);
    if (existing) {
      existing.entries.push(entry);
      existing.max_severity = maxSeverity(existing.max_severity, f.severity);
    } else {
      byPrincipal.set(pid, { entries: [entry], max_severity: f.severity });
    }
  }

  const summaries: PrincipalSummary[] = [];
  for (const [principal_id, data] of byPrincipal.entries()) {
    // Sort timeline chronologically.
    const sorted = [...data.entries].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
    );
    summaries.push({
      principal_id,
      max_severity: data.max_severity,
      finding_count: data.entries.length,
      timeline: sorted,
      consent_findings: sorted.filter(isConsentEntry),
    });
  }

  // Sort by finding_count desc, then severity desc.
  return summaries.sort((a, b) => {
    if (b.finding_count !== a.finding_count) return b.finding_count - a.finding_count;
    return (SEVERITY_RANK[b.max_severity] ?? 0) - (SEVERITY_RANK[a.max_severity] ?? 0);
  });
}

/**
 * Build OAuth grant table rows from a finding list.
 *
 * Deduplicates by (principal_id, app_id) — the row with the highest
 * severity finding wins for display purposes.
 */
export function buildGrantTableRows(findings: HuntFinding[]): GrantTableRow[] {
  const byKey = new Map<string, GrantTableRow>();

  for (const f of findings) {
    const ev = f.evidence as IdentityFindingEvidence;
    const principal_id = extractPrincipalId(f);
    const app_id = ev?.app_id ?? "";
    if (!app_id) continue; // no app context — not a grant-related finding

    const key = `${principal_id}::${app_id}`;
    const existing = byKey.get(key);
    // Codex #217 P2: when a later finding wins on severity, REBUILD the row
    // from that winning finding's evidence — keeping a stale display_name /
    // scopes / consent_type while only updating severity + finding_id linked
    // the high-severity card to the right finding but showed grant details
    // from the earlier, lower-severity one, misleading triage.
    const candidate: GrantTableRow = {
      principal_id,
      app_id,
      app_display_name: (ev?.app_display_name as string | undefined) ?? app_id,
      scopes: Array.isArray(ev?.scopes) ? (ev.scopes as string[]) : [],
      consent_type: (ev?.consent_type as GrantTableRow["consent_type"] | undefined) ?? "unknown",
      finding_id: f.id,
      severity: f.severity,
    };
    if (existing) {
      if ((SEVERITY_RANK[f.severity] ?? 0) > (SEVERITY_RANK[existing.severity] ?? 0)) {
        byKey.set(key, candidate);
      }
    } else {
      byKey.set(key, candidate);
    }
  }

  return Array.from(byKey.values()).sort((a, b) =>
    (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0),
  );
}

/**
 * Build the principal × app node-link graph from a list of OAuthGrants
 * (the live ``/api/v1/identity/grants`` payload).
 *
 * Pure + deterministic so it unit-tests without a DOM:
 * - Distinct principals become one node each in the LEFT column; distinct
 *   apps one node each in the RIGHT column. Within a column nodes are ordered
 *   by first appearance and stacked ``GRAPH_ROW_GAP`` apart.
 * - Each grant becomes one principal→app edge carrying its consent_type,
 *   scope count, and revoked flag (the component colours/styles from these).
 * - Node ids are namespaced (``p:``/``a:``) so a principal and an app that
 *   happen to share a raw id can't collide.
 */
export function buildGrantGraph(grants: OAuthGrant[]): GrantGraph {
  const principalIds: string[] = [];
  const appIds: string[] = [];
  const principalSeen = new Set<string>();
  const appSeen = new Set<string>();
  const appLabels = new Map<string, string>();

  for (const g of grants) {
    if (!principalSeen.has(g.principal_id)) {
      principalSeen.add(g.principal_id);
      principalIds.push(g.principal_id);
    }
    if (!appSeen.has(g.app_id)) {
      appSeen.add(g.app_id);
      appIds.push(g.app_id);
    }
    // Prefer a non-empty display name for the app label.
    if (g.app_display_name && !appLabels.get(g.app_id)) {
      appLabels.set(g.app_id, g.app_display_name);
    }
  }

  const nodes: GrantGraph["nodes"] = [
    ...principalIds.map((pid, i) => ({
      id: `p:${pid}`,
      kind: "principal" as const,
      label: pid,
      position: { x: GRAPH_COL_X.principal, y: i * GRAPH_ROW_GAP },
    })),
    ...appIds.map((aid, i) => ({
      id: `a:${aid}`,
      kind: "app" as const,
      label: appLabels.get(aid) || aid,
      position: { x: GRAPH_COL_X.app, y: i * GRAPH_ROW_GAP },
    })),
  ];

  // One edge per grant. A dedup'd grant list yields at most one edge per
  // (principal, app, provider); we still key on grant id so distinct
  // providers between the same pair render as parallel edges.
  const edges: GrantGraph["edges"] = grants.map((g) => ({
    id: `e:${g.id}`,
    source: `p:${g.principal_id}`,
    target: `a:${g.app_id}`,
    consent_type: g.consent_type,
    scope_count: g.scopes.length,
    revoked: g.revoked_at !== null,
  }));

  return { nodes, edges };
}

// --------------------------------------------------------------------------- //
// Store types
// --------------------------------------------------------------------------- //

export type IdentityStateFilter = "active" | "suppressed" | "promoted";

interface IdentityState {
  findings: HuntFinding[];
  totalFindings: number;
  page: number;
  pageSize: number;
  stateFilter: IdentityStateFilter;

  isLoading: boolean;
  isMutating: boolean;
  error: string | null;

  /** Findings selected for bulk promotion. */
  selectedFindingIds: string[];

  /** Live OAuth grants from GET /api/v1/identity/grants (drives the graph). */
  grants: OAuthGrant[];
  grantsLoading: boolean;
  grantsError: string | null;

  /**
   * Revocation proposal surfaced after a promote (#116 Phase C slice 2).
   * ``revocationInvestigationId`` anchors the accept / reject calls; both are
   * null when the last promotion carried no grant-flavoured findings or the
   * analyst dismissed the panel.
   */
  revocationProposal: RevocationProposal | null;
  revocationInvestigationId: string | null;
  revocationMutating: boolean;
  revocationError: string | null;

  /** Hydrate identity findings from the backend. */
  fetchFindings: (opts?: { page?: number }) => Promise<void>;
  /** Hydrate the live OAuth grant graph (optionally scoped to a principal). */
  fetchGrants: (opts?: { principalId?: string; active?: boolean }) => Promise<void>;
  setStateFilter: (filter: IdentityStateFilter) => void;
  setPage: (page: number) => void;

  /** Suppress a single finding. */
  suppress: (findingId: string, body: CreateSuppressionRequest) => Promise<void>;
  /** Promote one or more findings into a new investigation. */
  promote: (findingIds: string[], title?: string) => Promise<string>;

  /** Accept the pending revocation proposal (HITL) — creates the playbook. */
  acceptRevocation: (rationale?: string) => Promise<void>;
  /** Reject the pending revocation proposal with a rationale. */
  rejectRevocation: (rationale?: string) => Promise<void>;
  /** Hide the proposal panel without deciding (the proposal stays pending). */
  dismissRevocationPanel: () => void;

  toggleSelected: (findingId: string) => void;
  clearSelection: () => void;
  clearError: () => void;
}

// --------------------------------------------------------------------------- //
// Helpers
// --------------------------------------------------------------------------- //

function extractErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    const body = err.body as { detail?: string } | null;
    if (body?.detail) return body.detail;
  }
  if (err instanceof Error) return err.message;
  return fallback;
}

// --------------------------------------------------------------------------- //
// Store
// --------------------------------------------------------------------------- //

export const useIdentityStore = create<IdentityState>((set, get) => ({
  findings: [],
  totalFindings: 0,
  page: 1,
  pageSize: 50,
  stateFilter: "active",

  isLoading: false,
  isMutating: false,
  error: null,

  selectedFindingIds: [],

  grants: [],
  grantsLoading: false,
  grantsError: null,

  revocationProposal: null,
  revocationInvestigationId: null,
  revocationMutating: false,
  revocationError: null,

  fetchFindings: async (opts) => {
    const { stateFilter, page: currentPage, pageSize } = get();
    const page = opts?.page ?? currentPage;
    set({ isLoading: true, error: null });
    try {
      const resp = await listIdentityFindings({
        state: stateFilter,
        page,
        page_size: pageSize,
      });
      // Flatten findings out of clusters for per-principal grouping.
      set({
        findings: resp.findings ?? [],
        totalFindings: resp.total_findings ?? 0,
        page,
        isLoading: false,
      });
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to load identity findings");
      set({ isLoading: false, error: message });
    }
  },

  fetchGrants: async (opts) => {
    set({ grantsLoading: true, grantsError: null });
    try {
      const resp = await listIdentityGrants({
        principal_id: opts?.principalId,
        active: opts?.active,
        page_size: 200,
      });
      set({ grants: resp.items ?? [], grantsLoading: false });
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to load OAuth grants");
      set({ grantsLoading: false, grantsError: message });
    }
  },

  setStateFilter: (filter) => {
    set({ stateFilter: filter, page: 1 });
  },

  setPage: (page) => {
    set({ page });
    void get().fetchFindings({ page });
  },

  suppress: async (findingId, body) => {
    set({ isMutating: true, error: null });
    try {
      await suppressIdentityFinding(findingId, body);
      await get().fetchFindings();
      set({ isMutating: false });
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to suppress finding");
      set({ isMutating: false, error: message });
      throw err;
    }
  },

  promote: async (findingIds, title) => {
    set({ isMutating: true, error: null });
    try {
      const resp = await promoteIdentityFindings(findingIds, title);
      set({ isMutating: false, selectedFindingIds: [] });
      await get().fetchFindings();
      // #116 Phase C: grant-flavoured promotions carry a revoke-playbook
      // proposal — surface it for the HITL decision. 404 simply means this
      // promotion had nothing to revoke; other errors are non-fatal to the
      // promote itself (the proposal stays reachable via the investigation).
      try {
        const proposal = await getRevocationProposal(resp.investigation_id);
        set({
          revocationProposal: proposal,
          revocationInvestigationId: resp.investigation_id,
          revocationError: null,
        });
      } catch (proposalErr) {
        if (!(proposalErr instanceof ApiError) || proposalErr.status !== 404) {
          set({
            revocationError: extractErrorMessage(
              proposalErr,
              "Failed to load revocation proposal",
            ),
          });
        }
      }
      return resp.investigation_id;
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to promote findings");
      set({ isMutating: false, error: message });
      throw err;
    }
  },

  acceptRevocation: async (rationale = "") => {
    const invId = get().revocationInvestigationId;
    if (!invId) return;
    set({ revocationMutating: true, revocationError: null });
    try {
      const updated = await acceptRevocationProposal(invId, rationale);
      set({ revocationMutating: false, revocationProposal: updated });
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to accept revocation proposal");
      set({ revocationMutating: false, revocationError: message });
      throw err;
    }
  },

  rejectRevocation: async (rationale = "") => {
    const invId = get().revocationInvestigationId;
    if (!invId) return;
    set({ revocationMutating: true, revocationError: null });
    try {
      const updated = await rejectRevocationProposal(invId, rationale);
      set({ revocationMutating: false, revocationProposal: updated });
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to reject revocation proposal");
      set({ revocationMutating: false, revocationError: message });
      throw err;
    }
  },

  dismissRevocationPanel: () =>
    set({
      revocationProposal: null,
      revocationInvestigationId: null,
      revocationError: null,
    }),

  toggleSelected: (findingId) => {
    const current = get().selectedFindingIds;
    set({
      selectedFindingIds: current.includes(findingId)
        ? current.filter((id) => id !== findingId)
        : [...current, findingId],
    });
  },

  clearSelection: () => set({ selectedFindingIds: [] }),

  clearError: () => set({ error: null }),
}));
