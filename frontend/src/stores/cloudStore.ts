/**
 * Cloud Control-Plane Hunter Zustand store (#117 Phase B).
 *
 * State shape
 * -----------
 * - ``findings``   — raw cloud HuntFindings (domain=cloud), paginated.
 * - ``activeTab``  — current view: timeline | iam | shadow_workloads | tamper.
 * - Derived views (computed from findings on every fetch, not re-stored):
 *     timeline     → buildTimeline()
 *     iamLinks     → buildIAMLinks()
 *     matrix       → buildWorkloadMatrix()
 *     shadowList   → sorted shadow findings
 *     tamperGroups → findings grouped by evidence.technique_family
 *
 * Polling: 30-second interval (same model as behavioralStore / huntStore).
 * WebSocket upgrade is deferred to Phase C.
 */

import { create } from "zustand";
import { ApiError } from "@/api/client";
import {
  listCloudFindings,
  suppressCloudFinding,
  promoteCloudFindings,
} from "@/api/cloud";
import type { HuntFinding, CreateSuppressionRequest } from "@/api/cloud";
import type {
  CloudProvider,
  CloudFindingEvidence,
  CloudTab,
  CloudTimelineEntry,
  IAMRelationship,
  WorkloadMatrixCell,
} from "@/types/cloud_hunt";
import {
  CLOUD_PROVIDERS_ORDERED as PROVIDERS,
  WORKLOAD_KINDS_ORDERED as KINDS,
} from "@/types/cloud_hunt";

// ---------------------------------------------------------------------------
// Pure derivation helpers (exported for unit tests)
// ---------------------------------------------------------------------------

/** Extract typed evidence from a HuntFinding. */
export function extractEvidence(finding: HuntFinding): CloudFindingEvidence {
  return (finding.evidence ?? {}) as CloudFindingEvidence;
}

/**
 * Build a control-plane event timeline from cloud findings.
 *
 * Sorted chronologically (oldest first) so the timeline reads top-to-bottom.
 * Grouped-by-account rendering happens in the component.
 */
export function buildTimeline(findings: HuntFinding[]): CloudTimelineEntry[] {
  return findings
    .map((f) => {
      const ev = extractEvidence(f);
      return {
        finding_id: f.id,
        created_at: f.created_at,
        provider: (ev.provider ?? "aws") as CloudProvider,
        account_id: ev.account_id ?? "unknown",
        actor: ev.actor_arn ?? "unknown",
        target: ev.target_arn ?? "unknown",
        technique_ids: f.technique_ids,
        title: f.title,
        severity: f.severity,
      } satisfies CloudTimelineEntry;
    })
    .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
}

/**
 * Build IAM role relationships from cloud findings that carry an STS-chain
 * trace in evidence.
 *
 * The Phase-A ``detect_sts_chaining`` detector emits the trace under
 * ``evidence.path`` (with ``evidence.detection === "sts_chaining"``). An older
 * ``assume_chain`` key is accepted as a fallback for any tests / replays still
 * shaped to the pre-#216 contract.
 *
 * For each chain ``[A, B, C, ...]`` we emit A→B, B→C, etc. (each step).
 * Duplicate relationships (same source_role + trustee pair) are deduplicated,
 * keeping the first occurrence.
 */
export function buildIAMLinks(findings: HuntFinding[]): IAMRelationship[] {
  const seen = new Set<string>();
  const links: IAMRelationship[] = [];

  for (const f of findings) {
    const ev = extractEvidence(f);
    // Prefer the real emitter's key (``evidence.path``); fall back to the
    // legacy ``assume_chain`` for any caller still shaped that way.
    const chain = Array.isArray(ev.path) ? ev.path : ev.assume_chain;
    if (!Array.isArray(chain) || chain.length < 2) continue;

    for (let i = 0; i < chain.length - 1; i++) {
      const source = chain[i];
      const trustee = chain[i + 1];
      if (!source || !trustee) continue;

      const key = `${source}|${trustee}`;
      if (seen.has(key)) continue;
      seen.add(key);

      // Simple cross-account heuristic: AWS ARNs contain account IDs in
      // position 4 (arn:aws:iam::<account-id>:role/...). If the account
      // segment differs, flag as cross-account.
      const isCrossAccount = detectCrossAccount(source, trustee);

      links.push({
        source_role: source,
        trustee,
        finding_id: f.id,
        is_cross_account: isCrossAccount,
      });
    }
  }

  return links;
}

/**
 * Heuristic cross-account detection.
 * Extracts the account-ID segment from AWS ARNs (index 4 in ':'-split).
 * Returns false for non-ARN identifiers (GCP, Azure).
 */
function detectCrossAccount(a: string, b: string): boolean {
  const partsA = a.split(":");
  const partsB = b.split(":");
  if (partsA.length < 5 || partsB.length < 5) return false;
  const accA = partsA[4];
  const accB = partsB[4];
  return Boolean(accA && accB && accA !== accB);
}

/**
 * Build the agentic-workload inventory matrix.
 *
 * Each cloud finding may carry ``evidence.provider`` and a workload kind
 * under ``evidence.kind`` (the real ``detect_shadow_workloads`` /
 * ``detect_overprivileged_workload_identity`` emitters), with a legacy
 * ``evidence.workload_kind`` accepted as a fallback. Shadow status comes
 * from ``evidence.shadow_workload === true``.
 *
 * Returns one cell per (provider × workload_kind) pair in the ordered matrix.
 * Cells with zero count for both managed and shadow are still emitted so the
 * table renders a complete grid.
 */
export function buildWorkloadMatrix(findings: HuntFinding[]): WorkloadMatrixCell[] {
  const counts = new Map<string, WorkloadMatrixCell>();

  // Initialise all cells to zero.
  for (const p of PROVIDERS) {
    for (const k of KINDS) {
      counts.set(`${p}|${k}`, {
        provider: p,
        kind: k,
        managed_count: 0,
        shadow_count: 0,
      });
    }
  }

  // Tally from findings.
  for (const f of findings) {
    const ev = extractEvidence(f);
    const provider = ev.provider;
    // Prefer the real emitter's key (``evidence.kind``); fall back to the
    // legacy ``workload_kind``.
    const kind = ev.kind ?? ev.workload_kind;
    if (!provider || !kind) continue;

    const key = `${provider}|${kind}`;
    const cell = counts.get(key);
    if (!cell) continue;

    if (ev.shadow_workload === true) {
      cell.shadow_count += 1;
    } else {
      cell.managed_count += 1;
    }
  }

  return Array.from(counts.values());
}

/**
 * Extract shadow-workload findings, sorted by risk_score desc.
 *
 * A finding is a shadow workload finding when
 * ``evidence.shadow_workload === true``.
 */
export function buildShadowList(findings: HuntFinding[]): HuntFinding[] {
  return findings
    .filter((f) => extractEvidence(f).shadow_workload === true)
    .sort((a, b) => {
      const ra = (extractEvidence(a).risk_score as number | undefined) ?? 0;
      const rb = (extractEvidence(b).risk_score as number | undefined) ?? 0;
      return rb - ra;
    });
}

/**
 * Group findings by MITRE technique family (from
 * ``evidence.technique_family``). Findings without a family land in "Other".
 */
export function buildTamperGroups(
  findings: HuntFinding[],
): Map<string, HuntFinding[]> {
  const groups = new Map<string, HuntFinding[]>();
  for (const f of findings) {
    const family = (extractEvidence(f).technique_family as string | undefined) ?? "Other";
    const bucket = groups.get(family) ?? [];
    bucket.push(f);
    groups.set(family, bucket);
  }
  return groups;
}

// ---------------------------------------------------------------------------
// Store types
// ---------------------------------------------------------------------------

interface CloudState {
  findings: HuntFinding[];
  total: number;
  page: number;
  pageSize: number;
  activeTab: CloudTab;

  isLoading: boolean;
  isMutating: boolean;
  error: string | null;

  /** Fetch cloud findings (domain=cloud) from the hunt API. */
  fetchFindings: (opts?: { page?: number }) => Promise<void>;
  setTab: (tab: CloudTab) => void;
  setPage: (page: number) => void;

  /** Suppress a cloud finding by creating a suppression rule. */
  suppress: (findingId: string, body: CreateSuppressionRequest) => Promise<void>;
  /** Promote one or more cloud findings into a new investigation. */
  promote: (findingIds: string[], title?: string) => Promise<string>;

  clearError: () => void;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function extractErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    const body = err.body as { detail?: string } | null;
    if (body?.detail) return body.detail;
  }
  if (err instanceof Error) return err.message;
  return fallback;
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

export const useCloudStore = create<CloudState>((set, get) => ({
  findings: [],
  total: 0,
  page: 1,
  pageSize: 50,
  activeTab: "timeline",

  isLoading: false,
  isMutating: false,
  error: null,

  fetchFindings: async (opts) => {
    const { page: currentPage, pageSize } = get();
    const page = opts?.page ?? currentPage;
    set({ isLoading: true, error: null });
    try {
      const resp = await listCloudFindings({ state: "active", page, page_size: pageSize });
      // Codex #216 P1: the backend's ``list_findings`` now honours the
      // ``domain=cloud`` query param the API client sends — server-side filter
      // before pagination — so the page already contains only cloud findings
      // and ``total`` is the real cloud total. No client-side re-filter.
      set({
        findings: resp.findings ?? [],
        total: resp.total_findings ?? (resp.findings ?? []).length,
        page,
        isLoading: false,
      });
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to load cloud findings");
      set({ isLoading: false, error: message });
    }
  },

  setTab: (tab) => set({ activeTab: tab }),

  setPage: (page) => {
    set({ page });
    void get().fetchFindings({ page });
  },

  suppress: async (findingId, body) => {
    set({ isMutating: true, error: null });
    try {
      await suppressCloudFinding(findingId, body);
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
      const resp = await promoteCloudFindings(findingIds, title);
      await get().fetchFindings();
      set({ isMutating: false });
      return resp.investigation_id;
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to promote findings");
      set({ isMutating: false, error: message });
      throw err;
    }
  },

  clearError: () => set({ error: null }),
}));
