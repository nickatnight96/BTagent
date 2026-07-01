/**
 * Identity Hunts page — per-principal token-lifecycle timeline +
 * anomalous-consent panel + OAuth-grant table (#116 Phase B).
 *
 * Layout
 * ------
 * 1. Header row: title, finding counts, refresh button, state-filter tabs.
 * 2. Per-principal accordion: each principal gets an expandable card with:
 *    a. Vertical token-lifecycle timeline (identity events derived from
 *       evidence dict: token issuance / refresh / replay across ASNs;
 *       MFA challenge → deny → approve; dormant-app reactivation).
 *    b. Severity badge + technique chips per timeline entry.
 *    c. Inline triage actions (suppress / promote) gated on RBAC.
 * 3. Anomalous-consent panel: findings whose technique_ids include
 *    T1078.004 (OAuth grant abuse) or T1098.001 (SP credential), sorted
 *    by severity descending, each row clickable to reveal evidence.
 * 4. OAuth-grant table: grouped by principal + app, showing scopes and
 *    consent_type extracted from the evidence dict.
 *    NOTE: The live grant graph (real-time ``GET /api/v1/identity/grants``)
 *    is deferred to Phase C — that endpoint does not exist yet.  See the
 *    TODO comment at the bottom of this file.
 * 5. Empty state.
 *
 * RBAC
 * ----
 * - hunt:view     → analyst role or above (page is visible).
 * - hunt:triage   → analyst role or above (suppress action).
 * - hunt:promote  → senior_analyst role or above (promote action).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  KeyRound,
  RefreshCw,
  Loader2,
  ChevronDown,
  ChevronRight,
  ShieldOff,
  ArrowUpRight,
  AlertTriangle,
  Clock,
  Shield,
  Info,
} from "lucide-react";
import {
  useIdentityStore,
  buildPrincipalSummaries,
  buildGrantTableRows,
  // (graph derivation lives in the store; the page only needs the action + state)
  CONSENT_TECHNIQUE_IDS,
} from "@/stores/identityStore";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";
import { Button } from "@/components/ds/button";
import { Card, CardContent } from "@/components/ds/card";
import { Tabs, TabsList, TabsTrigger } from "@/components/ds/tabs";
import { IdentityGrantsGraph } from "./IdentityGrantsGraph";
import type {
  CreateSuppressionRequest,
  HuntDomain,
  HuntSource,
  SuppressionMatch,
} from "@/types/hunt";
import type {
  PrincipalSummary,
  IdentityTimelineEntry,
  GrantTableRow,
  IdentityFindingEvidence,
  RevocationProposal,
} from "@/types/identity_hunt";

// --------------------------------------------------------------------------- //
// RBAC helpers (mirrors BehavioralHuntsPage pattern from #211)
// --------------------------------------------------------------------------- //

/**
 * ``hunt:triage`` — suppress action; granted from analyst upward.
 * Mirrors the identical helper in BehavioralHuntsPage (#211).
 */
function useCanTriage(): boolean {
  const role = useAuthStore((s) => s.user?.role);
  return (
    role === UserRole.ANALYST ||
    role === UserRole.SENIOR_ANALYST ||
    role === UserRole.INCIDENT_COMMANDER ||
    role === UserRole.ADMIN
  );
}

/**
 * ``hunt:promote`` — promote-to-investigation; gated at senior_analyst+.
 * Mirrors the identical helper in BehavioralHuntsPage (#211).
 */
function useCanPromote(): boolean {
  const role = useAuthStore((s) => s.user?.role);
  return (
    role === UserRole.SENIOR_ANALYST ||
    role === UserRole.INCIDENT_COMMANDER ||
    role === UserRole.ADMIN
  );
}

// --------------------------------------------------------------------------- //
// Constants
// --------------------------------------------------------------------------- //

const POLL_INTERVAL_MS = 30_000;

type StateTab = "active" | "suppressed" | "promoted";

const STATE_TABS: { id: StateTab; label: string }[] = [
  { id: "active", label: "Active" },
  { id: "suppressed", label: "Suppressed" },
  { id: "promoted", label: "Promoted" },
];

// --------------------------------------------------------------------------- //
// Severity badge
// --------------------------------------------------------------------------- //

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-500/10 text-red-300 border-red-500/20",
  high: "bg-orange-500/10 text-orange-300 border-orange-500/20",
  medium: "bg-amber-500/10 text-amber-300 border-amber-500/20",
  low: "bg-blue-500/10 text-blue-300 border-blue-500/20",
  info: "bg-slate-700/50 text-slate-400 border-slate-600/30",
};

function SeverityBadge({ severity }: { severity: string }) {
  const cls = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES["info"]!;
  return (
    <span
      className={`px-2 py-0.5 rounded-full text-[11px] font-medium border ${cls}`}
      data-testid="identity-severity-badge"
      data-severity={severity}
    >
      {severity}
    </span>
  );
}

// --------------------------------------------------------------------------- //
// Timeline icon per event kind
// --------------------------------------------------------------------------- //

function timelineIcon(severity: string) {
  if (severity === "critical" || severity === "high") {
    return <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />;
  }
  if (severity === "medium") {
    return <Shield className="w-3.5 h-3.5 text-amber-400 shrink-0" />;
  }
  return <Info className="w-3.5 h-3.5 text-blue-400 shrink-0" />;
}

// --------------------------------------------------------------------------- //
// Evidence detail (expandable)
// --------------------------------------------------------------------------- //

function EvidenceDetail({ evidence }: { evidence: IdentityFindingEvidence }) {
  const ev = evidence as Record<string, unknown>;
  const keyFields: Array<{ key: keyof IdentityFindingEvidence; label: string }> = [
    { key: "principal_id", label: "Principal" },
    { key: "app_id", label: "App ID" },
    { key: "app_display_name", label: "App name" },
    { key: "cred_type", label: "Cred type" },
    { key: "distinct_asns", label: "Distinct ASNs" },
    { key: "asns", label: "ASNs" },
    { key: "ip_addresses", label: "IPs" },
    { key: "scopes", label: "Scopes" },
    { key: "consent_type", label: "Consent type" },
    { key: "provider", label: "Provider" },
    { key: "mfa_push_count", label: "MFA pushes" },
    { key: "mfa_deny_count", label: "MFA denials" },
    { key: "dormant_days", label: "Dormant days" },
    { key: "session_id", label: "Session ID" },
    { key: "token_id", label: "Token ID" },
  ];

  const rows = keyFields.filter(({ key }) => ev[key] !== undefined && ev[key] !== "");

  if (rows.length === 0) return null;

  return (
    <dl className="mt-2 space-y-1" data-testid="identity-evidence-detail">
      {rows.map(({ key, label }) => (
        <div key={key} className="flex gap-2 text-[11px]">
          <dt className="text-slate-500 shrink-0 w-28">{label}</dt>
          <dd className="text-slate-300 font-mono break-all">
            {Array.isArray(ev[key])
              ? (ev[key] as unknown[]).join(", ")
              : String(ev[key])}
          </dd>
        </div>
      ))}
    </dl>
  );
}

// --------------------------------------------------------------------------- //
// Timeline entry row
// --------------------------------------------------------------------------- //

function TimelineRow({
  entry,
  canTriage,
  canPromote,
  isMutating,
  onSuppress,
  onPromote,
}: {
  entry: IdentityTimelineEntry;
  canTriage: boolean;
  canPromote: boolean;
  isMutating: boolean;
  onSuppress: (findingId: string) => void;
  onPromote: (findingId: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  const ts = new Date(entry.timestamp);
  const timeStr = isNaN(ts.getTime()) ? entry.timestamp : ts.toLocaleString();

  return (
    <div
      className="relative pl-6 pb-4 last:pb-0"
      data-testid="identity-timeline-entry"
      data-finding-id={entry.finding_id}
      data-severity={entry.severity}
    >
      {/* Vertical connector line */}
      <div className="absolute left-2 top-0 bottom-0 w-px bg-slate-700/50 last:hidden" />
      {/* Dot */}
      <div className="absolute left-0 top-1 flex items-center justify-center w-4 h-4 rounded-full bg-slate-800 border border-slate-600/50">
        {timelineIcon(entry.severity)}
      </div>

      <div className="flex items-start justify-between gap-3">
        <button
          onClick={() => setExpanded((v) => !v)}
          className="flex-1 text-left"
          aria-expanded={expanded}
          data-testid="identity-timeline-expand"
        >
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-slate-300 font-medium">{entry.label}</span>
            <SeverityBadge severity={entry.severity} />
            {entry.technique_ids.slice(0, 3).map((t) => (
              <span
                key={t}
                className={[
                  "px-1.5 py-0.5 rounded text-[10px] border",
                  CONSENT_TECHNIQUE_IDS.has(t)
                    ? "bg-rose-500/10 text-rose-300 border-rose-500/20"
                    : "bg-blue-500/10 text-blue-300 border-blue-500/20",
                ].join(" ")}
                data-testid="identity-technique-chip"
              >
                {t}
              </span>
            ))}
          </div>
          <div className="flex items-center gap-1 mt-0.5 text-[11px] text-slate-500">
            <Clock className="w-3 h-3" />
            {timeStr}
          </div>
        </button>

        <div className="flex items-center gap-1 shrink-0">
          {/* State badge */}
          {entry.state !== "new" && entry.state !== "clustered" && (
            <span className="px-1.5 py-0.5 rounded text-[10px] text-slate-500 border border-slate-700/40">
              {entry.state}
            </span>
          )}
          {canTriage && (
            <Button
              variant="ghost"
              size="sm"
              className="h-6 px-2 text-[11px] text-slate-400 hover:text-amber-300 hover:bg-amber-500/10"
              disabled={isMutating || entry.state === "suppressed"}
              onClick={() => onSuppress(entry.finding_id)}
              data-testid="identity-suppress-btn"
            >
              <ShieldOff className="w-3 h-3 mr-1" />
              Suppress
            </Button>
          )}
          {canPromote && (
            <Button
              variant="ghost"
              size="sm"
              className="h-6 px-2 text-[11px] text-slate-400 hover:text-blue-300 hover:bg-blue-500/10"
              disabled={isMutating || entry.state === "promoted"}
              onClick={() => onPromote(entry.finding_id)}
              data-testid="identity-promote-btn"
            >
              <ArrowUpRight className="w-3 h-3 mr-1" />
              {entry.state === "promoted" ? "Promoted" : "Promote"}
            </Button>
          )}
        </div>
      </div>

      {expanded && (
        <div className="mt-2">
          <EvidenceDetail evidence={entry.evidence} />
        </div>
      )}
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Per-principal card
// --------------------------------------------------------------------------- //

function PrincipalCard({
  summary,
  canTriage,
  canPromote,
  isMutating,
  onSuppress,
  onPromote,
}: {
  summary: PrincipalSummary;
  canTriage: boolean;
  canPromote: boolean;
  isMutating: boolean;
  onSuppress: (findingId: string) => void;
  onPromote: (findingId: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className="rounded-lg border border-slate-700/50 bg-slate-800/40"
      data-testid="identity-principal-card"
      data-principal-id={summary.principal_id}
    >
      {/* Card header */}
      <div className="flex items-start gap-3 px-4 py-3">
        <button
          onClick={() => setExpanded((v) => !v)}
          className="flex items-center gap-2 text-muted-foreground hover:text-foreground mt-0.5 shrink-0"
          aria-label={expanded ? "Collapse principal" : "Expand principal"}
          data-testid="identity-principal-expand"
        >
          {expanded ? (
            <ChevronDown className="w-4 h-4" />
          ) : (
            <ChevronRight className="w-4 h-4" />
          )}
        </button>

        <div className="flex flex-1 items-start justify-between gap-3 min-w-0">
          <button onClick={() => setExpanded((v) => !v)} className="text-left min-w-0">
            <p
              className="text-sm font-medium text-slate-100 truncate font-mono"
              title={summary.principal_id}
              data-testid="identity-principal-id"
            >
              {summary.principal_id}
            </p>
            <p className="text-xs text-slate-500 mt-0.5">
              {summary.finding_count} finding{summary.finding_count === 1 ? "" : "s"}
              {summary.consent_findings.length > 0 && (
                <span className="ml-2 text-rose-400">
                  · {summary.consent_findings.length} consent/cred
                </span>
              )}
            </p>
          </button>

          <div className="flex items-center gap-2 shrink-0">
            <SeverityBadge severity={summary.max_severity} />
          </div>
        </div>
      </div>

      {/* Timeline */}
      {expanded && (
        <div className="border-t border-slate-700/50 px-4 py-3">
          <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wide mb-3">
            Token-lifecycle timeline
          </p>
          <div data-testid="identity-timeline">
            {summary.timeline.map((entry) => (
              <TimelineRow
                key={entry.finding_id}
                entry={entry}
                canTriage={canTriage}
                canPromote={canPromote}
                isMutating={isMutating}
                onSuppress={onSuppress}
                onPromote={onPromote}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Anomalous-consent panel
// --------------------------------------------------------------------------- //

function ConsentPanel({
  entries,
  canTriage,
  canPromote,
  isMutating,
  onSuppress,
  onPromote,
}: {
  entries: IdentityTimelineEntry[];
  canTriage: boolean;
  canPromote: boolean;
  isMutating: boolean;
  onSuppress: (findingId: string) => void;
  onPromote: (findingId: string) => void;
}) {
  if (entries.length === 0) return null;

  // Sort by severity desc.
  const sorted = [...entries].sort(
    (a, b) => {
      const SEVERITY_RANK: Record<string, number> = {
        info: 0, low: 1, medium: 2, high: 3, critical: 4,
      };
      return (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
    },
  );

  return (
    <section
      className="rounded-lg border border-rose-500/20 bg-rose-500/5"
      data-testid="identity-consent-panel"
    >
      <div className="flex items-center gap-2 px-4 py-3 border-b border-rose-500/20">
        <AlertTriangle className="w-4 h-4 text-rose-400" />
        <h2 className="text-sm font-semibold text-rose-300">
          Anomalous consent &amp; credential findings
        </h2>
        <span className="text-xs text-rose-400/70">
          ({sorted.length}) — techniques T1078.004 / T1098.001
        </span>
      </div>
      <div className="divide-y divide-rose-500/10">
        {sorted.map((entry) => (
          <div
            key={entry.finding_id}
            className="px-4 py-3"
            data-testid="identity-consent-row"
            data-finding-id={entry.finding_id}
          >
            <ConsentRow
              entry={entry}
              canTriage={canTriage}
              canPromote={canPromote}
              isMutating={isMutating}
              onSuppress={onSuppress}
              onPromote={onPromote}
            />
          </div>
        ))}
      </div>
    </section>
  );
}

function ConsentRow({
  entry,
  canTriage,
  canPromote,
  isMutating,
  onSuppress,
  onPromote,
}: {
  entry: IdentityTimelineEntry;
  canTriage: boolean;
  canPromote: boolean;
  isMutating: boolean;
  onSuppress: (findingId: string) => void;
  onPromote: (findingId: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div>
      <div className="flex items-start justify-between gap-3">
        <button
          onClick={() => setExpanded((v) => !v)}
          className="flex-1 text-left"
          aria-expanded={expanded}
          data-testid="identity-consent-expand"
        >
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={entry.severity} />
            <span className="text-xs text-slate-200">{entry.label}</span>
            {entry.technique_ids.map((t) => (
              <span
                key={t}
                className="px-1.5 py-0.5 rounded text-[10px] bg-rose-500/10 text-rose-300 border border-rose-500/20"
                data-testid="identity-consent-technique"
              >
                {t}
              </span>
            ))}
          </div>
          <p className="text-[11px] text-slate-500 mt-0.5 font-mono">
            {(entry.evidence as IdentityFindingEvidence).principal_id ?? "—"}
          </p>
        </button>

        <div className="flex items-center gap-1 shrink-0">
          {canTriage && (
            <Button
              variant="ghost"
              size="sm"
              className="h-6 px-2 text-[11px] text-slate-400 hover:text-amber-300 hover:bg-amber-500/10"
              disabled={isMutating || entry.state === "suppressed"}
              onClick={() => onSuppress(entry.finding_id)}
              data-testid="identity-consent-suppress"
            >
              <ShieldOff className="w-3 h-3 mr-1" />
              Suppress
            </Button>
          )}
          {canPromote && (
            <Button
              variant="ghost"
              size="sm"
              className="h-6 px-2 text-[11px] text-slate-400 hover:text-blue-300 hover:bg-blue-500/10"
              disabled={isMutating || entry.state === "promoted"}
              onClick={() => onPromote(entry.finding_id)}
              data-testid="identity-consent-promote"
            >
              <ArrowUpRight className="w-3 h-3 mr-1" />
              {entry.state === "promoted" ? "Promoted" : "Promote"}
            </Button>
          )}
        </div>
      </div>
      {expanded && (
        <div className="mt-2 ml-2">
          <EvidenceDetail evidence={entry.evidence} />
        </div>
      )}
    </div>
  );
}

// --------------------------------------------------------------------------- //
// OAuth grant table
// --------------------------------------------------------------------------- //

/**
 * OAuth-grant table grouped by principal + app, extracted from finding evidence.
 *
 * TODO (Phase C — deferred): Replace this with a live grant graph that calls
 * ``GET /api/v1/identity/grants?principal_id=<id>`` once that endpoint is
 * implemented.  The backend endpoint should return ``OAuthGrant[]`` (see
 * ``shared/btagent_shared/types/identity_hunt.py::OAuthGrant``).  The store
 * would call ``useIdentityStore.getState().fetchGrants(principalId)`` and the
 * result would drive a proper node-link graph (e.g. via react-flow or a custom
 * SVG renderer).  No graph library is added in Phase B to keep the bundle lean.
 */
function GrantTable({ rows }: { rows: GrantTableRow[] }) {
  if (rows.length === 0) return null;

  return (
    <section
      className="rounded-lg border border-slate-700/50 bg-slate-800/30"
      data-testid="identity-grant-table"
    >
      <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-700/50">
        <KeyRound className="w-4 h-4 text-cyan-400" />
        <h2 className="text-sm font-semibold text-slate-200">
          OAuth grant context
        </h2>
        <span className="text-xs text-slate-500">
          (from finding evidence — live graph deferred to Phase C)
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-slate-700/50">
              <th className="text-left px-4 py-2 text-slate-400 font-medium">Principal</th>
              <th className="text-left px-4 py-2 text-slate-400 font-medium">App</th>
              <th className="text-left px-4 py-2 text-slate-400 font-medium">Consent</th>
              <th className="text-left px-4 py-2 text-slate-400 font-medium">Scopes</th>
              <th className="text-left px-4 py-2 text-slate-400 font-medium">Severity</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {rows.map((row) => (
              <tr
                key={`${row.principal_id}::${row.app_id}`}
                className="hover:bg-slate-700/20"
                data-testid="identity-grant-row"
              >
                <td
                  className="px-4 py-2 font-mono text-slate-300 max-w-[180px] truncate"
                  title={row.principal_id}
                >
                  {row.principal_id}
                </td>
                <td
                  className="px-4 py-2 text-slate-300 max-w-[180px] truncate"
                  title={row.app_id}
                >
                  {row.app_display_name !== row.app_id
                    ? row.app_display_name
                    : row.app_id}
                </td>
                <td className="px-4 py-2">
                  <span
                    className={[
                      "px-1.5 py-0.5 rounded border text-[10px]",
                      row.consent_type === "admin"
                        ? "bg-violet-500/10 text-violet-300 border-violet-500/20"
                        : row.consent_type === "pre_authorized"
                          ? "bg-rose-500/10 text-rose-300 border-rose-500/20"
                          : "bg-slate-700/40 text-slate-400 border-slate-600/30",
                    ].join(" ")}
                    data-testid="identity-grant-consent-type"
                  >
                    {row.consent_type}
                  </span>
                </td>
                <td
                  className="px-4 py-2 text-slate-400 max-w-[200px] truncate"
                  title={row.scopes.join(", ")}
                >
                  {row.scopes.length > 0 ? row.scopes.join(", ") : "—"}
                </td>
                <td className="px-4 py-2">
                  <SeverityBadge severity={row.severity} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

// --------------------------------------------------------------------------- //
// Suppress modal (lightweight inline, mirrors HuntTriagePage)
// --------------------------------------------------------------------------- //

/**
 * Derive a scoped ``SuppressionMatch`` from the target finding's identifying
 * shape so the request can pass the backend's over-broad guard.
 *
 * Codex #217 P2 fix: previously we sent an all-empty match (no source/
 * domain/techniques/entities/observables), which the
 * ``triage.is_overbroad`` guard rejects unconditionally — so analysts and
 * senior analysts couldn't suppress identity findings at all (the
 * incident-commander acknowledge-overbroad path isn't exposed on this UI).
 * The hunt-triage inbox derives its match the same way (domain + a single
 * shared technique narrows it well below the over-broad threshold).
 */
function buildScopedMatch(finding: {
  source: HuntSource;
  domain: HuntDomain;
  technique_ids?: readonly string[];
}): SuppressionMatch {
  // Use a SINGLE technique (the first the finding declares) so the rule is
  // scoped to "this kind of identity-domain detection" without spanning many
  // techniques — the latter would re-trip the diversity cap in is_overbroad.
  const technique_ids =
    finding.technique_ids && finding.technique_ids.length > 0
      ? [finding.technique_ids[0]!]
      : [];
  return {
    source: finding.source,
    domain: finding.domain,
    technique_ids,
    entity_values: [],
    observable_values: [],
  };
}


function SuppressModal({
  finding,
  isMutating,
  onConfirm,
  onCancel,
}: {
  /** Codex #217 P2: take the full finding so the modal can derive a scoped
   * match that passes the backend over-broad guard. */
  finding: { id: string; source: HuntSource; domain: HuntDomain; technique_ids?: readonly string[] };
  isMutating: boolean;
  onConfirm: (findingId: string, body: CreateSuppressionRequest) => Promise<void>;
  onCancel: () => void;
}) {
  const [name, setName] = useState("");
  const [reason, setReason] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);

  async function handleSubmit() {
    if (!name.trim() || !reason.trim()) {
      setLocalError("Name and reason are required.");
      return;
    }
    setLocalError(null);
    try {
      await onConfirm(finding.id, {
        name: name.trim(),
        reason: reason.trim(),
        // Scoped match (Codex #217 P2): all-empty would always 409 as
        // over-broad. ``buildScopedMatch`` narrows to this finding's
        // source/domain + one technique, well inside the diversity gate.
        match: buildScopedMatch(finding),
      });
    } catch {
      // error surfaces in parent store
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      data-testid="identity-suppress-modal"
    >
      <div className="w-full max-w-sm rounded-lg border border-slate-700 bg-slate-900 p-6 shadow-xl">
        <h2 className="text-base font-semibold text-slate-100 mb-3">Suppress Finding</h2>
        {localError && (
          <p className="text-xs text-destructive mb-2" role="alert">
            {localError}
          </p>
        )}
        <label className="block text-xs text-slate-400 mb-1">Rule name</label>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. Known-benign OAuth app consent"
          className="w-full rounded-md border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-blue-500 mb-3"
          data-testid="identity-suppress-name"
        />
        <label className="block text-xs text-slate-400 mb-1">Reason</label>
        <textarea
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Why is this suppressed?"
          rows={2}
          className="w-full rounded-md border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-blue-500 mb-4 resize-none"
          data-testid="identity-suppress-reason"
        />
        <div className="flex justify-end gap-2">
          <Button variant="ghost" size="sm" onClick={onCancel} disabled={isMutating}>
            Cancel
          </Button>
          <Button
            size="sm"
            disabled={isMutating}
            onClick={() => void handleSubmit()}
            data-testid="identity-suppress-confirm"
          >
            {isMutating ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : null}
            Suppress
          </Button>
        </div>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Promote modal (lightweight inline)
// --------------------------------------------------------------------------- //

function PromoteModal({
  findingIds,
  isMutating,
  onConfirm,
  onCancel,
}: {
  findingIds: string[];
  isMutating: boolean;
  onConfirm: (findingIds: string[], title: string) => Promise<void>;
  onCancel: () => void;
}) {
  const [title, setTitle] = useState("");

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      data-testid="identity-promote-modal"
    >
      <div className="w-full max-w-sm rounded-lg border border-slate-700 bg-slate-900 p-6 shadow-xl">
        <h2 className="text-base font-semibold text-slate-100 mb-3">Promote to Investigation</h2>
        <p className="text-sm text-slate-400 mb-4">
          {findingIds.length} finding{findingIds.length === 1 ? "" : "s"} will be promoted into
          a new investigation.
        </p>
        <label className="block text-xs text-slate-400 mb-1">
          Investigation title (optional)
        </label>
        <input
          type="text"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="e.g. Identity compromise — <principal>"
          className="w-full rounded-md border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-blue-500 mb-4"
          data-testid="identity-promote-title"
        />
        <div className="flex justify-end gap-2">
          <Button variant="ghost" size="sm" onClick={onCancel} disabled={isMutating}>
            Cancel
          </Button>
          <Button
            size="sm"
            disabled={isMutating}
            onClick={() => void onConfirm(findingIds, title)}
            data-testid="identity-promote-confirm"
          >
            {isMutating ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <ArrowUpRight className="w-4 h-4 mr-2" />
            )}
            Promote
          </Button>
        </div>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Revocation proposal modal (#116 Phase C slice 2 — HITL gate)
// --------------------------------------------------------------------------- //

/**
 * Decision surface for the revoke-playbook proposal a grant-flavoured
 * promotion attaches to its investigation. Accept materialises the generated
 * playbook (senior_analyst+ — ``playbook:create``); reject records the
 * rationale; "Decide later" leaves the proposal pending on the investigation.
 * Shown BEFORE navigating to the new investigation so the HITL decision
 * isn't lost behind the redirect.
 */
function RevocationProposalModal({
  proposal,
  canDecide,
  isMutating,
  error,
  onAccept,
  onReject,
  onDismiss,
}: {
  proposal: RevocationProposal;
  canDecide: boolean;
  isMutating: boolean;
  error: string | null;
  onAccept: (rationale: string) => void;
  onReject: (rationale: string) => void;
  onDismiss: () => void;
}) {
  const [rationale, setRationale] = useState("");
  const decided = proposal.status !== "proposed";

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      data-testid="identity-revocation-modal"
    >
      <div className="w-full max-w-lg rounded-lg border border-slate-700 bg-slate-900 p-6 shadow-xl">
        <div className="flex items-center gap-2 mb-3">
          <ShieldOff className="w-4 h-4 text-rose-400" aria-hidden="true" />
          <h2 className="text-base font-semibold text-slate-100">
            Revocation playbook proposed
          </h2>
        </div>
        <p className="text-sm text-slate-400 mb-3">{proposal.rationale}</p>

        <ul
          className="mb-4 max-h-44 overflow-y-auto space-y-1 text-sm"
          data-testid="identity-revocation-targets"
        >
          {proposal.targets.map((t) => (
            <li
              key={`${t.provider}:${t.principal_id}:${t.app_id}`}
              className="rounded-md border border-slate-800 bg-slate-800/50 px-3 py-1.5 text-slate-300"
              data-testid="identity-revocation-target"
            >
              <span className="font-medium">{t.principal_id}</span>
              {" → "}
              {t.app_display_name || t.app_id}
              <span className="ml-2 text-xs text-slate-500">
                {t.provider} · {t.scopes.length} scope{t.scopes.length === 1 ? "" : "s"}
              </span>
            </li>
          ))}
        </ul>

        {decided ? (
          <div
            className="mb-4 rounded-md border border-emerald-500/20 bg-emerald-500/5 px-3 py-2 text-sm text-emerald-400"
            data-testid="identity-revocation-decided"
          >
            Proposal {proposal.status}
            {proposal.playbook_id ? ` — playbook ${proposal.playbook_id} created` : ""}. The
            playbook itself is HITL-gated again at execution time.
          </div>
        ) : (
          <>
            {!canDecide && (
              <div className="mb-3 rounded-md border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-xs text-amber-400">
                Accepting or rejecting requires the <strong>senior analyst</strong> role or
                above.
              </div>
            )}
            <label className="block text-xs text-slate-400 mb-1">Decision rationale</label>
            <textarea
              value={rationale}
              onChange={(e) => setRationale(e.target.value)}
              rows={2}
              placeholder="Why this revocation is (or isn't) warranted"
              className="w-full rounded-md border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-blue-500 mb-3"
              data-testid="identity-revocation-rationale"
            />
          </>
        )}

        {error && (
          <div
            className="mb-3 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive"
            role="alert"
            data-testid="identity-revocation-error"
          >
            {error}
          </div>
        )}

        <div className="flex justify-end gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={onDismiss}
            disabled={isMutating}
            data-testid="identity-revocation-dismiss"
          >
            {decided ? "Continue to investigation" : "Decide later"}
          </Button>
          {!decided && canDecide && (
            <>
              <Button
                variant="outline"
                size="sm"
                disabled={isMutating}
                onClick={() => onReject(rationale)}
                data-testid="identity-revocation-reject"
              >
                Reject
              </Button>
              <Button
                size="sm"
                disabled={isMutating}
                onClick={() => onAccept(rationale)}
                data-testid="identity-revocation-accept"
              >
                {isMutating ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <ShieldOff className="w-4 h-4 mr-2" />
                )}
                Accept &amp; create playbook
              </Button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Main page
// --------------------------------------------------------------------------- //

export function IdentityHuntsPage() {
  const navigate = useNavigate();
  const canTriage = useCanTriage();
  const canPromote = useCanPromote();

  const {
    findings,
    totalFindings,
    page,
    pageSize,
    stateFilter,
    isLoading,
    isMutating,
    error,
    grants,
    grantsLoading,
    grantsError,
    revocationProposal,
    revocationInvestigationId,
    revocationMutating,
    revocationError,
    fetchFindings,
    fetchGrants,
    setStateFilter,
    setPage,
    suppress,
    promote,
    acceptRevocation,
    rejectRevocation,
    dismissRevocationPanel,
    clearError,
  } = useIdentityStore();

  const [suppressTarget, setSuppressTarget] = useState<string | null>(null);
  const [promoteTargets, setPromoteTargets] = useState<string[] | null>(null);

  // Initial load.
  useEffect(() => {
    void fetchFindings();
    void fetchGrants();
  }, [fetchFindings, fetchGrants]);

  // Re-fetch when filter tab changes.
  useEffect(() => {
    void fetchFindings({ page: 1 });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stateFilter]);

  // 30-second polling fallback (WS upgrade deferred to Phase C).
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const scheduleRefetch = useCallback(() => {
    void fetchFindings();
  }, [fetchFindings]);

  useEffect(() => {
    pollTimerRef.current = setInterval(scheduleRefetch, POLL_INTERVAL_MS);
    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, [scheduleRefetch]);

  // Client-side aggregation.
  const principalSummaries = buildPrincipalSummaries(findings);
  const grantRows = buildGrantTableRows(findings);

  // All consent findings across all principals.
  const allConsentEntries = principalSummaries.flatMap((s) => s.consent_findings);

  // ----- Handlers -----

  const handleSuppress = useCallback(
    async (findingId: string, body: CreateSuppressionRequest) => {
      await suppress(findingId, body);
      setSuppressTarget(null);
    },
    [suppress],
  );

  const handlePromote = useCallback(
    async (findingIds: string[], title: string) => {
      const invId = await promote(findingIds, title || undefined);
      setPromoteTargets(null);
      // Grant-flavoured promotions surface a revoke-playbook proposal — hold
      // the redirect so the HITL decision modal isn't lost. Navigation happens
      // when the analyst decides (or dismisses) via the modal.
      if (!useIdentityStore.getState().revocationProposal) {
        navigate(`/investigations/${invId}`);
      }
    },
    [promote, navigate],
  );

  const closeRevocationModal = useCallback(() => {
    const invId = revocationInvestigationId;
    dismissRevocationPanel();
    if (invId) navigate(`/investigations/${invId}`);
  }, [revocationInvestigationId, dismissRevocationPanel, navigate]);

  const handleAcceptRevocation = useCallback(
    (rationale: string) => {
      // Keep the modal open on success so the analyst sees the playbook id;
      // errors surface inline via revocationError.
      void acceptRevocation(rationale).catch(() => undefined);
    },
    [acceptRevocation],
  );

  const handleRejectRevocation = useCallback(
    (rationale: string) => {
      void rejectRevocation(rationale).catch(() => undefined);
    },
    [rejectRevocation],
  );

  const handleTabChange = (value: string) => {
    clearError();
    setStateFilter(value as StateTab);
  };

  // Pagination.
  const totalPages = Math.ceil(totalFindings / pageSize) || 1;

  return (
    <div className="flex flex-col h-full" data-testid="identity-hunts-page">
      {/* ---- Header ---- */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-cyan-600/20 border border-cyan-500/30">
            <KeyRound className="w-4 h-4 text-cyan-400" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-foreground">Identity Hunts</h1>
            <p className="text-sm text-muted-foreground">
              {principalSummaries.length} principal{principalSummaries.length === 1 ? "" : "s"} ·{" "}
              {totalFindings} finding{totalFindings === 1 ? "" : "s"}
              {allConsentEntries.length > 0 && (
                <span className="ml-2 text-rose-400">
                  · {allConsentEntries.length} consent/cred alert{allConsentEntries.length === 1 ? "" : "s"}
                </span>
              )}
            </p>
          </div>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            void fetchFindings();
            void fetchGrants();
          }}
          disabled={isLoading}
          data-testid="identity-refresh"
        >
          {isLoading ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <RefreshCw className="w-4 h-4" />
          )}
          <span className="ml-2 hidden sm:inline">Refresh</span>
        </Button>
      </div>

      {/* ---- State filter tabs ---- */}
      <div className="px-6 pt-4 border-b border-border">
        <Tabs value={stateFilter} onValueChange={handleTabChange}>
          <TabsList data-testid="identity-state-tabs">
            {STATE_TABS.map((t) => (
              <TabsTrigger
                key={t.id}
                value={t.id}
                data-testid={`identity-tab-${t.id}`}
              >
                {t.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
      </div>

      {/* ---- RBAC notice ---- */}
      {!canTriage && (
        <div
          className="mx-6 mt-3 rounded-md border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-xs text-amber-400"
          data-testid="identity-rbac-notice"
        >
          Suppress and promote actions require the <strong>analyst</strong> role or higher.
        </div>
      )}

      {/* ---- Content ---- */}
      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-5xl mx-auto space-y-4">
          {error && (
            <div
              className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-2 text-sm text-destructive"
              role="alert"
              data-testid="identity-error"
            >
              {error}
            </div>
          )}

          {isLoading && findings.length === 0 && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="w-4 h-4 animate-spin" />
              Loading identity findings…
            </div>
          )}

          {/* ---- Empty state ---- */}
          {!isLoading && principalSummaries.length === 0 && (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                <KeyRound className="mx-auto mb-3 h-8 w-8 opacity-30" />
                <p className="text-sm">
                  {stateFilter === "active"
                    ? "No active identity findings."
                    : `No ${stateFilter} identity findings.`}
                </p>
                {stateFilter === "active" && (
                  <p className="text-xs text-muted-foreground mt-1">
                    Identity detectors scan token lifecycles, MFA events, and OAuth grants.
                    Findings appear here when anomalies are detected via the Okta / Entra / Google
                    Workspace connectors.
                  </p>
                )}
              </CardContent>
            </Card>
          )}

          {/* ---- Anomalous-consent panel (shown above per-principal list) ---- */}
          <ConsentPanel
            entries={allConsentEntries}
            canTriage={canTriage}
            canPromote={canPromote}
            isMutating={isMutating}
            onSuppress={(id) => setSuppressTarget(id)}
            onPromote={(id) => setPromoteTargets([id])}
          />

          {/* ---- Per-principal accordion ---- */}
          {principalSummaries.map((summary) => (
            <PrincipalCard
              key={summary.principal_id}
              summary={summary}
              canTriage={canTriage}
              canPromote={canPromote}
              isMutating={isMutating}
              onSuppress={(id) => setSuppressTarget(id)}
              onPromote={(id) => setPromoteTargets([id])}
            />
          ))}

          {/* ---- Live OAuth-grant graph (Phase C) ---- */}
          <IdentityGrantsGraph
            grants={grants}
            loading={grantsLoading}
            error={grantsError}
          />

          {/* ---- OAuth-grant detail table (severity + finding linkage) ---- */}
          <GrantTable rows={grantRows} />

          {/* ---- Pagination ---- */}
          {totalPages > 1 && (
            <div
              className="flex items-center justify-between text-xs text-muted-foreground pt-2"
              data-testid="identity-pagination"
            >
              <span>
                Page {page} of {totalPages} ({totalFindings} findings)
              </span>
              <div className="flex gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={page <= 1}
                  onClick={() => setPage(page - 1)}
                  data-testid="identity-prev"
                >
                  Prev
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={page >= totalPages}
                  onClick={() => setPage(page + 1)}
                  data-testid="identity-next"
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ---- Suppress modal ---- */}
      {(() => {
        if (!suppressTarget) return null;
        // Codex #217 P2: look up the full finding so the modal can derive a
        // scoped suppression match (otherwise the all-empty default 409s).
        const targetFinding = findings.find((f) => f.id === suppressTarget);
        if (!targetFinding) return null;
        return (
          <SuppressModal
            finding={targetFinding}
            isMutating={isMutating}
            onConfirm={handleSuppress}
            onCancel={() => setSuppressTarget(null)}
          />
        );
      })()}

      {/* ---- Promote modal ---- */}
      {promoteTargets && (
        <PromoteModal
          findingIds={promoteTargets}
          isMutating={isMutating}
          onConfirm={handlePromote}
          onCancel={() => setPromoteTargets(null)}
        />
      )}

      {/* ---- Revocation proposal modal (#116 Phase C slice 2) ---- */}
      {revocationProposal && (
        <RevocationProposalModal
          proposal={revocationProposal}
          canDecide={canPromote}
          isMutating={revocationMutating}
          error={revocationError}
          onAccept={handleAcceptRevocation}
          onReject={handleRejectRevocation}
          onDismiss={closeRevocationModal}
        />
      )}
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Phase C — Live OAuth-grant graph (LANDED)
// --------------------------------------------------------------------------- //
//
// The live grant graph is implemented above via <IdentityGrantsGraph>, backed
// by the read-derive endpoint:
//
//   GET /api/v1/identity/grants?principal_id=&active=&provider=&page=&page_size=
//   Response: { items: OAuthGrant[], total: number }
//
// The endpoint derives OAuthGrant records from identity-domain findings'
// evidence (no new table); ``identityStore.buildGrantGraph`` lays them out and
// the component renders the principal→app node-link diagram, edges coloured by
// consent_type (pre_authorized = rose, admin = violet, user = blue) and dashed
// when revoked. The GrantTable is retained as a severity/finding-linkage detail
// view beneath the graph.
//
// Follow-ups (not blocking): a first-class oauth_grants table + ingest-side
// writer (so grants persist independent of finding retention), and
// IDENTITY_GRANT_* WebSocket events to replace the 30s polling fallback.
