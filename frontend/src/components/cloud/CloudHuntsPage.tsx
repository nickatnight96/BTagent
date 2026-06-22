/**
 * Cloud Control-Plane Hunter page — Phase B (#117).
 *
 * Layout (four tabs)
 * ------------------
 * 1. Timeline    — control-plane events sorted chronologically, grouped by
 *                  cloud account (AWS/Azure/GCP).
 * 2. IAM Graph   — who-can-assume-whom; nested list of source-role → trustee
 *                  relationships derived from finding evidence.assume_chain.
 *                  NOTE: A live interactive graph (D3 / vis-network) is
 *                  deferred to Phase C — the nested-list view is sufficient
 *                  for Phase B analyst workflows.
 * 3. Shadow Workloads — inventory matrix (provider × workload kind,
 *                  managed vs. shadow) + explicit shadow-finding list sorted
 *                  by risk_score.
 * 4. Tamper      — findings grouped by evidence.technique_family.
 *
 * RBAC
 * ----
 * - hunt:view    → analyst role or above — page is visible.
 * - hunt:triage  → analyst role or above — suppress action.
 * - hunt:promote → senior_analyst or above — promote action.
 *
 * Polling: 30-second interval (same model as BehavioralHuntsPage).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Cloud,
  ChevronDown,
  ChevronRight,
  Loader2,
  RefreshCw,
  ArrowUpRight,
  AlertTriangle,
  Shield,
  GitBranch,
} from "lucide-react";
import {
  useCloudStore,
  buildTimeline,
  buildIAMLinks,
  buildWorkloadMatrix,
  buildShadowList,
  buildTamperGroups,
} from "@/stores/cloudStore";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";
import { Button } from "@/components/ds/button";
import { Card, CardContent } from "@/components/ds/card";
import { Tabs, TabsList, TabsTrigger } from "@/components/ds/tabs";
import type { HuntFinding } from "@/types/hunt";
import type {
  CloudTab,
  CloudTimelineEntry,
  IAMRelationship,
  WorkloadMatrixCell,
  CloudProvider,
} from "@/types/cloud_hunt";
import {
  CLOUD_PROVIDER_LABELS,
  WORKLOAD_KIND_LABELS,
  WORKLOAD_KINDS_ORDERED,
  CLOUD_PROVIDERS_ORDERED,
} from "@/types/cloud_hunt";

// ---------------------------------------------------------------------------
// RBAC hooks
// ---------------------------------------------------------------------------

/** hunt:view is the floor — all authenticated users see the page. */
function useCanTriage(): boolean {
  const role = useAuthStore((s) => s.user?.role);
  return (
    role === UserRole.ANALYST ||
    role === UserRole.SENIOR_ANALYST ||
    role === UserRole.INCIDENT_COMMANDER ||
    role === UserRole.ADMIN
  );
}

function useCanPromote(): boolean {
  const role = useAuthStore((s) => s.user?.role);
  return (
    role === UserRole.SENIOR_ANALYST ||
    role === UserRole.INCIDENT_COMMANDER ||
    role === UserRole.ADMIN
  );
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const POLL_INTERVAL_MS = 30_000;

const TAB_CONFIG: { id: CloudTab; label: string }[] = [
  { id: "timeline", label: "Timeline" },
  { id: "iam", label: "IAM Graph" },
  { id: "shadow_workloads", label: "Shadow Workloads" },
  { id: "tamper", label: "Tamper" },
];

// ---------------------------------------------------------------------------
// Severity badge
// ---------------------------------------------------------------------------

function SeverityBadge({ severity }: { severity: string }) {
  const styles: Record<string, string> = {
    critical: "bg-red-500/20 text-red-300 border-red-500/30",
    high: "bg-orange-500/20 text-orange-300 border-orange-500/30",
    medium: "bg-amber-500/20 text-amber-300 border-amber-500/30",
    low: "bg-blue-500/20 text-blue-300 border-blue-500/30",
    info: "bg-slate-500/20 text-slate-300 border-slate-500/30",
  };
  return (
    <span
      className={`px-1.5 py-0.5 rounded text-[11px] font-medium border ${styles[severity] ?? styles["info"]}`}
    >
      {severity}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Provider badge
// ---------------------------------------------------------------------------

function ProviderBadge({ provider }: { provider: CloudProvider }) {
  const styles: Record<CloudProvider, string> = {
    aws: "bg-orange-500/15 text-orange-300 border-orange-500/25",
    azure: "bg-blue-500/15 text-blue-300 border-blue-500/25",
    gcp: "bg-emerald-500/15 text-emerald-300 border-emerald-500/25",
  };
  return (
    <span
      className={`px-1.5 py-0.5 rounded text-[11px] font-medium border ${styles[provider]}`}
    >
      {CLOUD_PROVIDER_LABELS[provider]}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Promote confirmation modal
// ---------------------------------------------------------------------------

function PromoteModal({
  findingId,
  isMutating,
  onConfirm,
  onCancel,
}: {
  findingId: string;
  isMutating: boolean;
  onConfirm: (findingId: string) => Promise<void>;
  onCancel: () => void;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      data-testid="cloud-promote-modal"
    >
      <div className="w-full max-w-sm rounded-lg border border-slate-700 bg-slate-900 p-6 shadow-xl">
        <h2 className="text-base font-semibold text-slate-100 mb-3">
          Promote Cloud Finding
        </h2>
        <p className="text-sm text-slate-400 mb-4">
          This finding will be escalated into a new investigation.
        </p>
        <div className="flex justify-end gap-2">
          <Button variant="ghost" size="sm" onClick={onCancel} disabled={isMutating}>
            Cancel
          </Button>
          <Button
            size="sm"
            disabled={isMutating}
            onClick={() => void onConfirm(findingId)}
            data-testid="cloud-promote-confirm-btn"
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

// ---------------------------------------------------------------------------
// Tab 1: Control-plane event timeline
// ---------------------------------------------------------------------------

function TimelineTab({
  findings,
  canPromote,
  isMutating,
  onPromote,
}: {
  findings: HuntFinding[];
  canPromote: boolean;
  isMutating: boolean;
  onPromote: (id: string) => void;
}) {
  const timeline = buildTimeline(findings);

  if (timeline.length === 0) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-muted-foreground">
          <Cloud className="mx-auto mb-3 h-8 w-8 opacity-30" />
          <p className="text-sm">No cloud control-plane events detected yet.</p>
        </CardContent>
      </Card>
    );
  }

  // Group by account_id for display.
  const byAccount = new Map<string, CloudTimelineEntry[]>();
  for (const entry of timeline) {
    const key = `${entry.provider}|${entry.account_id}`;
    const bucket = byAccount.get(key) ?? [];
    bucket.push(entry);
    byAccount.set(key, bucket);
  }

  return (
    <div className="space-y-4" data-testid="cloud-timeline">
      {Array.from(byAccount.entries()).map(([accountKey, entries]) => {
        const [provider, accountId] = accountKey.split("|") as [CloudProvider, string];
        return (
          <div key={accountKey} className="rounded-lg border border-slate-700/50 bg-slate-800/40">
            {/* Account header */}
            <div className="flex items-center gap-3 px-4 py-2.5 border-b border-slate-700/40">
              <Cloud className="w-4 h-4 text-slate-400" />
              <ProviderBadge provider={provider} />
              <span className="text-sm font-medium text-slate-200 font-mono">{accountId}</span>
              <span className="text-xs text-slate-500">{entries.length} event{entries.length === 1 ? "" : "s"}</span>
            </div>
            {/* Events */}
            <div className="divide-y divide-slate-800">
              {entries.map((entry) => (
                <TimelineRow
                  key={entry.finding_id}
                  entry={entry}
                  canPromote={canPromote}
                  isMutating={isMutating}
                  onPromote={onPromote}
                />
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function TimelineRow({
  entry,
  canPromote,
  isMutating,
  onPromote,
}: {
  entry: CloudTimelineEntry;
  canPromote: boolean;
  isMutating: boolean;
  onPromote: (id: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className="px-4 py-2.5"
      data-testid="cloud-timeline-row"
      data-finding-id={entry.finding_id}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2 min-w-0">
          <button
            onClick={() => setExpanded((v) => !v)}
            className="mt-0.5 text-muted-foreground hover:text-foreground shrink-0"
            aria-label={expanded ? "Collapse event" : "Expand event"}
            data-testid="cloud-timeline-expand"
          >
            {expanded ? (
              <ChevronDown className="w-3.5 h-3.5" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5" />
            )}
          </button>
          <div className="min-w-0">
            <p className="text-xs text-slate-200 font-medium truncate" title={entry.title}>
              {entry.title}
            </p>
            <p className="text-[11px] text-slate-500 mt-0.5">
              {new Date(entry.created_at).toLocaleString()}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <SeverityBadge severity={entry.severity} />
          {entry.technique_ids.length > 0 && (
            <span className="text-[11px] text-slate-400 font-mono">
              {entry.technique_ids[0]}
              {entry.technique_ids.length > 1 && ` +${entry.technique_ids.length - 1}`}
            </span>
          )}
        </div>
      </div>

      {expanded && (
        <div className="mt-2 ml-5 space-y-1.5">
          <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs">
            <div>
              <span className="text-slate-500">Actor:</span>{" "}
              <span className="text-slate-300 font-mono text-[11px] break-all">{entry.actor}</span>
            </div>
            <div>
              <span className="text-slate-500">Target:</span>{" "}
              <span className="text-slate-300 font-mono text-[11px] break-all">{entry.target}</span>
            </div>
          </div>
          {entry.technique_ids.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {entry.technique_ids.map((t) => (
                <span
                  key={t}
                  className="px-1.5 py-0.5 rounded text-[11px] bg-slate-700/60 text-slate-300 font-mono border border-slate-600/30"
                >
                  {t}
                </span>
              ))}
            </div>
          )}
          {canPromote && (
            <div className="pt-1">
              <Button
                variant="ghost"
                size="sm"
                className="h-6 px-2 text-[11px] text-blue-400 hover:text-blue-300 hover:bg-blue-500/10"
                disabled={isMutating}
                onClick={() => onPromote(entry.finding_id)}
                data-testid="cloud-promote-btn"
              >
                <ArrowUpRight className="w-3 h-3 mr-1" />
                Promote to Investigation
              </Button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tab 2: IAM role-graph view (nested list, Phase B)
// ---------------------------------------------------------------------------

/**
 * Phase B IAM graph — nested list of source-role → trustee relationships.
 *
 * DEFERRED: A live interactive role graph (D3.js, vis-network, or a React
 * force-directed layout) would provide a much richer exploration experience,
 * particularly for multi-hop chains and cross-account trust. Phase C should
 * add a proper graph visualization backed by the same IAMRelationship data
 * this component already builds.
 */
function IAMGraphTab({ findings }: { findings: HuntFinding[] }) {
  const links = buildIAMLinks(findings);

  if (links.length === 0) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-muted-foreground">
          <GitBranch className="mx-auto mb-3 h-8 w-8 opacity-30" />
          <p className="text-sm">No IAM assume-role relationships found in current findings.</p>
          <p className="text-xs text-slate-600 mt-1">
            Findings must carry{" "}
            <code className="text-slate-500">evidence.assume_chain</code> with at least two
            entries for relationships to appear here.
          </p>
        </CardContent>
      </Card>
    );
  }

  // Group by source_role for the nested-list view.
  const bySourceRole = new Map<string, IAMRelationship[]>();
  for (const link of links) {
    const bucket = bySourceRole.get(link.source_role) ?? [];
    bucket.push(link);
    bySourceRole.set(link.source_role, bucket);
  }

  return (
    <div className="space-y-3" data-testid="cloud-iam-graph">
      <div className="rounded-md border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-xs text-amber-400">
        <strong>Phase B — Nested-list view.</strong> A live interactive graph
        (D3 / vis-network) is deferred to Phase C.
      </div>

      {Array.from(bySourceRole.entries()).map(([sourceRole, roleLinks]) => (
        <IAMSourceRoleCard
          key={sourceRole}
          sourceRole={sourceRole}
          links={roleLinks}
        />
      ))}
    </div>
  );
}

function IAMSourceRoleCard({
  sourceRole,
  links,
}: {
  sourceRole: string;
  links: IAMRelationship[];
}) {
  const [expanded, setExpanded] = useState(true);

  return (
    <div
      className="rounded-lg border border-slate-700/50 bg-slate-800/40"
      data-testid="cloud-iam-source-role"
      data-source-role={sourceRole}
    >
      <button
        className="flex items-center gap-2 w-full px-4 py-2.5 text-left"
        onClick={() => setExpanded((v) => !v)}
        aria-label={expanded ? "Collapse role" : "Expand role"}
        data-testid="cloud-iam-expand"
      >
        {expanded ? (
          <ChevronDown className="w-3.5 h-3.5 text-slate-400 shrink-0" />
        ) : (
          <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
        )}
        <Shield className="w-3.5 h-3.5 text-slate-400 shrink-0" />
        <span className="text-xs font-mono text-slate-200 truncate flex-1" title={sourceRole}>
          {sourceRole}
        </span>
        <span className="text-[11px] text-slate-500 shrink-0">
          {links.length} trustee{links.length === 1 ? "" : "s"}
        </span>
      </button>

      {expanded && (
        <div className="border-t border-slate-700/40 divide-y divide-slate-800">
          {links.map((link) => (
            <div
              key={`${link.source_role}|${link.trustee}`}
              className="flex items-start gap-3 px-6 py-2"
              data-testid="cloud-iam-trustee-row"
            >
              <span className="text-slate-600 text-xs mt-0.5">↳</span>
              <div className="min-w-0 flex-1">
                <p className="text-[11px] font-mono text-slate-300 break-all" title={link.trustee}>
                  {link.trustee}
                </p>
                <div className="flex items-center gap-2 mt-0.5">
                  {link.is_cross_account && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-500/10 text-red-400 border border-red-500/20">
                      cross-account
                    </span>
                  )}
                  <span className="text-[10px] text-slate-600 font-mono">
                    finding: {link.finding_id}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tab 3: Agentic-workload inventory matrix + shadow list
// ---------------------------------------------------------------------------

function ShadowWorkloadsTab({ findings }: { findings: HuntFinding[] }) {
  const matrix = buildWorkloadMatrix(findings);
  const shadowList = buildShadowList(findings);

  return (
    <div className="space-y-6" data-testid="cloud-shadow-tab">
      {/* Matrix */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 mb-3">
          Agentic-Workload Inventory Matrix
        </h2>
        <WorkloadMatrix matrix={matrix} />
      </div>

      {/* Shadow finding list */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 mb-3">
          Shadow Workload Findings{" "}
          <span className="text-xs font-normal text-slate-500">
            (sorted by risk score)
          </span>
        </h2>
        {shadowList.length === 0 ? (
          <Card>
            <CardContent className="py-8 text-center text-muted-foreground">
              <Shield className="mx-auto mb-3 h-6 w-6 opacity-30" />
              <p className="text-sm">No shadow-workload findings in this batch.</p>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-2">
            {shadowList.map((f) => (
              <ShadowFindingRow key={f.id} finding={f} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function WorkloadMatrix({ matrix }: { matrix: WorkloadMatrixCell[] }) {
  // Build a 2-D lookup: provider → kind → cell.
  const lookup = new Map<string, WorkloadMatrixCell>();
  for (const cell of matrix) {
    lookup.set(`${cell.provider}|${cell.kind}`, cell);
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-slate-700/50">
      <table className="w-full text-xs" data-testid="cloud-workload-matrix">
        <thead>
          <tr className="bg-slate-900/60 border-b border-slate-700/50">
            <th className="px-4 py-2.5 text-left text-slate-400 font-medium w-20">Provider</th>
            {WORKLOAD_KINDS_ORDERED.map((k) => (
              <th key={k} className="px-3 py-2.5 text-center text-slate-400 font-medium">
                {WORKLOAD_KIND_LABELS[k]}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800">
          {CLOUD_PROVIDERS_ORDERED.map((p) => (
            <tr key={p} className="bg-slate-800/30 hover:bg-slate-800/50 transition-colors">
              <td className="px-4 py-2.5">
                <span
                  className={`px-1.5 py-0.5 rounded text-[11px] font-medium border ${
                    p === "aws"
                      ? "bg-orange-500/15 text-orange-300 border-orange-500/25"
                      : p === "azure"
                        ? "bg-blue-500/15 text-blue-300 border-blue-500/25"
                        : "bg-emerald-500/15 text-emerald-300 border-emerald-500/25"
                  }`}
                >
                  {CLOUD_PROVIDER_LABELS[p]}
                </span>
              </td>
              {WORKLOAD_KINDS_ORDERED.map((k) => {
                const cell = lookup.get(`${p}|${k}`);
                const managed = cell?.managed_count ?? 0;
                const shadow = cell?.shadow_count ?? 0;
                return (
                  <td
                    key={k}
                    className="px-3 py-2.5 text-center"
                    data-testid="cloud-matrix-cell"
                    data-provider={p}
                    data-kind={k}
                  >
                    <div className="flex flex-col items-center gap-0.5">
                      <span
                        className={`text-[11px] font-medium ${managed > 0 ? "text-emerald-400" : "text-slate-600"}`}
                        title={`${managed} managed`}
                      >
                        {managed} mgd
                      </span>
                      <span
                        className={`text-[11px] font-medium ${shadow > 0 ? "text-red-400" : "text-slate-600"}`}
                        title={`${shadow} shadow`}
                        data-testid={shadow > 0 ? "cloud-matrix-shadow-nonzero" : undefined}
                      >
                        {shadow} shadow
                      </span>
                    </div>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ShadowFindingRow({ finding }: { finding: HuntFinding }) {
  const [expanded, setExpanded] = useState(false);
  const ev = finding.evidence as Record<string, unknown>;
  const riskScore = (ev["risk_score"] as number | undefined) ?? 0;
  const provider = (ev["provider"] as string | undefined) ?? "aws";
  const workloadKind = ev["workload_kind"] as string | undefined;

  return (
    <div
      className="rounded-lg border border-red-500/20 bg-red-500/5"
      data-testid="cloud-shadow-finding-row"
      data-finding-id={finding.id}
    >
      <div className="flex items-start gap-3 px-4 py-2.5">
        <button
          onClick={() => setExpanded((v) => !v)}
          className="mt-0.5 text-muted-foreground hover:text-foreground shrink-0"
          aria-label={expanded ? "Collapse" : "Expand"}
          data-testid="cloud-shadow-expand"
        >
          {expanded ? (
            <ChevronDown className="w-3.5 h-3.5" />
          ) : (
            <ChevronRight className="w-3.5 h-3.5" />
          )}
        </button>
        <div className="flex-1 min-w-0">
          <p className="text-xs font-medium text-slate-200 truncate">{finding.title}</p>
          <p className="text-[11px] text-slate-500 mt-0.5">
            {new Date(finding.created_at).toLocaleString()}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <ProviderBadge provider={provider as CloudProvider} />
          {workloadKind && (
            <span className="text-[11px] text-slate-400">
              {WORKLOAD_KIND_LABELS[workloadKind as keyof typeof WORKLOAD_KIND_LABELS] ?? workloadKind}
            </span>
          )}
          <span
            className="text-[11px] font-medium tabular-nums text-red-400"
            title="Risk score"
            data-testid="cloud-shadow-risk-score"
          >
            risk {riskScore.toFixed(2)}
          </span>
        </div>
      </div>

      {expanded && (
        <div className="border-t border-red-500/10 px-6 py-2.5">
          <p className="text-xs text-slate-400">{finding.description}</p>
          {finding.technique_ids.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {finding.technique_ids.map((t) => (
                <span
                  key={t}
                  className="px-1.5 py-0.5 rounded text-[11px] bg-slate-700/60 text-slate-300 font-mono border border-slate-600/30"
                >
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tab 4: Tamper (findings grouped by technique family)
// ---------------------------------------------------------------------------

function TamperTab({ findings }: { findings: HuntFinding[] }) {
  const groups = buildTamperGroups(findings);

  if (groups.size === 0) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-muted-foreground">
          <AlertTriangle className="mx-auto mb-3 h-8 w-8 opacity-30" />
          <p className="text-sm">No tamper/technique-family findings detected.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-3" data-testid="cloud-tamper-tab">
      {Array.from(groups.entries()).map(([family, familyFindings]) => (
        <TamperFamilyCard key={family} family={family} findings={familyFindings} />
      ))}
    </div>
  );
}

function TamperFamilyCard({
  family,
  findings,
}: {
  family: string;
  findings: HuntFinding[];
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className="rounded-lg border border-slate-700/50 bg-slate-800/40"
      data-testid="cloud-tamper-family-card"
      data-family={family}
    >
      <button
        className="flex items-center gap-2 w-full px-4 py-2.5 text-left"
        onClick={() => setExpanded((v) => !v)}
        data-testid="cloud-tamper-expand"
      >
        {expanded ? (
          <ChevronDown className="w-3.5 h-3.5 text-slate-400 shrink-0" />
        ) : (
          <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
        )}
        <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
        <span className="text-sm font-medium text-slate-200 flex-1">{family}</span>
        <span className="text-xs text-slate-500 shrink-0">
          {findings.length} finding{findings.length === 1 ? "" : "s"}
        </span>
      </button>

      {expanded && (
        <div className="border-t border-slate-700/40 divide-y divide-slate-800">
          {findings.map((f) => (
            <div key={f.id} className="px-6 py-2.5" data-testid="cloud-tamper-finding-row">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-xs font-medium text-slate-200 truncate">{f.title}</p>
                  <p className="text-[11px] text-slate-500 mt-0.5">
                    {new Date(f.created_at).toLocaleString()}
                  </p>
                </div>
                <SeverityBadge severity={f.severity} />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

function Pagination({
  page,
  total,
  pageSize,
  onPage,
}: {
  page: number;
  total: number;
  pageSize: number;
  onPage: (p: number) => void;
}) {
  const totalPages = Math.ceil(total / pageSize) || 1;
  if (totalPages <= 1) return null;
  return (
    <div
      className="flex items-center justify-between text-xs text-muted-foreground pt-2"
      data-testid="cloud-pagination"
    >
      <span>
        Page {page} of {totalPages} ({total} findings)
      </span>
      <div className="flex gap-2">
        <Button
          variant="ghost"
          size="sm"
          disabled={page <= 1}
          onClick={() => onPage(page - 1)}
          data-testid="cloud-prev"
        >
          Prev
        </Button>
        <Button
          variant="ghost"
          size="sm"
          disabled={page >= totalPages}
          onClick={() => onPage(page + 1)}
          data-testid="cloud-next"
        >
          Next
        </Button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export function CloudHuntsPage() {
  const navigate = useNavigate();
  const canTriage = useCanTriage();
  const canPromote = useCanPromote();

  const {
    findings,
    total,
    page,
    pageSize,
    activeTab,
    isLoading,
    isMutating,
    error,
    fetchFindings,
    setTab,
    setPage,
    promote,
    clearError,
  } = useCloudStore();

  const [promoteTargetId, setPromoteTargetId] = useState<string | null>(null);

  // Initial load.
  useEffect(() => {
    void fetchFindings();
  }, [fetchFindings]);

  // 30-second polling.
  const scheduleRefetch = useCallback(() => {
    void fetchFindings();
  }, [fetchFindings]);
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  useEffect(() => {
    pollTimerRef.current = setInterval(scheduleRefetch, POLL_INTERVAL_MS);
    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, [scheduleRefetch]);

  const shadowCount = findings.filter(
    (f) => (f.evidence as Record<string, unknown>)["shadow_workload"] === true,
  ).length;

  const handleTabChange = (value: string) => {
    clearError();
    setTab(value as CloudTab);
  };

  const handlePromoteConfirm = useCallback(
    async (findingId: string) => {
      const investigationId = await promote([findingId]);
      setPromoteTargetId(null);
      navigate(`/investigations/${investigationId}`);
    },
    [promote, navigate],
  );

  return (
    <div className="flex flex-col h-full" data-testid="cloud-hunts-page">
      {/* ---- Header ---- */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-cyan-600/20 border border-cyan-500/30">
            <Cloud className="w-4 h-4 text-cyan-400" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-foreground">Cloud Hunts</h1>
            <p className="text-sm text-muted-foreground">
              {total} finding{total === 1 ? "" : "s"}
              {shadowCount > 0 && (
                <span className="ml-2 text-red-400">
                  · {shadowCount} shadow workload{shadowCount === 1 ? "" : "s"}
                </span>
              )}
            </p>
          </div>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => void fetchFindings()}
          disabled={isLoading}
          data-testid="cloud-refresh"
        >
          {isLoading ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <RefreshCw className="w-4 h-4" />
          )}
          <span className="ml-2 hidden sm:inline">Refresh</span>
        </Button>
      </div>

      {/* ---- View tabs ---- */}
      <div className="px-6 pt-4 border-b border-border">
        <Tabs value={activeTab} onValueChange={handleTabChange}>
          <TabsList data-testid="cloud-tabs">
            {TAB_CONFIG.map((t) => (
              <TabsTrigger key={t.id} value={t.id} data-testid={`cloud-tab-${t.id}`}>
                {t.label}
                {t.id === "shadow_workloads" && shadowCount > 0 && (
                  <span className="ml-1.5 px-1.5 py-0.5 rounded-full text-[10px] bg-red-500/20 text-red-400 border border-red-500/20">
                    {shadowCount}
                  </span>
                )}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
      </div>

      {/* ---- RBAC notice ---- */}
      {!canTriage && (
        <div
          className="mx-6 mt-3 rounded-md border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-xs text-amber-400"
          data-testid="cloud-rbac-notice"
        >
          Triage and promote actions require the <strong>analyst</strong> role or higher.
        </div>
      )}

      {/* ---- Content ---- */}
      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-5xl mx-auto space-y-4">
          {error && (
            <div
              className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-2 text-sm text-destructive"
              role="alert"
              data-testid="cloud-error"
            >
              {error}
            </div>
          )}

          {isLoading && findings.length === 0 && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="w-4 h-4 animate-spin" />
              Loading cloud hunt findings…
            </div>
          )}

          {/* Active tab content */}
          {activeTab === "timeline" && (
            <TimelineTab
              findings={findings}
              canPromote={canPromote}
              isMutating={isMutating}
              onPromote={(id) => setPromoteTargetId(id)}
            />
          )}

          {activeTab === "iam" && <IAMGraphTab findings={findings} />}

          {activeTab === "shadow_workloads" && <ShadowWorkloadsTab findings={findings} />}

          {activeTab === "tamper" && <TamperTab findings={findings} />}

          <Pagination page={page} total={total} pageSize={pageSize} onPage={setPage} />
        </div>
      </div>

      {/* ---- Promote modal ---- */}
      {promoteTargetId && (
        <PromoteModal
          findingId={promoteTargetId}
          isMutating={isMutating}
          onConfirm={handlePromoteConfirm}
          onCancel={() => setPromoteTargetId(null)}
        />
      )}
    </div>
  );
}
