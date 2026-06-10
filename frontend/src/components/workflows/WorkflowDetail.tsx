import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft,
  CheckCircle2,
  Clock,
  Eye,
  Loader2,
  Pause,
  Pencil,
  Play,
  RefreshCw,
  ShieldCheck,
  Workflow as WorkflowIcon,
  XCircle,
} from "lucide-react";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ds/button";
import { Textarea } from "@/components/ds/textarea";
import { Label } from "@/components/ds/label";
import { Badge } from "@/components/ds/badge";
import { NativeSelect } from "@/components/ds/native-select";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ds/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ds/dialog";
import {
  getWorkflow,
  listRuns,
  listVersions,
  resumeRun,
  runVersion,
  type RunWorkflowRequest,
  type TLP,
  type Workflow,
  type WorkflowRun,
  type WorkflowRunStatus,
  type WorkflowVersion,
  type WorkflowVersionState,
} from "@/api/workflows";
import { listInvestigations } from "@/api/investigations";
import type { Investigation } from "@/types/investigation";

const TLP_OPTIONS: { value: "" | TLP; label: string }[] = [
  { value: "", label: "Inherit (investigation, else fail-closed RED)" },
  { value: "red", label: "TLP:RED" },
  { value: "amber_strict", label: "TLP:AMBER+STRICT" },
  { value: "amber", label: "TLP:AMBER" },
  { value: "green", label: "TLP:GREEN" },
  { value: "white", label: "TLP:WHITE" },
];

const VERSION_VARIANT: Record<WorkflowVersionState, "high" | "medium" | "secondary"> = {
  published: "high",
  draft: "medium",
  deprecated: "secondary",
};

const RUN_STATUS: Record<
  WorkflowRunStatus,
  { variant: "high" | "destructive" | "medium" | "secondary" | "low"; icon: React.ReactNode }
> = {
  succeeded: { variant: "low", icon: <CheckCircle2 className="w-3 h-3" /> },
  failed: { variant: "destructive", icon: <XCircle className="w-3 h-3" /> },
  paused: { variant: "medium", icon: <Pause className="w-3 h-3" /> },
  running: { variant: "high", icon: <Loader2 className="w-3 h-3 animate-spin" /> },
  pending: { variant: "secondary", icon: <Clock className="w-3 h-3" /> },
};

function formatRelativeTime(dateStr: string | null): string {
  if (!dateStr) return "Never";
  const date = new Date(dateStr);
  const diffMs = Date.now() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);
  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

export function WorkflowDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [workflow, setWorkflow] = useState<Workflow | null>(null);
  const [versions, setVersions] = useState<WorkflowVersion[]>([]);
  const [runs, setRuns] = useState<WorkflowRun[]>([]);
  const [runsTotal, setRunsTotal] = useState(0);
  const [runsPage, setRunsPage] = useState(1);
  const [loadingMoreRuns, setLoadingMoreRuns] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [resumingId, setResumingId] = useState<string | null>(null);

  const RUNS_PAGE_SIZE = 50;

  const [launchOpen, setLaunchOpen] = useState(false);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [launchVersion, setLaunchVersion] = useState<number | "">("");
  const [launchInvestigation, setLaunchInvestigation] = useState<string>("");
  const [launchTlp, setLaunchTlp] = useState<"" | TLP>("");
  const [launchPayload, setLaunchPayload] = useState("{}");
  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const [wf, vs, rs] = await Promise.all([
        getWorkflow(id),
        listVersions(id),
        listRuns(id, { page: 1, page_size: RUNS_PAGE_SIZE }),
      ]);
      setWorkflow(wf);
      setVersions(vs.items);
      setRuns(rs.items);
      setRunsTotal(rs.total);
      setRunsPage(1);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load workflow");
    } finally {
      setLoading(false);
    }
  }, [id]);

  // Load-more pagination for runs (addresses the codex P2 finding: workflows
  // with >50 runs previously had no UI affordance to reach older history).
  const loadMoreRuns = useCallback(async () => {
    if (!id || loadingMoreRuns || runs.length >= runsTotal) return;
    setLoadingMoreRuns(true);
    try {
      const next = runsPage + 1;
      const resp = await listRuns(id, { page: next, page_size: RUNS_PAGE_SIZE });
      setRuns((prev) => [...prev, ...resp.items]);
      setRunsTotal(resp.total);
      setRunsPage(next);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load more runs");
    } finally {
      setLoadingMoreRuns(false);
    }
  }, [id, loadingMoreRuns, runs.length, runsTotal, runsPage]);

  // Approve the paused step and resume the run (requires hitl:approve). The
  // run row is updated in place server-side; we just reload to reflect the
  // new status (succeeded / failed / paused-again at a later gate).
  const handleResume = useCallback(
    async (runId: string) => {
      if (!id) return;
      setResumingId(runId);
      setError(null);
      try {
        await resumeRun(id, runId);
        await load();
      } catch (e) {
        setError(e instanceof Error ? e.message : "Resume failed");
      } finally {
        setResumingId(null);
      }
    },
    [id, load],
  );

  useEffect(() => {
    void load();
  }, [load]);

  // Pick the published version (else the latest) as the launch default.
  const defaultLaunchVersion = useMemo(() => {
    const published = versions.find((v) => v.state === "published");
    if (published) return published.version_number;
    if (versions.length > 0) return versions[versions.length - 1]!.version_number;
    return "" as const;
  }, [versions]);

  const openLaunch = useCallback(async () => {
    setLaunchVersion(defaultLaunchVersion);
    setLaunchInvestigation("");
    setLaunchTlp("");
    setLaunchPayload("{}");
    setLaunchError(null);
    setLaunchOpen(true);
    // Lazy-load the investigation list the first time the dialog opens.
    if (investigations.length === 0) {
      try {
        const resp = await listInvestigations({ page_size: 50 });
        setInvestigations(resp.items);
      } catch {
        // Silent: the picker just stays empty; the analyst can run without an investigation.
      }
    }
  }, [defaultLaunchVersion, investigations.length]);

  const handleLaunch = useCallback(async () => {
    if (!id || launchVersion === "") return;
    setLaunching(true);
    setLaunchError(null);
    try {
      let payload: Record<string, unknown> = {};
      const raw = launchPayload.trim();
      if (raw) {
        try {
          payload = JSON.parse(raw);
        } catch {
          throw new Error("Trigger payload must be valid JSON");
        }
      }
      const body: RunWorkflowRequest = { trigger_payload: payload };
      if (launchInvestigation) body.investigation_id = launchInvestigation;
      if (launchTlp) body.active_tlp = launchTlp;
      await runVersion(id, Number(launchVersion), body);
      setLaunchOpen(false);
      await load();
    } catch (e) {
      setLaunchError(e instanceof Error ? e.message : "Launch failed");
    } finally {
      setLaunching(false);
    }
  }, [id, launchVersion, launchInvestigation, launchTlp, launchPayload, load]);

  if (!id) {
    return (
      <>
        <Header title="Workflow" />
        <div className="p-6">Missing workflow id.</div>
      </>
    );
  }

  return (
    <>
      <Header title={workflow?.name ?? "Workflow"} />
      <div className="flex-1 overflow-y-auto p-6 space-y-6" data-testid="workflow-detail">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={() => navigate("/workflows")}>
            <ArrowLeft className="w-4 h-4 mr-1.5" />
            All workflows
          </Button>
          <div className="ml-auto flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={load} disabled={loading}>
              <RefreshCw className={`w-4 h-4 mr-1.5 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </Button>
            <Button
              onClick={openLaunch}
              disabled={!workflow || versions.length === 0}
              data-testid="workflow-launch-open"
            >
              <Play className="w-4 h-4 mr-2" />
              Launch run
            </Button>
          </div>
        </div>

        {loading && (
          <div className="flex items-center gap-2 text-muted-foreground text-sm">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading…
          </div>
        )}
        {error && (
          <div
            className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
            role="alert"
          >
            {error}
          </div>
        )}

        {workflow && (
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <WorkflowIcon className="w-5 h-5 text-primary" />
                <span data-testid="workflow-name">{workflow.name}</span>
              </CardTitle>
              {workflow.description && (
                <CardDescription>{workflow.description}</CardDescription>
              )}
            </CardHeader>
            <CardContent className="text-xs text-muted-foreground flex items-center gap-1.5">
              <Clock className="w-3 h-3" />
              Updated {formatRelativeTime(workflow.updated_at)}
            </CardContent>
          </Card>
        )}

        {/* Versions */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Versions</CardTitle>
            <CardDescription>
              draft → published → deprecated. Exactly one version is published at a
              time; publishing a new draft auto-deprecates the prior one.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {versions.length === 0 ? (
              <p className="text-sm text-muted-foreground">No versions yet.</p>
            ) : (
              <ul className="space-y-2" data-testid="workflow-versions">
                {versions.map((v) => (
                  <li
                    key={v.id}
                    className="rounded-md border border-border p-3 flex flex-wrap items-center gap-3"
                    data-testid="workflow-version-row"
                    data-version-number={v.version_number}
                  >
                    <span className="font-medium text-sm">v{v.version_number}</span>
                    <Badge variant={VERSION_VARIANT[v.state]}>{v.state}</Badge>
                    <span className="text-xs text-muted-foreground">
                      Created {formatRelativeTime(v.created_at)}
                    </span>
                    {v.published_at && (
                      <span className="text-xs text-muted-foreground">
                        Published {formatRelativeTime(v.published_at)}
                      </span>
                    )}
                    <div className="ml-auto flex items-center gap-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          navigate(`/workflows/${id}/versions/${v.version_number}/canvas`)
                        }
                        data-testid="workflow-version-canvas-link"
                        data-version-number={v.version_number}
                      >
                        <Eye className="w-4 h-4 mr-1.5" />
                        View
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          navigate(`/workflows/${id}/versions/${v.version_number}/edit`)
                        }
                        data-testid="workflow-version-edit-link"
                        data-version-number={v.version_number}
                        title={
                          v.state === "draft"
                            ? "Edit this draft in place"
                            : "Saving will fork a new draft from this version"
                        }
                      >
                        <Pencil className="w-4 h-4 mr-1.5" />
                        {v.state === "draft" ? "Edit" : "Fork & edit"}
                      </Button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        {/* Runs */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Run history</CardTitle>
            <CardDescription>
              Newest first. Each run records its trigger payload, per-step outputs,
              the hash-linked evidence chain, and a link back to the originating
              investigation when launched from one.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {runs.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No runs yet. Click "Launch run" to start one.
              </p>
            ) : (
              <ul className="space-y-2" data-testid="workflow-runs">
                {runs.map((r) => {
                  const sm = RUN_STATUS[r.status];
                  return (
                    <li
                      key={r.id}
                      className="rounded-md border border-border p-3 space-y-1.5"
                      data-testid="workflow-run-row"
                      data-run-status={r.status}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge variant={sm.variant} className="gap-1">
                          {sm.icon}
                          {r.status}
                        </Badge>
                        <span className="text-sm">v{r.version_number}</span>
                        {r.investigation_id && (
                          <Badge variant="outline" className="gap-1">
                            <ShieldCheck className="w-3 h-3" />
                            inv {r.investigation_id.slice(0, 12)}…
                          </Badge>
                        )}
                        <span className="text-xs text-muted-foreground ml-auto">
                          {formatRelativeTime(r.created_at)}
                        </span>
                      </div>
                      <div className="text-xs text-muted-foreground flex flex-wrap gap-3">
                        <span>{r.nodes_executed.length} step(s) executed</span>
                        <span>{r.evidence_chain.length} evidence record(s)</span>
                        {r.approved_steps.length > 0 && (
                          <span>{r.approved_steps.length} approved</span>
                        )}
                      </div>
                      {r.error && (
                        <p className="text-xs text-destructive break-words">{r.error}</p>
                      )}
                      {r.status === "paused" && (
                        <div className="flex flex-wrap items-center gap-2 pt-1">
                          <span className="text-xs text-muted-foreground">
                            Awaiting approval at{" "}
                            <span className="font-mono text-foreground">
                              {r.paused_node_id ?? "?"}
                            </span>
                          </span>
                          <Button
                            size="sm"
                            className="ml-auto"
                            onClick={() => handleResume(r.id)}
                            disabled={resumingId === r.id}
                            data-testid="workflow-run-resume"
                            data-run-id={r.id}
                          >
                            {resumingId === r.id ? (
                              <>
                                <Loader2 className="w-4 h-4 mr-1.5 animate-spin" />
                                Resuming…
                              </>
                            ) : (
                              <>
                                <Play className="w-4 h-4 mr-1.5" />
                                Approve &amp; resume
                              </>
                            )}
                          </Button>
                        </div>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
            {runs.length > 0 && (
              <div
                className="mt-3 flex items-center justify-between text-xs text-muted-foreground"
                data-testid="workflow-runs-pagination"
              >
                <span>
                  Showing {runs.length} of {runsTotal}
                </span>
                {runs.length < runsTotal && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={loadMoreRuns}
                    disabled={loadingMoreRuns}
                    data-testid="workflow-runs-load-more"
                  >
                    {loadingMoreRuns ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" /> Loading…
                      </>
                    ) : (
                      "Load more"
                    )}
                  </Button>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Launch dialog */}
      <Dialog open={launchOpen} onOpenChange={setLaunchOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Launch workflow run</DialogTitle>
            <DialogDescription>
              Runs synchronously through the engine. Destructive integration steps
              pause for approval; nothing executes un-gated.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <div className="space-y-1.5">
              <Label htmlFor="launch-version">Version</Label>
              <NativeSelect
                id="launch-version"
                value={launchVersion === "" ? "" : String(launchVersion)}
                onChange={(e) => setLaunchVersion(e.target.value ? Number(e.target.value) : "")}
                data-testid="launch-version-select"
              >
                <option value="" disabled>
                  Pick a version…
                </option>
                {versions.map((v) => (
                  <option key={v.id} value={v.version_number}>
                    v{v.version_number} ({v.state})
                  </option>
                ))}
              </NativeSelect>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="launch-inv">Investigation (optional)</Label>
              <NativeSelect
                id="launch-inv"
                value={launchInvestigation}
                onChange={(e) => setLaunchInvestigation(e.target.value)}
                data-testid="launch-investigation-select"
              >
                <option value="">— None (ad-hoc) —</option>
                {investigations.map((inv) => (
                  <option key={inv.id} value={inv.id}>
                    {inv.title} {inv.tlp_level ? `(TLP:${inv.tlp_level})` : ""}
                  </option>
                ))}
              </NativeSelect>
              <p className="text-xs text-muted-foreground">
                Linking an investigation makes the run inherit its classification —
                see TLP override below.
              </p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="launch-tlp">Active TLP</Label>
              <NativeSelect
                id="launch-tlp"
                value={launchTlp}
                onChange={(e) => setLaunchTlp(e.target.value as "" | TLP)}
              >
                {TLP_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </NativeSelect>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="launch-payload">Trigger payload (JSON)</Label>
              <Textarea
                id="launch-payload"
                value={launchPayload}
                onChange={(e) => setLaunchPayload(e.target.value)}
                rows={4}
                className="font-mono text-xs"
                data-testid="launch-payload"
              />
            </div>
            {launchError && (
              <div
                className="rounded-md border border-destructive/30 bg-destructive/10 p-2.5 text-sm text-destructive"
                role="alert"
              >
                {launchError}
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setLaunchOpen(false)} disabled={launching}>
              Cancel
            </Button>
            <Button
              onClick={handleLaunch}
              disabled={launching || launchVersion === ""}
              data-testid="launch-submit"
            >
              {launching ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Running…
                </>
              ) : (
                "Run"
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
