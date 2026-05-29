import { useState, useCallback, useMemo } from "react";
import {
  Loader2,
  ShieldBan,
  AlertTriangle,
  RotateCcw,
  CheckCircle2,
  Sparkles,
  Ban,
  ShieldCheck,
} from "lucide-react";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ds/button";
import { Textarea } from "@/components/ds/textarea";
import { Label } from "@/components/ds/label";
import { Badge } from "@/components/ds/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ds/card";
import {
  planBulkMitigation,
  type IOCRef,
  type IOCType,
  type MitigationAction,
  type MitigationOutput,
} from "@/api/mitigation";

const DECISION_VARIANT: Record<string, "destructive" | "medium" | "secondary" | "low"> = {
  block: "destructive",
  skip_allowlisted: "low",
  skip_invalid: "secondary",
  skip_unsupported: "secondary",
  skip_duplicate: "secondary",
};

const SAMPLE = `45.83.12.7
185.220.101.42
evil-c2.example
https://phish.example/login
8.8.8.8
10.0.0.5
CVE-2024-1234
44d88612fea8a8f36de82e1278abb02f`;

const HASH_LEN: Record<number, IOCType> = {
  32: "hash_md5",
  40: "hash_sha1",
  64: "hash_sha256",
};

/** Best-effort client-side IOC typing. The backend re-validates everything. */
function classifyLine(raw: string): IOCRef | null {
  const value = raw.trim();
  if (!value) return null;
  if (/^https?:\/\//i.test(value)) return { type: "url", value };
  const hashType = /^[A-Fa-f0-9]+$/.test(value) ? HASH_LEN[value.length] : undefined;
  if (hashType) return { type: hashType, value };
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return { type: "ip", value };
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return { type: "email", value };
  if (/^CVE-\d{4}-\d+$/i.test(value)) return { type: "cve", value };
  if (/^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,}$/.test(value))
    return { type: "domain", value };
  return { type: "other", value };
}

export function BulkMitigationPage() {
  const [text, setText] = useState("");
  const [allowlist, setAllowlist] = useState("");
  const [output, setOutput] = useState<MitigationOutput | null>(null);
  const [approvals, setApprovals] = useState<Record<string, boolean>>({});
  const [staged, setStaged] = useState<MitigationAction[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const parsedIocs = useMemo(
    () => text.split("\n").map(classifyLine).filter((x): x is IOCRef => x !== null),
    [text],
  );

  const handlePlan = useCallback(async () => {
    if (parsedIocs.length === 0) return;
    setLoading(true);
    setError(null);
    setOutput(null);
    setApprovals({});
    setStaged(null);
    try {
      const extra = allowlist
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean);
      const out = await planBulkMitigation({ iocs: parsedIocs, extra_allowlist: extra });
      setOutput(out);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Plan generation failed");
    } finally {
      setLoading(false);
    }
  }, [parsedIocs, allowlist]);

  const actions = output?.plan.actions ?? [];
  const blocks = useMemo(() => actions.filter((a) => a.decision === "block"), [actions]);
  const approvedCount = blocks.filter((a) => approvals[a.id]).length;
  const allApproved = blocks.length > 0 && approvedCount === blocks.length;

  const toggle = (id: string) => setApprovals((p) => ({ ...p, [id]: !p[id] }));
  const approveAll = () =>
    setApprovals(Object.fromEntries(blocks.map((a) => [a.id, true])));

  const handleStage = useCallback(() => {
    setStaged(blocks.filter((a) => approvals[a.id]));
  }, [blocks, approvals]);

  return (
    <>
      <Header title="Bulk Mitigation" />
      <div className="flex-1 overflow-y-auto p-6 space-y-6" data-testid="bulk-mitigation">
        {/* Input */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <ShieldBan className="w-5 h-5 text-primary" />
              Bulk IOC block & mitigation
            </CardTitle>
            <CardDescription>
              Paste IOCs (one per line). The assistant screens each against a
              never-block allowlist, validates it, routes the block to the right
              connector + policy, and renders a policy-change preview with rollback.
              Nothing executes — you approve each block, then stage. (UC-3.3)
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="iocs">IOCs ({parsedIocs.length} parsed)</Label>
              <Textarea
                id="iocs"
                value={text}
                onChange={(e) => setText(e.target.value)}
                rows={7}
                placeholder={"45.83.12.7\nevil-c2.example\nhttps://phish.example/login"}
                className="font-mono text-sm"
                data-testid="bulk-mitigation-input"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="allow">Extra allowlist (never block — comma/line separated)</Label>
              <Textarea
                id="allow"
                value={allowlist}
                onChange={(e) => setAllowlist(e.target.value)}
                rows={2}
                placeholder="partner-api.example, 203.0.113.10"
                className="font-mono text-sm"
              />
            </div>
            <div className="flex items-center gap-3">
              <Button
                onClick={handlePlan}
                disabled={loading || parsedIocs.length === 0}
                data-testid="bulk-mitigation-submit"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Planning…
                  </>
                ) : (
                  "Plan mitigation"
                )}
              </Button>
              <Button variant="ghost" onClick={() => setText(SAMPLE)} disabled={loading}>
                Use sample IOCs
              </Button>
            </div>
            {error && (
              <div
                className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
                role="alert"
              >
                {error}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Result */}
        {output && (
          <div className="space-y-6" data-testid="bulk-mitigation-result">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex flex-wrap items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-primary" />
                  <Badge variant="destructive" className="gap-1">
                    <Ban className="w-3 h-3" /> {output.plan.block_count} to block
                  </Badge>
                  <Badge variant="secondary">{output.plan.skip_count} skipped</Badge>
                  {output.plan.tools.map((t) => (
                    <Badge key={t} variant="outline">
                      {t}
                    </Badge>
                  ))}
                  {!output.mock_mode && (
                    <Badge variant="secondary" className="gap-1">
                      <Sparkles className="w-3 h-3" /> AI-refined
                    </Badge>
                  )}
                </CardTitle>
                <CardDescription>{output.plan.summary}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <ul className="space-y-2">
                  {actions.map((a) => {
                    const isBlock = a.decision === "block";
                    const approved = !!approvals[a.id];
                    return (
                      <li
                        key={a.id}
                        className="rounded-md border border-border p-3 space-y-1.5"
                        data-testid="mitigation-action"
                        data-decision={a.decision}
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge variant={DECISION_VARIANT[a.decision] ?? "secondary"}>
                            {a.decision.replace(/_/g, " ")}
                          </Badge>
                          <span className="font-mono text-sm text-foreground break-all">
                            {a.ioc_value}
                          </span>
                          <Badge variant="outline">{a.ioc_type}</Badge>
                          {isBlock && (
                            <>
                              <Badge variant="outline">{a.tool}</Badge>
                              <Badge variant="destructive" className="gap-1">
                                <AlertTriangle className="w-3 h-3" /> destructive
                              </Badge>
                              <label className="ml-auto inline-flex items-center gap-1.5 text-xs font-medium cursor-pointer select-none">
                                <input
                                  type="checkbox"
                                  checked={approved}
                                  onChange={() => toggle(a.id)}
                                  className="h-4 w-4 accent-primary"
                                  data-testid={`approve-${a.id}`}
                                />
                                {approved ? "approved" : "approve"}
                              </label>
                            </>
                          )}
                        </div>
                        {isBlock ? (
                          <>
                            <p className="font-mono text-xs text-foreground bg-muted/50 rounded px-2 py-1 break-all">
                              {a.policy_preview}
                            </p>
                            {a.rollback && (
                              <p className="text-xs text-muted-foreground flex items-start gap-1">
                                <RotateCcw className="w-3 h-3 mt-0.5 shrink-0" />
                                Rollback: {a.rollback}
                              </p>
                            )}
                          </>
                        ) : (
                          <p className="text-xs text-muted-foreground">{a.reason}</p>
                        )}
                      </li>
                    );
                  })}
                </ul>

                {blocks.length > 0 && (
                  <div className="flex flex-wrap items-center gap-3 pt-1">
                    <Button
                      onClick={handleStage}
                      disabled={!allApproved}
                      data-testid="bulk-mitigation-stage"
                    >
                      Stage approved blocks
                    </Button>
                    <Button variant="ghost" onClick={approveAll} disabled={allApproved}>
                      Approve all
                    </Button>
                    <span className="text-sm text-muted-foreground">
                      {approvedCount} of {blocks.length} block(s) approved
                    </span>
                  </div>
                )}

                {staged && (
                  <div
                    className="rounded-md border border-primary/30 bg-primary/5 p-3 text-sm space-y-1"
                    data-testid="bulk-mitigation-staged"
                    role="status"
                  >
                    <p className="flex items-center gap-1.5 font-medium text-foreground">
                      <CheckCircle2 className="w-4 h-4 text-primary" />
                      Staged {staged.length} block(s) for execution.
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Execution requires incident-commander sign-off — nothing has run.
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </>
  );
}
