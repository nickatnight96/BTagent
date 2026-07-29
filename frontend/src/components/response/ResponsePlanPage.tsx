import { useState, useCallback, useMemo } from "react";
import {
  Loader2,
  Siren,
  ShieldCheck,
  Clock,
  RotateCcw,
  AlertTriangle,
  CheckCircle2,
  Sparkles,
} from "lucide-react";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
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
  generateResponsePlan,
  type ResponseAction,
  type ResponsePlanOutput,
  type TypedIntent,
} from "@/api/response-plan";
import { executeResponseAction, type ExecutionResult } from "@/api/containment";
import type { Severity } from "@/api/triage";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";

const INTENTS: TypedIntent[] = [
  "malware_detected",
  "c2_beaconing",
  "data_exfil_suspected",
  "privilege_escalation",
  "lateral_movement",
  "suspicious_login",
  "phishing",
  "reconnaissance",
  "policy_violation",
  "benign",
  "unknown",
];

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const CATEGORY_VARIANT: Record<string, "destructive" | "medium" | "secondary"> = {
  contain: "destructive",
  investigate: "medium",
  document: "secondary",
};

const SAMPLE = {
  intent: "malware_detected" as TypedIntent,
  severity: "critical" as Severity,
  host: "WS-12",
  ip: "185.220.101.42",
  user: "",
  domain: "",
};

function splitEntities(raw: string): string[] {
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

export function ResponsePlanPage() {
  const [intent, setIntent] = useState<TypedIntent>("malware_detected");
  const [severity, setSeverity] = useState<Severity>("high");
  const [host, setHost] = useState("");
  const [ip, setIp] = useState("");
  const [user, setUser] = useState("");
  const [domain, setDomain] = useState("");

  const [output, setOutput] = useState<ResponsePlanOutput | null>(null);
  const [approvals, setApprovals] = useState<Record<string, boolean>>({});
  const [staged, setStaged] = useState<ResponseAction[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [executing, setExecuting] = useState(false);
  const [results, setResults] = useState<Record<string, ExecutionResult> | null>(
    null,
  );

  // Execution is gated on the caller's scope: only incident_commander+ (or
  // admin) hold `containment:execute`. Analysts see the plan but not the button;
  // the backend re-enforces the scope regardless, so this is UX, not security.
  const role = useAuthStore((s) => s.user?.role);
  const canExecute =
    role === UserRole.INCIDENT_COMMANDER || role === UserRole.ADMIN;

  const handleGenerate = useCallback(async () => {
    setLoading(true);
    setError(null);
    setOutput(null);
    setApprovals({});
    setStaged(null);
    setResults(null);
    try {
      const entities: Record<string, string[]> = {};
      const h = splitEntities(host);
      const i = splitEntities(ip);
      const u = splitEntities(user);
      const d = splitEntities(domain);
      if (h.length) entities.host = h;
      if (i.length) entities.ip = i;
      if (u.length) entities.user = u;
      if (d.length) entities.domain = d;
      const out = await generateResponsePlan({ typed_intent: intent, severity, entities });
      setOutput(out);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Plan generation failed");
    } finally {
      setLoading(false);
    }
  }, [intent, severity, host, ip, user, domain]);

  // Memoized: a fresh `?? []` identity every render would invalidate the
  // approvalSteps memo and the handleStage callback each time.
  const steps = useMemo(() => output?.plan.tactical_steps ?? [], [output]);
  const approvalSteps = useMemo(() => steps.filter((s) => s.requires_approval), [steps]);
  const approvedCount = approvalSteps.filter((s) => approvals[s.id]).length;
  const allApproved = approvalSteps.length > 0 && approvedCount === approvalSteps.length;

  const toggle = (id: string) =>
    setApprovals((prev) => ({ ...prev, [id]: !prev[id] }));

  const handleStage = useCallback(() => {
    const chosen = steps.filter((s) => !s.requires_approval || approvals[s.id]);
    setStaged(chosen);
    setResults(null);
  }, [steps, approvals]);

  const handleExecute = useCallback(async () => {
    if (!staged || !canExecute) return;
    setExecuting(true);
    setError(null);
    const collected: Record<string, ExecutionResult> = {};
    try {
      // Only destructive/contain steps go through the connector layer; read-only
      // steps (investigate/document) are informational and skipped here.
      for (const action of staged.filter((s) => s.destructive)) {
        collected[action.id] = await executeResponseAction(action);
      }
      setResults(collected);
    } catch (e) {
      setResults(collected);
      setError(e instanceof Error ? e.message : "Execution failed");
    } finally {
      setExecuting(false);
    }
  }, [staged, canExecute]);

  return (
    <>
      <Header title="Response Plan" />
      <div className="flex-1 overflow-y-auto p-6 space-y-6" data-testid="response-plan">
        {/* Input */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Siren className="w-5 h-5 text-primary" />
              Build a containment & response plan
            </CardTitle>
            <CardDescription>
              For a confirmed true positive, generate a dual-path plan: a strategic
              goal plus a tactical list of connector actions. Destructive steps need
              explicit approval and carry a rollback. Planning runs nothing; only an
              incident commander can then execute the approved, safelist-guarded,
              audited containment. (UC-3.2)
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="space-y-1.5 flex-1">
                <Label htmlFor="intent">Typed intent</Label>
                <NativeSelect
                  id="intent"
                  value={intent}
                  onChange={(e) => setIntent(e.target.value as TypedIntent)}
                  data-testid="response-plan-intent"
                >
                  {INTENTS.map((it) => (
                    <option key={it} value={it}>
                      {it.replace(/_/g, " ")}
                    </option>
                  ))}
                </NativeSelect>
              </div>
              <div className="space-y-1.5 sm:w-40">
                <Label htmlFor="sev">Severity</Label>
                <NativeSelect
                  id="sev"
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value as Severity)}
                >
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </NativeSelect>
              </div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="host">Hosts</Label>
                <Input
                  id="host"
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  placeholder="WS-12, DB-03"
                  data-testid="response-plan-host"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="ip">IPs</Label>
                <Input
                  id="ip"
                  value={ip}
                  onChange={(e) => setIp(e.target.value)}
                  placeholder="185.220.101.42"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="user">Accounts</Label>
                <Input
                  id="user"
                  value={user}
                  onChange={(e) => setUser(e.target.value)}
                  placeholder="alice@corp"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="domain">Domains</Label>
                <Input
                  id="domain"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="evil.example"
                />
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Button
                onClick={handleGenerate}
                disabled={loading}
                data-testid="response-plan-submit"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Generating…
                  </>
                ) : (
                  "Generate plan"
                )}
              </Button>
              <Button
                variant="ghost"
                onClick={() => {
                  setIntent(SAMPLE.intent);
                  setSeverity(SAMPLE.severity);
                  setHost(SAMPLE.host);
                  setIp(SAMPLE.ip);
                  setUser(SAMPLE.user);
                  setDomain(SAMPLE.domain);
                }}
                disabled={loading}
              >
                Use sample incident
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
          <div className="space-y-6" data-testid="response-plan-result">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex flex-wrap items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-primary" />
                  <span className="text-foreground">{output.plan.strategic_goal}</span>
                  {output.plan.estimated_containment_minutes != null && (
                    <Badge variant="medium" className="gap-1">
                      <Clock className="w-3 h-3" />
                      {output.plan.estimated_containment_minutes}m target
                    </Badge>
                  )}
                  {!output.mock_mode && (
                    <Badge variant="secondary" className="gap-1">
                      <Sparkles className="w-3 h-3" /> AI-refined
                    </Badge>
                  )}
                </CardTitle>
                <CardDescription>{output.plan.rationale}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-xs font-semibold text-muted-foreground">
                  Tactical steps ({steps.length}) — {approvalSteps.length} require approval
                </p>
                <ol className="space-y-2">
                  {steps.map((s, i) => {
                    const approved = !!approvals[s.id];
                    return (
                      <li
                        key={s.id}
                        className="rounded-md border border-border p-3 space-y-1.5"
                        data-testid="response-action"
                        data-approved={s.requires_approval ? approved : undefined}
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-xs text-muted-foreground tabular-nums">
                            {i + 1}.
                          </span>
                          <Badge variant={CATEGORY_VARIANT[s.category] ?? "secondary"}>
                            {s.category}
                          </Badge>
                          <span className="font-medium text-foreground text-sm">
                            {s.action_type.replace(/_/g, " ")}
                          </span>
                          {s.target && (
                            <span className="text-sm text-muted-foreground">
                              → {s.target}
                            </span>
                          )}
                          <Badge variant="outline">{s.connector}</Badge>
                          {s.destructive && (
                            <Badge variant="destructive" className="gap-1">
                              <AlertTriangle className="w-3 h-3" /> destructive
                            </Badge>
                          )}
                          {s.requires_approval ? (
                            <label className="ml-auto inline-flex items-center gap-1.5 text-xs font-medium cursor-pointer select-none">
                              <input
                                type="checkbox"
                                checked={approved}
                                onChange={() => toggle(s.id)}
                                className="h-4 w-4 accent-primary"
                                data-testid={`approve-${s.id}`}
                              />
                              {approved ? "approved" : "approve"}
                            </label>
                          ) : (
                            <Badge variant="secondary" className="ml-auto">
                              read-only
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm text-foreground">{s.description}</p>
                        {s.rollback && (
                          <p className="text-xs text-muted-foreground flex items-start gap-1">
                            <RotateCcw className="w-3 h-3 mt-0.5 shrink-0" />
                            Rollback: {s.rollback}
                          </p>
                        )}
                      </li>
                    );
                  })}
                </ol>

                <div className="flex flex-wrap items-center gap-3 pt-1">
                  <Button
                    onClick={handleStage}
                    disabled={approvalSteps.length > 0 && !allApproved}
                    data-testid="response-plan-stage"
                  >
                    Stage approved actions
                  </Button>
                  {approvalSteps.length > 0 && (
                    <span className="text-sm text-muted-foreground">
                      {approvedCount} of {approvalSteps.length} destructive action(s) approved
                    </span>
                  )}
                </div>

                {staged && (
                  <div
                    className="rounded-md border border-primary/30 bg-primary/5 p-3 text-sm space-y-2"
                    data-testid="response-plan-staged"
                    role="status"
                  >
                    <p className="flex items-center gap-1.5 font-medium text-foreground">
                      <CheckCircle2 className="w-4 h-4 text-primary" />
                      Staged {staged.length} action(s) for execution.
                    </p>
                    {canExecute ? (
                      <div className="flex flex-wrap items-center gap-3">
                        <Button
                          onClick={handleExecute}
                          disabled={executing || staged.every((s) => !s.destructive)}
                          data-testid="response-plan-execute"
                        >
                          {executing ? (
                            <>
                              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                              Executing…
                            </>
                          ) : (
                            "Execute approved containment"
                          )}
                        </Button>
                        <span className="text-xs text-muted-foreground">
                          Runs the destructive steps through the connector layer,
                          safelist-guarded and audited.
                        </span>
                      </div>
                    ) : (
                      <p className="text-xs text-muted-foreground">
                        Execution requires incident-commander sign-off
                        (containment:execute) — nothing has run.
                      </p>
                    )}
                  </div>
                )}

                {results && (
                  <div
                    className="rounded-md border border-border p-3 text-sm space-y-1"
                    data-testid="response-plan-results"
                    role="status"
                  >
                    <p className="font-medium text-foreground">Execution results</p>
                    <ul className="space-y-1">
                      {Object.entries(results).map(([id, r]) => (
                        <li key={id} className="flex items-center gap-2">
                          <Badge
                            variant={
                              r.outcome === "success"
                                ? "secondary"
                                : "destructive"
                            }
                          >
                            {r.outcome}
                          </Badge>
                          <span className="text-muted-foreground">
                            {r.tool} → {r.target || "n/a"}
                          </span>
                          {r.change_ref && (
                            <span className="text-xs text-muted-foreground">
                              change: {r.change_ref}
                            </span>
                          )}
                        </li>
                      ))}
                    </ul>
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
