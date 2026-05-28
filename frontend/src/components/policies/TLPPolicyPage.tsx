import { useState, useEffect, useCallback } from "react";
import { Loader2, ShieldCheck, Trash2, Plus, FlaskConical } from "lucide-react";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ds/button";
import { Label } from "@/components/ds/label";
import { Badge } from "@/components/ds/badge";
import { Textarea } from "@/components/ds/textarea";
import { NativeSelect } from "@/components/ds/native-select";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ds/card";
import {
  listTLPPolicies,
  createTLPPolicy,
  deleteTLPPolicy,
  evaluateTLPPolicy,
  EGRESS_KINDS,
  type TLPPolicy,
  type TLPPolicyAction,
  type TLP,
  type PolicyDecision,
} from "@/api/tlpPolicies";

const ACTIONS: { value: TLPPolicyAction; label: string }[] = [
  { value: "allow", label: "Allow" },
  { value: "deny", label: "Deny" },
  { value: "downgrade_then_allow", label: "Downgrade then allow" },
];

const TLP_LEVELS: TLP[] = ["red", "amber_strict", "amber", "green", "white"];

const ACTION_VARIANT: Record<TLPPolicyAction, "low" | "destructive" | "medium"> = {
  allow: "low",
  deny: "destructive",
  downgrade_then_allow: "medium",
};

export function TLPPolicyPage() {
  const [policies, setPolicies] = useState<TLPPolicy[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // create-form state
  const [action, setAction] = useState<TLPPolicyAction>("allow");
  const [egressKinds, setEgressKinds] = useState<string[]>([]);
  const [appliesTo, setAppliesTo] = useState<TLP[]>([]);
  const [downgradeTo, setDowngradeTo] = useState<TLP>("amber");
  const [rationale, setRationale] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // evaluate state
  const [evalTlp, setEvalTlp] = useState<TLP>("red");
  const [evalKind, setEvalKind] = useState<string>("stix_export");
  const [decision, setDecision] = useState<PolicyDecision | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setPolicies(await listTLPPolicies());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load policies");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const toggle = <T extends string>(arr: T[], v: T): T[] =>
    arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v];

  const handleCreate = useCallback(async () => {
    setSubmitting(true);
    setError(null);
    try {
      await createTLPPolicy({
        action,
        egress_kinds: egressKinds,
        applies_to_tlp: appliesTo,
        downgrade_to: action === "downgrade_then_allow" ? downgradeTo : null,
        rationale: rationale.trim(),
      });
      setRationale("");
      setEgressKinds([]);
      setAppliesTo([]);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create policy");
    } finally {
      setSubmitting(false);
    }
  }, [action, egressKinds, appliesTo, downgradeTo, rationale, load]);

  const handleDelete = useCallback(
    async (id: string) => {
      setError(null);
      try {
        await deleteTLPPolicy(id);
        await load();
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to revoke policy");
      }
    },
    [load],
  );

  const handleEvaluate = useCallback(async () => {
    setError(null);
    try {
      setDecision(await evaluateTLPPolicy(evalTlp, evalKind));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Evaluation failed");
    }
  }, [evalTlp, evalKind]);

  return (
    <>
      <Header title="TLP Egress Policies" />
      <div className="flex-1 overflow-y-auto p-6 space-y-6" data-testid="tlp-policies">
        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-primary" />
              Default-deny egress, with approved exceptions
            </CardTitle>
            <CardDescription>
              All data defaults to TLP:RED and is blocked from leaving the enclave.
              Policies here are CISO-approved exceptions that <em>widen</em> (allow /
              downgrade) or explicitly deny a specific channel. Creating or revoking a
              policy requires admin. (UC-7.2)
            </CardDescription>
          </CardHeader>
          {error && (
            <CardContent>
              <div
                className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
                role="alert"
              >
                {error}
              </div>
            </CardContent>
          )}
        </Card>

        {/* Create */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Plus className="w-4 h-4 text-primary" />
              New policy
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4" data-testid="tlp-policy-create-form">
            <div className="grid sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="action">Action</Label>
                <NativeSelect
                  id="action"
                  value={action}
                  onChange={(e) => setAction(e.target.value as TLPPolicyAction)}
                >
                  {ACTIONS.map((a) => (
                    <option key={a.value} value={a.value}>
                      {a.label}
                    </option>
                  ))}
                </NativeSelect>
              </div>
              {action === "downgrade_then_allow" && (
                <div className="space-y-1.5">
                  <Label htmlFor="downgrade">Downgrade to</Label>
                  <NativeSelect
                    id="downgrade"
                    value={downgradeTo}
                    onChange={(e) => setDowngradeTo(e.target.value as TLP)}
                  >
                    {TLP_LEVELS.map((t) => (
                      <option key={t} value={t}>
                        {t}
                      </option>
                    ))}
                  </NativeSelect>
                </div>
              )}
            </div>

            <div className="space-y-1.5">
              <Label>Egress channels (empty = any)</Label>
              <div className="flex flex-wrap gap-2">
                {EGRESS_KINDS.map((k) => (
                  <Button
                    key={k}
                    type="button"
                    variant={egressKinds.includes(k) ? "default" : "outline"}
                    size="sm"
                    onClick={() => setEgressKinds((p) => toggle(p, k))}
                  >
                    {k}
                  </Button>
                ))}
              </div>
            </div>

            <div className="space-y-1.5">
              <Label>Applies to TLP (empty = any)</Label>
              <div className="flex flex-wrap gap-2">
                {TLP_LEVELS.map((t) => (
                  <Button
                    key={t}
                    type="button"
                    variant={appliesTo.includes(t) ? "default" : "outline"}
                    size="sm"
                    onClick={() => setAppliesTo((p) => toggle(p, t))}
                  >
                    {t}
                  </Button>
                ))}
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="rationale">Rationale</Label>
              <Textarea
                id="rationale"
                value={rationale}
                onChange={(e) => setRationale(e.target.value)}
                placeholder="Why this exception is approved (recorded for audit)…"
                rows={2}
              />
            </div>

            <Button onClick={handleCreate} disabled={submitting} data-testid="tlp-policy-create-button">
              {submitting ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" /> Creating…
                </>
              ) : (
                "Create policy"
              )}
            </Button>
          </CardContent>
        </Card>

        {/* List */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Active policies {loading && <Loader2 className="inline w-4 h-4 animate-spin" />}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto rounded-md border border-border">
              <table className="w-full text-xs" data-testid="tlp-policy-table">
                <thead className="bg-card">
                  <tr className="text-left text-muted-foreground">
                    <th className="px-2 py-2 font-medium">Action</th>
                    <th className="px-2 py-2 font-medium">Applies to</th>
                    <th className="px-2 py-2 font-medium">Channels</th>
                    <th className="px-2 py-2 font-medium">Approver</th>
                    <th className="px-2 py-2 font-medium">Rationale</th>
                    <th className="px-2 py-2 font-medium text-right" />
                  </tr>
                </thead>
                <tbody>
                  {policies.map((p) => (
                    <tr key={p.id} className="border-t border-border/40">
                      <td className="px-2 py-1.5">
                        <Badge variant={ACTION_VARIANT[p.action]}>
                          {p.action}
                          {p.downgrade_to ? ` → ${p.downgrade_to}` : ""}
                        </Badge>
                      </td>
                      <td className="px-2 py-1.5">
                        {p.applies_to_tlp.length ? p.applies_to_tlp.join(", ") : "any"}
                      </td>
                      <td className="px-2 py-1.5">
                        {p.egress_kinds.length ? p.egress_kinds.join(", ") : "any"}
                      </td>
                      <td className="px-2 py-1.5 font-mono">{p.approver_id}</td>
                      <td className="px-2 py-1.5 text-muted-foreground max-w-xs truncate">
                        {p.rationale}
                      </td>
                      <td className="px-2 py-1.5 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleDelete(p.id)}
                          data-testid={`tlp-policy-delete-${p.id}`}
                        >
                          <Trash2 className="w-4 h-4 text-destructive" />
                        </Button>
                      </td>
                    </tr>
                  ))}
                  {policies.length === 0 && !loading && (
                    <tr>
                      <td colSpan={6} className="px-2 py-8 text-center text-muted-foreground">
                        No policies — default-deny is in full effect.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        {/* Evaluate */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <FlaskConical className="w-4 h-4 text-primary" />
              Dry-run a decision
            </CardTitle>
            <CardDescription>
              Check what the gate would do for a given classification + channel,
              given the current policy set.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col sm:flex-row gap-3 sm:items-end">
              <div className="space-y-1.5">
                <Label htmlFor="eval-tlp">TLP</Label>
                <NativeSelect
                  id="eval-tlp"
                  value={evalTlp}
                  onChange={(e) => setEvalTlp(e.target.value as TLP)}
                  className="sm:w-40"
                >
                  {TLP_LEVELS.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </NativeSelect>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="eval-kind">Egress channel</Label>
                <NativeSelect
                  id="eval-kind"
                  value={evalKind}
                  onChange={(e) => setEvalKind(e.target.value)}
                  className="sm:w-48"
                >
                  {EGRESS_KINDS.map((k) => (
                    <option key={k} value={k}>
                      {k}
                    </option>
                  ))}
                </NativeSelect>
              </div>
              <Button onClick={handleEvaluate} data-testid="tlp-evaluate-button">
                Evaluate
              </Button>
            </div>
            {decision && (
              <div className="mt-4" data-testid="tlp-evaluate-result">
                <Badge variant={decision.allowed ? "low" : "destructive"}>
                  {decision.allowed ? "ALLOWED" : "BLOCKED"} · {decision.effective_tlp}
                </Badge>
                <p className="text-sm text-muted-foreground mt-1">{decision.reason}</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}
