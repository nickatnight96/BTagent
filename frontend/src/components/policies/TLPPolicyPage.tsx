import { useState, useEffect, useCallback } from "react";
import { Loader2, ShieldCheck, Trash2, Plus, FlaskConical, AlertTriangle } from "lucide-react";
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
  listEgressKinds,
  createTLPPolicy,
  deleteTLPPolicy,
  evaluateTLPPolicy,
  EGRESS_KINDS,
  type EgressKindInfo,
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

const ADVISORY_NOTE =
  "Advisory: this channel has no runtime gate, so a policy naming it is recorded and evaluated but never applied to a real egress.";

// Fallback used only if `GET /tlp-policies/egress-kinds` fails. Every channel
// is shown, none claimed as enforced: an outage must not silently upgrade an
// advisory channel to a governed one in the operator's mind. The reverse
// mistake — an enforced channel briefly labelled advisory — costs nothing.
const FALLBACK_KINDS: EgressKindInfo[] = EGRESS_KINDS.map((kind) => ({
  kind,
  policy_enforced: false,
}));

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
  // The channel the displayed decision was computed for. Changing the select
  // afterwards leaves the decision on screen, so naming `evalKind` in the
  // warning below would attribute the verdict to a channel it is not about.
  const [decidedKind, setDecidedKind] = useState<string>("");

  const [kinds, setKinds] = useState<EgressKindInfo[]>(FALLBACK_KINDS);

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

  // Separate from `load` so a policy-list failure does not also blank the
  // picker — the two are independent reads and the form stays usable.
  useEffect(() => {
    void (async () => {
      try {
        setKinds(await listEgressKinds());
      } catch {
        setKinds(FALLBACK_KINDS);
      }
    })();
  }, []);

  const advisoryKinds = kinds.filter((k) => !k.policy_enforced).map((k) => k.kind);
  // An empty selection means "any channel" on the backend, so it covers the
  // ungoverned ones too. Reporting the broadest policy in the system as fully
  // enforced is the one reading that is exactly backwards.
  const selectedAdvisory =
    egressKinds.length === 0
      ? advisoryKinds
      : advisoryKinds.filter((k) => egressKinds.includes(k));

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
      setDecidedKind(evalKind);
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
                {kinds.map(({ kind, policy_enforced }) => (
                  <Button
                    key={kind}
                    type="button"
                    variant={egressKinds.includes(kind) ? "default" : "outline"}
                    size="sm"
                    title={policy_enforced ? undefined : ADVISORY_NOTE}
                    data-testid={`egress-kind-${kind}`}
                    data-advisory={policy_enforced ? undefined : "true"}
                    onClick={() => setEgressKinds((p) => toggle(p, kind))}
                  >
                    {kind}
                    {!policy_enforced && <span className="ml-1.5 opacity-70">·&nbsp;advisory</span>}
                  </Button>
                ))}
              </div>
              {selectedAdvisory.length > 0 && (
                <p
                  className="flex items-start gap-1.5 text-xs text-amber-400"
                  data-testid="advisory-channel-warning"
                  role="status"
                >
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-px" />
                  <span>
                    {selectedAdvisory.join(", ")}{" "}
                    {selectedAdvisory.length === 1 ? "has" : "have"} no runtime gate. This policy
                    will be recorded and shown here, but nothing consults it when data leaves over{" "}
                    {selectedAdvisory.length === 1 ? "that channel" : "those channels"}.
                  </span>
                </p>
              )}
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
                  {kinds.map(({ kind, policy_enforced }) => (
                    <option key={kind} value={kind}>
                      {kind}
                      {policy_enforced ? "" : " (advisory)"}
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
                {!decision.policy_enforced && (
                  // Without this the verdict above reads as a description of
                  // what the system does. For an ungoverned channel it is a
                  // description of what the policy set says and nothing else,
                  // which is the more dangerous half of the pair when it says
                  // BLOCKED.
                  <p
                    className="flex items-start gap-1.5 text-xs text-amber-400 mt-2"
                    data-testid="tlp-evaluate-unenforced"
                    role="status"
                  >
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-px" />
                    <span>
                      Not enforced at runtime. This is what the policy set says for{" "}
                      <code>{decidedKind}</code>; no gate consults it when data actually leaves
                      over that channel.
                    </span>
                  </p>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}
