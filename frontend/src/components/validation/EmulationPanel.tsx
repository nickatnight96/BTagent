import { useState } from "react";
import { Crosshair, Loader2, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
import { NativeSelect } from "@/components/ds/native-select";
import { emulationDenial, runEmulation } from "@/api/validation";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";
import type {
  Emulator,
  EmulationDenied,
  TargetEnv,
  TechniqueVerdict,
  ValidationRunResponse,
} from "@/types/validation";

const VERDICT_STYLE: Record<string, string> = {
  validated: "text-emerald-400",
  wrong_severity: "text-amber-400",
  late: "text-amber-400",
  silent_gap: "text-rose-400",
  errored: "text-rose-400",
};

/**
 * Adversary-emulation trigger (#118).
 *
 * `POST /validation/emulate` shipped with no consumer, so the emulation path —
 * the part of detection validation that actually fires a technique and scores
 * what the SIEM saw — was unreachable outside curl.
 *
 * Three things about this control are deliberate:
 *
 * 1. **The target-env selector offers non-sandbox values.** It would be easy to
 *    hardcode `sandbox` and call that safe, but that would only hide the
 *    control, not enforce it — the server's allowlist is the enforcement, and
 *    it is fail-closed. Letting an operator pick `production` and receive the
 *    audited refusal is how they learn the guardrail is real, and it exercises
 *    the denial path in the product rather than only in tests.
 * 2. **A denial is rendered as an outcome, not an error.** The 403 body carries
 *    a ledger `audit_id`; showing "request failed" would discard the operator's
 *    only pointer into the audit trail.
 * 3. **The panel hides below incident commander.** `validation:emulate` is
 *    gated at the same tier as `containment:execute`, and the server enforces
 *    it regardless — this just avoids showing a control that can only 403.
 */
export function EmulationPanel({
  onComplete,
  prefillTechnique,
}: {
  onComplete?: () => void;
  /**
   * Technique to load into the form, e.g. from a stale row in the coverage
   * map. Deliberately fills the field WITHOUT submitting — this control fires
   * a technique, so the operator still has to press the button.
   */
  prefillTechnique?: string | null;
}) {
  const role = useAuthStore((s) => s.user?.role);
  const mayEmulate = role === UserRole.INCIDENT_COMMANDER || role === UserRole.ADMIN;

  const [techniqueId, setTechniqueId] = useState("");
  const [targetEnv, setTargetEnv] = useState<TargetEnv>("sandbox");
  const [emulator, setEmulator] = useState<Emulator>("atomic_red_team");
  const [busy, setBusy] = useState(false);
  const [denial, setDenial] = useState<EmulationDenied | null>(null);
  const [verdicts, setVerdicts] = useState<TechniqueVerdict[]>([]);
  const [error, setError] = useState<string | null>(null);

  // Adjusting state when a prop changes, done during render rather than in an
  // effect (https://react.dev/learn/you-might-not-need-an-effect). An effect
  // here would cost a second render pass on every hand-off from the coverage
  // map, and trips react-hooks/set-state-in-effect.
  const [lastPrefill, setLastPrefill] = useState<string | null>(null);
  if (prefillTechnique && prefillTechnique !== lastPrefill) {
    setLastPrefill(prefillTechnique);
    setTechniqueId(prefillTechnique);
    setError(null);
  }

  if (!mayEmulate) return null;

  const handleEmulate = async () => {
    const technique = techniqueId.trim().toUpperCase();
    if (!technique) {
      setError("Enter an ATT&CK technique id, e.g. T1059.");
      return;
    }
    setError(null);
    setDenial(null);
    setVerdicts([]);
    setBusy(true);
    try {
      const run: ValidationRunResponse = await runEmulation({
        technique_id: technique,
        target_env: targetEnv,
        emulator,
      });
      setVerdicts(run.verdicts ?? []);
      onComplete?.();
    } catch (e) {
      const refused = emulationDenial(e);
      if (refused) {
        setDenial(refused);
      } else {
        setError("Emulation run failed.");
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <section
      className="mb-6 rounded-lg border border-border bg-card/50 p-4"
      data-testid="emulation-panel"
    >
      <div className="mb-2 flex items-center gap-2">
        <Crosshair className="h-4 w-4 text-primary" aria-hidden="true" />
        <h2 className="text-sm font-semibold">Adversary emulation</h2>
        <span className="text-xs text-muted-foreground">
          fires one ATT&amp;CK technique and scores what fired back
        </span>
        {busy && (
          <Loader2
            className="h-3.5 w-3.5 animate-spin text-muted-foreground"
            aria-label="Emulating"
          />
        )}
      </div>

      <p className="mb-3 max-w-3xl text-xs text-muted-foreground">
        Only <span className="font-mono">sandbox</span> is an approved target. Anything
        else is refused before an emulator is reached, and the refusal is written to
        the audit ledger.
      </p>

      <form
        className="flex flex-wrap items-start gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          void handleEmulate();
        }}
      >
        <Input
          value={techniqueId}
          onChange={(e) => {
            setTechniqueId(e.target.value);
            setError(null);
          }}
          placeholder="T1059"
          aria-label="ATT&CK technique id"
          data-testid="emulation-technique"
          className="h-9 w-36 font-mono"
        />
        <NativeSelect
          value={targetEnv}
          onChange={(e) => setTargetEnv(e.target.value as TargetEnv)}
          aria-label="Target environment"
          data-testid="emulation-target-env"
          className="h-9 w-40"
        >
          <option value="sandbox">sandbox (approved)</option>
          <option value="staging">staging</option>
          <option value="production">production</option>
        </NativeSelect>
        <NativeSelect
          value={emulator}
          onChange={(e) => setEmulator(e.target.value as Emulator)}
          aria-label="Emulator"
          data-testid="emulation-emulator"
          className="h-9 w-44"
        >
          <option value="atomic_red_team">Atomic Red Team</option>
          <option value="caldera">MITRE Caldera</option>
        </NativeSelect>
        <Button type="submit" size="sm" disabled={busy} data-testid="emulation-run">
          Emulate
        </Button>
      </form>

      {error && (
        <p className="mt-2 text-xs text-severity-medium" role="alert" data-testid="emulation-error">
          {error}
        </p>
      )}

      {denial && (
        <div
          className="mt-3 rounded-md border border-rose-500/30 bg-rose-600/10 p-3 text-xs"
          role="alert"
          data-testid="emulation-denied"
        >
          <div className="flex items-center gap-2 font-semibold text-rose-300">
            <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
            Refused — no emulator ran
          </div>
          <p className="mt-1 text-rose-200/90">{denial.reason}</p>
          <p className="mt-1 text-muted-foreground">
            Audit entry{" "}
            <span className="font-mono" data-testid="emulation-denied-audit">
              {denial.audit_id}
            </span>
          </p>
        </div>
      )}

      {verdicts.length > 0 && (
        <ul className="mt-3 space-y-1.5" data-testid="emulation-verdicts">
          {verdicts.map((v) => (
            <li
              key={`${v.technique_id}-${v.verdict}`}
              className="flex flex-wrap items-center gap-3 rounded-md border border-border bg-background/40 px-3 py-2 text-xs"
              data-testid={`emulation-verdict-${v.technique_id}`}
            >
              <span className="font-mono">{v.technique_id}</span>
              <span className={`font-semibold ${VERDICT_STYLE[v.verdict] ?? ""}`}>
                {v.verdict.replace(/_/g, " ")}
              </span>
              <span className="text-muted-foreground">
                {v.latency_seconds == null
                  ? "no firing observed"
                  : `${v.latency_seconds.toFixed(1)}s / ${v.latency_sla_seconds}s SLA`}
              </span>
              {v.detail && <span className="flex-1 text-muted-foreground">{v.detail}</span>}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
