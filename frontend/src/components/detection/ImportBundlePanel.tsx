import { useState } from "react";
import { FileUp, Loader2 } from "lucide-react";
import { Button } from "@/components/ds/button";
import { Textarea } from "@/components/ds/textarea";
import { NativeSelect } from "@/components/ds/native-select";
import { proposeDetections, type ProposeDetectionsResponse } from "@/api/detection";
import { ApiError } from "@/api/client";

/** Pull a server-supplied reason out of an ApiError, or fall back. */
function errMessage(e: unknown, fallback: string): string {
  if (e instanceof ApiError) {
    const detail = (e.body as { detail?: unknown } | null)?.detail;
    if (typeof detail === "string" && detail) return detail;
  }
  return fallback;
}

/**
 * STIX bundle → Sigma proposals (#113).
 *
 * `POST /cti/propose-detections` is the front of the detection-engineering
 * funnel — every proposal on this page originates from it — and it had no
 * consumer. The review, validate, compose-PR and PR-outcome halves were all
 * reachable; the step that *creates* the work was curl-only. The reachability
 * ratchet (#473) named it.
 *
 * Two server answers are contentful and get surfaced verbatim rather than
 * collapsed into "import failed": a TLP:RED bundle is refused (403) and
 * malformed STIX is rejected (422). Both tell the analyst what to change.
 *
 * The skipped list is shown, not hidden. An indicator that couldn't be
 * converted is the most useful output of an import — it's the CTI the
 * pipeline can't act on — and burying it would make a partial import look
 * complete.
 */
export function ImportBundlePanel({ onImported }: { onImported?: () => void }) {
  const [raw, setRaw] = useState("");
  const [tlp, setTlp] = useState("green");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ProposeDetectionsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleImport = async () => {
    const text = raw.trim();
    if (!text) {
      setError("Paste a STIX 2.1 bundle to import.");
      return;
    }
    let bundle: Record<string, unknown>;
    try {
      bundle = JSON.parse(text);
    } catch {
      // Caught client-side only because the message can be more specific
      // than the server's; the server still validates the STIX shape.
      setError("That isn't valid JSON.");
      return;
    }
    setError(null);
    setResult(null);
    setBusy(true);
    try {
      const resp = await proposeDetections(bundle, tlp);
      setResult(resp);
      onImported?.();
    } catch (e) {
      setError(errMessage(e, "Import failed."));
    } finally {
      setBusy(false);
    }
  };

  const persisted = result?.persisted;

  return (
    <section
      className="mb-6 rounded-lg border border-border bg-card/50 p-4"
      data-testid="import-bundle-panel"
    >
      <div className="mb-2 flex items-center gap-2">
        <FileUp className="w-4 h-4 text-primary" aria-hidden="true" />
        <h2 className="text-sm font-semibold">Import STIX bundle</h2>
        <span className="text-xs text-muted-foreground">
          converts indicators into Sigma proposals for review
        </span>
        {busy && (
          <Loader2
            className="w-3.5 h-3.5 animate-spin text-muted-foreground"
            aria-label="Importing"
          />
        )}
      </div>

      <p className="mb-2 max-w-3xl text-xs text-muted-foreground">
        Re-importing a bundle updates proposals still awaiting review and leaves
        any you have already decided alone. TLP:RED bundles are refused.
      </p>

      <Textarea
        value={raw}
        onChange={(e) => {
          setRaw(e.target.value);
          setError(null);
        }}
        rows={5}
        placeholder='{"type": "bundle", "objects": [...]}'
        aria-label="STIX 2.1 bundle JSON"
        data-testid="import-bundle-input"
        className="font-mono text-xs"
      />

      <div className="mt-2 flex flex-wrap items-center gap-2">
        <NativeSelect
          value={tlp}
          onChange={(e) => setTlp(e.target.value)}
          aria-label="Active TLP"
          data-testid="import-bundle-tlp"
          className="h-9 w-40"
        >
          <option value="white">TLP:WHITE</option>
          <option value="green">TLP:GREEN</option>
          <option value="amber">TLP:AMBER</option>
          <option value="amber_strict">TLP:AMBER+STRICT</option>
        </NativeSelect>
        <Button
          size="sm"
          disabled={busy}
          onClick={() => void handleImport()}
          data-testid="import-bundle-submit"
        >
          Import bundle
        </Button>
      </div>

      {error && (
        <p
          className="mt-2 text-xs text-severity-medium"
          role="alert"
          data-testid="import-bundle-error"
        >
          {error}
        </p>
      )}

      {result && (
        <div className="mt-3 space-y-2 text-xs" role="status" data-testid="import-bundle-result">
          <p>
            {result.proposals.length} proposal
            {result.proposals.length === 1 ? "" : "s"} generated
            {persisted && (
              <>
                {" — "}
                <span data-testid="import-bundle-persisted">
                  {persisted.created} new · {persisted.updated} updated ·{" "}
                  {persisted.unchanged} left as decided
                </span>
              </>
            )}
          </p>
          {result.skipped.length > 0 && (
            // The indicators that DIDN'T convert are the actionable output of
            // an import — hiding them would make a partial run look complete.
            <div data-testid="import-bundle-skipped">
              <p className="text-amber-400">
                {result.skipped.length} indicator
                {result.skipped.length === 1 ? "" : "s"} could not be converted:
              </p>
              <ul className="mt-1 list-disc pl-4 text-muted-foreground">
                {result.skipped.map((s, i) => (
                  <li key={`${s.stix_id}-${i}`}>
                    <span className="font-mono">{s.stix_id || s.pattern || "unknown"}</span> —{" "}
                    {s.reason}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {result.proposals.length === 0 && result.skipped.length === 0 && (
            <p className="text-muted-foreground" data-testid="import-bundle-empty">
              The bundle contained no indicators to convert.
            </p>
          )}
        </div>
      )}
    </section>
  );
}
