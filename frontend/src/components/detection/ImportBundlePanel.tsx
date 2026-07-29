import { useState } from "react";
import { FileUp, Loader2 } from "lucide-react";
import { Button } from "@/components/ds/button";
import { Textarea } from "@/components/ds/textarea";
import { NativeSelect } from "@/components/ds/native-select";
import {
  proposeDetections,
  proposeDetectionsFromReport,
  type ProposeDetectionsResponse,
} from "@/api/detection";
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
  // "bundle" = STIX 2.1 JSON; "report" = unstructured CTI prose (#113 back
  // half) — the server refangs + extracts IOCs into a synthetic bundle.
  const [mode, setMode] = useState<"bundle" | "report">("bundle");
  const [reportName, setReportName] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ProposeDetectionsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleImport = async () => {
    const text = raw.trim();
    if (!text) {
      setError(
        mode === "bundle" ? "Paste a STIX 2.1 bundle to import." : "Paste CTI report text.",
      );
      return;
    }
    let bundle: Record<string, unknown> | null = null;
    if (mode === "bundle") {
      try {
        bundle = JSON.parse(text) as Record<string, unknown>;
      } catch {
        // Caught client-side only because the message can be more specific
        // than the server's; the server still validates the STIX shape.
        setError("That isn't valid JSON.");
        return;
      }
    }
    setError(null);
    setResult(null);
    setBusy(true);
    try {
      const resp = bundle
        ? await proposeDetections(bundle, tlp)
        : await proposeDetectionsFromReport(text, reportName.trim(), tlp);
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
        <h2 className="text-sm font-semibold">Import CTI</h2>
        <span className="text-xs text-muted-foreground">
          converts indicators into Sigma proposals for review
        </span>
        <div className="ml-2 flex overflow-hidden rounded-md border border-border text-xs">
          <button
            type="button"
            onClick={() => setMode("bundle")}
            data-testid="import-mode-bundle"
            className={
              mode === "bundle"
                ? "bg-primary/20 px-2 py-0.5 text-primary"
                : "px-2 py-0.5 text-muted-foreground hover:text-foreground"
            }
          >
            STIX bundle
          </button>
          <button
            type="button"
            onClick={() => setMode("report")}
            data-testid="import-mode-report"
            className={
              mode === "report"
                ? "bg-primary/20 px-2 py-0.5 text-primary"
                : "px-2 py-0.5 text-muted-foreground hover:text-foreground"
            }
          >
            Report text
          </button>
        </div>
        {busy && (
          <Loader2
            className="w-3.5 h-3.5 animate-spin text-muted-foreground"
            aria-label="Importing"
          />
        )}
      </div>

      <p className="mb-2 max-w-3xl text-xs text-muted-foreground">
        {mode === "bundle"
          ? "Re-importing a bundle updates proposals still awaiting review and leaves any you have already decided alone. TLP:RED bundles are refused."
          : "Paste an advisory, blog post or incident write-up. IOCs are extracted (defanged hxxp:// and [.] forms handled) and each proposal picks up ATT&CK techniques from its surrounding prose. Re-submitting the same report updates, never duplicates."}
      </p>

      <Textarea
        value={raw}
        onChange={(e) => {
          setRaw(e.target.value);
          setError(null);
        }}
        rows={5}
        placeholder={
          mode === "bundle"
            ? '{"type": "bundle", "objects": [...]}'
            : "APT campaign report: spearphishing from billing[at]example[.]net delivered a dropper beaconing to hxxps://c2[.]example[.]com …"
        }
        aria-label={mode === "bundle" ? "STIX 2.1 bundle JSON" : "CTI report text"}
        data-testid="import-bundle-input"
        className="font-mono text-xs"
      />

      {mode === "report" && (
        <input
          type="text"
          value={reportName}
          onChange={(e) => setReportName(e.target.value)}
          placeholder="Report name (optional, shown in proposal provenance)"
          aria-label="Report name"
          data-testid="import-report-name"
          className="mt-2 h-9 w-full max-w-md rounded-md border border-border bg-background px-3 text-xs"
        />
      )}

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
          {mode === "bundle" ? "Import bundle" : "Extract & propose"}
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
