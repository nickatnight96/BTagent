/**
 * IOC notebook-annotation section (EPIC-5 UC-5.2).
 *
 * Rendered inside the IOC detail panel: pin toggle, disposition select,
 * free-form tags (comma-separated input), and a working note, saved through
 * ``PATCH /iocs/{id}/annotate``. State is seeded from the selected IOC and
 * the whole patch is sent on Save so what the analyst sees is exactly what
 * lands. RBAC (`ioc:edit`) is enforced server-side — a 403 surfaces in the
 * section's error line.
 */

import { useCallback, useEffect, useState } from "react";
import { Loader2, Pin, PinOff, Save } from "lucide-react";
import { Button } from "@/components/ds/button";
import { annotateIOC } from "@/api/iocs";
import type { IOC, IOCDisposition } from "@/types/ioc";

const DISPOSITIONS: Array<{ value: IOCDisposition; label: string }> = [
  { value: "", label: "No disposition" },
  { value: "under_review", label: "Under review" },
  { value: "confirmed_malicious", label: "Confirmed malicious" },
  { value: "benign", label: "Benign" },
  { value: "false_positive", label: "False positive" },
];

interface AnnotationSectionProps {
  ioc: IOC;
  /** Called with the server's updated IOC after a successful save. */
  onAnnotated?: (updated: IOC) => void;
}

export function AnnotationSection({ ioc, onAnnotated }: AnnotationSectionProps) {
  const [pinned, setPinned] = useState(Boolean(ioc.pinned));
  const [disposition, setDisposition] = useState<IOCDisposition>(
    (ioc.disposition ?? "") as IOCDisposition,
  );
  const [tagsText, setTagsText] = useState((ioc.tags ?? []).join(", "));
  const [note, setNote] = useState(ioc.analyst_note ?? "");
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  // Re-seed when the analyst switches to a different IOC.
  useEffect(() => {
    setPinned(Boolean(ioc.pinned));
    setDisposition((ioc.disposition ?? "") as IOCDisposition);
    setTagsText((ioc.tags ?? []).join(", "));
    setNote(ioc.analyst_note ?? "");
    setError(null);
    setSaved(false);
  }, [ioc.id, ioc.pinned, ioc.disposition, ioc.tags, ioc.analyst_note]);

  const handleSave = useCallback(async () => {
    setIsSaving(true);
    setError(null);
    setSaved(false);
    try {
      const tags = tagsText
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
      const updated = await annotateIOC(ioc.id, {
        pinned,
        tags,
        analyst_note: note,
        disposition,
      });
      setSaved(true);
      onAnnotated?.(updated);
    } catch {
      setError("Failed to save annotations.");
    } finally {
      setIsSaving(false);
    }
  }, [ioc.id, pinned, tagsText, note, disposition, onAnnotated]);

  return (
    <div className="space-y-3" data-testid="ioc-annotations">
      <div className="flex items-center justify-between">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setPinned((p) => !p)}
          data-testid="ioc-annotations-pin"
          title={pinned ? "Unpin from the case notebook" : "Pin to the top of the case notebook"}
        >
          {pinned ? <Pin className="w-4 h-4 text-amber-400" /> : <PinOff className="w-4 h-4" />}
          <span className="ml-2">{pinned ? "Pinned" : "Pin"}</span>
        </Button>
        <select
          value={disposition}
          onChange={(e) => setDisposition(e.target.value as IOCDisposition)}
          data-testid="ioc-annotations-disposition"
          className="rounded-md border border-border bg-background px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-sky-500"
        >
          {DISPOSITIONS.map((d) => (
            <option key={d.value} value={d.value}>
              {d.label}
            </option>
          ))}
        </select>
      </div>

      <input
        type="text"
        value={tagsText}
        onChange={(e) => setTagsText(e.target.value)}
        placeholder="Tags (comma-separated)"
        data-testid="ioc-annotations-tags"
        className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-sky-500"
      />

      <textarea
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="Analyst note…"
        rows={3}
        data-testid="ioc-annotations-note"
        className="w-full resize-y rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-sky-500"
      />

      <div className="flex items-center gap-3">
        <Button
          variant="outline"
          size="sm"
          onClick={() => void handleSave()}
          disabled={isSaving}
          data-testid="ioc-annotations-save"
        >
          {isSaving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
          <span className="ml-2">Save annotations</span>
        </Button>
        {saved && (
          <span className="text-xs text-emerald-400" data-testid="ioc-annotations-saved">
            Saved
          </span>
        )}
        {error && (
          <span className="text-xs text-rose-300" data-testid="ioc-annotations-error">
            {error}
          </span>
        )}
      </div>
    </div>
  );
}
