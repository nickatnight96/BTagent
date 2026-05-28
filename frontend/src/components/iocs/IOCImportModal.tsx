import { useState, useCallback, useMemo } from "react";
import {
  Upload,
  FileText,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
} from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ds/dialog";
import { Button } from "@/components/ds/button";
import { Badge } from "@/components/ds/badge";
import { Label } from "@/components/ds/label";
import { Textarea } from "@/components/ds/textarea";
import { NativeSelect } from "@/components/ds/native-select";
import { cn } from "@/lib/utils";
import { useIOCStore } from "@/stores/iocStore";
import { useInvestigationStore } from "@/stores/investigationStore";
import type { ImportPreviewRow, IOCType } from "@/types/ioc";

interface IOCImportModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

type ImportFormat = "csv" | "stix";

/** Attempt to parse raw text as CSV rows for preview */
function parseCSVPreview(text: string): ImportPreviewRow[] {
  const lines = text
    .trim()
    .split("\n")
    .filter((l) => l.trim());
  if (lines.length === 0) return [];

  const firstLine = lines[0].toLowerCase();
  const hasHeader =
    firstLine.includes("type") ||
    firstLine.includes("value") ||
    firstLine.includes("ioc");
  const dataLines = hasHeader ? lines.slice(1) : lines;

  return dataLines.map((line) => {
    const parts = line.split(",").map((p) => p.trim().replace(/^"|"$/g, ""));
    const type = (parts[0] ?? "other") as IOCType;
    const value = parts[1] ?? "";
    const source = parts[2] ?? "manual";
    const confidence = parseFloat(parts[3] ?? "0.5");
    const tags = parts[4] ? parts[4].split(";").map((t) => t.trim()) : [];

    const validTypes: IOCType[] = [
      "ip",
      "domain",
      "hash_md5",
      "hash_sha1",
      "hash_sha256",
      "url",
      "email",
      "cve",
      "file_path",
      "other",
    ];

    const valid = validTypes.includes(type) && value.length > 0;
    const error = !validTypes.includes(type)
      ? `Invalid type: ${type}`
      : value.length === 0
        ? "Empty value"
        : undefined;

    return { type, value, source, confidence, tags, valid, error };
  });
}

/** Attempt to parse raw text as STIX 2.1 JSON for preview */
function parseSTIXPreview(text: string): ImportPreviewRow[] {
  try {
    const parsed = JSON.parse(text);
    const objects =
      parsed.objects ?? (Array.isArray(parsed) ? parsed : [parsed]);

    const stixTypeMap: Record<string, IOCType> = {
      "ipv4-addr": "ip",
      "ipv6-addr": "ip",
      "domain-name": "domain",
      url: "url",
      "email-addr": "email",
      file: "hash_sha256",
    };

    return objects
      .filter(
        (obj: Record<string, unknown>) =>
          obj.type === "indicator" || stixTypeMap[obj.type as string]
      )
      .map((obj: Record<string, unknown>) => {
        const pattern = (obj.pattern as string) ?? "";
        const name = (obj.name as string) ?? "";
        const type = stixTypeMap[obj.type as string] ?? "other";

        const valueMatch = pattern.match(/'([^']+)'/);
        const value = valueMatch?.[1] ?? name ?? String(obj.value ?? "");

        return {
          type,
          value,
          source: "stix_import",
          confidence:
            typeof obj.confidence === "number" ? obj.confidence / 100 : 0.5,
          tags: [] as string[],
          valid: value.length > 0,
          error:
            value.length === 0
              ? "Could not extract value from STIX object"
              : undefined,
        };
      });
  } catch {
    return [];
  }
}

export function IOCImportModal({ open, onOpenChange }: IOCImportModalProps) {
  const { importIOCs, isImporting } = useIOCStore();
  const { investigations } = useInvestigationStore();

  const [format, setFormat] = useState<ImportFormat>("csv");
  const [rawText, setRawText] = useState("");
  const [investigationId, setInvestigationId] = useState("");
  const [importResult, setImportResult] = useState<{
    imported: number;
    skipped: number;
    errors: number;
  } | null>(null);
  const [importError, setImportError] = useState<string | null>(null);

  const preview = useMemo(() => {
    if (!rawText.trim()) return [];
    return format === "csv"
      ? parseCSVPreview(rawText)
      : parseSTIXPreview(rawText);
  }, [rawText, format]);

  const validCount = preview.filter((r) => r.valid).length;
  const invalidCount = preview.filter((r) => !r.valid).length;

  const handleImport = useCallback(async () => {
    setImportError(null);
    setImportResult(null);
    try {
      const result = await importIOCs(
        rawText,
        format,
        investigationId || undefined
      );
      setImportResult({
        imported: result.imported ?? 0,
        skipped: result.skipped ?? 0,
        errors: (result.errors ?? []).length,
      });
    } catch (err) {
      setImportError(err instanceof Error ? err.message : "Import failed");
    }
  }, [rawText, format, investigationId, importIOCs]);

  const handleClose = useCallback(() => {
    setRawText("");
    setImportResult(null);
    setImportError(null);
    setFormat("csv");
    setInvestigationId("");
    onOpenChange(false);
  }, [onOpenChange]);

  return (
    <Dialog open={open} onOpenChange={(o) => (o ? onOpenChange(o) : handleClose())}>
      <DialogContent
        className="max-w-2xl"
        data-testid="ioc-import"
      >
        <DialogHeader>
          <DialogTitle>Import IOCs</DialogTitle>
          <DialogDescription>
            Paste CSV data or STIX 2.1 JSON to import indicators of compromise.
          </DialogDescription>
        </DialogHeader>

        {/* Format selector */}
        <div className="flex items-center gap-2">
          <Label>Format</Label>
          <div
            className="flex items-center gap-0.5 bg-muted rounded-md p-0.5"
            role="tablist"
            aria-label="Import format"
          >
            {(["csv", "stix"] as ImportFormat[]).map((f) => {
              const active = format === f;
              return (
                <button
                  key={f}
                  onClick={() => setFormat(f)}
                  role="tab"
                  aria-selected={active}
                  data-testid={`ioc-import-format-tab-${f}`}
                  className={cn(
                    "px-3 py-1.5 rounded text-xs font-medium transition-colors",
                    active
                      ? "bg-primary/20 text-primary"
                      : "text-muted-foreground hover:text-foreground"
                  )}
                >
                  <span className="flex items-center gap-1.5">
                    <FileText className="w-3.5 h-3.5" aria-hidden="true" />
                    {f === "csv" ? "CSV" : "STIX 2.1"}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Investigation assignment */}
        <div className="space-y-1.5">
          <Label htmlFor="ioc-import-investigation">
            Assign to Investigation (optional)
          </Label>
          <NativeSelect
            id="ioc-import-investigation"
            value={investigationId}
            onChange={(e) => setInvestigationId(e.target.value)}
            aria-label="Assign import to investigation"
            data-testid="ioc-import-investigation-input"
          >
            <option value="">No investigation</option>
            {investigations.map((inv) => (
              <option key={inv.id} value={inv.id}>
                {inv.title}
              </option>
            ))}
          </NativeSelect>
        </div>

        {/* Paste area */}
        <div className="space-y-1.5">
          <Label htmlFor="ioc-import-paste">
            {format === "csv"
              ? "Paste CSV (type,value,source,confidence,tags)"
              : "Paste STIX 2.1 JSON"}
          </Label>
          <Textarea
            id="ioc-import-paste"
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            placeholder={
              format === "csv"
                ? "ip,192.168.1.1,siem,0.9,malware;c2\ndomain,evil.com,analyst,0.8,phishing"
                : '{"type": "bundle", "objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = \'10.0.0.1\']", ...}]}'
            }
            rows={6}
            aria-label={
              format === "csv" ? "Paste CSV IOC data" : "Paste STIX 2.1 JSON"
            }
            data-testid="ioc-import-paste-input"
            className="font-mono resize-none"
          />
        </div>

        {/* Preview table */}
        {preview.length > 0 && (
          <div className="space-y-2" data-testid="ioc-import-preview">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-muted-foreground">
                Preview ({preview.length} rows)
              </span>
              <div className="flex items-center gap-3 text-xs">
                <span className="flex items-center gap-1 text-severity-low">
                  <CheckCircle2 className="w-3 h-3" aria-hidden="true" />
                  {validCount} valid
                </span>
                {invalidCount > 0 && (
                  <span className="flex items-center gap-1 text-destructive">
                    <XCircle className="w-3 h-3" aria-hidden="true" />
                    {invalidCount} invalid
                  </span>
                )}
              </div>
            </div>
            <div className="max-h-48 overflow-auto rounded-md border border-border">
              <table
                className="w-full text-xs"
                data-testid="ioc-import-preview-table"
              >
                <thead className="bg-card sticky top-0">
                  <tr>
                    <th className="px-2 py-1.5 text-left text-muted-foreground font-medium">
                      Status
                    </th>
                    <th className="px-2 py-1.5 text-left text-muted-foreground font-medium">
                      Type
                    </th>
                    <th className="px-2 py-1.5 text-left text-muted-foreground font-medium">
                      Value
                    </th>
                    <th className="px-2 py-1.5 text-left text-muted-foreground font-medium">
                      Confidence
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {preview.slice(0, 50).map((row, idx) => (
                    <tr
                      key={idx}
                      data-testid={`ioc-import-preview-row-${idx}`}
                      className={cn(
                        "border-b border-border/40",
                        idx % 2 === 0 ? "bg-background" : "bg-card/40"
                      )}
                    >
                      <td className="px-2 py-1.5">
                        {row.valid ? (
                          <CheckCircle2
                            className="w-3.5 h-3.5 text-severity-low"
                            aria-label="Valid row"
                          />
                        ) : (
                          <span title={row.error}>
                            <XCircle
                              className="w-3.5 h-3.5 text-destructive"
                              aria-label={row.error ?? "Invalid row"}
                            />
                          </span>
                        )}
                      </td>
                      <td className="px-2 py-1.5">
                        <Badge variant="secondary" className="text-[9px]">
                          {row.type}
                        </Badge>
                      </td>
                      <td className="px-2 py-1.5 font-mono text-foreground max-w-[200px] truncate">
                        {row.value}
                      </td>
                      <td className="px-2 py-1.5 text-muted-foreground tabular-nums">
                        {Math.round(row.confidence * 100)}%
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {preview.length > 50 && (
              <p className="text-[10px] text-muted-foreground/60">
                Showing first 50 of {preview.length} rows
              </p>
            )}
          </div>
        )}

        {/* Import result */}
        {importResult && (
          <div
            className="p-3 rounded-md border border-severity-low/30 bg-severity-low/10"
            data-testid="ioc-import-result"
          >
            <div className="flex items-center gap-2 mb-1">
              <CheckCircle2
                className="w-4 h-4 text-severity-low"
                aria-hidden="true"
              />
              <span className="text-sm font-medium text-severity-low">
                Import Complete
              </span>
            </div>
            <div className="flex items-center gap-4 text-xs text-foreground mt-1">
              <span>{importResult.imported} imported</span>
              <span>{importResult.skipped} skipped</span>
              {importResult.errors > 0 && (
                <span className="text-destructive">
                  {importResult.errors} errors
                </span>
              )}
            </div>
          </div>
        )}

        {/* Import error */}
        {importError && (
          <div
            className="p-3 rounded-md border border-destructive/30 bg-destructive/10"
            role="alert"
            data-testid="ioc-import-error"
          >
            <div className="flex items-center gap-2">
              <AlertTriangle
                className="w-4 h-4 text-destructive"
                aria-hidden="true"
              />
              <span className="text-sm text-destructive">{importError}</span>
            </div>
          </div>
        )}

        <DialogFooter>
          <Button
            variant="ghost"
            onClick={handleClose}
            data-testid="ioc-import-cancel-button"
          >
            {importResult ? "Done" : "Cancel"}
          </Button>
          {!importResult && (
            <Button
              onClick={handleImport}
              disabled={validCount === 0 || isImporting}
              data-testid="ioc-import-submit-button"
            >
              {isImporting ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Upload className="w-4 h-4 mr-2" aria-hidden="true" />
              )}
              Import {validCount} IOC{validCount !== 1 ? "s" : ""}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
