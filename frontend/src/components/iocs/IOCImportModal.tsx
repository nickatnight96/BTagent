import { useState, useCallback, useMemo } from "react";
import { Upload, FileText, AlertTriangle, CheckCircle2, XCircle, Loader2 } from "lucide-react";
import { Dialog, DialogContent, DialogFooter } from "@/components/ui/Dialog";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
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

  // Detect if first line is a header
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
      "ip", "domain", "hash_md5", "hash_sha1", "hash_sha256",
      "url", "email", "cve", "file_path", "other",
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
    const objects = parsed.objects ?? (Array.isArray(parsed) ? parsed : [parsed]);

    const stixTypeMap: Record<string, IOCType> = {
      "ipv4-addr": "ip",
      "ipv6-addr": "ip",
      "domain-name": "domain",
      "url": "url",
      "email-addr": "email",
      "file": "hash_sha256",
    };

    return objects
      .filter(
        (obj: Record<string, unknown>) =>
          obj.type === "indicator" || stixTypeMap[obj.type as string],
      )
      .map((obj: Record<string, unknown>) => {
        const pattern = (obj.pattern as string) ?? "";
        const name = (obj.name as string) ?? "";
        const type = stixTypeMap[obj.type as string] ?? "other";

        // Try to extract value from STIX pattern
        const valueMatch = pattern.match(/'([^']+)'/);
        const value = valueMatch?.[1] ?? name ?? String(obj.value ?? "");

        return {
          type,
          value,
          source: "stix_import",
          confidence: typeof obj.confidence === "number" ? obj.confidence / 100 : 0.5,
          tags: [] as string[],
          valid: value.length > 0,
          error: value.length === 0 ? "Could not extract value from STIX object" : undefined,
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
        investigationId || undefined,
      );
      setImportResult({
        imported: result.imported,
        skipped: result.skipped,
        errors: result.errors.length,
      });
    } catch (err) {
      setImportError(
        err instanceof Error ? err.message : "Import failed",
      );
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
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent
        title="Import IOCs"
        description="Paste CSV data or STIX 2.1 JSON to import indicators of compromise."
        className="max-w-2xl"
      >
        {/* Format selector */}
        <div className="flex items-center gap-2 mb-4">
          <label className="text-xs text-slate-500 font-medium">Format</label>
          <div className="flex items-center gap-0.5 bg-slate-800 rounded-md p-0.5">
            <button
              onClick={() => setFormat("csv")}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                format === "csv"
                  ? "bg-blue-600/20 text-blue-400"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <span className="flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5" />
                CSV
              </span>
            </button>
            <button
              onClick={() => setFormat("stix")}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                format === "stix"
                  ? "bg-blue-600/20 text-blue-400"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <span className="flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5" />
                STIX 2.1
              </span>
            </button>
          </div>
        </div>

        {/* Investigation assignment */}
        <div className="mb-4">
          <label className="block text-xs text-slate-500 font-medium mb-1.5">
            Assign to Investigation (optional)
          </label>
          <select
            value={investigationId}
            onChange={(e) => setInvestigationId(e.target.value)}
            className="w-full bg-slate-800 border border-slate-600/50 rounded-md px-3 py-2 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
          >
            <option value="">No investigation</option>
            {investigations.map((inv) => (
              <option key={inv.id} value={inv.id}>
                {inv.title}
              </option>
            ))}
          </select>
        </div>

        {/* Paste area */}
        <div className="mb-4">
          <label className="block text-xs text-slate-500 font-medium mb-1.5">
            {format === "csv"
              ? "Paste CSV (type,value,source,confidence,tags)"
              : "Paste STIX 2.1 JSON"}
          </label>
          <textarea
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            placeholder={
              format === "csv"
                ? "ip,192.168.1.1,siem,0.9,malware;c2\ndomain,evil.com,analyst,0.8,phishing"
                : '{"type": "bundle", "objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = \'10.0.0.1\']", ...}]}'
            }
            rows={6}
            className="w-full bg-slate-800 border border-slate-600/50 rounded-md px-3 py-2 text-sm text-slate-100 font-mono placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-colors resize-none"
          />
        </div>

        {/* Preview table */}
        {preview.length > 0 && (
          <div className="mb-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-medium text-slate-400">
                Preview ({preview.length} rows)
              </span>
              <div className="flex items-center gap-3 text-xs">
                <span className="flex items-center gap-1 text-green-400">
                  <CheckCircle2 className="w-3 h-3" />
                  {validCount} valid
                </span>
                {invalidCount > 0 && (
                  <span className="flex items-center gap-1 text-red-400">
                    <XCircle className="w-3 h-3" />
                    {invalidCount} invalid
                  </span>
                )}
              </div>
            </div>
            <div className="max-h-48 overflow-auto rounded-lg border border-slate-700/50">
              <table className="w-full text-xs">
                <thead className="bg-slate-900 sticky top-0">
                  <tr>
                    <th className="px-2 py-1.5 text-left text-slate-500 font-medium">
                      Status
                    </th>
                    <th className="px-2 py-1.5 text-left text-slate-500 font-medium">
                      Type
                    </th>
                    <th className="px-2 py-1.5 text-left text-slate-500 font-medium">
                      Value
                    </th>
                    <th className="px-2 py-1.5 text-left text-slate-500 font-medium">
                      Confidence
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {preview.slice(0, 50).map((row, idx) => (
                    <tr
                      key={idx}
                      className={`border-b border-slate-800/50 ${
                        idx % 2 === 0 ? "bg-slate-950" : "bg-slate-900/50"
                      }`}
                    >
                      <td className="px-2 py-1.5">
                        {row.valid ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
                        ) : (
                          <span title={row.error}>
                            <XCircle className="w-3.5 h-3.5 text-red-400" />
                          </span>
                        )}
                      </td>
                      <td className="px-2 py-1.5">
                        <Badge className="text-[9px]">{row.type}</Badge>
                      </td>
                      <td className="px-2 py-1.5 font-mono text-slate-300 max-w-[200px] truncate">
                        {row.value}
                      </td>
                      <td className="px-2 py-1.5 text-slate-400 tabular-nums">
                        {Math.round(row.confidence * 100)}%
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {preview.length > 50 && (
              <p className="text-[10px] text-slate-600 mt-1">
                Showing first 50 of {preview.length} rows
              </p>
            )}
          </div>
        )}

        {/* Import result */}
        {importResult && (
          <div className="mb-4 p-3 bg-green-500/10 border border-green-500/20 rounded-lg">
            <div className="flex items-center gap-2 mb-1">
              <CheckCircle2 className="w-4 h-4 text-green-400" />
              <span className="text-sm font-medium text-green-400">
                Import Complete
              </span>
            </div>
            <div className="flex items-center gap-4 text-xs text-slate-300 mt-1">
              <span>{importResult.imported} imported</span>
              <span>{importResult.skipped} skipped</span>
              {importResult.errors > 0 && (
                <span className="text-red-400">
                  {importResult.errors} errors
                </span>
              )}
            </div>
          </div>
        )}

        {/* Import error */}
        {importError && (
          <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400" />
              <span className="text-sm text-red-400">{importError}</span>
            </div>
          </div>
        )}

        <DialogFooter>
          <Button variant="ghost" size="sm" onClick={handleClose}>
            {importResult ? "Done" : "Cancel"}
          </Button>
          {!importResult && (
            <Button
              size="sm"
              onClick={handleImport}
              disabled={validCount === 0 || isImporting}
              isLoading={isImporting}
            >
              <Upload className="w-4 h-4" />
              Import {validCount} IOC{validCount !== 1 ? "s" : ""}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
