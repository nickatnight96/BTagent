import { useState, useCallback } from "react";
import { Download, AlertTriangle } from "lucide-react";
import { Dialog, DialogContent, DialogFooter } from "@/components/ui/Dialog";
import { Button } from "@/components/ui/Button";
import { useIOCStore } from "@/stores/iocStore";
import { useInvestigationStore } from "@/stores/investigationStore";
import { TLP } from "@/types/config";
import type { ExportOptions, IOCType } from "@/types/ioc";

interface IOCExportDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const FORMAT_OPTIONS: { label: string; value: ExportOptions["format"]; description: string }[] = [
  {
    label: "STIX 2.1",
    value: "stix_2.1",
    description: "Structured Threat Information Expression - standard CTI format",
  },
  {
    label: "CSV",
    value: "csv",
    description: "Comma-separated values - for spreadsheets and SIEM import",
  },
  {
    label: "JSON",
    value: "json",
    description: "Raw JSON - for programmatic processing",
  },
];

const IOC_TYPE_OPTIONS: { label: string; value: IOCType | "" }[] = [
  { label: "All Types", value: "" },
  { label: "IP Address", value: "ip" },
  { label: "Domain", value: "domain" },
  { label: "MD5 Hash", value: "hash_md5" },
  { label: "SHA1 Hash", value: "hash_sha1" },
  { label: "SHA256 Hash", value: "hash_sha256" },
  { label: "URL", value: "url" },
  { label: "Email", value: "email" },
  { label: "CVE", value: "cve" },
  { label: "File Path", value: "file_path" },
  { label: "Other", value: "other" },
];

const TLP_OPTIONS: { label: string; value: TLP | ""; warning?: boolean }[] = [
  { label: "All TLP levels", value: "" },
  { label: "TLP:CLEAR", value: TLP.CLEAR },
  { label: "TLP:GREEN", value: TLP.GREEN },
  { label: "TLP:AMBER", value: TLP.AMBER, warning: true },
  { label: "TLP:AMBER+STRICT", value: TLP.AMBER_STRICT, warning: true },
  { label: "TLP:RED", value: TLP.RED, warning: true },
];

export function IOCExportDialog({ open, onOpenChange }: IOCExportDialogProps) {
  const { exportIOCs, isExporting } = useIOCStore();
  const { investigations } = useInvestigationStore();

  const [format, setFormat] = useState<ExportOptions["format"]>("stix_2.1");
  const [investigationId, setInvestigationId] = useState("");
  const [iocType, setIocType] = useState<IOCType | "">("");
  const [confidenceMin, setConfidenceMin] = useState(0);
  const [tlpMax, setTlpMax] = useState<TLP | "">("");

  const showTlpWarning =
    tlpMax === TLP.AMBER || tlpMax === TLP.AMBER_STRICT || tlpMax === TLP.RED;

  const handleExport = useCallback(async () => {
    const options: ExportOptions = {
      format,
      investigation_id: investigationId || undefined,
      type: iocType || undefined,
      confidence_min: confidenceMin > 0 ? confidenceMin : undefined,
      tlp_max: tlpMax || undefined,
    };
    await exportIOCs(options);
    onOpenChange(false);
  }, [format, investigationId, iocType, confidenceMin, tlpMax, exportIOCs, onOpenChange]);

  const handleClose = useCallback(() => {
    onOpenChange(false);
  }, [onOpenChange]);

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent
        title="Export IOCs"
        description="Export indicators in your preferred format with optional filters."
      >
        <div data-testid="ioc-export">
        {/* Format selector */}
        <div className="space-y-3 mb-5">
          <label className="block text-xs text-slate-500 font-medium">
            Export Format
          </label>
          <div
            className="grid grid-cols-3 gap-2"
            role="radiogroup"
            aria-label="Export format"
          >
            {FORMAT_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                onClick={() => setFormat(opt.value)}
                role="radio"
                aria-checked={format === opt.value}
                aria-label={`Export as ${opt.label}`}
                data-testid={`ioc-export-format-${opt.value}-button`}
                className={`flex flex-col items-start p-3 rounded-lg border text-left transition-colors ${
                  format === opt.value
                    ? "bg-blue-600/10 border-blue-500/30 text-blue-400"
                    : "bg-slate-900 border-slate-700/50 text-slate-400 hover:border-slate-600"
                }`}
              >
                <span className="text-sm font-medium">{opt.label}</span>
                <span className="text-[10px] mt-1 leading-tight opacity-70">
                  {opt.description}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Filter options */}
        <div className="space-y-4 mb-5">
          <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Filters
          </h4>

          {/* Investigation filter */}
          <div>
            <label className="block text-xs text-slate-500 font-medium mb-1.5">
              Investigation
            </label>
            <select
              value={investigationId}
              onChange={(e) => setInvestigationId(e.target.value)}
              aria-label="Filter export by investigation"
              data-testid="ioc-export-investigation-input"
              className="w-full bg-slate-800 border border-slate-600/50 rounded-md px-3 py-2 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            >
              <option value="">All Investigations</option>
              {investigations.map((inv) => (
                <option key={inv.id} value={inv.id}>
                  {inv.title}
                </option>
              ))}
            </select>
          </div>

          {/* Type filter */}
          <div>
            <label className="block text-xs text-slate-500 font-medium mb-1.5">
              IOC Type
            </label>
            <select
              value={iocType}
              onChange={(e) => setIocType(e.target.value as IOCType | "")}
              aria-label="Filter export by IOC type"
              data-testid="ioc-export-type-input"
              className="w-full bg-slate-800 border border-slate-600/50 rounded-md px-3 py-2 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            >
              {IOC_TYPE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          {/* Confidence threshold */}
          <div>
            <label className="block text-xs text-slate-500 font-medium mb-1.5">
              Minimum Confidence: {Math.round(confidenceMin * 100)}%
            </label>
            <input
              type="range"
              min="0"
              max="100"
              step="5"
              value={confidenceMin * 100}
              onChange={(e) => setConfidenceMin(Number(e.target.value) / 100)}
              aria-label="Minimum confidence for export"
              data-testid="ioc-export-confidence-input"
              className="w-full accent-blue-500"
            />
          </div>

          {/* TLP max */}
          <div>
            <label className="block text-xs text-slate-500 font-medium mb-1.5">
              Maximum TLP Level
            </label>
            <select
              value={tlpMax}
              onChange={(e) => setTlpMax(e.target.value as TLP | "")}
              aria-label="Maximum TLP level for export"
              data-testid="ioc-export-tlp-input"
              className="w-full bg-slate-800 border border-slate-600/50 rounded-md px-3 py-2 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            >
              {TLP_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* TLP warning */}
        {showTlpWarning && (
          <div
            className="mb-5 p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg"
            role="alert"
            data-testid="ioc-export-tlp-warning"
          >
            <div className="flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />
              <div>
                <p className="text-sm font-medium text-amber-400">
                  TLP Handling Warning
                </p>
                <p className="text-xs text-amber-400/70 mt-1">
                  {tlpMax === TLP.RED
                    ? "TLP:RED indicators are for named recipients only. Exporting these IOCs may violate sharing agreements. Ensure you have authorization to share these indicators."
                    : "TLP:AMBER indicators are limited to the organization and its clients. Verify that this export will remain within authorized boundaries."}
                </p>
              </div>
            </div>
          </div>
        )}

        <DialogFooter>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleClose}
            data-testid="ioc-export-cancel-button"
          >
            Cancel
          </Button>
          <Button
            size="sm"
            onClick={handleExport}
            isLoading={isExporting}
            data-testid="ioc-export-submit-button"
          >
            <Download className="w-4 h-4" aria-hidden="true" />
            Export IOCs
          </Button>
        </DialogFooter>
        </div>
      </DialogContent>
    </Dialog>
  );
}
