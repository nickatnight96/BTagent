import { useState, useCallback } from "react";
import { Download, AlertTriangle, Loader2 } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ds/dialog";
import { Button } from "@/components/ds/button";
import { Label } from "@/components/ds/label";
import { NativeSelect } from "@/components/ds/native-select";
import { cn } from "@/lib/utils";
import { useIOCStore } from "@/stores/iocStore";
import { useInvestigationStore } from "@/stores/investigationStore";
import { TLP } from "@/types/config";
import type { ExportOptions, IOCType } from "@/types/ioc";

interface IOCExportDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const FORMAT_OPTIONS: {
  label: string;
  value: ExportOptions["format"];
  description: string;
}[] = [
  {
    label: "STIX 2.1",
    value: "stix_2.1",
    description: "Structured Threat Information Expression — standard CTI format",
  },
  {
    label: "CSV",
    value: "csv",
    description: "Comma-separated values — for spreadsheets and SIEM import",
  },
  {
    label: "JSON",
    value: "json",
    description: "Raw JSON — for programmatic processing",
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
  }, [
    format,
    investigationId,
    iocType,
    confidenceMin,
    tlpMax,
    exportIOCs,
    onOpenChange,
  ]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent data-testid="ioc-export">
        <DialogHeader>
          <DialogTitle>Export IOCs</DialogTitle>
          <DialogDescription>
            Export indicators in your preferred format with optional filters.
          </DialogDescription>
        </DialogHeader>

        {/* Format selector */}
        <div className="space-y-3">
          <Label>Export Format</Label>
          <div
            className="grid grid-cols-3 gap-2"
            role="radiogroup"
            aria-label="Export format"
          >
            {FORMAT_OPTIONS.map((opt) => {
              const active = format === opt.value;
              return (
                <button
                  key={opt.value}
                  onClick={() => setFormat(opt.value)}
                  role="radio"
                  aria-checked={active}
                  aria-label={`Export as ${opt.label}`}
                  data-testid={`ioc-export-format-${opt.value}-button`}
                  className={cn(
                    "flex flex-col items-start p-3 rounded-md border text-left transition-colors",
                    active
                      ? "bg-primary/10 border-primary/30 text-primary"
                      : "bg-card border-border text-muted-foreground hover:border-border hover:text-foreground"
                  )}
                >
                  <span className="text-sm font-medium">{opt.label}</span>
                  <span className="text-[10px] mt-1 leading-tight opacity-70">
                    {opt.description}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Filter options */}
        <div className="space-y-4">
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            Filters
          </h4>

          <div className="space-y-1.5">
            <Label htmlFor="ioc-export-investigation">Investigation</Label>
            <NativeSelect
              id="ioc-export-investigation"
              value={investigationId}
              onChange={(e) => setInvestigationId(e.target.value)}
              aria-label="Filter export by investigation"
              data-testid="ioc-export-investigation-input"
            >
              <option value="">All Investigations</option>
              {investigations.map((inv) => (
                <option key={inv.id} value={inv.id}>
                  {inv.title}
                </option>
              ))}
            </NativeSelect>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="ioc-export-type">IOC Type</Label>
            <NativeSelect
              id="ioc-export-type"
              value={iocType}
              onChange={(e) => setIocType(e.target.value as IOCType | "")}
              aria-label="Filter export by IOC type"
              data-testid="ioc-export-type-input"
            >
              {IOC_TYPE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </NativeSelect>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="ioc-export-confidence">
              Minimum Confidence: {Math.round(confidenceMin * 100)}%
            </Label>
            <input
              id="ioc-export-confidence"
              type="range"
              min="0"
              max="100"
              step="5"
              value={confidenceMin * 100}
              onChange={(e) =>
                setConfidenceMin(Number(e.target.value) / 100)
              }
              aria-label="Minimum confidence for export"
              data-testid="ioc-export-confidence-input"
              className="w-full accent-primary"
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="ioc-export-tlp">Maximum TLP Level</Label>
            <NativeSelect
              id="ioc-export-tlp"
              value={tlpMax}
              onChange={(e) => setTlpMax(e.target.value as TLP | "")}
              aria-label="Maximum TLP level for export"
              data-testid="ioc-export-tlp-input"
            >
              {TLP_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </NativeSelect>
          </div>
        </div>

        {showTlpWarning && (
          <div
            className="p-3 rounded-md border border-severity-medium/30 bg-severity-medium/10"
            role="alert"
            data-testid="ioc-export-tlp-warning"
          >
            <div className="flex items-start gap-2">
              <AlertTriangle
                className="w-4 h-4 text-severity-medium shrink-0 mt-0.5"
                aria-hidden="true"
              />
              <div>
                <p className="text-sm font-medium text-severity-medium">
                  TLP Handling Warning
                </p>
                <p className="text-xs text-severity-medium/80 mt-1">
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
            onClick={() => onOpenChange(false)}
            data-testid="ioc-export-cancel-button"
          >
            Cancel
          </Button>
          <Button
            onClick={handleExport}
            disabled={isExporting}
            data-testid="ioc-export-submit-button"
          >
            {isExporting ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Download className="w-4 h-4 mr-2" aria-hidden="true" />
            )}
            Export IOCs
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
