/**
 * Reports page (EPIC-6 UC-6.1).
 *
 * Surfaces the backend report generator: the analyst picks an investigation and
 * a report template (internal IR, CISA incident form, executive briefing,
 * regulatory notification, external advisory, …), generates it, and sees the
 * rendered sections plus a field-completeness banner. The banner reports the
 * required-field completeness percentage and lists any gaps — required sections
 * that are unpopulated or need analyst input before sign-off — closing the
 * UC-6.1 "report gaps to the analyst" loop in the UI.
 *
 * RBAC is enforced server-side (report:view to list templates, report:generate
 * to generate). Mock-first: the backend replays deterministic case data until
 * live investigation data is wired to the report plugin.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { Download, FileText, Landmark, Loader2, Play } from "lucide-react";
import { Button } from "@/components/ds/button";
import { Card, CardContent } from "@/components/ds/card";
import {
  exportReportPdf,
  generateReport,
  listReportTemplates,
  summarizeInvestigations,
} from "@/api/reports";
import type { AgencyFormat, ReportTemplateName } from "@/api/reports";
import { listInvestigations } from "@/api/investigations";
import type { Investigation } from "@/types/investigation";
import type {
  AgencyFormattedReport,
  GeneratedReport,
  ReportTemplate,
} from "@/types/reports";

function completenessColor(pct: number): string {
  if (pct >= 90) return "text-emerald-400";
  if (pct >= 60) return "text-amber-400";
  return "text-rose-400";
}

const AGENCY_FORMATS: Array<{ value: AgencyFormat; label: string }> = [
  { value: "cisa", label: "CISA" },
  { value: "fbi_ic3", label: "FBI IC3" },
  { value: "isac", label: "ISAC" },
  { value: "generic", label: "Generic" },
];

export function ReportsPage() {
  const [templates, setTemplates] = useState<ReportTemplate[]>([]);
  const [template, setTemplate] = useState<ReportTemplateName | "">("");
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [investigationId, setInvestigationId] = useState("");
  const [report, setReport] = useState<GeneratedReport | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [agencyFormat, setAgencyFormat] = useState<AgencyFormat>("cisa");
  const [agencySummary, setAgencySummary] = useState<AgencyFormattedReport | null>(null);
  const [isSummarizing, setIsSummarizing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const resp = await listReportTemplates();
        if (cancelled) return;
        setTemplates(resp.templates);
        const first = resp.templates[0];
        if (first) {
          setTemplate(first.name as ReportTemplateName);
        }
      } catch {
        if (!cancelled) setError("Failed to load report templates.");
      }
    })();
    // Best-effort: real cases feed the picker's suggestions, but the field
    // stays free-text (mock IDs remain typable), so a failure here must
    // never block report generation.
    void (async () => {
      try {
        const resp = await listInvestigations({ page_size: 50 });
        if (!cancelled) setInvestigations(resp.items);
      } catch {
        // Suggestions are an enhancement only — swallow and keep free text.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const matchedInvestigation = useMemo(
    () => investigations.find((inv) => inv.id === investigationId.trim()) ?? null,
    [investigations, investigationId],
  );

  const canGenerate = template !== "" && investigationId.trim() !== "" && !isGenerating;

  const handleGenerate = useCallback(async () => {
    if (template === "" || investigationId.trim() === "") return;
    setIsGenerating(true);
    setError(null);
    try {
      const result = await generateReport(investigationId.trim(), template);
      setReport(result);
    } catch {
      setError("Report generation failed. Check the investigation ID and try again.");
      setReport(null);
    } finally {
      setIsGenerating(false);
    }
  }, [template, investigationId]);

  const handleExport = useCallback(async () => {
    if (!report) return;
    setIsExporting(true);
    setError(null);
    try {
      const blob = await exportReportPdf(
        report.investigation_id,
        report.template as ReportTemplateName,
      );
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `report_${report.investigation_id}_${report.template}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to export report PDF");
    } finally {
      setIsExporting(false);
    }
  }, [report]);

  const handleSummarize = useCallback(async () => {
    const id = investigationId.trim();
    if (!id) return;
    setIsSummarizing(true);
    setError(null);
    try {
      const resp = await summarizeInvestigations([id], agencyFormat);
      setAgencySummary(resp.formatted_report);
    } catch {
      setError("Agency summarization failed. Check the investigation ID and try again.");
      setAgencySummary(null);
    } finally {
      setIsSummarizing(false);
    }
  }, [investigationId, agencyFormat]);

  const orderedSections = useMemo(() => {
    if (!report) return [];
    return Object.entries(report.sections);
  }, [report]);

  return (
    <div className="flex flex-col h-full" data-testid="reports-page">
      {/* ---- Header ---- */}
      <div className="flex items-center gap-3 px-6 py-4 border-b border-border">
        <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-sky-600/20 border border-sky-500/30">
          <FileText className="w-4 h-4 text-sky-400" aria-hidden="true" />
        </div>
        <div>
          <h1 className="text-lg font-semibold text-foreground">Reports</h1>
          <p className="text-sm text-muted-foreground">
            Generate an incident report from a case and review completeness gaps
          </p>
        </div>
      </div>

      {/* ---- Body ---- */}
      <div className="flex-1 overflow-auto p-6 space-y-6">
        {/* Controls */}
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-muted-foreground">Investigation</span>
            <input
              type="text"
              value={investigationId}
              onChange={(e) => setInvestigationId(e.target.value)}
              placeholder="inv_…"
              list="reports-investigation-options"
              data-testid="reports-investigation-input"
              className="w-64 rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-sky-500"
            />
            {/* Native combobox: suggests real cases while keeping free text
                (mock IDs stay typable). */}
            <datalist id="reports-investigation-options" data-testid="reports-investigation-options">
              {investigations.map((inv) => (
                <option key={inv.id} value={inv.id}>
                  {`${inv.title} (${inv.severity})`}
                </option>
              ))}
            </datalist>
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-muted-foreground">Template</span>
            <select
              value={template}
              onChange={(e) => setTemplate(e.target.value as ReportTemplateName)}
              data-testid="reports-template-select"
              className="w-64 rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-sky-500"
            >
              {templates.map((t) => (
                <option key={t.name} value={t.name}>
                  {t.title}
                </option>
              ))}
            </select>
          </label>
          <Button
            variant="default"
            size="sm"
            onClick={() => void handleGenerate()}
            disabled={!canGenerate}
            data-testid="reports-generate"
            title="Generate the report from the selected case and template"
          >
            {isGenerating ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4" />
            )}
            <span className="ml-2">Generate</span>
          </Button>
        </div>

        {matchedInvestigation && (
          <div
            className="-mt-4 text-xs text-muted-foreground"
            data-testid="reports-investigation-hint"
          >
            {matchedInvestigation.title} — {matchedInvestigation.severity} ·{" "}
            {matchedInvestigation.status}
          </div>
        )}

        {error && (
          <div
            className="rounded-md border border-rose-500/30 bg-rose-600/10 px-4 py-2 text-sm text-rose-300"
            data-testid="reports-error"
          >
            {error}
          </div>
        )}

        {!report && !error && (
          <Card>
            <CardContent className="py-10 text-center text-sm text-muted-foreground">
              Pick an investigation and a template, then generate a report.
            </CardContent>
          </Card>
        )}

        {report && (
          <>
            {/* Completeness banner */}
            <Card data-testid="reports-completeness">
              <CardContent className="py-4">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-sm text-muted-foreground">{report.template_title}</div>
                    <div className="text-xs text-muted-foreground">
                      {report.section_count} sections · generated {report.generated_at}
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => void handleExport()}
                      disabled={isExporting}
                      data-testid="reports-export-pdf"
                      title="Download this report as a PDF (TLP:RED investigations are refused)"
                    >
                      {isExporting ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <Download className="w-4 h-4" />
                      )}
                      <span className="ml-2 hidden sm:inline">Export PDF</span>
                    </Button>
                    <div className="text-right">
                      <div
                        className={`text-2xl font-semibold ${completenessColor(
                          report.completeness.completeness_pct,
                        )}`}
                        data-testid="reports-completeness-pct"
                      >
                        {report.completeness.completeness_pct}%
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {report.completeness.required_populated}/
                        {report.completeness.required_total} required fields
                      </div>
                    </div>
                  </div>
                </div>

                {report.completeness.gaps.length > 0 && (
                  <div className="mt-4 border-t border-border pt-3" data-testid="reports-gaps">
                    <div className="mb-2 text-xs font-medium uppercase tracking-wide text-amber-400">
                      {report.completeness.gaps.length} gap
                      {report.completeness.gaps.length === 1 ? "" : "s"} to resolve
                    </div>
                    <ul className="space-y-1 text-sm">
                      {report.completeness.gaps.map((g) => (
                        <li
                          key={g.section}
                          className="flex items-center justify-between"
                          data-testid={`reports-gap-${g.section}`}
                        >
                          <span className="text-foreground">{g.title}</span>
                          <span className="text-xs text-muted-foreground">{g.reason}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Rendered sections */}
            <div className="space-y-4" data-testid="reports-sections">
              {orderedSections.map(([name, content]) => (
                <Card key={name} data-testid={`reports-section-${name}`}>
                  <CardContent className="py-4">
                    <div className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      {name}
                    </div>
                    <pre className="whitespace-pre-wrap font-sans text-sm text-foreground">
                      {content}
                    </pre>
                  </CardContent>
                </Card>
              ))}
            </div>
          </>
        )}

        {/* ---- Agency submission draft (UC-6.2) ---- */}
        <Card data-testid="reports-agency-panel">
          <CardContent className="py-4 space-y-4">
            <div className="flex items-center gap-2">
              <Landmark className="w-4 h-4 text-sky-400" aria-hidden="true" />
              <span className="text-sm font-semibold text-foreground">
                Agency submission draft
              </span>
              <span className="text-xs text-muted-foreground">
                Format the case for CISA / FBI IC3 / ISAC hand-off
              </span>
            </div>
            <div className="flex flex-wrap items-end gap-3">
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-muted-foreground">Agency format</span>
                <select
                  value={agencyFormat}
                  onChange={(e) => setAgencyFormat(e.target.value as AgencyFormat)}
                  data-testid="reports-agency-format"
                  className="w-48 rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-sky-500"
                >
                  {AGENCY_FORMATS.map((f) => (
                    <option key={f.value} value={f.value}>
                      {f.label}
                    </option>
                  ))}
                </select>
              </label>
              <Button
                variant="outline"
                size="sm"
                onClick={() => void handleSummarize()}
                disabled={investigationId.trim() === "" || isSummarizing}
                data-testid="reports-summarize"
                title="Summarize the selected investigation into an agency-submission draft"
              >
                {isSummarizing ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Play className="w-4 h-4" />
                )}
                <span className="ml-2">Summarize</span>
              </Button>
            </div>

            {agencySummary && (
              <div className="space-y-3" data-testid="reports-agency-sections">
                <div className="text-xs text-muted-foreground">
                  {agencySummary.format.toUpperCase()} draft · generated{" "}
                  {agencySummary.generated_at}
                </div>
                {Object.entries(agencySummary.sections).map(([name, content]) => (
                  <div key={name} data-testid={`reports-agency-section-${name}`}>
                    <pre className="whitespace-pre-wrap rounded-md border border-border/50 bg-background/50 p-3 font-mono text-xs text-foreground">
                      {content}
                    </pre>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
