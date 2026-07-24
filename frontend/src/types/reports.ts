/**
 * Report-generation types (EPIC-6 UC-6.1).
 *
 * Mirror of the backend report plugin's `generate_report` / `list_templates`
 * tool outputs surfaced through `/api/v1/reports`.
 */

export interface ReportTemplate {
  name: string;
  title: string;
  description: string;
  sections: string[];
}

export interface ReportTemplateListResponse {
  templates: ReportTemplate[];
  count: number;
  status: string;
}

/** One unfilled required field flagged by the completeness gate. */
export interface ReportGap {
  section: string;
  title: string;
  reason: string;
}

/** Field-completeness score returned alongside a generated report. */
export interface ReportCompleteness {
  required_total: number;
  required_populated: number;
  completeness_pct: number;
  gaps: ReportGap[];
}

export interface GeneratedReport {
  investigation_id: string;
  template: string;
  template_title: string;
  generated_at: string;
  sections: Record<string, string>;
  section_count: number;
  completeness: ReportCompleteness;
  status: string;
}

/** Agency-formatted submission draft (UC-6.2, `POST /reports/summarize`). */
export interface AgencyFormattedReport {
  format: string;
  sections: Record<string, string>;
  generated_at: string;
  status: string;
}

export interface SummarizeResponse {
  summary: Record<string, unknown>;
  formatted_report: AgencyFormattedReport;
  status: string;
}
