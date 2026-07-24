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

/**
 * One remediation checklist item (UC-6.2, `POST /reports/remediation`).
 *
 * `priority` + `action` are common to every audience; the remaining fields
 * are audience-specific (executive: effort/owner, technical: commands/
 * verification, compliance: deadline/framework), so they stay open-typed.
 */
export interface RemediationAction {
  priority: string;
  action: string;
  [key: string]: unknown;
}

export interface RemediationGuidance {
  audience: string;
  title: string;
  severity?: string;
  business_impact?: string;
  actions: RemediationAction[];
  investigation_id: string;
  generated_at: string;
  status: string;
}
