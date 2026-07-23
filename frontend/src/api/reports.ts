/**
 * Reports API client (EPIC-6 UC-6.1).
 *
 * Thin typed wrapper over `/api/v1/reports`: enumerate the available report
 * templates and generate a report (sections + field-completeness gaps) for an
 * investigation. RBAC is enforced server-side (`report:view` to list,
 * `report:generate` to generate).
 */

import api from "./client";
import type { GeneratedReport, ReportTemplateListResponse } from "@/types/reports";

const BASE = "/v1/reports";

export type ReportTemplateName =
  | "incident_report"
  | "ioc_report"
  | "executive_briefing"
  | "regulatory_notification"
  | "cisa_incident"
  | "external_advisory";

/** List the available report templates with their section lists. */
export async function listReportTemplates(): Promise<ReportTemplateListResponse> {
  return api.get<ReportTemplateListResponse>(`${BASE}/templates`);
}

/** Generate a report for an investigation using the named template. */
export async function generateReport(
  investigationId: string,
  template: ReportTemplateName,
): Promise<GeneratedReport> {
  return api.post<GeneratedReport>(`${BASE}/generate`, {
    investigation_id: investigationId,
    template,
  });
}
