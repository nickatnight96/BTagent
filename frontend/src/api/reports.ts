/**
 * Reports API client (EPIC-6 UC-6.1).
 *
 * Thin typed wrapper over `/api/v1/reports`: enumerate the available report
 * templates and generate a report (sections + field-completeness gaps) for an
 * investigation. RBAC is enforced server-side (`report:view` to list,
 * `report:generate` to generate).
 */

import api from "./client";
import type {
  DetectionContentResponse,
  GeneratedReport,
  RemediationGuidance,
  ReportTemplateListResponse,
  SummarizeResponse,
} from "@/types/reports";

const BASE = "/v1/reports";

export type AgencyFormat = "cisa" | "fbi_ic3" | "isac" | "generic";

export type RemediationAudience = "executive" | "technical" | "compliance";

export type SiemPlatform = "splunk" | "elastic" | "sentinel";

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

/**
 * Summarize investigation(s) into an agency-submission draft (UC-6.2).
 *
 * RBAC server-side (`report:summarize`); every requested investigation must
 * be in the caller's scope or the backend 404s.
 */
export async function summarizeInvestigations(
  investigationIds: string[],
  format: AgencyFormat,
): Promise<SummarizeResponse> {
  return api.post<SummarizeResponse>(`${BASE}/summarize`, {
    investigation_ids: investigationIds,
    format,
  });
}

/**
 * Generate audience-tuned remediation guidance for an investigation (UC-6.2).
 *
 * RBAC server-side (`remediation:generate`); the investigation must be in the
 * caller's scope.
 */
export async function generateRemediation(
  investigationId: string,
  audience: RemediationAudience,
): Promise<RemediationGuidance> {
  return api.post<RemediationGuidance>(`${BASE}/remediation`, {
    investigation_id: investigationId,
    audience,
  });
}

/**
 * Generate platform-specific SIEM rules from an investigation's IOCs (UC-6.2).
 *
 * RBAC server-side (`remediation:generate`); the investigation must be in the
 * caller's scope.
 */
export async function generateDetectionContent(
  investigationId: string,
  platform: SiemPlatform,
): Promise<DetectionContentResponse> {
  return api.post<DetectionContentResponse>(`${BASE}/detection-content`, {
    investigation_id: investigationId,
    platform,
  });
}

/**
 * Download an investigation's report as a PDF blob.
 *
 * Mirrors `exportHuntPlan`: a raw fetch (the JSON api client can't carry
 * blobs) with httpOnly-cookie auth. The backend TLP egress gate refuses
 * TLP:RED investigations with a 403 — surfaced as a distinct error so the
 * page can tell a policy block from a plain failure.
 */
export async function exportReportPdf(
  investigationId: string,
  template: ReportTemplateName,
): Promise<Blob> {
  const response = await fetch(
    `${import.meta.env.VITE_API_BASE_URL ?? "/api"}${BASE}/${investigationId}/export?format=pdf&template=${template}`,
    {
      method: "GET",
      credentials: "include",
    },
  );
  if (response.status === 403) {
    throw new Error("Export blocked by TLP policy (classified investigation)");
  }
  if (!response.ok) {
    throw new Error(`Export failed (${response.status})`);
  }
  return response.blob();
}
