/** Shift-handover summary types (EPIC-5 UC-5.1, `GET /api/v1/handover`). */

export interface HandoverInvestigationItem {
  id: string;
  title: string;
  severity: string;
  status: string;
  is_new: boolean;
  updated_at: string;
}

export interface HandoverSummary {
  window_hours: number;
  window_start: string;
  generated_at: string;
  headline: string;
  investigations: HandoverInvestigationItem[];
  open_by_severity: Record<string, number>;
  findings_by_severity: Record<string, number>;
  findings_untriaged: number;
}
