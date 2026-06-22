/**
 * Behavioral Hunter API client (#114 Phase B).
 *
 * Typed thin wrappers over ``/api/v1/behavioral/*`` — mirrors the shape of
 * ``@/api/hunt`` so the store layer can stay symmetrical.
 */

import api from "./client";
import type {
  BehavioralOutlier,
  BehavioralOutlierListResponse,
  IntentLabel,
  PromoteOutlierRequest,
  PromoteOutlierResponse,
  SetIntentRequest,
} from "@/types/behavioral";

const BASE = "/v1/behavioral";

// --------------------------------------------------------------------------- //
// Read
// --------------------------------------------------------------------------- //

/** Org-scoped, paginated outlier list (optionally filtered by intent). */
export async function listOutliers(params?: {
  intent_label?: IntentLabel | null;
  page?: number;
  page_size?: number;
}): Promise<BehavioralOutlierListResponse> {
  const search = new URLSearchParams();
  if (params?.intent_label) search.set("intent_label", params.intent_label);
  if (params?.page) search.set("page", String(params.page));
  if (params?.page_size) search.set("page_size", String(params.page_size));
  const qs = search.toString();
  return api.get<BehavioralOutlierListResponse>(`${BASE}/outliers${qs ? `?${qs}` : ""}`);
}

/** Fetch a single outlier by id. */
export async function getOutlier(outlierId: string): Promise<BehavioralOutlier> {
  return api.get<BehavioralOutlier>(`${BASE}/outliers/${outlierId}`);
}

// --------------------------------------------------------------------------- //
// Triage mutations
// --------------------------------------------------------------------------- //

/** Record an analyst intent verdict on an outlier. */
export async function setIntent(
  outlierId: string,
  body: SetIntentRequest,
): Promise<BehavioralOutlier> {
  return api.post<BehavioralOutlier>(`${BASE}/outliers/${outlierId}/intent`, body);
}

/**
 * Fold a benign-triaged outlier back into the entity baseline (closed-loop).
 * The outlier must already carry ``intent_label = "benign"``; the backend
 * returns 400 otherwise.
 */
export async function feedbackBenign(outlierId: string): Promise<BehavioralOutlier> {
  return api.post<BehavioralOutlier>(`${BASE}/outliers/${outlierId}/feedback-benign`);
}

/** Escalate an outlier into the HuntFinding queue. */
export async function promoteOutlier(
  outlierId: string,
  body: PromoteOutlierRequest,
): Promise<PromoteOutlierResponse> {
  return api.post<PromoteOutlierResponse>(`${BASE}/outliers/${outlierId}/promote`, body);
}

/** Run the IntentClassifier LLM chain on an outlier and persist its verdict. */
export async function classifyOutlier(outlierId: string): Promise<BehavioralOutlier> {
  return api.post<BehavioralOutlier>(`${BASE}/outliers/${outlierId}/classify`);
}
