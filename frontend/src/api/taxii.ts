import api from "./client";

/**
 * TAXII 2.1 feed-subscription client (#105 / UC-2.1).
 *
 * Mirrors ``backend/btagent_backend/api/v1/taxii_feeds.py``. Two things about
 * this surface are load-bearing and deliberately reflected here:
 *
 * * ``auth_secret_ref`` is a **reference** — one complete
 *   ``${secret:vault:...}`` / ``${secret:aws:...}`` / ``${env:VAR}`` token. The
 *   server rejects raw credential material with 422, and nothing on this side
 *   ever resolves a reference, so the credential itself never reaches the
 *   browser in either direction.
 * * Everything is org-scoped server-side; a feed id from another tenant 404s
 *   exactly like a nonexistent one. There is no org parameter to pass, and
 *   there must never be one.
 */

const BASE = "/v1/taxii/feeds";

/** A feed's stored configuration plus the sweep's poll telemetry. */
export interface TaxiiFeed {
  id: string;
  name: string;
  server_url: string;
  collection_id: string;
  /** "none" | "bearer" | "basic". */
  auth_style: TaxiiAuthStyle;
  /** The reference string — never the credential it names. */
  auth_secret_ref: string;
  poll_interval_minutes: number;
  enabled: boolean;
  /** TAXII ``X-TAXII-Date-Added-Last`` of the newest page ingested. */
  last_cursor: string | null;
  last_polled_at: string | null;
  /** "" (never polled) | "ok" | "error". */
  last_status: string;
  /** Scrubbed failure reason from the most recent poll. */
  last_error: string;
  objects_ingested: number;
  intake_investigation_id: string | null;
  created_at: string;
  updated_at: string;
}

export type TaxiiAuthStyle = "none" | "bearer" | "basic";

export interface TaxiiFeedListResponse {
  items: TaxiiFeed[];
  total: number;
}

export interface CreateTaxiiFeedRequest {
  name: string;
  server_url: string;
  collection_id: string;
  auth_style: TaxiiAuthStyle;
  /** Empty when ``auth_style`` is "none"; a ``${...}`` reference otherwise. */
  auth_secret_ref: string;
  poll_interval_minutes: number;
  enabled: boolean;
}

/** Partial update — only the supplied keys change (server uses exclude_unset). */
export type UpdateTaxiiFeedRequest = Partial<CreateTaxiiFeedRequest>;

/** Poll-cadence bounds enforced by ``taxii_feed_service._validate_interval``. */
export const MIN_POLL_INTERVAL_MINUTES = 5;
export const MAX_POLL_INTERVAL_MINUTES = 7 * 24 * 60;

/** Requires ``taxii:view`` (senior_analyst+). */
export async function listTaxiiFeeds(params?: {
  enabledOnly?: boolean;
}): Promise<TaxiiFeedListResponse> {
  const qs = params?.enabledOnly ? "?enabled_only=true" : "";
  return api.get<TaxiiFeedListResponse>(`${BASE}${qs}`);
}

/** Requires ``taxii:view``. A foreign org's id 404s like a missing one. */
export async function getTaxiiFeed(feedId: string): Promise<TaxiiFeed> {
  return api.get<TaxiiFeed>(`${BASE}/${feedId}`);
}

/** Requires ``taxii:manage`` (admin). 422 on a raw (non-reference) secret. */
export async function createTaxiiFeed(
  body: CreateTaxiiFeedRequest,
): Promise<TaxiiFeed> {
  return api.post<TaxiiFeed>(BASE, body);
}

/** Requires ``taxii:manage`` (admin). */
export async function updateTaxiiFeed(
  feedId: string,
  body: UpdateTaxiiFeedRequest,
): Promise<TaxiiFeed> {
  return api.patch<TaxiiFeed>(`${BASE}/${feedId}`, body);
}

/** Requires ``taxii:manage`` (admin). */
export async function deleteTaxiiFeed(feedId: string): Promise<void> {
  await api.delete(`${BASE}/${feedId}`);
}
