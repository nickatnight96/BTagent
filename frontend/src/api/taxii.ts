/**
 * TAXII 2.1 feed-configuration API client (#105 / UC-2.1).
 *
 * Configuration only — the scheduled backend sweep is what polls. The
 * `auth_secret_ref` field carries a `${secret:...}` / `${env:VAR}` REFERENCE;
 * raw credential material is rejected server-side with 422 and is never
 * echoed back resolved.
 *
 * RBAC (server-enforced): taxii:view (senior_analyst+) to read,
 * taxii:manage (admin) to create / edit / delete.
 */
import api from "./client";

export interface TaxiiFeed {
  id: string;
  name: string;
  server_url: string;
  collection_id: string;
  auth_style: string;
  auth_secret_ref: string;
  poll_interval_minutes: number;
  enabled: boolean;
  last_cursor: string | null;
  last_polled_at: string | null;
  last_status: string;
  last_error: string;
  objects_ingested: number;
  intake_investigation_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface TaxiiFeedListResponse {
  items: TaxiiFeed[];
  total: number;
}

export interface CreateTaxiiFeedRequest {
  name: string;
  server_url: string;
  collection_id: string;
  auth_style?: string;
  auth_secret_ref?: string;
  poll_interval_minutes?: number;
  enabled?: boolean;
}

export type UpdateTaxiiFeedRequest = Partial<CreateTaxiiFeedRequest>;

const BASE = "/taxii/feeds";

export async function listTaxiiFeeds(): Promise<TaxiiFeedListResponse> {
  return api.get<TaxiiFeedListResponse>(`${BASE}`);
}

export async function getTaxiiFeed(feedId: string): Promise<TaxiiFeed> {
  return api.get<TaxiiFeed>(`${BASE}/${feedId}`);
}

export async function createTaxiiFeed(body: CreateTaxiiFeedRequest): Promise<TaxiiFeed> {
  return api.post<TaxiiFeed>(`${BASE}`, body);
}

export async function updateTaxiiFeed(
  feedId: string,
  body: UpdateTaxiiFeedRequest,
): Promise<TaxiiFeed> {
  return api.patch<TaxiiFeed>(`${BASE}/${feedId}`, body);
}

export async function deleteTaxiiFeed(feedId: string): Promise<void> {
  await api.delete(`${BASE}/${feedId}`);
}
