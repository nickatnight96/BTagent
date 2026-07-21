/** In-app notifications API client. */

import api from "./client";
import type { NotificationListResponse } from "@/types/notification";

const BASE = "/v1/notifications";

/** List the current user's notifications (with unread badge count). */
export async function listNotifications(params?: {
  unread_only?: boolean;
  limit?: number;
  offset?: number;
}): Promise<NotificationListResponse> {
  const search = new URLSearchParams();
  if (params?.unread_only) search.set("unread_only", "true");
  if (params?.limit) search.set("limit", String(params.limit));
  if (params?.offset) search.set("offset", String(params.offset));
  const qs = search.toString();
  return api.get<NotificationListResponse>(`${BASE}${qs ? `?${qs}` : ""}`);
}

/** Mark one notification read. */
export async function markNotificationRead(id: string): Promise<void> {
  await api.post<void>(`${BASE}/${id}/read`, {});
}

/** Mark all of the current user's notifications read; returns the count marked. */
export async function markAllNotificationsRead(): Promise<{ marked: number }> {
  return api.post<{ marked: number }>(`${BASE}/read-all`, {});
}
