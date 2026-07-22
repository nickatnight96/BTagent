/** In-app notification types — mirrors api/v1/notifications.py. */

export interface AppNotification {
  id: string;
  type: string;
  title: string;
  message: string;
  investigation_id: string | null;
  /** App-relative deep-link target (e.g. "/hunt"); investigation fallback when null. */
  link: string | null;
  read: boolean;
  created_at: string;
}

/** Response from GET /notifications. */
export interface NotificationListResponse {
  items: AppNotification[];
  /** Whole-store unread count (the bell badge). */
  unread: number;
}

/** Per-user mute list — notification type values skipped in-app. */
export interface NotificationPrefs {
  muted_types: string[];
}
