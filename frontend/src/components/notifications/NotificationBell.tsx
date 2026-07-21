/**
 * Notification bell — header entry point to the in-app notification centre.
 *
 * Loads the current user's notifications from `GET /notifications` (initial +
 * 30 s poll), shows an unread badge, and opens a dropdown panel where an
 * analyst can read individual notifications (marking them read) or clear the
 * whole queue. Real-time delivery over the WebSocket hub is a follow-up; this
 * poll keeps the badge fresh in the meantime.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Bell, CheckCheck, Loader2 } from "lucide-react";
import { Button } from "@/components/ds/button";
import {
  listNotifications,
  markNotificationRead,
  markAllNotificationsRead,
} from "@/api/notifications";
import type { AppNotification } from "@/types/notification";

const POLL_INTERVAL_MS = 30_000;

export function NotificationBell() {
  const navigate = useNavigate();
  const [items, setItems] = useState<AppNotification[]>([]);
  const [unread, setUnread] = useState(0);
  const [open, setOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const containerRef = useRef<HTMLDivElement | null>(null);

  const refresh = useCallback(async () => {
    setIsLoading(true);
    try {
      const resp = await listNotifications({ limit: 20 });
      setItems(resp.items);
      setUnread(resp.unread);
    } catch {
      /* best-effort — leave the last known state */
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), POLL_INTERVAL_MS);
    return () => clearInterval(t);
  }, [refresh]);

  // Close the panel on an outside click.
  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [open]);

  const handleOpen = useCallback(() => {
    setOpen((v) => !v);
    void refresh();
  }, [refresh]);

  const handleItemClick = useCallback(
    async (n: AppNotification) => {
      if (!n.read) {
        try {
          await markNotificationRead(n.id);
        } catch {
          /* non-fatal */
        }
      }
      if (n.investigation_id) {
        setOpen(false);
        navigate(`/investigations/${n.investigation_id}`);
      }
      await refresh();
    },
    [navigate, refresh],
  );

  const handleMarkAll = useCallback(async () => {
    try {
      await markAllNotificationsRead();
    } catch {
      /* non-fatal */
    }
    await refresh();
  }, [refresh]);

  return (
    <div className="relative" ref={containerRef} data-testid="notification-bell">
      <Button
        variant="ghost"
        size="icon"
        onClick={handleOpen}
        aria-label="Notifications"
        data-testid="notification-bell-button"
      >
        <Bell className="w-5 h-5" />
        {unread > 0 && (
          <span
            className="absolute -top-0.5 -right-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-rose-500 px-1 text-[10px] font-semibold text-white"
            data-testid="notification-unread-badge"
          >
            {unread > 99 ? "99+" : unread}
          </span>
        )}
      </Button>

      {open && (
        <div
          className="absolute right-0 z-50 mt-2 w-80 rounded-md border border-border bg-card shadow-lg"
          data-testid="notification-panel"
        >
          <div className="flex items-center justify-between border-b border-border px-3 py-2">
            <span className="text-sm font-medium text-foreground">Notifications</span>
            <button
              type="button"
              onClick={() => void handleMarkAll()}
              disabled={unread === 0}
              className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground disabled:opacity-40"
              data-testid="notification-mark-all"
            >
              <CheckCheck className="w-3 h-3" />
              Mark all read
            </button>
          </div>

          <div className="max-h-96 overflow-auto">
            {isLoading && items.length === 0 ? (
              <div className="flex justify-center py-6 text-muted-foreground">
                <Loader2 className="w-4 h-4 animate-spin" />
              </div>
            ) : items.length === 0 ? (
              <div
                className="px-3 py-6 text-center text-sm text-muted-foreground"
                data-testid="notification-empty"
              >
                No notifications.
              </div>
            ) : (
              items.map((n) => (
                <button
                  type="button"
                  key={n.id}
                  onClick={() => void handleItemClick(n)}
                  className={`flex w-full flex-col items-start gap-0.5 border-b border-border/50 px-3 py-2 text-left hover:bg-muted/40 ${
                    n.read ? "opacity-60" : ""
                  }`}
                  data-testid={`notification-item-${n.id}`}
                >
                  <div className="flex w-full items-center gap-2">
                    {!n.read && (
                      <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-sky-400" />
                    )}
                    <span className="truncate text-sm font-medium text-foreground">
                      {n.title}
                    </span>
                  </div>
                  {n.message && (
                    <span className="line-clamp-2 text-xs text-muted-foreground">{n.message}</span>
                  )}
                </button>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
