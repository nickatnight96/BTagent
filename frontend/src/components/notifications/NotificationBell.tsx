/**
 * Notification bell — header entry point to the in-app notification centre.
 *
 * Loads the current user's notifications from `GET /notifications` (initial +
 * 30 s poll), shows an unread badge, and opens a dropdown panel where an
 * analyst can read individual notifications (marking them read) or clear the
 * whole queue. Real-time delivery arrives over the WebSocket hub (the poll is
 * the fallback when the socket is down). Rows carry a per-type accent icon
 * and a compact relative timestamp so the queue scans at a glance.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AlertTriangle,
  Bell,
  CheckCheck,
  CheckCircle2,
  Info,
  Loader2,
  Settings2,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { Button } from "@/components/ds/button";
import {
  listNotifications,
  markNotificationRead,
  markAllNotificationsRead,
  getNotificationPrefs,
  putNotificationPrefs,
} from "@/api/notifications";
import { getWSClient } from "@/api/ws";
import type { AppNotification } from "@/types/notification";

const POLL_INTERVAL_MS = 30_000;

/** Mutable notification types, with analyst-facing labels. */
const MUTABLE_TYPES: { type: string; label: string }[] = [
  { type: "hitl_checkpoint", label: "HITL approvals" },
  { type: "critical_finding", label: "Critical findings" },
  { type: "investigation_complete", label: "Investigation completed" },
  { type: "investigation_failed", label: "Investigation failed" },
  { type: "noise_digest", label: "Noise digest" },
];

/** Compact relative timestamp for dropdown rows ("just now" / "5m ago"). */
export function relativeTime(iso: string, now: Date = new Date()): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const seconds = Math.max(0, Math.floor((now.getTime() - then) / 1000));
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

/** Per-type accent icon so an analyst can scan the queue by category. */
function typeAccent(type: string): { Icon: LucideIcon; className: string } {
  switch (type) {
    case "hitl_checkpoint":
      return { Icon: ShieldAlert, className: "text-amber-400" };
    case "investigation_complete":
      return { Icon: CheckCircle2, className: "text-emerald-400" };
    case "investigation_failed":
      return { Icon: XCircle, className: "text-rose-400" };
    case "critical_finding":
      return { Icon: AlertTriangle, className: "text-rose-400" };
    default:
      return { Icon: Info, className: "text-sky-400" };
  }
}

export function NotificationBell() {
  const navigate = useNavigate();
  const [items, setItems] = useState<AppNotification[]>([]);
  const [unread, setUnread] = useState(0);
  const [open, setOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [showPrefs, setShowPrefs] = useState(false);
  const [mutedTypes, setMutedTypes] = useState<string[] | null>(null);
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

  // Real-time delivery: the WS hub forwards per-user notifications as
  // {type:"notification"} messages. Refresh on arrival so the badge and panel
  // update immediately; the 30 s poll above stays as the fallback when the
  // socket is down.
  useEffect(() => {
    const ws = getWSClient();
    const previous = ws.onNotification;
    ws.onNotification = () => void refresh();
    return () => {
      ws.onNotification = previous;
    };
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
      // Producers may attach an app-relative deep link (triage inbox,
      // workflow detail, ...); the investigation view stays the fallback.
      const target =
        n.link ?? (n.investigation_id ? `/investigations/${n.investigation_id}` : null);
      if (target) {
        setOpen(false);
        navigate(target);
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

  const handleTogglePrefs = useCallback(async () => {
    const next = !showPrefs;
    setShowPrefs(next);
    if (next && mutedTypes === null) {
      try {
        const prefs = await getNotificationPrefs();
        setMutedTypes(prefs.muted_types);
      } catch {
        setMutedTypes([]); // best-effort — start from "nothing muted"
      }
    }
  }, [showPrefs, mutedTypes]);

  const handleToggleMute = useCallback(
    async (type: string) => {
      const current = mutedTypes ?? [];
      const next = current.includes(type)
        ? current.filter((t) => t !== type)
        : [...current, type];
      setMutedTypes(next); // optimistic
      try {
        const saved = await putNotificationPrefs({ muted_types: next });
        setMutedTypes(saved.muted_types);
      } catch {
        setMutedTypes(current); // roll back on failure
      }
    },
    [mutedTypes],
  );

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
            <div className="flex items-center gap-3">
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
              <button
                type="button"
                onClick={() => void handleTogglePrefs()}
                className={`flex items-center text-xs hover:text-foreground ${
                  showPrefs ? "text-foreground" : "text-muted-foreground"
                }`}
                aria-label="Notification preferences"
                data-testid="notification-prefs-toggle"
              >
                <Settings2 className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {showPrefs && (
            <div
              className="border-b border-border px-3 py-2"
              data-testid="notification-prefs-panel"
            >
              <p className="mb-1.5 text-[11px] text-muted-foreground">
                Muted types are skipped for you entirely (in-app only).
              </p>
              {mutedTypes === null ? (
                <div className="flex justify-center py-2 text-muted-foreground">
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                </div>
              ) : (
                MUTABLE_TYPES.map(({ type, label }) => {
                  const muted = mutedTypes.includes(type);
                  return (
                    <label
                      key={type}
                      className="flex cursor-pointer items-center justify-between py-1 text-xs text-foreground"
                    >
                      {label}
                      <input
                        type="checkbox"
                        checked={!muted}
                        onChange={() => void handleToggleMute(type)}
                        className="h-3.5 w-3.5 accent-sky-500"
                        aria-label={`Deliver ${label}`}
                        data-testid={`notification-pref-${type}`}
                      />
                    </label>
                  );
                })
              )}
            </div>
          )}

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
              items.map((n) => {
                const { Icon, className } = typeAccent(n.type);
                return (
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
                      <Icon
                        className={`h-3.5 w-3.5 shrink-0 ${className}`}
                        aria-hidden="true"
                        data-testid={`notification-icon-${n.id}`}
                      />
                      <span className="truncate text-sm font-medium text-foreground">
                        {n.title}
                      </span>
                      <span
                        className="ml-auto shrink-0 text-[10px] text-muted-foreground"
                        data-testid={`notification-time-${n.id}`}
                      >
                        {relativeTime(n.created_at)}
                      </span>
                    </div>
                    {n.message && (
                      <span className="line-clamp-2 text-xs text-muted-foreground">
                        {n.message}
                      </span>
                    )}
                  </button>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}
