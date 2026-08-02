/**
 * Owns the WebSocket connection for the whole authenticated session.
 *
 * Previously the ONLY `connect()` call site was InvestigationWorkspace's
 * effect, so the socket existed only while an investigation was open. Every
 * other real-time surface — the notification bell, the TLP egress-violation
 * alerter mounted in the Layout shell, `useLiveEventRefresh` on the hunt and
 * coverage pages — was therefore silently dead unless the analyst happened to
 * have a workspace open. Mount this once in the Layout shell instead.
 *
 * Lifecycle rules:
 * - connect when (and only when) there is a hydrated user;
 * - key the effect on the user's ID, not the user OBJECT. `fetchMe()` replaces
 *   the user object on bootstrap with an equal-but-not-identical value; an
 *   effect keyed on the object would re-run and (before `connect()` became
 *   idempotent) tear down a healthy socket;
 * - tear the singleton down when the user goes away, so a socket authenticated
 *   as user A cannot outlive A's session.
 */

import { useEffect } from "react";
import { getWSClient, resetWSClient } from "@/api/ws";
import { useAuthStore } from "@/stores/authStore";

export function useWebSocketSession(): void {
  const userId = useAuthStore((state) => state.user?.id ?? null);

  useEffect(() => {
    if (!userId) {
      // No session (logged out, or bootstrap found no cookie): make sure no
      // socket is left streaming.
      resetWSClient();
      return;
    }

    // Idempotent: a no-op when a socket is already CONNECTING/OPEN, so a
    // StrictMode double-invoke or any effect re-run cannot start the
    // connect/close churn loop.
    getWSClient().connect();

    // Deliberately NOT disconnecting on cleanup: the connection is
    // session-scoped, and StrictMode's mount→unmount→mount would otherwise
    // drop and re-establish it on every dev render. `resetWSClient()` on
    // logout / 401 is what ends the session's socket.
  }, [userId]);
}
