import { useEffect } from "react";
import { toast } from "sonner";
import { getWSClient } from "@/api/ws";
import { EventType } from "@/types/events";
import type { AgentEvent } from "@/types/events";

/**
 * Real-time TLP-violation alerter (EPIC-7 UC-7.2).
 *
 * The backend's central egress gate refuses any cloud-LLM / connector / event
 * / STIX egress carrying TLP:RED (or policy-blocked AMBER) content and
 * broadcasts a ``tlp.violation_attempt`` event over the WebSocket hub. This
 * headless component subscribes to that event and surfaces it as a persistent
 * error toast so an accidental-egress attempt is never silent — closing the
 * "policy violations alerted in real time" acceptance bullet.
 *
 * Chains the existing ``onEvent`` handler so other WS consumers keep working.
 */
export function useTlpViolationAlerts(): void {
  useEffect(() => {
    const ws = getWSClient();
    const prev = ws.onEvent;
    ws.onEvent = (ev: AgentEvent) => {
      prev(ev);
      if (ev.type !== EventType.TLP_VIOLATION_ATTEMPT) return;
      const data = (ev.data ?? {}) as Record<string, unknown>;
      const tlp = String(data["tlp"] ?? "").toUpperCase() || "CLASSIFIED";
      const kind = String(data["egress_kind"] ?? "egress");
      const reason = data["reason"] ? String(data["reason"]) : undefined;
      toast.error(`Blocked TLP:${tlp} egress via ${kind}`, {
        description: reason,
        duration: 12_000,
      });
    };
    return () => {
      ws.onEvent = prev;
    };
  }, []);
}

/** Headless mount point — renders nothing, just wires the alerter. */
export function TlpViolationAlerts(): null {
  useTlpViolationAlerts();
  return null;
}
