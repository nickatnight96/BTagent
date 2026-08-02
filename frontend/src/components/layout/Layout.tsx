import { Outlet } from "react-router";
import { Sidebar } from "./Sidebar";
import { CommandPalette } from "@/components/command-palette";
import { TlpViolationAlerts } from "@/components/governance/TlpViolationAlerts";
import { useWebSocketSession } from "@/hooks/useWebSocketSession";

export function Layout() {
  // Session-scoped WebSocket. Lives here (inside ProtectedRoute, above every
  // page) rather than in InvestigationWorkspace, so notifications, TLP
  // violation alerts and the hunt/coverage live-refresh hooks work on every
  // route — not only while an investigation happens to be open.
  useWebSocketSession();

  return (
    <div className="flex h-screen bg-background overflow-hidden">
      {/* Sidebar */}
      <Sidebar />

      {/* Main content area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Outlet />
      </div>

      {/* Global Cmd-K palette — listens for ⌘K / Ctrl-K */}
      <CommandPalette />

      {/* Headless — surfaces backend TLP egress-block events as toasts (UC-7.2) */}
      <TlpViolationAlerts />
    </div>
  );
}
