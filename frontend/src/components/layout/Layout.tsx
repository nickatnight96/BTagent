import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { CommandPalette } from "@/components/command-palette";
import { TlpViolationAlerts } from "@/components/governance/TlpViolationAlerts";

export function Layout() {
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
