import { useLocation, useNavigate } from "react-router-dom";
import {
  Shield,
  LayoutDashboard,
  Search,
  Settings,
  ChevronLeft,
  ChevronRight,
  Database,
  Grid3X3,
  BookOpen,
  Workflow,
  Crosshair,
  FileSearch,
  Network,
  ScrollText,
  Lock,
  ShieldAlert,
  Siren,
  ShieldBan,
  GitBranch,
  KeyRound,
} from "lucide-react";
import { useUIStore } from "@/stores/uiStore";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";
import { cn } from "@/lib/utils";

interface NavItem {
  label: string;
  path: string;
  icon: React.ReactNode;
  testId: string;
  /** When set, only users with this role (admin) see the item. */
  adminOnly?: boolean;
}

const navItems: NavItem[] = [
  {
    label: "PunchList",
    path: "/",
    icon: <LayoutDashboard className="w-5 h-5" />,
    testId: "nav-punchlist-link",
  },
  {
    label: "Investigations",
    path: "/",
    icon: <Search className="w-5 h-5" />,
    testId: "nav-investigations-link",
  },
  {
    label: "IOC Notebook",
    path: "/iocs",
    icon: <Database className="w-5 h-5" />,
    testId: "nav-iocs-link",
  },
  {
    label: "ATT&CK Matrix",
    path: "/mitre",
    icon: <Grid3X3 className="w-5 h-5" />,
    testId: "nav-mitre-link",
  },
  {
    label: "Knowledge Base",
    path: "/knowledge",
    icon: <BookOpen className="w-5 h-5" />,
    testId: "nav-knowledge-link",
  },
  {
    label: "Hunt Triage",
    path: "/hunt",
    icon: <Crosshair className="w-5 h-5" />,
    testId: "nav-hunt-link",
  },
  {
    label: "Hunt Package",
    path: "/hunts",
    icon: <FileSearch className="w-5 h-5" />,
    testId: "nav-hunts-link",
  },
  {
    label: "Correlation",
    path: "/correlate",
    icon: <Network className="w-5 h-5" />,
    testId: "nav-correlate-link",
  },
  {
    label: "Alert Triage",
    path: "/triage",
    icon: <ShieldAlert className="w-5 h-5" />,
    testId: "nav-triage-link",
  },
  {
    label: "Response Plan",
    path: "/response-plan",
    icon: <Siren className="w-5 h-5" />,
    testId: "nav-response-plan-link",
  },
  {
    label: "Bulk Mitigation",
    path: "/mitigation",
    icon: <ShieldBan className="w-5 h-5" />,
    testId: "nav-mitigation-link",
  },
  {
    label: "Workflows",
    path: "/workflows",
    icon: <GitBranch className="w-5 h-5" />,
    testId: "nav-workflows-link",
  },
  {
    label: "Playbooks",
    path: "/playbooks",
    icon: <Workflow className="w-5 h-5" />,
    testId: "nav-playbooks-link",
  },
  {
    label: "Audit Ledger",
    path: "/audit",
    icon: <ScrollText className="w-5 h-5" />,
    testId: "nav-audit-link",
  },
  {
    label: "TLP Policies",
    path: "/policies",
    icon: <Lock className="w-5 h-5" />,
    testId: "nav-policies-link",
  },
  {
    label: "SSO Linking",
    path: "/sso-identities",
    icon: <KeyRound className="w-5 h-5" />,
    testId: "nav-sso-identities-link",
    adminOnly: true,
  },
  {
    label: "Settings",
    path: "/settings",
    icon: <Settings className="w-5 h-5" />,
    testId: "nav-settings-link",
  },
];

export function Sidebar() {
  const location = useLocation();
  const navigate = useNavigate();
  const { sidebarOpen, toggleSidebar } = useUIStore();
  const role = useAuthStore((s) => s.user?.role);

  const isActive = (path: string) => {
    if (path === "/") return location.pathname === "/";
    return location.pathname.startsWith(path);
  };

  // Admin-only surfaces (e.g. SSO account linking) are hidden from the nav for
  // everyone else; the routes themselves remain server-RBAC-protected.
  const visibleNavItems = navItems.filter(
    (item) => !item.adminOnly || role === UserRole.ADMIN
  );

  return (
    <aside
      className={cn(
        "flex flex-col bg-card border-r border-border transition-all duration-300 h-full",
        sidebarOpen ? "w-60" : "w-16"
      )}
      data-testid="sidebar"
      data-sidebar-open={sidebarOpen}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 h-16 border-b border-border shrink-0">
        <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 shrink-0">
          <Shield className="w-4 h-4 text-primary" aria-hidden="true" />
        </div>
        {sidebarOpen && (
          <span
            className="text-lg font-bold text-foreground tracking-tight whitespace-nowrap"
            data-testid="sidebar-brand"
          >
            BTagent
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav
        className="flex-1 px-2 py-4 space-y-1 overflow-y-auto"
        aria-label="Primary"
      >
        {visibleNavItems.map((item) => {
          const active = isActive(item.path);
          return (
            <button
              key={item.label}
              onClick={() => navigate(item.path)}
              className={cn(
                "flex items-center gap-3 w-full px-3 py-2.5 rounded-md text-sm font-medium transition-all duration-150 border",
                active
                  ? "bg-primary/10 text-primary border-primary/20"
                  : "text-muted-foreground hover:text-foreground hover:bg-accent border-transparent",
                !sidebarOpen && "justify-center px-2"
              )}
              title={!sidebarOpen ? item.label : undefined}
              aria-label={item.label}
              aria-current={active ? "page" : undefined}
              data-testid={item.testId}
            >
              {item.icon}
              {sidebarOpen && <span>{item.label}</span>}
            </button>
          );
        })}
      </nav>

      {/* Collapse toggle */}
      <div className="px-2 py-3 border-t border-border shrink-0">
        <button
          onClick={toggleSidebar}
          className="flex items-center justify-center w-full p-2 rounded-md text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
          title={sidebarOpen ? "Collapse sidebar" : "Expand sidebar"}
          aria-label={sidebarOpen ? "Collapse sidebar" : "Expand sidebar"}
          aria-expanded={sidebarOpen}
          data-testid="sidebar-collapse-toggle"
        >
          {sidebarOpen ? (
            <ChevronLeft className="w-5 h-5" />
          ) : (
            <ChevronRight className="w-5 h-5" />
          )}
        </button>
      </div>
    </aside>
  );
}
