import { useLocation, useNavigate } from "react-router-dom";
import { Shield, LayoutDashboard, Search, Settings, ChevronLeft, ChevronRight, Database, Grid3X3, BookOpen, Workflow } from "lucide-react";
import { clsx } from "clsx";
import { useUIStore } from "@/stores/uiStore";

interface NavItem {
  label: string;
  path: string;
  icon: React.ReactNode;
}

const navItems: NavItem[] = [
  {
    label: "PunchList",
    path: "/",
    icon: <LayoutDashboard className="w-5 h-5" />,
  },
  {
    label: "Investigations",
    path: "/",
    icon: <Search className="w-5 h-5" />,
  },
  {
    label: "IOC Notebook",
    path: "/iocs",
    icon: <Database className="w-5 h-5" />,
  },
  {
    label: "ATT&CK Matrix",
    path: "/mitre",
    icon: <Grid3X3 className="w-5 h-5" />,
  },
  {
    label: "Knowledge Base",
    path: "/knowledge",
    icon: <BookOpen className="w-5 h-5" />,
  },
  {
    label: "Playbooks",
    path: "/playbooks",
    icon: <Workflow className="w-5 h-5" />,
  },
  {
    label: "Settings",
    path: "/settings",
    icon: <Settings className="w-5 h-5" />,
  },
];

export function Sidebar() {
  const location = useLocation();
  const navigate = useNavigate();
  const { sidebarOpen, toggleSidebar } = useUIStore();

  const isActive = (path: string) => {
    if (path === "/") return location.pathname === "/";
    return location.pathname.startsWith(path);
  };

  return (
    <aside
      className={clsx(
        "flex flex-col bg-slate-900 border-r border-slate-700/50 transition-all duration-300 h-full",
        sidebarOpen ? "w-60" : "w-16",
      )}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 h-16 border-b border-slate-700/50 shrink-0">
        <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/30 shrink-0">
          <Shield className="w-4 h-4 text-blue-400" />
        </div>
        {sidebarOpen && (
          <span className="text-lg font-bold text-slate-100 tracking-tight whitespace-nowrap">
            BTagent
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2 py-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => (
          <button
            key={item.label}
            onClick={() => navigate(item.path)}
            className={clsx(
              "flex items-center gap-3 w-full px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150",
              isActive(item.path)
                ? "bg-blue-600/20 text-blue-400 border border-blue-500/20"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-transparent",
              !sidebarOpen && "justify-center px-2",
            )}
            title={!sidebarOpen ? item.label : undefined}
          >
            {item.icon}
            {sidebarOpen && <span>{item.label}</span>}
          </button>
        ))}
      </nav>

      {/* Collapse toggle */}
      <div className="px-2 py-3 border-t border-slate-700/50 shrink-0">
        <button
          onClick={toggleSidebar}
          className="flex items-center justify-center w-full p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          title={sidebarOpen ? "Collapse sidebar" : "Expand sidebar"}
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
