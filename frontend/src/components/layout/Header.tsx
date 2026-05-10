import { useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { LogOut, User, Menu } from "lucide-react";
import { useAuthStore } from "@/stores/authStore";
import { useUIStore } from "@/stores/uiStore";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";

interface HeaderProps {
  title: string;
}

export function Header({ title }: HeaderProps) {
  const navigate = useNavigate();
  const { user, logout } = useAuthStore();
  const { toggleSidebar } = useUIStore();

  const handleLogout = useCallback(() => {
    logout();
    navigate("/login", { replace: true });
  }, [logout, navigate]);

  return (
    <header
      className="flex items-center justify-between h-16 px-6 bg-slate-900/80 backdrop-blur-sm border-b border-slate-700/50 shrink-0"
      data-testid="header"
    >
      <div className="flex items-center gap-4">
        {/* Mobile menu toggle */}
        <button
          onClick={toggleSidebar}
          className="md:hidden text-slate-400 hover:text-slate-200 p-1"
          aria-label="Toggle navigation menu"
          data-testid="header-menu-toggle"
        >
          <Menu className="w-5 h-5" />
        </button>

        <h1
          className="text-lg font-semibold text-slate-100"
          data-testid="header-title"
        >
          {title}
        </h1>
      </div>

      <div className="flex items-center gap-4">
        {user && (
          <div className="flex items-center gap-3" data-testid="header-user">
            {/* User info */}
            <div className="hidden sm:flex items-center gap-2">
              <div className="w-8 h-8 rounded-full bg-slate-700 border border-slate-600 flex items-center justify-center">
                <User className="w-4 h-4 text-slate-300" aria-hidden="true" />
              </div>
              <div className="text-sm">
                <span
                  className="text-slate-200 font-medium"
                  data-testid="header-user-name"
                >
                  {user.username}
                </span>
              </div>
              <Badge
                className="text-[10px] uppercase tracking-wider"
                data-testid="header-user-role"
              >
                {user.role}
              </Badge>
            </div>

            {/* Logout */}
            <Button
              variant="ghost"
              size="sm"
              onClick={handleLogout}
              className="text-slate-400 hover:text-red-400"
              aria-label="Sign out"
              data-testid="header-logout-button"
            >
              <LogOut className="w-4 h-4" aria-hidden="true" />
              <span className="hidden sm:inline">Logout</span>
            </Button>
          </div>
        )}
      </div>
    </header>
  );
}
