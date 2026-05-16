import { useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { LogOut, Menu } from "lucide-react";
import { useAuthStore } from "@/stores/authStore";
import { useUIStore } from "@/stores/uiStore";
import { Badge } from "@/components/ds/badge";
import { Button } from "@/components/ds/button";
import { Avatar, AvatarFallback } from "@/components/ds/avatar";
import { ThemeToggle } from "@/components/theme-toggle";

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

  const initials = (user?.username ?? "")
    .split(/[\s._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0]?.toUpperCase() ?? "")
    .join("") || "U";

  return (
    <header
      className="flex items-center justify-between h-16 px-6 bg-card/80 backdrop-blur-sm border-b border-border shrink-0"
      data-testid="header"
    >
      <div className="flex items-center gap-4">
        {/* Mobile menu toggle */}
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleSidebar}
          className="md:hidden"
          aria-label="Toggle navigation menu"
          data-testid="header-menu-toggle"
        >
          <Menu className="w-5 h-5" />
        </Button>

        <h1
          className="text-lg font-semibold text-foreground"
          data-testid="header-title"
        >
          {title}
        </h1>
      </div>

      <div className="flex items-center gap-2">
        <ThemeToggle />
        {user && (
          <div className="flex items-center gap-3" data-testid="header-user">
            {/* User info */}
            <div className="hidden sm:flex items-center gap-2">
              <Avatar className="h-8 w-8">
                <AvatarFallback className="text-xs">{initials}</AvatarFallback>
              </Avatar>
              <span
                className="text-sm text-foreground font-medium"
                data-testid="header-user-name"
              >
                {user.username}
              </span>
              <Badge
                variant="secondary"
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
              className="text-muted-foreground hover:text-destructive"
              aria-label="Sign out"
              data-testid="header-logout-button"
            >
              <LogOut className="w-4 h-4 sm:mr-2" aria-hidden="true" />
              <span className="hidden sm:inline">Logout</span>
            </Button>
          </div>
        )}
      </div>
    </header>
  );
}
