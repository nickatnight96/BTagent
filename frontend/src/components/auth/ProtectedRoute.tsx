import { Navigate, useLocation } from "react-router-dom";
import { useIsAuthenticated } from "@/stores/authStore";

interface ProtectedRouteProps {
  children: React.ReactNode;
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const isAuthenticated = useIsAuthenticated();
  const location = useLocation();

  if (!isAuthenticated) {
    // Preserve the deep-link target as a ``?redirect=`` query param so
    // the LoginPage can navigate back after a successful login.
    const target = `${location.pathname}${location.search}`;
    const search =
      target && target !== "/"
        ? `?redirect=${encodeURIComponent(target)}`
        : "";
    return (
      <Navigate
        to={`/login${search}`}
        state={{ from: location }}
        replace
      />
    );
  }

  return <>{children}</>;
}
