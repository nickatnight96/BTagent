import { Navigate, useLocation } from "react-router";
import { useIsAuthenticated, useIsBootstrapping } from "@/stores/authStore";

interface ProtectedRouteProps {
  children: React.ReactNode;
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const isAuthenticated = useIsAuthenticated();
  const isBootstrapping = useIsBootstrapping();
  const location = useLocation();

  // F13: on a hard refresh a valid-cookie user starts with user=null until
  // fetchMe() resolves. Redirecting during that window bounced authenticated
  // users to /login. Hold the route until the initial session probe settles.
  if (isBootstrapping) {
    return null;
  }

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
