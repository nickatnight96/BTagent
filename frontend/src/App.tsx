import { useEffect } from "react";
import { RouterProvider } from "react-router-dom";
import { router } from "./router";
import {
  setAuthStoreAccessor,
  setUnauthenticatedHandler,
} from "./api/client";
import { useAuthStore } from "./stores/authStore";

// Wire auth store into the API client to break the circular dependency.
setAuthStoreAccessor(() => useAuthStore.getState());

// On a 401 from any API call, the client clears the local user and we
// route the SPA to /login. Using react-router's imperative navigation API
// avoids forcing a full page reload (which would lose any unsaved state
// the user has in editors etc.).
setUnauthenticatedHandler(() => {
  // Replace so the user can't "back" into the protected page they came from.
  router.navigate("/login", { replace: true }).catch(() => {
    // Last-resort fallback if the router isn't ready (initial bootstrap
    // race): hard-redirect.
    if (typeof window !== "undefined") {
      window.location.assign("/login");
    }
  });
});

export default function App() {
  // Ensure dark class is always on the html element
  useEffect(() => {
    document.documentElement.classList.add("dark");
  }, []);

  // Phase C2 bootstrap: the persisted user is a UI hint only — the cookie
  // is the source of truth. Verify the session on app load by hitting
  // /auth/me. If the cookie is missing/expired, fetchMe() clears the user
  // and ProtectedRoute will bounce us to /login.
  useEffect(() => {
    void useAuthStore.getState().fetchMe();
  }, []);

  return <RouterProvider router={router} />;
}
