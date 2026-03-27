import { useEffect } from "react";
import { RouterProvider } from "react-router-dom";
import { router } from "./router";
import { setAuthStoreAccessor } from "./api/client";
import { useAuthStore } from "./stores/authStore";

// Wire auth store into the API client to break the circular dependency
setAuthStoreAccessor(() => useAuthStore.getState());

export default function App() {
  // Ensure dark class is always on the html element
  useEffect(() => {
    document.documentElement.classList.add("dark");
  }, []);

  return <RouterProvider router={router} />;
}
