import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";

afterEach(() => {
  // Clear localStorage between tests so persisted Zustand state from one
  // test cannot leak into the next (especially relevant for the auth store,
  // which we explicitly assert against).
  if (typeof localStorage !== "undefined") {
    localStorage.clear();
  }
});
