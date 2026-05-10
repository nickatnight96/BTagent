/**
 * Cross-page navigation helpers — small utilities that capture multi-
 * step "go to X with the necessary store state hydrated" patterns.
 *
 * These exist because some Zustand stores in the SPA are populated
 * lazily by individual page mounts. A test that goes straight to
 * ``/iocs`` and then opens the export dialog can find the
 * investigation dropdown empty (because the IOC notebook never
 * fetched investigations on its own; the dashboard does). The
 * helpers below sequence the visits so the store is hydrated before
 * the assertion under test runs.
 */
import type { Page } from "@playwright/test";
import { IOCNotebookPage } from "../pages/ioc-notebook-page";

/**
 * Hydrate the Zustand investigation store by visiting the dashboard
 * first, then navigate to ``/iocs``. The notebook page itself does
 * not fetch investigations on mount, so without this the export
 * dialog dropdown is empty and ``selectOption(seededInvId)`` throws.
 *
 * Returns a constructed ``IOCNotebookPage`` for chaining.
 */
export async function hydrateInvestigationsThenGotoIOCs(
  page: Page,
): Promise<IOCNotebookPage> {
  await page.goto("/");
  await page.getByTestId("investigation-list").waitFor({
    state: "visible",
    timeout: 10_000,
  });
  const notebook = new IOCNotebookPage(page);
  await notebook.goto();
  return notebook;
}
