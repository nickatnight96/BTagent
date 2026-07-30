/**
 * Org-custom hunt packs E2E spec (#112 slice 3).
 *
 * Browser coverage for the CustomPacksPanel on /hunt-packs (#530 shipped it
 * with unit tests only): the real file-input upload path (files are read
 * client-side with File.text() and POSTed as content), the two-step delete,
 * the server-side 422 surfacing, and the RBAC split.
 *
 * Server contract (backend/btagent_backend/api/v1/hunt_packs.py):
 * - GET    /api/v1/hunt/packs/custom          hunt:view (analyst+)
 * - POST   /api/v1/hunt/packs/custom          huntpack:manage (senior+); the
 *          validator IS the engine bundle loader, so its 422 detail is the
 *          loader's message verbatim.
 * - DELETE /api/v1/hunt/packs/custom/{row_id} huntpack:manage (senior+)
 *
 * Per-run unique pack names/versions keep parallel shards from sharing
 * state; the upload test deletes its own pack through the UI.
 */
import { test, expect } from "../../fixtures/auth";

/** Minimal manifest the engine loader accepts (id derives from name+version). */
function manifestYaml(name: string): string {
  return [
    `name: ${name}`,
    "version: 1.0.0",
    "description: Uploaded by the custom-packs E2E spec",
    "",
  ].join("\n");
}

/** One minimal valid Sigma rule, unique per run. */
function ruleYaml(runTag: string): string {
  return [
    `title: E2E custom rule ${runTag}`,
    "status: experimental",
    "logsource:",
    "  category: process_creation",
    "  product: windows",
    "detection:",
    "  selection:",
    `    Image|endswith: '\\\\e2e-${runTag}.exe'`,
    "  condition: selection",
    "level: medium",
    "",
  ].join("\n");
}

test.describe("Custom hunt packs panel", () => {
  test("renders on the Hunt Packs page with the upload form for senior", async ({
    seniorPage,
  }) => {
    await seniorPage.goto("/hunt-packs");
    await seniorPage
      .getByTestId("custom-packs-panel")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Senior holds huntpack:manage — the file-input form is offered.
    await expect(seniorPage.getByTestId("custom-pack-form")).toBeVisible();
    await expect(seniorPage.getByTestId("custom-pack-files")).toBeVisible();
  });

  test("uploading a valid bundle lists the pack; two-step delete removes it", async ({
    seniorPage,
  }) => {
    const runTag = `cp-e2e-${Date.now()}`;
    const packName = `E2E Pack ${runTag}`;

    await seniorPage.goto("/hunt-packs");
    await seniorPage
      .getByTestId("custom-pack-files")
      .waitFor({ state: "visible", timeout: 10_000 });

    // The real upload path: the panel reads these with File.text() and POSTs
    // their content — no drag-drop shim, no API shortcut.
    await seniorPage.getByTestId("custom-pack-files").setInputFiles([
      {
        name: "pack.yaml",
        mimeType: "application/yaml",
        buffer: Buffer.from(manifestYaml(packName)),
      },
      {
        name: `rule_${runTag}.yml`,
        mimeType: "application/yaml",
        buffer: Buffer.from(ruleYaml(runTag)),
      },
    ]);

    // The uploaded pack appears in the list with its parsed rule count.
    const row = seniorPage
      .getByTestId("custom-packs-list")
      .locator("li", { hasText: packName });
    await expect(row).toBeVisible({ timeout: 15_000 });
    await expect(row.getByTestId("custom-pack-rules")).toHaveText("1 rule");
    await expect(seniorPage.getByTestId("custom-packs-error")).toHaveCount(0);

    // Two-step delete: first click arms, second deletes.
    const deleteBtn = row.getByRole("button", { name: /delete/i });
    await deleteBtn.click();
    await expect(deleteBtn).toHaveText(/Confirm delete/);
    await deleteBtn.click();
    await expect(row).toHaveCount(0, { timeout: 15_000 });
  });

  test("a bundle with a broken rule surfaces the loader's 422 verbatim", async ({
    seniorPage,
  }) => {
    const runTag = `cp-bad-${Date.now()}`;

    await seniorPage.goto("/hunt-packs");
    await seniorPage
      .getByTestId("custom-pack-files")
      .waitFor({ state: "visible", timeout: 10_000 });

    await seniorPage.getByTestId("custom-pack-files").setInputFiles([
      {
        name: "pack.yaml",
        mimeType: "application/yaml",
        buffer: Buffer.from(manifestYaml(`E2E Broken ${runTag}`)),
      },
      {
        name: `broken_${runTag}.yml`,
        mimeType: "application/yaml",
        // Invalid YAML: the engine loader's parse-stage message must surface.
        buffer: Buffer.from("{{{{not yaml"),
      },
    ]);

    const error = seniorPage.getByTestId("custom-packs-error");
    await expect(error).toBeVisible({ timeout: 15_000 });
    await expect(error).toContainText(/not valid YAML/i);

    // A refused bundle must not have been stored.
    await expect(
      seniorPage
        .getByTestId("custom-packs-panel")
        .locator("li", { hasText: `E2E Broken ${runTag}` }),
    ).toHaveCount(0);
  });

  test("selecting rule files without pack.yaml is refused client-side", async ({
    seniorPage,
  }) => {
    const runTag = `cp-noman-${Date.now()}`;

    await seniorPage.goto("/hunt-packs");
    await seniorPage
      .getByTestId("custom-pack-files")
      .waitFor({ state: "visible", timeout: 10_000 });

    await seniorPage.getByTestId("custom-pack-files").setInputFiles([
      {
        name: `orphan_${runTag}.yml`,
        mimeType: "application/yaml",
        buffer: Buffer.from(ruleYaml(runTag)),
      },
    ]);

    await expect(seniorPage.getByTestId("custom-packs-error")).toContainText(
      /Select the pack\.yaml manifest/,
    );
  });

  test("plain analyst sees the catalog but no upload form or delete buttons", async ({
    analystPage,
  }) => {
    await analystPage.goto("/hunt-packs");
    await analystPage
      .getByTestId("custom-packs-panel")
      .waitFor({ state: "visible", timeout: 10_000 });

    // hunt:view lets the analyst read the list; huntpack:manage is senior+,
    // so neither the upload form nor any delete button is rendered.
    await expect(analystPage.getByTestId("custom-pack-form")).toHaveCount(0);
    await expect(
      analystPage.getByTestId("custom-packs-panel").getByRole("button", {
        name: /delete/i,
      }),
    ).toHaveCount(0);
  });
});
