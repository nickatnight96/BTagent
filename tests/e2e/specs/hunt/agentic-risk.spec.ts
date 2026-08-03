/**
 * Agentic Risk page E2E (#121).
 *
 * /agentic-risk was one of the last routed pages with no browser coverage.
 * Writing this found a real defect: the Register/Sunset affordance was keyed
 * on the page's *display bucket* (`bucketOf(f) === "shadow_agent"`) while the
 * backend gate accepts any finding carrying `evidence.shadow_workload`. The
 * identity-drift detector sets that marker deliberately — its own comment says
 * drift "converges into the one governance queue" — but its detection string
 * buckets as identity_abuse, so the buttons never rendered for a finding the
 * API would have accepted. `governs an identity-drift finding` below is that
 * case, end to end.
 *
 * The bucket-population test is the other one worth keeping: it asserts the
 * frontend's detection→bucket mapping still agrees with the strings the
 * backend detectors actually emit. Renaming a detection string is a silent
 * failure today — the finding drops into "other" and disappears from every
 * tile while still sitting in the list.
 *
 * Runs against the mock-mode stack; the agentic hunt has no live connector, so
 * `POST /hunt/agentic/run` is deterministic over the demo bundle.
 *
 * Per-run unique IDs: every seeded record carries a per-invocation `runTag` so
 * parallel shards don't collide on the org-shared findings inbox.
 */
import { test, expect } from "../../fixtures/auth";
import type { Page } from "@playwright/test";

const PAGE_TIMEOUT = 10_000;
const RUN_TIMEOUT = 30_000;

interface SeedPayload {
  title: string;
  severity?: string;
  technique_ids?: string[];
  entities?: Array<{ kind: string; value: string }>;
  observables?: Array<{ type: string; value: string }>;
  evidence?: Record<string, unknown>;
}

/** Seed an agentic HuntFinding through the real ingest route (hunt:create). */
async function seedAgenticFinding(page: Page, payload: SeedPayload): Promise<string> {
  const resp = await page.request.post("/api/v1/hunt/findings", {
    data: {
      source: "agentic",
      domain: "agentic",
      severity: "high",
      confidence: 0.8,
      technique_ids: [],
      entities: [],
      observables: [],
      evidence: {},
      description: "",
      ...payload,
    },
  });
  expect(
    resp.ok(),
    `seedAgenticFinding failed: ${resp.status()} ${await resp.text()}`,
  ).toBeTruthy();
  return ((await resp.json()) as { id: string }).id;
}

async function openPage(page: Page): Promise<void> {
  await page.goto("/agentic-risk");
  await page.getByTestId("agentic-risk-page").waitFor({ state: "visible", timeout: PAGE_TIMEOUT });
}

test.describe("Agentic Risk page", () => {
  test("page structure renders — bucket tiles and the run control", async ({ analystPage }) => {
    await openPage(analystPage);

    await expect(analystPage.getByRole("heading", { name: "Agentic Risk" })).toBeVisible();
    for (const bucket of ["prompt_injection", "shadow_agent", "identity_abuse", "llm_exfil"]) {
      await expect(analystPage.getByTestId(`bucket-${bucket}`)).toBeVisible();
    }
    await expect(analystPage.getByTestId("run-agentic-hunt")).toBeVisible();
  });

  test("sidebar nav link reaches the page", async ({ analystPage }) => {
    await analystPage.goto("/");
    await analystPage.getByTestId("nav-agentic-risk-link").click();
    await analystPage
      .getByTestId("agentic-risk-page")
      .waitFor({ state: "visible", timeout: PAGE_TIMEOUT });
    expect(analystPage.url()).toContain("/agentic-risk");
  });

  test("running the hunt populates every detector bucket", async ({ analystPage }) => {
    await openPage(analystPage);
    await analystPage.getByTestId("run-agentic-hunt").click();

    // The demo bundle trips prompt-injection, llm-exfil, shadow agent
    // (workload + identity), and identity abuse. A bucket stuck on 0 after a
    // run means the detector's `evidence.detection` string no longer matches
    // the tile's predicate, so its findings render only in the flat list.
    for (const bucket of ["prompt_injection", "shadow_agent", "identity_abuse", "llm_exfil"]) {
      await expect
        .poll(
          async () =>
            Number(
              (await analystPage.getByTestId(`bucket-${bucket}`).innerText())
                .split("\n")
                .pop()
                ?.trim() ?? "0",
            ),
          { timeout: RUN_TIMEOUT, message: `bucket ${bucket} never left zero` },
        )
        .toBeGreaterThan(0);
    }
  });

  test("prompt-injection timeline shows matched patterns and the redacted excerpt", async ({
    analystPage,
  }) => {
    const runTag = `ar-pi-${Date.now()}`;
    const findingId = await seedAgenticFinding(analystPage, {
      title: `Prompt injection ${runTag}`,
      severity: "critical",
      technique_ids: ["T1059"],
      entities: [{ kind: "agent_call_event", value: `evt-${runTag}` }],
      evidence: {
        detection: "prompt_injection",
        matched_patterns: [`instruction_override.${runTag}`],
        // The detector redacts before the excerpt ever reaches evidence; the
        // page must render that redacted form and nothing else.
        redacted_excerpts: [`Ignore previous instructions and [REDACTED-${runTag}]`],
      },
    });

    await openPage(analystPage);
    const entry = analystPage.getByTestId(`injection-entry-${findingId}`);
    await expect(entry).toBeVisible({ timeout: PAGE_TIMEOUT });
    await expect(entry).toContainText(`instruction_override.${runTag}`);
    await expect(entry).toContainText(`[REDACTED-${runTag}]`);
    await expect(analystPage.getByTestId("injection-timeline")).toBeVisible();
  });

  test("identity-abuse findings render declared vs observed drift rows", async ({
    analystPage,
  }) => {
    const runTag = `ar-id-${Date.now()}`;
    const findingId = await seedAgenticFinding(analystPage, {
      title: `Agent identity abuse ${runTag}`,
      technique_ids: ["T1078.004"],
      entities: [{ kind: "agent_identity", value: `arn:aws:iam::1:role/Triage-${runTag}` }],
      evidence: {
        detection: "agent_identity_abuse",
        agent_identity_ref: `arn:aws:iam::1:role/Triage-${runTag}`,
        declared_role: `declared-${runTag}`,
        observed_role: `observed-${runTag}`,
        invoked_tool: `tool-${runTag}`,
        reasons: ["role_mismatch"],
      },
    });

    await openPage(analystPage);
    const row = analystPage.getByTestId(`drift-entry-${findingId}`);
    await expect(row).toBeVisible({ timeout: PAGE_TIMEOUT });
    // Declared *and* observed both shown — a row that prints only one side
    // tells the analyst nothing about what actually drifted.
    await expect(row).toContainText(`declared-${runTag}`);
    await expect(row).toContainText(`observed-${runTag}`);
    await expect(row).toContainText(`tool-${runTag}`);
    await expect(row).toContainText("role_mismatch");
  });

  test("bucket tiles filter the findings list and toggle back off", async ({ analystPage }) => {
    const runTag = `ar-flt-${Date.now()}`;
    const injectionId = await seedAgenticFinding(analystPage, {
      title: `Filterable injection ${runTag}`,
      technique_ids: ["T1059"],
      entities: [{ kind: "agent_call_event", value: `evt-${runTag}` }],
      evidence: { detection: "prompt_injection", matched_patterns: ["x"] },
    });
    const exfilId = await seedAgenticFinding(analystPage, {
      title: `Filterable exfil ${runTag}`,
      technique_ids: ["T1567"],
      entities: [{ kind: "agent_call_event", value: `evt2-${runTag}` }],
      evidence: { detection: "llm_exfil" },
    });

    await openPage(analystPage);
    await expect(analystPage.getByTestId(`agentic-finding-${injectionId}`)).toBeVisible({
      timeout: PAGE_TIMEOUT,
    });

    await analystPage.getByTestId("bucket-prompt_injection").click();
    await expect(analystPage.getByTestId("bucket-prompt_injection")).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    await expect(analystPage.getByTestId(`agentic-finding-${injectionId}`)).toBeVisible();
    await expect(analystPage.getByTestId(`agentic-finding-${exfilId}`)).toBeHidden();

    // Clicking the active tile clears the filter rather than re-applying it.
    await analystPage.getByTestId("bucket-prompt_injection").click();
    await expect(analystPage.getByTestId(`agentic-finding-${exfilId}`)).toBeVisible();
  });

  test("governs an identity-drift finding — the marker, not the bucket", async ({
    seniorPage,
  }) => {
    const runTag = `ar-drift-${Date.now()}`;
    const driftRef = `arn:aws:iam::1:role/Undeclared-${runTag}`;
    // Shape emitted by `detect_identity_drift`: the governance routing marker
    // is set, but the detection string buckets as identity_abuse. Keying the
    // affordance off the bucket hid these buttons entirely.
    const findingId = await seedAgenticFinding(seniorPage, {
      title: `Agent identity drift ${runTag}`,
      technique_ids: ["T1078.004"],
      entities: [{ kind: "agent_identity", value: driftRef }],
      evidence: {
        detection: "agent_identity_drift",
        shadow_workload: true,
        agent_identity_ref: driftRef,
        drift: [driftRef],
      },
    });

    await openPage(seniorPage);
    await expect(seniorPage.getByTestId(`agentic-finding-${findingId}`)).toBeVisible({
      timeout: PAGE_TIMEOUT,
    });
    await seniorPage.getByTestId(`govern-register-${findingId}`).click();

    const badge = seniorPage.getByTestId(`governance-status-${findingId}`);
    await expect(badge).toHaveText("registered", { timeout: PAGE_TIMEOUT });

    // The ruling is a stored decision, not local state — it must survive a
    // reload, which is what proves it reached shadow_agent_registry.
    await seniorPage.reload();
    await seniorPage
      .getByTestId("agentic-risk-page")
      .waitFor({ state: "visible", timeout: PAGE_TIMEOUT });
    await expect(seniorPage.getByTestId(`governance-status-${findingId}`)).toHaveText(
      "registered",
      { timeout: PAGE_TIMEOUT },
    );
  });

  test("a plain analyst gets no governance buttons, and the API refuses anyway", async ({
    analystPage,
  }) => {
    const runTag = `ar-rbac-${Date.now()}`;
    const findingId = await seedAgenticFinding(analystPage, {
      title: `Shadow agent ${runTag}`,
      technique_ids: ["T1583.006"],
      entities: [{ kind: "agentic_workload", value: `wl-${runTag}` }],
      observables: [{ type: "cloud_resource_id", value: `projects/demo/services/${runTag}` }],
      evidence: { detection: "shadow_agent_workload", shadow_workload: true, kind: "cloud_run_mcp" },
    });

    await openPage(analystPage);
    await expect(analystPage.getByTestId(`agentic-finding-${findingId}`)).toBeVisible({
      timeout: PAGE_TIMEOUT,
    });
    await expect(analystPage.getByTestId(`govern-register-${findingId}`)).toHaveCount(0);

    // Hiding the button is presentation. hunt:suppress is the control, so the
    // route has to refuse the analyst who calls it directly.
    const resp = await analystPage.request.post(
      `/api/v1/hunt/findings/${findingId}/govern`,
      { data: { action: "register", rationale: "" } },
    );
    expect(resp.status()).toBe(403);
  });
});
