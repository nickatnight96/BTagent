/**
 * Accessibility assertions via axe-core.
 *
 * Tests that want a11y coverage import ``expectNoA11yViolations`` and
 * call it on the current page after navigation has settled. The check
 * is opinionated:
 *
 *   * ``critical`` and ``serious`` impact rules fail the test.
 *   * ``moderate`` and ``minor`` are surfaced but don't fail (they
 *     accumulate as warnings in the test report).
 *   * Color-contrast is a known noisy rule on dark themes; enabling
 *     it without per-test waivers would generate false positives. It
 *     is *off* by default; tests can opt into it by passing
 *     ``{ enableColorContrast: true }``.
 *
 * Usage:
 *
 *   import { expectNoA11yViolations } from "../fixtures/a11y";
 *
 *   test("login is accessible", async ({ page }) => {
 *     await page.goto("/login");
 *     await expectNoA11yViolations(page);
 *   });
 */
import AxeBuilder from "@axe-core/playwright";
import { expect, type Page } from "@playwright/test";

interface A11yOptions {
  /** Re-enable color-contrast checks. Off by default. */
  enableColorContrast?: boolean;
  /** CSS selectors to exclude from the scan (e.g., third-party widgets). */
  exclude?: string[];
  /** Restrict the scan to a single root selector. */
  scope?: string;
}

const SEVERITY_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"];

export async function expectNoA11yViolations(
  page: Page,
  options: A11yOptions = {},
): Promise<void> {
  let builder = new AxeBuilder({ page }).withTags(SEVERITY_TAGS);

  if (!options.enableColorContrast) {
    builder = builder.disableRules(["color-contrast"]);
  }

  for (const sel of options.exclude ?? []) {
    builder = builder.exclude(sel);
  }
  if (options.scope) {
    builder = builder.include(options.scope);
  }

  const result = await builder.analyze();

  // Only critical + serious are blocking. Moderate / minor get
  // attached to the test annotation surface so a triage pass can
  // catch up over time.
  const blocking = result.violations.filter(
    (v) => v.impact === "critical" || v.impact === "serious",
  );
  const advisory = result.violations.filter(
    (v) => v.impact === "moderate" || v.impact === "minor",
  );

  if (advisory.length > 0) {
    // eslint-disable-next-line no-console
    console.warn(
      `[a11y] ${advisory.length} advisory finding(s) on ${page.url()}:\n` +
        advisory
          .map((v) => `  - ${v.id} (${v.impact}): ${v.description}`)
          .join("\n"),
    );
  }

  if (blocking.length > 0) {
    const summary = blocking
      .map(
        (v) =>
          `  ${v.id} (${v.impact}): ${v.description}\n` +
          v.nodes
            .map(
              (n) =>
                `    target: ${n.target.join(" ")}\n    html: ${n.html.slice(0, 120)}…`,
            )
            .join("\n"),
      )
      .join("\n\n");
    expect.soft(blocking, `a11y violations on ${page.url()}:\n${summary}`).toEqual([]);
    // Hard-fail after collecting the soft to surface in HTML report
    expect(blocking).toEqual([]);
  }
}
