/**
 * Every routed page has E2E browser coverage, or is declared here.
 *
 * Three pages shipped, were unit-tested, passed review, and had never been
 * opened by a browser in CI: `/hunt-plan` (#550), `/agentic-risk` (#551),
 * `/detection-validation` (#552). Covering them found a real governance bug
 * and a broken report-generation path. Nothing failed while they were
 * uncovered — that is the point. A route added tomorrow inherits none of that
 * history, and I twice asserted coverage was complete when it was not.
 *
 * This is the ratchet, in the same shape as the API-reachability guard and the
 * MCP-dispatch guard: the list only shrinks, and adding to it is a deliberate,
 * checkable claim rather than a silent omission.
 *
 * ## Why the matching is indirect
 *
 * Specs rarely name a route. They navigate three ways, and a scan that only
 * understands the first reports covered pages as uncovered — I made exactly
 * that mistake while writing the specs above, once reporting 12 uncovered
 * routes when the true answer was 3. So all three hops count:
 *
 *  1. **Directly** — `goto("/reports")`, or the sidebar testid.
 *  2. **Through the Sidebar POM** — `sidebar.goToPolicies()`, whose body waits
 *     for the route.
 *  3. **Through a per-page POM** — `new CorrelationPage(page).goto()`, where
 *     the POM itself calls a Sidebar method.
 *
 * Deliberately *not* counted: a route mentioned only inside `pages/sidebar.ts`.
 * That file is a catalogue of every nav link, so treating it as coverage would
 * mark every route covered forever — which is precisely how `/memory` sat
 * uncovered behind a `goToAgentMemory()` helper no spec ever called.
 *
 * Runs in the E2E project because that is what it guards, but it opens no
 * browser: it only reads source text.
 */
import { test, expect } from "@playwright/test";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

const E2E = resolve(__dirname, "../..");
const REPO = resolve(E2E, "../..");
const ROUTER = join(REPO, "frontend/src/router.tsx");
const SIDEBAR_TSX = join(REPO, "frontend/src/components/layout/Sidebar.tsx");
const SPECS = join(E2E, "specs");
const PAGES = join(E2E, "pages");

/** Routes with no E2E coverage, and why that is currently acceptable. */
const ROUTES_WITHOUT_E2E: Record<string, string> = {
  // (empty — keep it that way; see the file docstring)
};

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (full.endsWith(".ts")) out.push(full);
  }
  return out;
}

/** Static route paths declared in the router, minus login and the shell. */
function routedPaths(): string[] {
  const src = readFileSync(ROUTER, "utf8");
  return [...src.matchAll(/path:\s*"([^"]+)"/g)]
    .map((m) => m[1] ?? "")
    .filter((p) => p !== "" && p !== "/login" && p !== "/")
    // A parameterised child (`workflows/:id`) is the same surface as its
    // parent for coverage purposes — reaching one reaches the other.
    .filter((p) => !p.includes("/:"))
    .map((p) => p.replace(/^\//, ""));
}

/** `/path` -> `nav-x-link`, read off the Sidebar's own nav table. */
function navTestIds(): Record<string, string> {
  const src = readFileSync(SIDEBAR_TSX, "utf8");
  const out: Record<string, string> = {};
  for (const m of src.matchAll(/path:\s*"([^"]+)"[\s\S]{0,200}?testId:\s*"([^"]+)"/g)) {
    const path = m[1];
    const testId = m[2];
    if (path && testId) out[path.replace(/^\//, "")] = testId;
  }
  return out;
}

/** Sidebar POM method -> the route its `waitForURL` lands on. */
function sidebarMethodRoutes(): Record<string, string> {
  const src = readFileSync(join(PAGES, "sidebar.ts"), "utf8");
  const out: Record<string, string> = {};
  for (const m of src.matchAll(
    /async\s+(goTo\w+)\([^)]*\)[^{]*\{[\s\S]{0,300}?waitForURL\("\*\*\/([\w-]*)"/g,
  )) {
    const method = m[1];
    const route = m[2];
    if (method && route) out[method] = route;
  }
  return out;
}

function mentionsRoute(text: string, route: string, navId: string | undefined): boolean {
  const literals = [`"/${route}"`, `'/${route}'`, `/${route}/`, `/${route}?`];
  if (literals.some((l) => text.includes(l))) return true;
  return Boolean(navId && text.includes(navId));
}

function uncoveredRoutes(): string[] {
  const navIds = navTestIds();
  const methodRoutes = sidebarMethodRoutes();
  const specs = walk(SPECS).map((f) => readFileSync(f, "utf8"));
  const poms = walk(PAGES)
    .filter((f) => !f.endsWith("sidebar.ts"))
    .map((f) => ({
      name: f.split("/").pop()!.replace(/\.ts$/, ""),
      src: readFileSync(f, "utf8"),
    }));

  const uncovered: string[] = [];
  for (const route of routedPaths()) {
    const navId = navIds[route];
    const methods = Object.entries(methodRoutes)
      .filter(([, r]) => r === route)
      .map(([m]) => m);

    const covered = specs.some((spec) => {
      if (mentionsRoute(spec, route, navId)) return true;
      if (methods.some((m) => spec.includes(`${m}(`))) return true;
      // A per-page POM the spec imports counts, including when the POM reaches
      // the route via a Sidebar method rather than a literal path.
      return poms.some(
        (pom) =>
          spec.includes(`pages/${pom.name}"`) &&
          (mentionsRoute(pom.src, route, navId) ||
            methods.some((m) => pom.src.includes(`${m}(`))),
      );
    });
    if (!covered) uncovered.push(route);
  }
  return uncovered;
}

test.describe("routed pages have E2E coverage", () => {
  test("finds routes and specs at all (guard the guard)", () => {
    // A broken matcher would wave every route through silently.
    expect(routedPaths().length).toBeGreaterThan(25);
    expect(walk(SPECS).length).toBeGreaterThan(20);
    expect(Object.keys(navTestIds()).length).toBeGreaterThan(15);
    expect(Object.keys(sidebarMethodRoutes()).length).toBeGreaterThan(8);
  });

  test("follows the Sidebar POM hop, not just literal paths", () => {
    // `/policies` is only ever reached via `sidebar.goToPolicies()`. Pinned
    // because if this regresses the scan reports genuinely-covered routes as
    // holes, and the tempting "fix" is to exempt them — writing a falsehood
    // into the one list people trust.
    expect(uncoveredRoutes()).not.toContain("policies");
  });

  test("follows the per-page POM hop", () => {
    // `/correlate` is reached via slice-pages' CorrelationPage.goto(), which
    // itself calls sidebar.goToCorrelate() — two hops from the spec.
    expect(uncoveredRoutes()).not.toContain("correlate");
  });

  test("every routed page is covered or declared", () => {
    const undeclared = uncoveredRoutes()
      .filter((r) => !(r in ROUTES_WITHOUT_E2E))
      .sort();
    expect(
      undeclared,
      "These routed pages have no E2E spec that ever opens them, so nothing " +
        "would fail if they broke in a browser. Add a spec under " +
        "tests/e2e/specs/, or add the route to ROUTES_WITHOUT_E2E with the " +
        "reason it cannot have one.",
    ).toEqual([]);
  });

  test("declared exemptions are still real routes", () => {
    const routes = new Set(routedPaths());
    const stale = Object.keys(ROUTES_WITHOUT_E2E).filter((r) => !routes.has(r));
    expect(stale, "Exempted but no longer routed — the list only shrinks.").toEqual([]);
  });

  test("exemptions that gained coverage are removed", () => {
    const uncovered = new Set(uncoveredRoutes());
    const nowCovered = Object.keys(ROUTES_WITHOUT_E2E).filter((r) => !uncovered.has(r));
    expect(nowCovered, "These have coverage now, so their exemption is stale.").toEqual([]);
  });
});
