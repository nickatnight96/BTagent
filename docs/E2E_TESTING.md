# BTagent E2E Testing Guide

End-to-end browser tests using Playwright. These exercise the real
React SPA against a real FastAPI backend, real Postgres, real Redis,
and the seeded user / investigation / IOC fixtures from the dev stack.

## TL;DR

```bash
# One-time
make e2e-install        # install Playwright + Chromium

# Full local run (needs the dev stack already up)
make dev                # in another terminal: starts pg + redis + minio
cd backend && uvicorn btagent_backend.main:app --reload &
cd frontend && npm run dev &
BTAGENT_ENV=test python infra/scripts/seed-data.py

make e2e                # runs all specs headless

# Iteration
make e2e-headed         # watch the browser
make e2e-ui             # interactive Playwright UI
make e2e-debug          # paused at first step

# Subsets
make e2e-auth           # auth + RBAC specs only
make e2e-investigations
make e2e-iocs
make e2e-knowledge
make e2e-mitre
make e2e-playbooks
make e2e-security
```

## Architecture

```
tests/e2e/
├── playwright.config.ts        Project setup, retries, traces, video, web-server
├── package.json                Playwright + axe-core devDeps
├── tsconfig.json               strict, noUncheckedIndexedAccess
├── fixtures/
│   ├── api-client.ts           BTAgentApiClient — cookie + header transports
│   ├── auth.ts                 test.extend with adminPage / analystPage / seniorPage
│   │                           and adminApi / analystApi / seniorApi / api fixtures
│   ├── seed-helpers.ts         seedInvestigationWithIOCs, seedRedInvestigation,
│   │                           seedKnowledgeDoc — shape-named test data
│   └── ws-helpers.ts           connectInvestigationWs(...) — WS auth via cookie jar
├── pages/                      Page Object Models — one per surface
│   ├── login-page.ts
│   ├── header.ts, sidebar.ts
│   ├── investigation-list-page.ts, new-investigation-modal.ts
│   ├── investigation-workspace-page.ts (embeds AgentChat, EventStream, CostBadge)
│   ├── ioc-notebook-page.ts (embeds IOCDetailPanel, IOCImportModal, IOCExportDialog)
│   ├── knowledge-page.ts (embeds KnowledgeSearch, KnowledgeIngestModal, ...)
│   ├── mitre-page.ts (embeds TechniqueDetailModal)
│   └── playbook-pages.ts (List, Builder, ConfigPanel, YamlEditor, Execution)
└── specs/
    ├── auth.setup.ts           Logs each persona in once; persists storageState
    ├── auth/                   Sprint C: login, logout, RBAC, cookie/header,
    │                           JWT revocation, refresh rotation, persona smoke
    ├── investigations/         Sprint D: list, search, filter, workspace, tabs,
    │                           pause/resume/stop, cost badge, event stream
    ├── iocs/                   Sprint E: notebook, import (CSV/STIX), export,
    │                           detail, bulk actions, TLP egress regression
    ├── knowledge/              Sprint F: search, ingest, doc list, TLP block
    ├── mitre/                  Sprint F: matrix, technique detail, coverage,
    │                           Navigator export
    ├── playbooks/              Sprint F: list, builder, config panel,
    │                           execution, HITL gate
    └── security/               Sprint G: XSS, SQL-i, CSRF, rate limit,
                                auth redirect, JWT revocation, WS access,
                                TLP egress, CSP/HSTS headers, CORS
```

## Selectors

Every interactive element in the React frontend has a `data-testid`
following [E2E_SELECTORS.md](./E2E_SELECTORS.md). Tests reach
elements through Page Object methods, never via raw XPath / CSS / role
queries from a test body. The convention is binding: when adding a new
component, add testids in the same PR.

## Personas

`infra/scripts/seed-data.py` running under `BTAGENT_ENV=test` creates
three users with deterministic credentials (password === username) so
tests can log in without leaking real secrets:

| Persona | Username | Password | Role |
|---|---|---|---|
| Admin | `admin` | `admin` | `admin` |
| Analyst | `analyst1` | `analyst1` | `analyst` |
| Senior | `senior1` | `senior1` | `senior_analyst` |

A test asks for the persona it needs as a fixture:

```ts
import { test, expect } from "../../fixtures/auth";

test("analyst can read own investigation", async ({ analystApi }) => {
  const inv = await analystApi.createInvestigation({ title: "X" });
  // …
});

test("admin sees the dashboard", async ({ adminPage }) => {
  await adminPage.goto("/");
  await expect(adminPage.getByTestId("header-user-name")).toHaveText("admin");
});
```

The `auth.setup.ts` project runs once per test run, logs each persona
in via the **UI** (so a regression in the login form fails the setup
loudly), and dumps `storageState` to `.auth/{persona}.json`. The
persona fixtures hydrate browser contexts from those state files.

## Writing a new test

```ts
import { test, expect } from "../../fixtures/auth";
import { InvestigationListPage } from "../../pages/investigation-list-page";
import { seedInvestigationWithIOCs } from "../../fixtures/seed-helpers";

test("seed and open via the list", async ({ analystPage, analystApi }) => {
  // Seed via the API helper — never via the UI for preconditions.
  const { investigation } = await seedInvestigationWithIOCs(analystApi, {
    title: "[E2E] My new flow",
  });

  // Use the POM, never raw selectors.
  const list = new InvestigationListPage(analystPage);
  await list.goto();
  await expect(list.cardFor(investigation.id)).toBeVisible();
  await list.openInvestigation(investigation.id);
  expect(analystPage.url()).toContain(`/investigations/${investigation.id}`);
});
```

### Conventions

1. **Seed via API, assert via UI.** UI is for what the user does, not
   for setting up the world.
2. **Unique titles.** `Date.now()` or `crypto.randomUUID()` so parallel
   workers don't collide.
3. **POM only.** If a selector you need isn't on a POM, add it on the
   POM in the same PR. Never `page.locator('[data-testid=...]')` from a
   test body.
4. **Persona fixtures.** Use `analystPage` / `seniorPage` / `adminPage`.
   For tests that need *two* personas (cross-org IDOR, etc.), request
   both fixtures.
5. **Network mocks.** `page.route("**/api/v1/iocs/*/enrich", h)` for
   anything that hits a CTI provider. Never call real CTI APIs.
6. **Tag mobile-only tests** with `@mobile`. Tag cross-browser tests
   with `@cross-browser`. Default runs only chromium-desktop.

## CI

`.github/workflows/ci.yml` includes an `e2e` job that runs after
`backend-tests`. It:

1. Brings up Postgres + Redis as service containers (same as the
   `backend-tests` job).
2. Installs the Python workspace + the frontend.
3. Builds the frontend with `npm run build`.
4. Installs Playwright + Chromium (`--with-deps`).
5. Runs the database migrations + seeds the test users.
6. Starts uvicorn on `:8000`, vite preview on `:5173`.
7. Runs `npx playwright test --reporter=html,junit,github`.
8. Uploads the HTML report (always) + traces/videos on failure +
   backend log on failure.

The job is on the dependency path of `Build & Push Images` so a red
E2E blocks production-image builds on `main`.

## Debugging a failure

CI uploads three artifacts on a red e2e job:

- **`playwright-report`** — `npx playwright show-report path/to/report`
- **`playwright-traces`** — open the `.zip` in `npx playwright show-trace`
- **`backend-log`** — uvicorn stdout/stderr from the run

Locally, retry with `make e2e-headed` to watch the browser, or
`make e2e-debug` to step through.

For one specific spec:

```bash
cd tests/e2e
npx playwright test specs/auth/login.spec.ts -g "valid credentials" --headed
```

## Adding a new persona

1. Add the user to `infra/scripts/seed-data.py` (under `BTAGENT_ENV=test`,
   use `username` as password).
2. Update `tests/e2e/fixtures/api-client.ts` `TEST_CREDENTIALS`.
3. Add a fixture branch in `tests/e2e/fixtures/auth.ts`:
   - new entry in the `Persona` union type
   - new `STATE_FILE` mapping
   - new `{persona}Api` and `{persona}Page` fixture
4. Add a setup test in `specs/auth.setup.ts`.
5. Smoke-test the new persona in `specs/auth/persona.spec.ts`.

## Adding a new surface

1. Instrument the React component per [E2E_SELECTORS.md](./E2E_SELECTORS.md).
2. Add a Page Object class under `tests/e2e/pages/`.
3. Add a spec subdir under `tests/e2e/specs/`.
4. Add a `make e2e-<surface>` target if it deserves its own subset.

## Cross-browser + mobile

Default `make e2e` runs only Chromium-desktop. To exercise other browsers:

```bash
make e2e-cross-browser    # Firefox + WebKit on @cross-browser-tagged tests
make e2e-mobile           # Pixel 7 viewport on @mobile-tagged tests
```

Tag a test:

```ts
test("works on mobile @mobile", async ({ analystPage }) => { … });
test("works on Firefox @cross-browser", async ({ analystPage }) => { … });
```

## Visual regression + a11y

Sprint I lands axe-core integration on every page-load via a fixture
hook (`expectNoA11yViolations(page)`) and Playwright snapshot tests on
key surfaces. Pending: see the punchlist in `docs/E2E_SELECTORS.md`.
