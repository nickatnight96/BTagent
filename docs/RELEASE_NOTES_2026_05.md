# BTagent — May 2026 Pre-Release Notes (User Testing)

This release closes out the security-audit findings from the three audit
waves (agents, backend+shared, frontend+infra+CI) and lands the
foundation of the engine-extraction work that powers the upcoming
n8n-style workflow surface. The engine work is dormant — the running
investigation pipeline still routes through the same orchestrator code
testers have been using — so the user-visible delta in this release is
**almost entirely security/auth-related**.

Read the [Action Required](#action-required) section before your first
login on the new build.

---

## Action Required

1. **Log out and back in.** Sessions issued before this build cannot be
   refreshed: the access/refresh-token transport changed. You will be
   forced to the login screen on first request after upgrade. New
   credentials issued on login work for the full session.
2. **If you script the API**, switch from
   `Authorization: Bearer <access_token>` headers to the
   `btagent_access` HttpOnly cookie set by `/auth/login`. The header
   path **still works** as a compat fallback (mobile / CLI / unit
   tests); the SPA itself no longer reads or writes tokens to
   `localStorage`.
3. **If you run the WebSocket client outside the SPA** (custom
   notebook, k6 script, etc.), drop the `?token=...` query string —
   the WS endpoint now reads auth from the cookie instead. The query
   string is still accepted for one release as a compat shim; it will
   be removed in the next.
4. **If you use TLP:RED-classified IOCs**, audit your usage. Egress is
   now hard-blocked at four points (MCP return, WebSocket emit, STIX
   export, Knowledge ingest). Previously some of these silently
   succeeded with the data dropped to an empty result; now they raise
   `TLPViolation` and the caller has to pre-filter.
5. **If your account belongs to a non-default org**, expect cross-org
   investigation reads / IOC writes / WS subscriptions to start
   returning 403 / 404. Previously any authenticated user could read
   any record by ID. The default-org tenant is unaffected.

---

## What Changed (User-Visible)

### Auth Surface

- **httpOnly cookie auth.** `/auth/login` now writes
  `btagent_access` (15 min TTL) and `btagent_refresh` (7 d TTL)
  cookies with `HttpOnly; Secure; SameSite=Lax`. The frontend no
  longer touches `localStorage` for tokens, eliminating the XSS
  exfiltration path the audit flagged.
- **`/auth/logout` exists.** Posting to `/auth/logout` clears both
  cookies and adds the access-token's `jti` to the revocation list.
  Previously logout was a client-side token-discard with no
  server-side effect.
- **`/auth/refresh` reads the refresh cookie.** No longer needs the
  refresh token in the body. Token rotation: each refresh issues a
  new pair and revokes the old `jti`.
- **JWT revocation list.** Access tokens carry a `jti`. Tokens revoked
  via logout (or refresh rotation) fail with `401 invalid_token` even
  before their TTL expires. Backed by Redis with an in-memory
  fallback in dev / test.
- **Header-Bearer auth still accepted.** For tests, mobile clients,
  and CLI scripts. Same revocation rules apply.

### Authorization

- **Org-scoped tenancy.** Every core row (`users`, `investigations`,
  `iocs`, `evidence`) carries an `org_id` and the API filters
  reads/writes by the caller's org. Existing rows backfill to
  `org_default`. Cross-org access returns 404 (read) or 403 (write).
- **IDOR fixes.** Non-owner reads of investigations and IOCs now
  return 404. Senior analysts and incident commanders retain
  same-org broad-read; analysts only see what they own or are
  assigned to.
- **WebSocket investigation-access check.** Subscribing to
  `/ws/investigations/{id}` now verifies the caller owns or is
  assigned to that investigation (or has a `senior_analyst`/`ic`
  role) before forwarding events. Previously any authenticated user
  could subscribe to any stream and watch live agent output.

### TLP Egress

- **TLP:RED is a hard block.** `assert_tlp_allows_egress(...)` runs
  at four egress points: MCP tool returns, EventEmitter
  WebSocket pushes, STIX export, and Knowledge-document ingest.
  Calling any of them with a TLP:RED-tagged payload raises
  `TLPViolation`. Pre-filter the payload (the API layer already
  does this for STIX export — see
  `backend/btagent_backend/api/v1/iocs.py:export_stix`).
- **TLP-vs-provider gate.** The LLM router (Sprint 3A) now
  cross-checks the message TLP against the upstream provider's
  data-residency profile and refuses to send TLP:AMBER+ payloads
  to providers not on the allowlist.

### Hardening (Plumbing)

- **MCP transport.** TLS verification is on by default; backoff is
  30 → 60 → 120 → 240 → 600s; per-response cap is 10 MiB. New
  `MCPHardenedServerConfig` for production use; the legacy
  `MCPServerConfig` is kept untouched for back-compat.
- **EventEmitter redaction.** Bearer / API-key / AWS / Slack /
  GitHub / JWT / basic-auth-URL patterns are stripped *before*
  payload truncation, so a redaction can't be cut off mid-secret.
- **HITL gate integration test.** The HITL pause path is exercised
  end-to-end against the real orchestrator (was previously only unit
  tested on the callback in isolation).
- **Playbook YAML hardening.** 1 MiB file cap, 500-step cap,
  allowlisted top-level keys, parallel-fork branch caps, and
  unknown-step-type rejection. Stops a malicious or
  agent-synthesized YAML from blowing up the compiler.

### Supply-Chain

- **Docker base images pinned by digest** (Dockerfile.backend +
  Dockerfile.frontend). Reused tags can no longer silently change
  the runtime under our feet.
- **CI uses commit-SHA tags only.** `:latest` no longer published.
  Production deploys reference the SHA via the deploy workflow.
- **CSP, HSTS, X-Content-Type-Options, X-Frame-Options** added at
  the nginx edge.
- **`pip-audit` + `npm audit` in CI.** Advisory for now (won't
  block merges) until the team has a triage workflow; promote to
  required after.
- **gitleaks secret-scan in CI.** Every PR. Test fixtures
  (admin/admin, the deterministic JWT secret in conftest) are
  allowlisted in `.gitleaks.toml`.

---

## What Did Not Change

- The investigation pipeline (Triage → Query → Enrich → Knowledge)
  routes through the same code as before. Templates exist as the
  Phase-2 target but are still loaded as dormant YAML — no one runs
  through them yet. You should not see behavior differences in a
  real investigation.
- The MITRE matrix, knowledge base, and STIX import/export views.
- All 9 MCP integrations (Splunk, CrowdStrike, Sentinel, Elastic,
  VirusTotal, Shodan, GreyNoise, AbuseIPDB, MISP). Same configs,
  same outputs.
- The 4 plugin types and 6 policy hooks (Triage, Query, Enrichment,
  Knowledge / HITL, EventEmitter, PromptBudget, EvidenceChain,
  ScopeEnforcement, Classification).

---

## Known Issues

- **Frontend tsc has 21 pre-existing errors** (vite-env.d.ts gaps,
  ReactFlow type drift, the cookie-migration's WS-client private-access
  leak, unused imports, `noUncheckedIndexedAccess` violations). The
  CI build still produces a working bundle; the type errors are
  surfaced in the job log. Tracked as a frontend-cleanup pass.
- **`HITLInterrupt` is dead code.** The orchestrator pauses via
  LangGraph's native `interrupt_before=["hitl_checkpoint"]`, not via
  the callback that raises this exception. Will be wired or removed
  in the engine middleware refactor.

---

## How To Report

- Reproducible bug → file an issue on `nickatnight96/btagent` with
  the build SHA from `/api/v1/health` and a copy of the failing
  request (cookies stripped).
- Auth/SSO weirdness → tag `@security` on the issue. The cookie
  migration is the most user-visible change; expect the most reports
  here.
- Suspected data leak (cross-org / cross-user) → page directly. Do
  not file a public issue.

---

## Rollout Plan

This build will roll first to a small group of internal testers
(plan: 3-5 analysts on the default org, 1 IC, 1 admin). The engine
work is dormant in this build, so the only user-visible delta is the
auth/security one — if testers can log in, do an investigation,
launch a hunt, and see the same MITRE matrix / knowledge view they're
used to, the build is safe to widen.

After 48 h with no auth-related regressions surfaced, the build moves
to the broader staging tenant.
