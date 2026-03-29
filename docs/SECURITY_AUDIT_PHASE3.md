# Security Audit - Phase 3 (Incremental)

**Date:** 2026-03-26
**Scope:** Phase 3 features (coordination, report, mitigation agents), reports API, frontend auth changes, CI/seed-data updates.
**Auditor:** Claude Opus 4.6

---

## Summary

Phase 3 introduces three new agent plugins (coordination, report, mitigation), a reports REST API, corresponding service layer, and orchestrator wiring. The frontend auth store and API client were also updated, and CI workflows adjusted.

Overall the new code follows the security patterns established in Phases 1-2. Three findings were identified and fixed in-place; the remaining items are low-severity observations.

| ID | Severity | Status | Title |
|----|----------|--------|-------|
| SEC-P3-001 | **HIGH** | **FIXED** | Path traversal in template loader |
| SEC-P3-002 | **MEDIUM** | **FIXED** | Seed script prints credentials in non-test mode |
| SEC-P3-003 | **MEDIUM** | **FIXED** | Pydantic models accepted arbitrary strings for enum-like fields |
| SEC-P3-004 | LOW | Observation | CI hardcodes JWT secret and DB password in workflow env |
| SEC-P3-005 | LOW | Observation | Seed script uses username as password in test mode |
| SEC-P3-006 | INFO | Pass | No eval/exec in new agent code |
| SEC-P3-007 | INFO | Pass | All new endpoints have RBAC checks |
| SEC-P3-008 | INFO | Pass | All plugin system prompts include external-data boundary instructions |
| SEC-P3-009 | INFO | Pass | Frontend auth store handles token refresh correctly |
| SEC-P3-010 | INFO | Pass | API client auto-refreshes and injects auth headers |

---

## Findings

### SEC-P3-001: Path Traversal in Template Loader [HIGH - FIXED]

**File:** `agents/btagent_agents/plugins/report/tools/report_generator.py` line 77-83

**Before:**
```python
def _load_template(template_name: str) -> dict[str, Any] | None:
    yaml_path = _TEMPLATES_DIR / f"{template_name}.yaml"
    if not yaml_path.exists():
        return None
    with yaml_path.open() as f:
        return yaml.safe_load(f)
```

**Issue:** The `template_name` parameter was concatenated directly into a filesystem path without validation. An attacker who could control the template name (via the `/reports/generate` API) could use `../../etc/passwd` or similar payloads to read arbitrary YAML-parseable files from the server. While the API-level Pydantic validation was also missing (see SEC-P3-003), the tool itself is callable directly from the agent graph.

**Fix applied:**
1. Added regex validation: only `[a-zA-Z0-9_-]+` names are accepted.
2. Added `.resolve()` + prefix check to ensure the final path stays within `_TEMPLATES_DIR`.

---

### SEC-P3-002: Seed Script Prints Credentials in Non-Test Mode [MEDIUM - FIXED]

**File:** `infra/scripts/seed-data.py` lines 87-91

**Issue:** The script unconditionally printed generated passwords to stdout. In test mode (`BTAGENT_ENV=test`) passwords are deterministic (username = password), so this is benign. However, if someone ran the script without `BTAGENT_ENV=test` (production/staging), it would print randomly generated `secrets.token_urlsafe(16)` passwords to stdout, which could end up in CI logs, terminal scrollback, or log aggregators.

**Fix applied:** Password printing is now conditional on `BTAGENT_ENV == "test"`. In other environments, a message instructs the operator to use the admin CLI.

---

### SEC-P3-003: Pydantic Models Accept Arbitrary Strings [MEDIUM - FIXED]

**File:** `backend/btagent_backend/api/v1/reports.py` lines 27-51

**Issue:** The request models for `template`, `format`, `audience`, and `platform` fields used plain `str` types, allowing arbitrary user-supplied values to flow into the service layer and plugin tools. While the tools themselves validate against allowed values, defense-in-depth requires rejecting invalid input at the API boundary.

Additionally, `investigation_id` had no format validation, allowing injection of path separators or other unexpected characters.

**Fix applied:**
- `template`: Changed to `Literal["incident_report", "ioc_report", "executive_briefing", "regulatory_notification"]`
- `format`: Changed to `Literal["cisa", "fbi_ic3", "isac", "generic"]`
- `audience`: Changed to `Literal["executive", "technical", "compliance"]`
- `platform`: Changed to `Literal["splunk", "elastic", "sentinel"]`
- `investigation_id`: Added `Field(..., pattern=r"^[a-zA-Z0-9_-]+$")` on all models
- `investigation_ids`: Added `Field(..., min_length=1)` to enforce non-empty list

---

### SEC-P3-004: CI Hardcodes Test Secrets in Workflow Env [LOW - OBSERVATION]

**File:** `.github/workflows/ci.yml` lines 68-71, 178-181

**Observation:** `BTAGENT_JWT_SECRET: ci-test-secret-not-for-production` and `POSTGRES_PASSWORD: btagent_ci_password` are hardcoded in the workflow file. These are test-only values used with ephemeral CI databases, so the risk is minimal. The naming (`not-for-production`) indicates awareness. The `GITHUB_TOKEN` used for image push is properly sourced from `secrets`.

**Recommendation:** No action required. If production deployment workflows are added later, ensure all secrets use `${{ secrets.* }}` references.

---

### SEC-P3-005: Test-Mode Passwords Use Username [LOW - OBSERVATION]

**File:** `infra/scripts/seed-data.py` line 24

**Observation:** In test mode, `_generate_seed_password("admin")` returns `"admin"`, meaning the admin account password is `admin`. This is intentional for UAT test determinism and is guarded by `BTAGENT_ENV=test`. The CI workflow correctly sets `BTAGENT_ENV: test`.

**Risk:** Low. An accidental production deployment with `BTAGENT_ENV=test` would create trivially guessable credentials. The existing `SEC-002` comment documents this tradeoff.

**Recommendation:** Consider adding a startup check in the backend that refuses to start with `BTAGENT_ENV=test` if the database URL does not contain `localhost` or `_test`.

---

## Passed Checks

### SEC-P3-006: No eval/exec in New Agent Code [PASS]

Searched all files under `agents/` and `backend/` for `eval(`, `exec(`, `__import__`, `os.system`, and `subprocess`. Results:
- `redis.eval(lua, ...)` in rate_limiter.py -- this is Redis server-side Lua execution with a hardcoded script, not Python eval. Safe.
- `asyncio.create_subprocess_exec` in MCP transports -- pre-existing Phase 1 code, not in scope.
- Comments explicitly noting `No eval()` in playbook code.
- No `eval`/`exec` found in any Phase 3 file.

### SEC-P3-007: All New Endpoints Have RBAC Checks [PASS]

All five endpoints in `reports.py` follow the pattern:
```python
user: CurrentUser = Depends(get_current_user)
user.require_permission("report:generate")  # or appropriate permission
```

| Endpoint | Permission |
|----------|-----------|
| `POST /reports/generate` | `report:generate` |
| `GET /reports/templates` | `report:view` |
| `POST /reports/summarize` | `report:summarize` |
| `POST /reports/remediation` | `remediation:generate` |
| `POST /reports/detection-content` | `remediation:generate` |

### SEC-P3-008: External-Data Boundary Instructions in All Prompts [PASS]

All seven plugin system prompts include `<external-data>` boundary instructions:
- `plugins/coordination/system_prompt.md` -- lines 34-36
- `plugins/report/system_prompt.md` -- lines 35-36
- `plugins/mitigation/system_prompt.md` -- lines 35-36
- (Phase 1/2: triage, query, enrichment, knowledge -- already audited)

The orchestrator `nodes.py` uses `_wrap_external_data()` to wrap untrusted text.

### SEC-P3-009: Frontend Auth Store [PASS]

`frontend/src/stores/authStore.ts`:
- Tokens stored via Zustand `persist` middleware (uses `localStorage` by default). Acceptable for SPA architecture as documented in CLAUDE.md.
- `refreshTokens()` properly clears all auth state on failure (line 97, 113).
- `login()` fetches user profile with the new token to populate user state.
- `partialize` correctly limits persisted state to tokens + user (no error/loading state persisted).
- No `dangerouslySetInnerHTML`, `innerHTML`, or `v-html` found anywhere in the frontend source.

### SEC-P3-010: API Client Auth Header Injection [PASS]

`frontend/src/api/client.ts`:
- Auth header injected on every request unless `skipAuth: true` is set (line 50-54).
- Auto-refresh on 401: attempts token refresh, retries the request, logs out on failure (lines 62-75).
- Uses `Bearer` scheme consistently.
- Avoids circular dependency with auth store via external accessor pattern.

---

## Architecture Notes

### New Plugin Tools (No Direct LLM Calls)

The Phase 3 tools (`summarizer.py`, `report_generator.py`, `remediation_generator.py`) are currently template-based and do not make LLM calls directly. They use mock investigation data stores. When upgraded to real LLM calls in a future phase:
- Ensure all investigation data passed to LLM prompts is wrapped in `<external-data>` tags.
- Apply the same output sanitization patterns used in triage/query nodes.

### YAML Template Loading

`report_generator.py` uses `yaml.safe_load()` (not `yaml.load()`). This is the correct choice -- `safe_load` prevents arbitrary Python object deserialization. No `yaml.load()` or `yaml.unsafe_load()` calls were found anywhere in the codebase.

### Service Layer (report_service.py)

The service layer properly delegates to plugin tools and does not perform any direct database queries or raw SQL. All data flows through the tool abstraction layer.

---

## Files Modified by This Audit

| File | Change |
|------|--------|
| `agents/btagent_agents/plugins/report/tools/report_generator.py` | SEC-P3-001: Path traversal fix in `_load_template()` |
| `backend/btagent_backend/api/v1/reports.py` | SEC-P3-003: Hardened Pydantic models with `Literal` types and `Field` patterns |
| `infra/scripts/seed-data.py` | SEC-P3-002: Conditional credential printing |
