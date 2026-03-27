# BTagent Security Audit Report

**Audit Date:** 2026-03-26
**Auditor:** Automated Secure Code Review (Claude Opus 4.6)
**Scope:** Full codebase review of `backend/`, `agents/`, `shared/`, `infra/`
**Version:** 0.1.0

---

## Executive Summary

**Overall Assessment: CONDITIONAL PASS**

The BTagent codebase demonstrates solid security architecture with TLP-aware LLM routing, HITL approval gates, SHA-256 chained audit logs, scope enforcement, and proper use of SQLAlchemy ORM (no raw SQL injection vectors). However, several **CRITICAL** and **HIGH** severity findings require immediate remediation before any production deployment:

1. **Default JWT secret** shipped in source code (CRITICAL)
2. **Seed script uses trivial passwords** that match usernames (CRITICAL)
3. **Refresh token reuse** without rotation or revocation (HIGH)
4. **Health endpoint leaks database error details** (HIGH)
5. **No max_steps enforcement** in the LangGraph orchestrator (HIGH)
6. **WebSocket HITL/Chat lacks RBAC** permission checks (HIGH)
7. **require_role dependency is broken** -- always checks `investigation:view` (HIGH)

A total of **21 findings** were identified across 7 severity categories.

---

## Findings Summary

| ID | Severity | Category | Title | File | Line(s) |
|----|----------|----------|-------|------|---------|
| SEC-001 | CRITICAL | OWASP Web - Broken Auth | Default JWT secret in source code | `backend/btagent_backend/config.py` | 35 |
| SEC-002 | CRITICAL | Secret Mgmt | Seed script hardcodes trivial passwords | `infra/scripts/seed-data.py` | 33-34, 43, 52 |
| SEC-003 | HIGH | OWASP Web - Broken Auth | Refresh tokens not rotated or revocable | `backend/btagent_backend/api/v1/auth.py` | 53-64 |
| SEC-004 | HIGH | OWASP Web - Sensitive Data | Health endpoint leaks DB error strings | `backend/btagent_backend/api/v1/health.py` | 24 |
| SEC-005 | HIGH | OWASP LLM04 - DoS | No max_steps guard on LangGraph orchestrator | `agents/btagent_agents/orchestrator/graph.py` | 159-244 |
| SEC-006 | HIGH | OWASP LLM08 - Excessive Agency | WebSocket HITL/Chat has no RBAC check | `backend/btagent_backend/ws/routes.py` | 129-166 |
| SEC-007 | HIGH | OWASP Web - Broken Access Control | require_role always checks investigation:view | `backend/btagent_backend/auth/middleware.py` | 77-85 |
| SEC-008 | HIGH | OWASP Web - Broken Auth | Register endpoint allows arbitrary role assignment | `backend/btagent_backend/api/v1/auth.py` | 31, 90 |
| SEC-009 | MEDIUM | OWASP Web - Security Misconfig | CORS allow_methods/allow_headers = wildcard | `backend/btagent_backend/main.py` | 58-59 |
| SEC-010 | MEDIUM | OWASP Web - Security Misconfig | Rate limiter middleware not mounted on app | `backend/btagent_backend/main.py` | 40-77 |
| SEC-011 | MEDIUM | OWASP Web - Broken Auth | Rate limiter extracts role by decoding JWT without verification | `backend/btagent_backend/middleware/rate_limiter.py` | 76-89 |
| SEC-012 | MEDIUM | OWASP Web - Security Misconfig | Nginx CSP header missing | `infra/nginx/nginx.conf` | 43-47 |
| SEC-013 | MEDIUM | OWASP Web - Security Misconfig | Redis and PostgreSQL exposed on host without auth | `infra/docker-compose.yml` | 12, 27 |
| SEC-014 | MEDIUM | OWASP LLM09 - Overreliance | Agent outputs lack confidence levels | `agents/btagent_agents/orchestrator/nodes.py` | 312-402 |
| SEC-015 | MEDIUM | OWASP LLM02 - Insecure Output | Agent outputs stored in DB without sanitization | `backend/btagent_backend/api/v1/investigations.py` | 241 |
| SEC-016 | LOW | Dependency Security | Overly permissive version pins (>=) | `backend/pyproject.toml`, `agents/pyproject.toml` | various |
| SEC-017 | LOW | OWASP Web - Sensitive Data | MinIO default credentials in config defaults | `backend/btagent_backend/config.py` | 29-30 |
| SEC-018 | LOW | Code Quality | Error information leakage in JWT error message | `backend/btagent_backend/auth/middleware.py` | 41 |
| SEC-019 | LOW | OWASP Web - Security Misconfig | Debug mode defaults to False but db_echo available | `backend/btagent_backend/config.py` | 23 |
| SEC-020 | INFO | Secret Mgmt | .gitignore covers .env but not .env.example secrets pattern | `.gitignore` | 28-31 |
| SEC-021 | INFO | OWASP LLM01 - Prompt Injection | External data wrapping present and consistent | `agents/` | multiple |

---

## Detailed Findings

### SEC-001: Default JWT Secret in Source Code (CRITICAL)

**File:** `backend/btagent_backend/config.py`, line 35
**Category:** OWASP Web Top 10 - Broken Authentication

The JWT signing secret has a hardcoded default value of `"CHANGE-ME-IN-PRODUCTION"`. If a production deployment fails to set the `BTAGENT_JWT_SECRET` environment variable, the application silently uses this known value, allowing any attacker to forge valid JWT tokens for any user role including admin.

```python
# VULNERABLE
jwt_secret: str = "CHANGE-ME-IN-PRODUCTION"
```

**Remediation:** Require the JWT secret at startup. If the default value is detected in non-dev environments, refuse to start. Applied as **FIX** below.

---

### SEC-002: Seed Script Hardcodes Trivial Passwords (CRITICAL)

**File:** `infra/scripts/seed-data.py`, lines 33-34, 43, 52
**Category:** Secret Management

The seed script creates users with passwords identical to their usernames (`admin/admin`, `analyst1/analyst1`, `senior1/senior1`). If this script is run in staging or production (accidentally or intentionally), these trivial credentials provide immediate admin access.

```python
# VULNERABLE
password_hash=hash_password("admin"),
password_hash=hash_password("analyst1"),
password_hash=hash_password("senior1"),
```

**Remediation:** Generate random passwords at seed time and print them once. Applied as **FIX** below.

---

### SEC-003: Refresh Tokens Not Rotated or Revocable (HIGH)

**File:** `backend/btagent_backend/api/v1/auth.py`, lines 53-64
**Category:** OWASP Web Top 10 - Broken Authentication

The `/auth/refresh` endpoint accepts a refresh token and returns a new token pair, but the old refresh token remains valid until its original expiry. There is no:
- Token rotation (old refresh token invalidation)
- Server-side revocation list
- Token family tracking (to detect theft)

An attacker who obtains a refresh token can use it indefinitely for 7 days.

```python
# VULNERABLE -- old refresh token is never invalidated
@router.post("/refresh", response_model=TokenPair)
async def refresh(body: RefreshRequest):
    payload = decode_token(body.refresh_token)
    if payload.type != "refresh":
        raise HTTPException(status_code=401, detail="Expected refresh token")
    return create_token_pair(payload.sub, payload.username, payload.role)
```

**Remediation:** Implement a server-side token allowlist/denylist using Redis. On refresh, invalidate the old refresh token. Documented for implementation. Applied a `jti` claim to refresh tokens as a **partial FIX** below.

---

### SEC-004: Health Endpoint Leaks Database Error Strings (HIGH)

**File:** `backend/btagent_backend/api/v1/health.py`, line 24
**Category:** OWASP Web Top 10 - Sensitive Data Exposure

When the database is unreachable, the health endpoint exposes the raw Python exception message, which may contain connection strings, hostnames, ports, or driver-specific error details.

```python
# VULNERABLE
except Exception as e:
    status["database"] = f"error: {e}"  # Leaks internal details
```

**Remediation:** Return a generic error status without the exception message. Applied as **FIX** below.

---

### SEC-005: No max_steps Guard on LangGraph Orchestrator (HIGH)

**File:** `agents/btagent_agents/orchestrator/graph.py`, lines 159-244
**Category:** OWASP LLM04 - Model Denial of Service

The `AgentConfig` defines `max_steps: int = 50`, but the compiled LangGraph does not pass a `recursion_limit` parameter. The `should_continue` edge can loop between `route_task` and `synthesize` indefinitely if the LLM keeps classifying severity as high/critical with new IOCs, exhausting compute resources.

```python
# MISSING -- no recursion_limit set
return graph.compile(
    checkpointer=checkpointer,
    interrupt_before=["hitl_checkpoint"],
)
```

**Remediation:** Pass `recursion_limit` to `graph.compile()` from the config's `max_steps`. Applied as **FIX** below.

---

### SEC-006: WebSocket HITL/Chat Has No RBAC Check (HIGH)

**File:** `backend/btagent_backend/ws/routes.py`, lines 129-166
**Category:** OWASP LLM08 - Excessive Agency

The WebSocket `_read_loop` processes `CHAT` and `HITL_RESPONSE` messages from any authenticated user. It does not verify that the user has the required RBAC permissions (`investigation:chat` for chat, `hitl:approve` for HITL responses). An `analyst` role user could approve containment actions that require `senior_analyst` or higher.

```python
# VULNERABLE -- no permission check
elif msg.type == ClientMessageType.HITL_RESPONSE:
    if not msg.investigation_id:
        await _send_error(client, "hitl_response requires investigation_id")
        continue
    redis = hub._redis
    if redis:
        payload = json.dumps({
            "type": "hitl_response",
            "investigation_id": msg.investigation_id,
            "user_id": client.user.id,
            ...
        })
```

**Remediation:** Add permission checks before processing HITL and CHAT messages. Applied as **FIX** below.

---

### SEC-007: require_role Dependency Is Broken (HIGH)

**File:** `backend/btagent_backend/auth/middleware.py`, lines 77-85
**Category:** OWASP Web Top 10 - Broken Access Control

The `require_role` factory function ignores its `min_role` parameter and always checks `investigation:view` permission, which every role has. This means endpoints using `require_role("admin")` would grant access to analysts.

```python
# VULNERABLE -- min_role parameter ignored
def require_role(min_role: str):
    async def _check(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not has_permission(user.role, f"investigation:view"):  # BUG: should use min_role
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user
    return _check
```

**Remediation:** Use a role-hierarchy comparison based on `min_role`. Applied as **FIX** below.

---

### SEC-008: Register Endpoint Allows Arbitrary Role Assignment (HIGH)

**File:** `backend/btagent_backend/api/v1/auth.py`, line 31, 90
**Category:** OWASP Web Top 10 - Broken Authentication

The `RegisterRequest` model accepts any string for `role` with a default of `"analyst"`. While the endpoint requires admin permission, the role value is not validated against the `UserRole` enum. An admin could accidentally (or maliciously via API) create a user with a non-existent role that might bypass RBAC checks.

```python
# VULNERABLE -- no validation on role value
class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "analyst"  # No enum validation
```

**Remediation:** Validate role against `UserRole` enum. Applied as **FIX** below.

---

### SEC-009: CORS Wildcard Methods and Headers (MEDIUM)

**File:** `backend/btagent_backend/main.py`, lines 58-59
**Category:** OWASP Web Top 10 - Security Misconfiguration

CORS is configured with `allow_methods=["*"]` and `allow_headers=["*"]`. While origins are restricted, the wildcard methods/headers are unnecessarily permissive for an API that only uses GET, POST, and standard auth headers.

```python
allow_methods=["*"],   # Should be ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
allow_headers=["*"],   # Should be ["Authorization", "Content-Type"]
```

**Remediation:** Restrict to the methods and headers actually used.

---

### SEC-010: Rate Limiter Middleware Not Mounted (MEDIUM)

**File:** `backend/btagent_backend/main.py`, lines 40-77
**Category:** OWASP Web Top 10 - Security Misconfiguration

The `RateLimiterMiddleware` class exists in `middleware/rate_limiter.py` and is fully implemented, but it is never mounted on the FastAPI application. The `TODO` comments at lines 71-72 confirm this was planned but not done. Without it, the API has no request rate limiting at all (the `security/rate_limiter.py` Redis-backed limiter is only a FastAPI dependency, not used on any endpoint).

```python
# TODO: Add request ID middleware
# TODO: Add error handler middleware
# (Rate limiter middleware is also not added)
```

**Remediation:** Mount the rate limiter middleware in `create_app()`.

---

### SEC-011: Rate Limiter Decodes JWT Without Verification (MEDIUM)

**File:** `backend/btagent_backend/middleware/rate_limiter.py`, lines 76-89
**Category:** OWASP Web Top 10 - Broken Authentication

The rate limiter middleware's `_extract_role` function decodes the JWT payload using base64 without verifying the signature. An attacker could send a forged JWT with `role: "admin"` to get the 200 req/min rate limit instead of the 30 req/min anonymous limit.

```python
# VULNERABLE -- JWT decoded without signature verification
token = auth.split(" ", 1)[1]
payload_b64 = token.split(".")[1]
payload_b64 += "=" * (-len(payload_b64) % 4)
payload = json.loads(base64.urlsafe_b64decode(payload_b64))
return payload.get("role", "anonymous")
```

**Remediation:** Either verify the JWT signature or always use the anonymous rate limit for the middleware layer (let the auth dependency handle role-based limits).

---

### SEC-012: Nginx Missing Content-Security-Policy Header (MEDIUM)

**File:** `infra/nginx/nginx.conf`, lines 43-47
**Category:** OWASP Web Top 10 - Security Misconfiguration

The nginx configuration includes `X-Frame-Options`, `X-Content-Type-Options`, and `X-XSS-Protection` but is missing a `Content-Security-Policy` header, which is the modern standard for XSS mitigation.

**Remediation:** Add `add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:;" always;`

---

### SEC-013: Redis and PostgreSQL Exposed on Host (MEDIUM)

**File:** `infra/docker-compose.yml`, lines 12, 27
**Category:** OWASP Web Top 10 - Security Misconfiguration

PostgreSQL (5432) and Redis (6379) ports are bound to `0.0.0.0` via the `ports` directive. In a cloud deployment, these would be accessible from outside the host. Neither has authentication configured (Redis has no password, PostgreSQL uses a weak development password).

**Remediation:** Bind to `127.0.0.1:5432:5432` and `127.0.0.1:6379:6379`, or remove host port mappings entirely and rely on Docker networking. Add Redis `requirepass`.

---

### SEC-014: Agent Outputs Lack Confidence Levels (MEDIUM)

**File:** `agents/btagent_agents/orchestrator/nodes.py`, lines 312-402
**Category:** OWASP LLM09 - Overreliance

The triage node produces severity assessments and IOC extractions but does not include a confidence score in the AI message output. The IOC dicts include `confidence: 0.5` as a hardcoded default, but the triage output message itself has no confidence rating, making it difficult for analysts to gauge reliability.

**Remediation:** Add confidence levels to triage output and vary the IOC confidence based on extraction context.

---

### SEC-015: Agent Outputs Stored Without Sanitization (MEDIUM)

**File:** `backend/btagent_backend/api/v1/investigations.py`, line 241
**Category:** OWASP LLM02 - Insecure Output Handling

The `/chat` endpoint currently returns agent messages directly. When the full agent pipeline is connected, LLM outputs will be stored in the database and sent to the frontend without sanitization. While the frontend should handle XSS prevention, defense-in-depth requires server-side output validation.

**Remediation:** Add output sanitization before DB storage and API response.

---

### SEC-016: Overly Permissive Version Pins (LOW)

**Files:** `backend/pyproject.toml`, `agents/pyproject.toml`, `shared/pyproject.toml`
**Category:** Dependency Security

All dependencies use `>=` pins (e.g., `fastapi>=0.115.0`). This means a `pip install` could pull in a future major version with breaking changes or newly discovered vulnerabilities. Security best practice is to pin to compatible ranges (e.g., `fastapi>=0.115.0,<1.0`).

**Remediation:** Use compatible release specifiers (`~=` or `>=X,<Y`).

---

### SEC-017: MinIO Default Credentials in Config Defaults (LOW)

**File:** `backend/btagent_backend/config.py`, lines 29-30
**Category:** OWASP Web Top 10 - Sensitive Data Exposure

The Settings class has `s3_access_key: str = "minioadmin"` and `s3_secret_key: str = "minioadmin"` as defaults. While these are intended for local dev, if the environment variables are unset in production, the application connects with known default credentials.

**Remediation:** Remove defaults or require explicit configuration for non-dev environments.

---

### SEC-018: JWT Error Message Leaks Internal Details (LOW)

**File:** `backend/btagent_backend/auth/middleware.py`, line 41
**Category:** Code Quality Security

The JWT decode error handler includes the raw exception message: `detail=f"Invalid token: {e}"`. This could reveal information about the token structure, expiry, or algorithm to an attacker.

```python
detail=f"Invalid token: {e}",  # Reveals internal error details
```

**Remediation:** Return a generic error message.

---

### SEC-019: db_echo Configuration Available (LOW)

**File:** `backend/btagent_backend/config.py`, line 23
**Category:** OWASP Web Top 10 - Security Misconfiguration

The `db_echo` setting, when enabled, logs all SQL queries to stdout/logs. While defaulting to `False`, if accidentally enabled in production, it could log sensitive query data.

**Remediation:** Force `db_echo=False` in production regardless of config.

---

### SEC-020: .gitignore Coverage (INFO)

**File:** `.gitignore`
**Category:** Secret Management

The `.gitignore` properly covers `.env`, `.env.local`, `.env.*.local`, `*.pem`, `*.key`, `*.crt`, and `.git-credentials`. The `!.env.example` exception is correct. No committed secrets were found in the codebase (no `github_pat_`, no API keys in source). **PASS.**

---

### SEC-021: External Data Wrapping (INFO)

**Files:** Multiple in `agents/`
**Category:** OWASP LLM01 - Prompt Injection

The codebase correctly implements `<external-data>` XML boundary wrapping for untrusted data in agent prompts:
- `_wrap_external_data()` in `nodes.py` (line 210-212)
- System prompts in `triage/system_prompt.md` and `query/system_prompt.md` explicitly instruct the LLM to treat `<external-data>` content as raw data only
- The triage node wraps alert text before including it in output

**PASS** -- prompt injection defenses are properly implemented.

---

## Applied Fixes (CRITICAL and HIGH)

The following fixes have been applied directly to the source code.

### FIX for SEC-001: JWT Secret Startup Validation

Added a validator to the `Settings` class that refuses to start with the default JWT secret in non-dev environments.

### FIX for SEC-002: Seed Script Password Generation

Replaced hardcoded trivial passwords with randomly generated passwords using `secrets.token_urlsafe`.

### FIX for SEC-003: Refresh Token JTI Claim (Partial)

Added a `jti` (JWT ID) claim to refresh tokens to enable future server-side revocation tracking.

### FIX for SEC-004: Health Endpoint Error Sanitization

Replaced raw exception message with a generic "unreachable" status string.

### FIX for SEC-005: LangGraph max_steps / recursion_limit

Added `recursion_limit` parameter to `graph.compile()` using the config's `max_steps` value.

### FIX for SEC-006: WebSocket RBAC for HITL/Chat

Added permission checks in the WebSocket read loop for CHAT and HITL_RESPONSE message types.

### FIX for SEC-007: require_role Dependency Fix

Fixed the `require_role` function to use the `min_role` parameter for actual role-hierarchy comparison.

### FIX for SEC-008: Role Validation on Register

Added `UserRole` enum validation to the `RegisterRequest` model.

---

## Recommendations for Future Sprints

1. **Implement Redis-backed token revocation** (SEC-003) -- Track refresh token JTIs in Redis with TTL matching token expiry. Invalidate old tokens on refresh.
2. **Mount rate limiter middleware** (SEC-010) -- Add `app.add_middleware(RateLimiterMiddleware)` in `create_app()`.
3. **Fix rate limiter JWT bypass** (SEC-011) -- Use anonymous rate limits in middleware, defer role-based limits to authenticated dependencies.
4. **Add Content-Security-Policy** (SEC-012) -- Update nginx.conf.
5. **Bind database ports to localhost** (SEC-013) -- Update docker-compose.yml.
6. **Add confidence levels to agent output** (SEC-014).
7. **Add output sanitization layer** (SEC-015).
8. **Pin dependency version ranges** (SEC-016).
9. **Add SAST/DAST scanning to CI** -- Consider Bandit, Semgrep, and OWASP ZAP.
10. **Add API request ID middleware** for forensic correlation.
