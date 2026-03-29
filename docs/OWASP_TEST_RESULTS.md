# OWASP Web Application Security Testing -- Top 10 (2021)

**Target:** BTagent API v0.1.0 at `http://localhost:8000`
**Date:** 2026-03-29
**Tester:** Automated OWASP assessment
**Methodology:** Live curl/httpx testing against running API + source code review

---

## Executive Summary

| Category | Tests | Pass | Fail | Critical | High | Medium | Low |
|----------|-------|------|------|----------|------|--------|-----|
| A01 Broken Access Control | 8 | 7 | 1 | 0 | 0 | 1 | 0 |
| A02 Cryptographic Failures | 6 | 4 | 2 | 0 | 1 | 0 | 1 |
| A03 Injection | 5 | 5 | 0 | 0 | 0 | 0 | 0 |
| A04 Insecure Design | 3 | 0 | 3 | 0 | 0 | 3 | 0 |
| A05 Security Misconfiguration | 7 | 3 | 4 | 0 | 1 | 2 | 1 |
| A06 Vulnerable Components | 2 | 1 | 1 | 0 | 0 | 1 | 0 |
| A07 Auth Failures | 5 | 2 | 3 | 0 | 1 | 2 | 0 |
| A08 Data Integrity | 3 | 2 | 1 | 0 | 0 | 1 | 0 |
| A09 Logging & Monitoring | 4 | 4 | 0 | 0 | 0 | 0 | 0 |
| A10 SSRF | 3 | 2 | 1 | 0 | 0 | 1 | 0 |
| **TOTAL** | **46** | **30** | **16** | **0** | **3** | **11** | **2** |

**Overall Risk Rating:** MEDIUM -- No critical findings. Three HIGH and eleven MEDIUM findings require remediation before production deployment.

---

## A01:2021 -- Broken Access Control

### A01-01: Register endpoint blocked for analyst -- PASS
- **Request:** `POST /api/v1/auth/register` with analyst Bearer token
- **Response:** `403 Forbidden` -- "Permission denied: user:create requires higher role than analyst"
- **Evidence:** RBAC correctly enforces `user:create` -> `admin` minimum role

### A01-02: Org-profile PUT blocked for analyst -- PASS
- **Request:** `PUT /api/v1/config/org-profile` with analyst Bearer token
- **Response:** `403 Forbidden` -- "Permission denied: config:org_profile requires higher role than analyst"
- **Evidence:** RBAC correctly enforces `config:org_profile` -> `admin` minimum role

### A01-03: IDOR -- Analyst can access admin's investigation -- FAIL (MEDIUM)
- **Request:** `GET /api/v1/investigations/{admin_inv_id}` with analyst Bearer token
- **Response:** `200 OK` -- Full investigation detail returned
- **Evidence:** Analyst user `testanalyst` successfully retrieved investigation `inv_01KMVQWK6KJ7BPVEDRZW4Q9A7Z` created by and assigned to admin user. Investigation list also shows all 168 investigations across all users.
- **Root Cause:** `investigations.py` L159-175 checks `investigation:view` permission but does not filter by `assigned_to` or implement any ownership/org-scoping model.
- **Remediation:**
  - **File:** `backend/btagent_backend/api/v1/investigations.py` L127-175
  - Add tenant/ownership filtering: either filter by `assigned_to == user.id` for analyst role, or implement team-based scoping. Consider adding an `org_id` field for multi-tenant deployments.
  - For list endpoint (L137): add `.where(InvestigationRow.assigned_to == user.id)` for non-admin roles.

### A01-04: Unauthenticated access blocked -- PASS
- **Request:** `GET /api/v1/investigations` with no Authorization header
- **Response:** `403 Forbidden` -- "Not authenticated"
- **Evidence:** FastAPI HTTPBearer dependency correctly rejects unauthenticated requests

### A01-05: Path traversal in investigation ID -- PASS
- **Request:** `GET /api/v1/investigations/..%2F..%2Fetc%2Fpasswd` with valid token
- **Response:** `404 Not Found` -- "Investigation not found"
- **Evidence:** SQLAlchemy `WHERE id = ?` parameterized query treats the path traversal string as a literal ID lookup, which correctly returns no match

### A01-06: Stop investigation restricted by role -- PASS
- **Request:** `POST /api/v1/investigations/{id}/stop` with analyst Bearer token
- **Response:** `403 Forbidden`
- **Evidence:** `investigation:stop` correctly requires `senior_analyst` or higher

### A01-07: JWT role escalation via tampered payload -- PASS
- **Request:** Modified JWT payload to change `role: analyst` to `role: admin`, reattached original signature
- **Response:** `401 Unauthorized` -- "Invalid or expired token"
- **Evidence:** JWT signature verification correctly detects payload tampering

### A01-08: IOC delete restricted to senior_analyst+ -- PASS
- **Request:** `DELETE /api/v1/iocs/{id}` with analyst Bearer token
- **Response:** `403 Forbidden`
- **Evidence:** `ioc:delete` correctly requires `senior_analyst` minimum role

---

## A02:2021 -- Cryptographic Failures

### A02-01: JWT uses HS256 algorithm -- PASS
- **Evidence:** JWT header decoded: `{"alg": "HS256", "typ": "JWT"}`
- The `none` algorithm is not used. HS256 is acceptable for single-backend deployments.
- **Note:** Consider RS256 (asymmetric) for microservice architectures where multiple services verify tokens.

### A02-02: JWT alg=none attack rejected -- PASS
- **Request:** Crafted token with `{"alg":"none"}` header and no signature
- **Response:** `401 Unauthorized` -- "Invalid or expired token"
- **Evidence:** `decode_token()` in `auth/jwt.py` L79 enforces `algorithms=[settings.jwt_algorithm]`, preventing algorithm confusion attacks

### A02-03: No password hashes in API responses -- PASS
- **Request:** `GET /api/v1/auth/me`
- **Response:** `{"id": "usr_...", "username": "admin", "role": "admin"}`
- **Evidence:** Only `id`, `username`, and `role` are returned. No `password_hash` or other sensitive fields.

### A02-04: No credential leaks in investigation list -- PASS
- **Request:** `GET /api/v1/investigations`
- **Evidence:** Response contains only investigation fields. No `database_url`, `jwt_secret`, or `password_hash` found.

### A02-05: WebSocket token in URL query parameter -- FAIL (LOW)
- **Evidence:** `ws/routes.py` L39-42 and `auth/middleware.py` L55-75 authenticate WebSocket connections via `?token=<jwt>` query parameter.
- **Risk:** JWT tokens in URL query strings may be logged in server access logs, proxy logs, browser history, and Referer headers.
- **Remediation:**
  - **File:** `backend/btagent_backend/auth/middleware.py` L55-75
  - Implement ticket-based WebSocket auth: client exchanges JWT for a short-lived (30s) single-use WS ticket via `POST /api/v1/auth/ws-ticket`, then connects with `?ticket=<ticket>`. The ticket is invalidated after first use.

### A02-06: No TLS configured in nginx -- FAIL (HIGH)
- **Evidence:** `infra/nginx/nginx.conf` L39 has `listen 80;` only. No `listen 443 ssl`, no `ssl_certificate`, no HSTS header.
- **Remediation:**
  - **File:** `infra/nginx/nginx.conf`
  - Add TLS termination with `listen 443 ssl; ssl_certificate /etc/nginx/ssl/cert.pem; ssl_certificate_key /etc/nginx/ssl/key.pem;`
  - Add HSTS: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`
  - Redirect HTTP to HTTPS: `return 301 https://$host$request_uri;`

---

## A03:2021 -- Injection

### A03-01: SQL injection in investigation title -- PASS
- **Request:** `POST /api/v1/investigations` with title `test'; DROP TABLE investigations;--`
- **Response:** `201 Created` -- Title stored as literal string
- **Evidence:** SQLAlchemy ORM uses parameterized queries. The malicious string is stored verbatim as data, not executed as SQL. Verified by retrieving the investigation and confirming the title is the literal injection string.

### A03-02: SQL injection in IOC search -- PASS
- **Request:** `GET /api/v1/iocs/search?value=' OR '1'='1`
- **Response:** `200 OK` with `items: [], total: 0`
- **Evidence:** `ioc_service.py` L226-229 uses SQLAlchemy `IOCRow.value.ilike(like_pattern)` which generates a parameterized `ILIKE` query. The injection payload is treated as a literal search string.

### A03-03: SQL injection in status filter -- PASS
- **Request:** `GET /api/v1/investigations?status=active'; DROP TABLE investigations;--`
- **Response:** `200 OK` with `items: [], total: 0`
- **Evidence:** `investigations.py` L141 uses `InvestigationRow.status == status_filter` which is parameterized by SQLAlchemy.

### A03-04: Command injection in webhook payload -- PASS
- **Request:** `POST /api/v1/webhooks/splunk` with `search_name: "; cat /etc/passwd"` and `result: {"cmd": "$(whoami)"}`
- **Response:** `202 Accepted`
- **Evidence:** Webhook payloads are stored as JSON data in the `config` JSONB column. No shell execution or `os.system()` calls exist in the webhook processing path.

### A03-05: STIX import pattern injection -- PASS
- **Request:** `POST /api/v1/iocs/import` with malicious STIX pattern `[file:name = 'test' OR 1=1]` and name `'; DROP TABLE iocs;--`
- **Response:** `201 Created` with `imported: 0` (pattern parsing rejected the malformed pattern)
- **Evidence:** STIX patterns are parsed by `stix_service.py`, not executed as queries. SQLAlchemy parameterized queries protect against any injection in stored IOC names.

---

## A04:2021 -- Insecure Design

### A04-01: Rate limiting not enforced -- FAIL (MEDIUM)
- **Request:** 35 rapid `GET /api/v1/investigations` requests with analyst token
- **Response:** All 35 returned `200 OK`, no `429 Too Many Requests`
- **Evidence:** The `RateLimiterMiddleware` in `middleware/rate_limiter.py` exists but is not registered as middleware in `main.py` (only `RequestIDMiddleware` and `CORSMiddleware` are added). The rate limiter module defines limits (analyst: 60/min) but the middleware is never `app.add_middleware(RateLimiterMiddleware)`.
- **Remediation:**
  - **File:** `backend/btagent_backend/main.py` L73 (after RequestIDMiddleware)
  - Add: `app.add_middleware(RateLimiterMiddleware)` (import from `btagent_backend.middleware.rate_limiter`)
  - Note: nginx.conf has rate limiting configured, but only applies when nginx is the reverse proxy (not during direct API access)

### A04-02: No account lockout after failed logins -- FAIL (MEDIUM)
- **Request:** 15 sequential failed login attempts with wrong password for `admin` user
- **Response:** All returned `401 Unauthorized`, no lockout or rate limiting
- **Evidence:** `auth.py` L52-62 has no failed-attempt counter. An attacker can perform unlimited brute-force attempts against the login endpoint.
- **Remediation:**
  - **File:** `backend/btagent_backend/api/v1/auth.py` L52-62
  - Add Redis-backed login attempt counter per username. After 5 failures in 15 minutes, return `429 Too Many Requests` with exponential backoff. Log failed attempts for SIEM alerting.

### A04-03: Webhook secret brute-force not rate-limited -- FAIL (MEDIUM)
- **Request:** 20 sequential `POST /api/v1/webhooks/splunk` with different X-Webhook-Secret values
- **Response:** All returned `401 Unauthorized`, no rate limiting or lockout
- **Evidence:** `webhooks.py` L114-125 validates the secret with `hmac.compare_digest` (good timing-safe comparison) but has no rate limiting on failed auth attempts.
- **Remediation:**
  - **File:** `backend/btagent_backend/api/v1/webhooks.py`
  - Apply per-IP rate limiting to webhook endpoints (either via middleware or nginx). Track failed auth attempts per source IP.

---

## A05:2021 -- Security Misconfiguration

### A05-01: CORS properly configured -- PASS
- **Request:** `OPTIONS /api/v1/auth/me` with `Origin: http://evil.com`
- **Response:** `400 Bad Request` -- No `access-control-allow-origin` header set for evil.com
- **Request:** `OPTIONS /api/v1/auth/me` with `Origin: http://localhost:5173`
- **Response:** `200 OK` -- `access-control-allow-origin: http://localhost:5173`
- **Evidence:** CORS is locked to explicit allowed origins in `config.py` L83-88. No wildcard `*` origin.

### A05-02: Error responses do not leak stack traces -- PASS
- **Request:** `GET /api/v1/investigations/nonexistent`
- **Response:** `{"detail": "Investigation not found"}` -- Clean error, no traceback
- **Evidence:** FastAPI HTTPExceptions return only the `detail` string. No Python traceback information.

### A05-03: API docs accessible in dev mode -- FAIL (MEDIUM)
- **Request:** `GET /api/docs`
- **Response:** `200 OK` -- Full Swagger UI rendered
- **Request:** `GET /openapi.json`
- **Response:** `200 OK` -- Complete OpenAPI specification (69KB)
- **Evidence:** `main.py` L68-69 conditionally disables docs in prod (`docs_url=None if env == "prod"`), but the current instance runs in dev mode with full API documentation publicly accessible.
- **Root Cause:** The env is set to `dev` (default). In production, docs are disabled.
- **Remediation:**
  - **File:** `backend/btagent_backend/main.py` L68-69
  - Ensure `BTAGENT_ENV=prod` is set in all production deployments. Consider requiring authentication for docs even in non-prod environments.

### A05-04: Prometheus metrics unauthenticated -- FAIL (MEDIUM)
- **Request:** `GET /metrics`
- **Response:** `200 OK` -- Full Prometheus metrics including request counts, DB pool stats, etc.
- **Evidence:** `main.py` L94 registers `/metrics` endpoint with no authentication.
- **Remediation:**
  - **File:** `backend/btagent_backend/main.py` L94
  - Either require authentication for the metrics endpoint, or restrict access via network policy (only allow Prometheus scraper IP). In nginx.conf, add `location /metrics { deny all; }` for external access.

### A05-05: Default credentials accepted -- FAIL (HIGH)
- **Request:** `POST /api/v1/auth/login` with `{"username": "admin", "password": "admin"}`
- **Response:** `200 OK` -- Valid JWT token pair returned
- **Evidence:** The admin user is seeded with password `admin`. While `config.py` L56 warns about insecure JWT secrets in non-dev, there is no check for weak user passwords.
- **Remediation:**
  - **File:** `backend/btagent_backend/api/v1/auth.py`
  - Add password complexity validation in `RegisterRequest` (minimum 8 chars, require mixed case/numbers). Force password change on first login for seeded accounts.

### A05-06: Missing security headers on direct API access -- FAIL (LOW)
- **Evidence:** Response headers from direct API access (bypassing nginx):
  - Missing: `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Content-Security-Policy`, `Strict-Transport-Security`
  - Present: `x-request-id` (good)
- Note: nginx.conf L44-47 adds these headers, but only when nginx is the reverse proxy.
- **Remediation:**
  - **File:** `backend/btagent_backend/main.py`
  - Add a SecurityHeadersMiddleware that sets these headers at the application level, so they apply even without nginx.

### A05-07: JWT secret uses known insecure default -- PASS (in dev mode)
- **Evidence:** `config.py` L48 default is `"CHANGE-ME-IN-PRODUCTION"`. The `_validate_jwt_secret` validator at L54-70 correctly refuses to start with this value in non-dev environments and logs a warning in dev/test.
- This is acceptable for development but would be a CRITICAL finding in production.

---

## A06:2021 -- Vulnerable & Outdated Components

### A06-01: Python dependencies use flexible version ranges -- FAIL (MEDIUM)
- **Evidence:** `backend/pyproject.toml` specifies minimum versions with `>=` constraints (e.g., `fastapi>=0.115.0`, `python-jose[cryptography]>=3.3.0`). While the pinned minimums are recent, `>=` allows installation of any newer version without upper bound.
- **Key dependency:** `python-jose>=3.3.0` -- python-jose has had reported CVEs. The project should consider migrating to `PyJWT` or `joserfc` which are more actively maintained.
- **Remediation:**
  - Pin exact versions or use upper-bound constraints (e.g., `fastapi>=0.115.0,<1.0.0`)
  - Add `uv.lock` or `pip-compile` lockfile to CI
  - Run `pip-audit` or `safety check` in CI pipeline
  - Consider replacing `python-jose` with `PyJWT` (more actively maintained, fewer CVEs)

### A06-02: Frontend dependencies are reasonably current -- PASS
- **Evidence:** `frontend/package.json` uses recent versions of React 18, Vite 6, and Tailwind 3.4. No known critical CVEs in the listed versions as of the test date.

---

## A07:2021 -- Identification & Authentication Failures

### A07-01: No password complexity requirements -- FAIL (MEDIUM)
- **Request:** `POST /api/v1/auth/register` with `password: "a"` (single character)
- **Response:** `201 Created` -- User successfully registered with password "a"
- **Evidence:** `auth.py` `RegisterRequest` model has no password validation beyond being a non-empty string. `hash_password()` in `jwt.py` L29 accepts any string.
- **Remediation:**
  - **File:** `backend/btagent_backend/api/v1/auth.py` L28-44
  - Add `@field_validator("password")` requiring minimum 8 characters, at least one uppercase, one lowercase, one digit, and one special character.

### A07-02: Refresh token reuse allowed -- FAIL (HIGH)
- **Request:** Used the same refresh token twice in `POST /api/v1/auth/refresh`
- **Response:** Both returned `200 OK` with new token pairs
- **Evidence:** `auth.py` L67-77 decodes and validates the refresh token but does not check if the `jti` (JWT ID) has been used before. The code comment at `jwt.py` L53-55 acknowledges this: "A Redis-backed revocation list should check this jti on refresh and invalidate the old token. Full implementation tracked for a future sprint."
- **Risk:** If an attacker captures a refresh token, they can use it indefinitely (until expiry) even after the legitimate user has refreshed. This enables persistent unauthorized access.
- **Remediation:**
  - **File:** `backend/btagent_backend/api/v1/auth.py` L67-77
  - Implement Redis-backed `jti` tracking: on refresh, check if the `jti` has been used. If yes, revoke all tokens for that user (potential token theft). If no, mark the `jti` as used and issue new tokens.

### A07-03: No token invalidation on logout -- FAIL (MEDIUM)
- **Evidence:** There is no `/api/v1/auth/logout` endpoint in the codebase. Once issued, JWTs remain valid until their expiry time (15 minutes for access, 7 days for refresh). There is no server-side token revocation mechanism.
- **Remediation:**
  - **File:** `backend/btagent_backend/api/v1/auth.py`
  - Add `POST /api/v1/auth/logout` endpoint that adds the token's `jti` to a Redis revocation set.
  - **File:** `backend/btagent_backend/auth/middleware.py` L32-52
  - In `get_current_user`, check the token's `jti` against the revocation set before accepting it.

### A07-04: Access token type validation works -- PASS
- **Request:** Used refresh token as Bearer token for `POST /api/v1/auth/refresh` with access token
- **Response:** `401 Unauthorized` -- "Expected refresh token"
- **Evidence:** `auth/middleware.py` L46-50 correctly checks `payload.type != "access"` and `auth.py` L74 checks `payload.type != "refresh"`.

### A07-05: Invalid role in registration rejected -- PASS
- **Request:** `POST /api/v1/auth/register` with `role: "superadmin"`
- **Response:** `422 Unprocessable Entity` -- "Invalid role 'superadmin'. Must be one of: admin, analyst, incident_commander, senior_analyst"
- **Evidence:** `RegisterRequest.validate_role` at `auth.py` L34-44 validates against the `UserRole` enum.

---

## A08:2021 -- Software & Data Integrity Failures

### A08-01: Audit trail uses SHA-256 chaining (tamper-evident) -- PASS
- **Evidence:** `services/audit_trail.py` implements a SHA-256 chained log. Each entry's hash is computed over all fields plus the previous entry's hash (L24-50), creating a blockchain-like tamper-evident chain. The `verify_chain()` method (L136-198) can detect any modification to historical entries.
- Audit entries are append-only (`record()` at L63-134). No update or delete methods exist.

### A08-02: Docker image runs as non-root -- PASS
- **Evidence:** `infra/docker/Dockerfile.backend` L30 creates a non-root user: `RUN useradd --uid 1000 btagent`. L41: `USER btagent`. The container runs as unprivileged user 1000.

### A08-03: CI pipeline does not verify dependency integrity -- FAIL (MEDIUM)
- **Evidence:** `.github/workflows/ci.yml` L93-95 installs dependencies with `uv pip install --system -e` but does not:
  - Run `pip-audit` or `safety check` for known CVE scanning
  - Verify package checksums against a lockfile
  - Use `--require-hashes` for integrity verification
- **Remediation:**
  - **File:** `.github/workflows/ci.yml`
  - Add a dependency audit step: `uv pip install pip-audit && pip-audit` after dependency installation
  - Generate and commit a `uv.lock` file for reproducible builds
  - Consider adding SLSA provenance verification for container images

---

## A09:2021 -- Security Logging & Monitoring Failures

### A09-01: Structured JSON logging with correlation IDs -- PASS
- **Evidence:** `observability/logging.py` implements `JSONFormatter` (L59-82) that emits structured JSON logs with `timestamp`, `level`, `logger`, `message`, `request_id`, `trace_id`, and `investigation_id` fields.

### A09-02: Sensitive data redaction in logs -- PASS
- **Evidence:** `logging.py` L24-41 defines a `_SENSITIVE_PATTERN` regex matching `password|token|secret|api_key|apikey|authorization|credential|private_key` and a `SensitiveFilter` (L86-95) that recursively redacts matching values in log arguments before they reach the formatter.

### A09-03: Audit logging for admin and security actions -- PASS
- **Evidence:** `services/audit_trail.py` provides a structured `AuditTrail.record()` method that logs `actor`, `category`, `action`, `resource`, `outcome`, and `details`. Categories include authentication, configuration, and investigation lifecycle events.

### A09-04: Failed authentication logged -- PASS
- **Evidence:** Login failures raise `HTTPException(401)` which is logged by the web framework. The `observability/logging.py` structured logger captures these with request correlation IDs. The webhook `_verify_secret` at `webhooks.py` L121 explicitly logs: `logger.warning("Webhook secret mismatch from source=%s", source)`.

---

## A10:2021 -- Server-Side Request Forgery (SSRF)

### A10-01: Webhook stores URLs without fetching -- PASS
- **Request:** `POST /api/v1/webhooks/splunk` with `results_link: "http://169.254.169.254/latest/meta-data/"`
- **Response:** `202 Accepted`
- **Evidence:** Webhook endpoint stores the `results_link` URL in the investigation's `config` JSONB column as data. The URL is never fetched server-side during webhook processing. The webhook pipeline only creates an `InvestigationRow` -- it does not make outbound HTTP requests.

### A10-02: IOC enrichment does not currently fetch URLs -- PASS
- **Evidence:** `services/ioc_service.py` L307-340 `trigger_enrichment()` generates a task ID and returns status metadata. The current implementation is a stub that does not make outbound HTTP requests. When enrichment is fully implemented (via MCP connectors), each connector should validate destination URLs against an allowlist and block RFC 1918/link-local addresses.

### A10-03: Knowledge ingest accepts content, not URLs -- FAIL (MEDIUM)
- **Evidence:** `api/v1/knowledge.py` `IngestRequest` accepts `content` as a raw string (L31: `content: str = Field(max_length=1_000_000)`). Currently the ingest endpoint does not fetch external URLs. However, the `metadata` field (L33) is an unvalidated `dict[str, Any]` that could contain URLs. If future features add URL-based ingestion, SSRF protections must be implemented.
- **Remediation:**
  - **File:** `backend/btagent_backend/api/v1/knowledge.py` L28-33
  - If URL-based ingestion is added, implement an SSRF-safe HTTP client that: (1) resolves DNS and blocks RFC 1918/link-local/loopback addresses, (2) follows an allowlist of permitted domains, (3) sets a short timeout. Use the `ssrf_proxy` pattern or equivalent.

---

## Findings Summary (Sorted by Severity)

| # | ID | Severity | Finding | Category |
|---|-----|----------|---------|----------|
| 1 | A02-06 | HIGH | No TLS configured in nginx | A02 |
| 2 | A05-05 | HIGH | Default credentials accepted (admin/admin) | A05 |
| 3 | A07-02 | HIGH | Refresh token reuse allowed (no jti tracking) | A07 |
| 4 | A01-03 | MEDIUM | IDOR: Any authenticated user can view all investigations | A01 |
| 5 | A04-01 | MEDIUM | Rate limiting middleware not registered | A04 |
| 6 | A04-02 | MEDIUM | No account lockout after failed logins | A04 |
| 7 | A04-03 | MEDIUM | Webhook auth not rate-limited | A04 |
| 8 | A05-03 | MEDIUM | API docs accessible (dev mode) | A05 |
| 9 | A05-04 | MEDIUM | Prometheus metrics unauthenticated | A05 |
| 10 | A06-01 | MEDIUM | No dependency pinning or audit in CI | A06 |
| 11 | A07-01 | MEDIUM | No password complexity requirements | A07 |
| 12 | A07-03 | MEDIUM | No logout / token revocation | A07 |
| 13 | A08-03 | MEDIUM | CI pipeline does not verify dependency integrity | A08 |
| 14 | A10-03 | MEDIUM | Knowledge ingest metadata not validated for SSRF | A10 |
| 15 | A02-05 | LOW | WebSocket token in URL query parameter | A02 |
| 16 | A05-06 | LOW | Missing security headers on direct API access | A05 |

---

## Remediation Priority

### Priority 1 (Before Production)
1. Configure TLS in nginx and add HSTS header
2. Implement refresh token `jti` revocation tracking (Redis-backed)
3. Add password complexity validation to RegisterRequest
4. Set `BTAGENT_ENV=prod` and rotate all default credentials
5. Register `RateLimiterMiddleware` in `main.py`

### Priority 2 (Sprint Backlog)
6. Implement login attempt lockout (5 failures -> exponential backoff)
7. Add investigation ownership scoping (filter by assigned_to for non-admins)
8. Add `/api/v1/auth/logout` with token revocation
9. Restrict `/metrics` endpoint access
10. Add `pip-audit` and lockfile verification to CI

### Priority 3 (Hardening)
11. Implement ticket-based WebSocket auth
12. Add security headers middleware at application level
13. Pin Python dependency versions with lockfile
14. Add SSRF protection to any future URL-fetching features
15. Replace `python-jose` with `PyJWT`
