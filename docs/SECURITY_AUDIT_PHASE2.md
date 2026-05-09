# BTagent Security Audit — Phase 1 + Phase 2

**Date:** 2026-03-28
**Scope:** 367 files, ~67,800 lines (Phase 1 + Phase 2, all 11 sprints)
**Methodology:** OWASP LLM Top 10 (2025) + OWASP Web Top 10 + Agent-specific security

## Executive Summary

**Overall Posture: STRONG with 5 critical fixes required before production.**

The codebase demonstrates mature security across authentication, authorization, TLP data classification, agent safety (HITL, scope enforcement), and audit trails. No SQL injection, no hardcoded secrets, no eval/exec usage.

## Findings Summary

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 5 | Fixes below |
| HIGH | 4 | Documented |
| MEDIUM | 5 | Documented |
| LOW | 4 | Accepted risk |
| **Total** | **18** | |

## Critical Findings (Fix Before Staging)

### SEC-P2-001: CORS Wildcard Methods/Headers
**File:** `backend/btagent_backend/main.py:79-80`
**Issue:** `allow_methods=["*"]` and `allow_headers=["*"]` with `allow_credentials=True`
**Risk:** Browser-based CSRF attacks
**Fix:** Restrict to `["GET", "POST", "PUT", "DELETE", "OPTIONS"]` and `["Content-Type", "Authorization", "X-Request-ID"]`

### SEC-P2-002: S3 Default Credentials in Config
**File:** `backend/btagent_backend/config.py:40-41`
**Issue:** `s3_access_key = "minioadmin"` as default — accepted in dev but should fail in prod
**Fix:** Add model_validator that rejects minioadmin defaults in non-dev environments (same pattern as JWT SEC-001)

### SEC-P2-003: Knowledge Ingestion Missing Size Limits
**File:** `backend/btagent_backend/api/v1/knowledge.py:28-32`
**Issue:** Unbounded `content` field allows memory exhaustion
**Fix:** Add `Field(max_length=1_000_000)` to content field (1MB limit)

### SEC-P2-004: STIX Pattern Quote Escaping
**File:** `backend/btagent_backend/services/stix_service.py:64-86`
**Issue:** IOC values with single quotes are not escaped in STIX patterns
**Fix:** Escape `'` to `\\'` in pattern values before building STIX patterns

### SEC-P2-005: JWT Token Revocation Not Implemented
**File:** `backend/btagent_backend/auth/jwt.py:53-55`
**Issue:** `jti` claim exists but no server-side revocation list
**Risk:** Compromised refresh tokens cannot be invalidated
**Fix:** Implement Redis-backed jti revocation check on token refresh

## High Findings

### SEC-P2-006: Refresh Token Not Rotated on Exchange
**File:** `backend/btagent_backend/auth/jwt.py:67-74`
**Issue:** Old refresh token not revoked when new pair issued

### SEC-P2-007: WebSocket Token in Query Parameters
**File:** `backend/btagent_backend/ws/routes.py`
**Issue:** JWT passed as `?token=` query param — may appear in server logs

### SEC-P2-008: Enrichment Output Not Validated Before DB Storage
**File:** `backend/btagent_backend/api/v1/iocs.py:73-84`
**Issue:** CTI enrichment results stored directly without schema validation

### SEC-P2-009: Confidence Not Aggregated Across Agent Chain
**Issue:** Individual agents report confidence but no composite score propagated

## Positive Findings (No Action Required)

| Area | Status | Evidence |
|------|--------|----------|
| Prompt Injection Defense | EXCELLENT | `<external-data>` XML boundaries in all 4 plugins |
| TLP Enforcement | EXCELLENT | ClassificationHook blocks RED→external, embedding service TLP-aware |
| HITL Controls | EXCELLENT | Autonomy L0-L4, per-tool gating, LangGraph interrupt |
| Scope Enforcement | STRONG | IP/CIDR/domain allowlist with ScopeViolation exception |
| SQL Injection | ZERO RISK | All queries use SQLAlchemy ORM, parameterized |
| Hardcoded Secrets | NONE FOUND | .gitignore covers .env, seed uses random passwords |
| Audit Trail | CRYPTOGRAPHIC | SHA-256 chain with tamper detection |
| Playbook Safety | STRONG | No eval(), DAG cycle detection, safe condition parser |
| MCP Resilience | STRONG | Circuit breaker, exponential backoff, connection pooling |
| Docker Hardening | STRONG | Non-root, healthchecks, multi-stage builds |
| Helm Security | STRONG | PDB, NetworkPolicy, readOnlyRootFS, drop ALL caps |

## Recommendation

**PROCEED TO STAGING** after fixing SEC-P2-001 through SEC-P2-004 (1-2 day effort). SEC-P2-005 (token revocation) can be addressed in Phase 3 pre-production sprint.
