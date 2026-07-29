# Controls Mapping

**Sovereign Pack (#502).** A cross-reference from the security controls BTagent
**already implements** to recognised control families, with a citation to the
file and function that implements each one.

---

## How to read this document

**This is a code-to-framework cross-reference, not an assessment.**

* Every row cites a real file and symbol. Open it — the citation is the claim.
* Framework identifiers (NIST SP 800-53 Rev. 5 controls, ISO/IEC 42001:2023
  Annex A objectives) are **indicative cross-references chosen by the
  maintainers**. They have not been reviewed by an assessor, and they are not
  the output of any assessment process. Verify against the authoritative
  catalogue for your own programme before relying on them.
* A row means "this platform mechanism is relevant to that control family". It
  does **not** mean the control is satisfied. Most 800-53 controls are largely
  organisational — policy, training, personnel, physical security, incident
  response procedures — and a software platform can only ever contribute a
  technical portion.
* ISO/IEC 42001 references are given at the Annex A **objective** level (A.6.2,
  A.9.2, …) rather than at individual control granularity, deliberately: coarse
  and correct beats precise and wrong.
* Where a mechanism has a meaningful limit, the limit is stated. Rows without a
  stated limit are not therefore limitless — they are rows where the limit was
  not material enough to list.

**Not claimed anywhere in this repository:** any accreditation, authorisation
to operate, certification, or third-party attestation. None is held and none is
being pursued.

---

## 1. Audit — hash-chained ledger

**Implementation:** [`backend/btagent_backend/services/audit_trail.py`](../../backend/btagent_backend/services/audit_trail.py)

| Aspect | Detail |
|---|---|
| Append | `AuditTrail.record()` — writes an entry with a monotonic `seq`, an `org_id` (keyword-only, no default at the call site), and a SHA-256 chain hash |
| Chaining | `_compute_hash()` — hashes a JSON-encoded ordered field list *including* `prev_hash`. JSON encoding rather than a `|`-join is deliberate: a plain delimiter is forgeable across free-text fields (`actor="a\|b"` vs `actor="a", category="b"` would hash identically) |
| Genesis | `_GENESIS_HASH` — 64 zeros for the first entry |
| Verification | `AuditTrail.verify_chain(org_id)` → `(bool, list[str])` — recomputes every hash and reports each break; exposed at `GET /api/v1/audit/verify` |
| Export | `GET /api/v1/audit/export`; lineage graph at `GET /api/v1/audit/lineage` |
| Retention | `Settings.audit_retention_years` (default 7), applied by `backend/btagent_backend/services/data_retention.py` |

**Cross-reference:** NIST AU-2, AU-3, AU-9, AU-10, AU-11, AU-12 · ISO/IEC 42001 A.6.2 (AI system life cycle — event logging)

**Limits.** The chain detects tampering; it does not prevent it. An actor with
write access to the `audit_logs` table can rewrite the chain end to end and it
will verify cleanly. Making the ledger genuinely append-only (database-level
grants, WORM storage, external anchoring) is a deployment responsibility, not
something this code does.

---

## 2. Access control — RBAC

**Implementation:** [`backend/btagent_backend/auth/rbac.py`](../../backend/btagent_backend/auth/rbac.py),
[`backend/btagent_backend/auth/middleware.py`](../../backend/btagent_backend/auth/middleware.py)

| Aspect | Detail |
|---|---|
| Roles | `ROLE_HIERARCHY` — `analyst` < `senior_analyst` < `incident_commander` < `admin`, higher inheriting lower |
| Permissions | `PERMISSIONS` — a flat map of `resource:action` → minimum role, covering investigations, HITL, containment, config, users, SSO linking, webhooks, MITRE, IOCs, knowledge, playbooks, workflows and more |
| Enforcement | `has_permission()`; routes call `CurrentUser.require_permission("…")` |
| Notable gradations | `containment:approve` / `containment:execute` require `incident_commander`; `hitl:approve` requires `senior_analyst` — the same level that approves the gates it would bypass; `mitre:seed`, `config:edit`, `user:*` are admin-only |

**Cross-reference:** NIST AC-2, AC-3, AC-6 · ISO/IEC 42001 A.9.2 (responsible use of AI systems)

**Limits.** Role-based, not attribute- or relationship-based. Permissions are
compiled into the codebase, not runtime-configurable per tenant.

---

## 3. Multi-tenancy — organisation scoping

**Implementation:** [`backend/btagent_backend/auth/scoping.py`](../../backend/btagent_backend/auth/scoping.py)

| Aspect | Detail |
|---|---|
| Row scoping | `assert_can_access_investigation()` / the sibling IOC and evidence helpers, called after fetching a row and before returning or mutating it |
| Failure mode | Out-of-scope access raises **404, not 403** — a 403 confirms the identifier exists, which is enough to enumerate case IDs across tenants |
| Org-wide roles | `_ORG_WIDE_ROLES` — `admin`, `incident_commander`, `senior_analyst` see everything **within their own org**, never across orgs |
| Storage | `org_id` columns with FK constraints across investigations, IOCs, evidence, knowledge documents and chunks, agent memory, playbooks, audit logs |
| Regression cover | `backend/tests/test_org_scoping.py`, `test_knowledge_org_scoping.py`, `test_audit_org_scoping.py`, `test_playbook_org_scoping.py`, `test_mitre_scoping.py`, `test_route_idor.py` |

**Cross-reference:** NIST AC-3, AC-4, SC-4 · ISO/IEC 42001 A.7 (data for AI systems)

**Limits.** Scoping is enforced in application code, not by database row-level
security. A query written without the scoping clause bypasses it; the
regression suite exists precisely because that has happened before.

---

## 4. Information-flow control — TLP egress enforcement (fail-closed)

**Implementation (baseline):** [`shared/btagent_shared/security/tlp.py`](../../shared/btagent_shared/security/tlp.py)
**Implementation (org policy):** [`backend/btagent_backend/services/tlp_egress_guard.py`](../../backend/btagent_backend/services/tlp_egress_guard.py)

| Aspect | Detail |
|---|---|
| Gate | `assert_tlp_allows_egress(payload, egress_kind, classification_ctx, org_id=…)` |
| Channels | `stix_export`, `knowledge_ingest`, `mcp_return`, `event_emit`, `report_export`. An unrecognised `egress_kind` raises `ValueError` — call sites must opt into a *known* channel, so a typo cannot create a silent unguarded path |
| Rule | TLP:RED is blocked on every channel; AMBER_STRICT is allowed with a logged warning |
| Fail-closed | An absent classification resolves to GREEN (the documented default); a classification that **was supplied** but is unrecognised or empty resolves to **RED** and blocks. A typo can never buy a laxer decision |
| Deep scan | The payload is walked recursively for embedded `tlp` / `tlp_level` fields, with a depth limit that also fails closed |
| Org overlay | `assert_org_policy_allows_egress()` — runs *after* the baseline and acts **only** on a policy decision of `allowed=False`. `ALLOW` and `DOWNGRADE_THEN_ALLOW` policies are deliberately inert at runtime, because honouring them would *widen* a default-deny gate |
| Observability | Violations emit a `tlp.violation_attempt` event carrying the matched policy id (`shared/btagent_shared/security/tlp_policy.py`), surfaced over WebSocket via `backend/btagent_backend/services/tlp_alert_sink.py` |
| Model routing | `TLPAwareLLMRouter.TLP_ROUTING` (`agents/btagent_agents/llm/router.py`) — TLP:RED routes to a local Ollama model **only**; AMBER_STRICT to Ollama or Bedrock |
| Regression cover | `backend/tests/test_tlp_egress.py`, `test_tlp_org_policy_enforcement.py`, `test_ws_tlp_egress.py`, `test_tlp_alert_sink.py` |

**Cross-reference:** NIST AC-4, AC-16, SC-7 · ISO/IEC 42001 A.7 (data), A.9.2 (responsible use)

**Limits.** "Egress" here means *out of the investigation context* over one of
the five enumerated channels. It is a classification control, not a network
control: it cannot stop a socket that never calls the gate. Network confinement
is separate — see [`docs/deployment/air-gap.md`](../deployment/air-gap.md).

---

## 5. Human-in-the-loop gates

**Implementation:** [`engine/btagent_engine/middleware/hitl.py`](../../engine/btagent_engine/middleware/hitl.py),
[`agents/btagent_agents/hooks/hitl_hook.py`](../../agents/btagent_agents/hooks/hitl_hook.py),
[`agents/btagent_agents/playbook/steps/hitl_gate.py`](../../agents/btagent_agents/playbook/steps/hitl_gate.py)

| Aspect | Detail |
|---|---|
| Engine gate | `HITLMiddleware` — on `before_run`, an integration-category node whose autonomy policy requires approval raises `HITLPause`; the orchestrator turns that into a paused run with a persisted checkpoint |
| Explicit gate | `HITLGateMiddleware` keyed on the `HITLGateNode` id that the `hitl_gate` playbook step compiles to |
| Agent-side gate | `requires_approval()` + `HITLCallback.on_tool_start` — the LangChain callback path, kept in lockstep with the engine map by hand (the engine tier has zero dependency on `btagent_agents`) |
| Always-gated | Containment actions (`cs_isolate_host`, `mde_isolate_machine`, `s1_mitigate_threat`, `cortex_isolate_endpoint`) and the detection-repo PR composer; declared per capability in `ConnectorManifest` (`agents/btagent_agents/mcp/manifests.py`) and enforced at dispatch by `ConnectorPolicyMiddleware` (`engine/btagent_engine/middleware/connector_policy.py`) |
| Autonomy levels | `AutonomyLevel` L1–L4 (`shared/btagent_shared/types/config.py`); raising an investigation to L3/L4 at create time requires `hitl:approve`, i.e. the same permission that approves the gates being relaxed |
| Approval authority | `hitl:approve` / `hitl:reject` → `senior_analyst`; containment approve/execute → `incident_commander` |

**Cross-reference:** NIST AC-3, CM-5, IR-4 · ISO/IEC 42001 A.9.2 (responsible use — human oversight), A.6.2 (life cycle — operation)

**Limits.** The gate binds the orchestrated agent paths and the manifest-declared
capabilities. It is not a mandatory access control on the underlying connector
API: an operator with credentials can always act directly on the target system.

---

## 6. Sandbox-only adversary emulation (#118)

**Implementation:** [`shared/btagent_shared/security/sandbox.py`](../../shared/btagent_shared/security/sandbox.py),
[`backend/btagent_backend/services/detection_emulation_service.py`](../../backend/btagent_backend/services/detection_emulation_service.py),
[`agents/btagent_agents/validation/orchestrator.py`](../../agents/btagent_agents/validation/orchestrator.py)

| Aspect | Detail |
|---|---|
| Policy | `APPROVED_SANDBOX_ENVS` — an **allowlist** (`TargetEnv.SANDBOX` only), so a new environment name is denied by default until an operator adds it |
| Decision | `evaluate_sandbox_target()` → `SandboxDecision` (never raises for a business denial, so the caller can audit before responding) |
| Hard stop | `require_sandbox()` raises `SandboxViolationError` |
| Enforcement point 1 | `run_emulation_validation()` — denial is written to the hash-chained ledger by `_record_denial()` **before** any emulator method is reachable |
| Enforcement point 2 | `ValidationOrchestrator` calls `require_sandbox()` at its own entry — defence in depth, so no in-process caller can reach an emulator dispatch path unchecked |
| Fail-closed | Unknown, blank or unparseable `target_env` is denied, never waved through |
| TLP posture | Emulation telemetry capabilities declare `tlp_egress=TLP.RED` in `agents/btagent_agents/mcp/manifests.py` |
| Regression cover | `backend/tests/test_detection_emulation_sandbox.py`, `backend/tests/test_validation_emulation_api.py` |

**Cross-reference:** NIST CA-8, CM-7, SI-4 · ISO/IEC 42001 A.6.2 (verification and validation)

**Limits.** The guard constrains what *this platform* will dispatch. It does not
verify that the environment labelled `sandbox` is genuinely isolated — that is
an infrastructure assertion the operator makes.

---

## 7. Secret-reference indirection

**Implementation:** [`shared/btagent_shared/utils/secrets.py`](../../shared/btagent_shared/utils/secrets.py)

| Aspect | Detail |
|---|---|
| Reference forms | `${secret:vault:path[#field]}`, `${secret:aws:name[#field]}`, `${secret:keyring:key}`, `${env:VAR}` |
| Resolution | `resolve_secret()` / `resolve_secret_cached()`; `is_secret_reference()` identifies a value that is exactly one reference token |
| Storage | Connector configuration stores the **reference**, not the material. Per-org credential *references* bind through the credential-reference API (`backend/btagent_backend/services/connector_credential_service.py`); raw material stays in Vault / AWS Secrets Manager / the environment |
| Prod fail-loud | With no provider client wired and no environment fallback, resolution in prod raises `UnresolvedSecretError` rather than emitting a `<unresolved:…>` placeholder downstream. Non-prod keeps the placeholder plus a warning |
| Secret scanning | CI job `secret-scan` (gitleaks, `.gitleaks.toml`) fails the pipeline on committed secret-shaped strings |
| At rest | MFA TOTP secrets are Fernet-encrypted (`backend/btagent_backend/auth/mfa.py`, `encrypt_secret()` / `decrypt_secret()`) |

**Cross-reference:** NIST IA-5, IA-5(7), SC-12, SC-28 · ISO/IEC 42001 A.4 (resources for AI systems)

**Limits.** The Vault and AWS branches currently resolve through an environment
fallback; a real Vault/Secrets Manager client is not wired in this repository.
In prod a missing value fails loudly rather than silently, but the indirection
is only as strong as the store the operator actually points it at.

---

## 8. Identification and authentication

**Implementation:** [`backend/btagent_backend/auth/`](../../backend/btagent_backend/auth/)

| Mechanism | Where |
|---|---|
| JWT access/refresh pairs, token families | `auth/jwt.py` — `create_token_pair()` |
| Password policy (min 12 chars, complexity) | `auth/jwt.py` — `MIN_PASSWORD_LENGTH`, validator; `backend/tests/test_password_policy.py` |
| TOTP MFA + recovery codes | `auth/mfa.py` — `verify_totp()`, `generate_recovery_codes()` |
| Revocation (per-token, per-family, per-user epoch) | `auth/revocation.py` — `revoke()`, `is_revoked()`, `revoke_family()` |
| OIDC SSO | `auth/oidc.py` — the callback **409s rather than auto-linking** an IdP identity to an existing password account (takeover defence); explicit linking is admin-gated behind `sso:link` |
| SAML 2.0 SSO | `auth/saml.py` (optional `saml` extra) |
| Admin bootstrap | `auth/bootstrap.py` — outside test mode the admin password must come from `BTAGENT_SEED_ADMIN_PASSWORD`; the seed refuses to invent an unrecoverable random one |

**Cross-reference:** NIST IA-2, IA-2(1), IA-5, AC-12 · ISO/IEC 42001 A.9.2

---

## 9. Boundary protection and availability

| Mechanism | Where |
|---|---|
| Zero-egress verification (default posture) | `backend/tests/test_zero_egress.py`, `backend/tests/egress_guard.py` |
| Network policy, internet egress removable | `infra/helm/btagent/templates/networkpolicy.yaml` + `networkPolicy.allowInternetEgress` |
| Per-role rate limiting | `backend/btagent_backend/middleware/rate_limiter.py` — `RateLimiterMiddleware` |
| Security response headers (CSP etc.) | `backend/btagent_backend/middleware/security_headers.py` |
| CORS allowlist | `backend/btagent_backend/main.py`; `backend/tests/test_cors_config.py` |
| MCP transport hardening — TLS on by default, 10 MiB response cap | `agents/btagent_agents/mcp/transports.py` — `enforce_cap()` |
| Request correlation IDs | `backend/btagent_backend/middleware/request_id.py` |

**Cross-reference:** NIST SC-5, SC-7, SC-8, SI-4, AU-3 · ISO/IEC 42001 A.6.2

**Limits.** The zero-egress test observes one Python process and only the code
paths it walks. It is corroborating evidence about the application, never a
substitute for network-layer enforcement. Its full stated scope — and its
explicit non-claims — are in
[`docs/deployment/air-gap.md`](../deployment/air-gap.md) §1.

---

## 10. Supply chain and configuration baseline

| Mechanism | Where |
|---|---|
| CycloneDX 1.5 SBOM, Python + frontend, per build | CI job `sbom` in `.github/workflows/ci.yml` → artifact `sbom-cyclonedx` |
| Dependency vulnerability audit | CI jobs `python-audit` (pip-audit) and `npm-audit` — both non-blocking by design |
| Deterministic frontend install | `frontend/package-lock.json` + `npm ci` |
| Image digest pinning | `image.digest` / `frontendImage.digest` in the Helm chart; digest-only refs in `infra/docker-compose.airgap.yml` |
| Reproducible offline bundle with checksums | `infra/scripts/airgap-bundle.sh` → `MANIFEST.txt` (digests, git commit, SHA-256 per file) |
| Only commit-SHA image tags ship from CI | `build-images` job — no mutable `latest` |

**Cross-reference:** NIST CM-2, CM-6, CM-8, RA-5, SA-15, SR-3, SR-4 · ISO/IEC 42001 A.10 (third-party relationships)

**Limits.** The SBOM job is non-blocking: a broken generator produces a loud
step failure and no artifact, not a failed build. No artifact signing or
attestation (Sigstore, in-toto, SLSA provenance) is implemented.

---

## 11. AI-specific handling

| Mechanism | Where |
|---|---|
| Untrusted content fenced before reaching a model | `<external-data>` wrapping, e.g. `shared/btagent_shared/hunt/detection_engineer.py` |
| TLP-aware model routing (RED → local only) | `agents/btagent_agents/llm/router.py` — `TLPAwareLLMRouter.resolve()` |
| Per-workflow prompt/token budget | `engine/btagent_engine/middleware/prompt_budget.py` — `PromptBudgetMiddleware`, `PromptBudgetExceeded` |
| Evidence chain over agent steps | `engine/btagent_engine/middleware/evidence_chain.py` |
| Scope enforcement on agent actions | `engine/btagent_engine/middleware/scope.py` |
| Classification propagation | `engine/btagent_engine/middleware/classification.py` |
| Mock-first connectors; live paths raise `NotImplementedError` | `agents/btagent_agents/mcp/servers/*`, `engine/btagent_engine/integrations/*` |
| Declarative connectors: live egress needs `routing.live_egress_approved=true` **and** mocks off, else `NotImplementedError` | `engine/btagent_engine/integrations/_declarative.py` — `DeclarativeRunner._select_sender()` |
| Credential scrubbing in declarative request/response logging | `engine/btagent_engine/integrations/_declarative.py` — `_Scrubber` |
| Fail-safe LLM enablement (only literal `"false"` enables live) | `backend/btagent_backend/main.py` |
| Deterministic mock LLM/embedding fallbacks | `engine/btagent_engine/integrations/llm_call.py`, `backend/btagent_backend/services/embedding_service.py` |

**Cross-reference:** ISO/IEC 42001 A.6.2 (life cycle), A.7 (data), A.9.2 (responsible use) · NIST SI-10, AC-4

**Limits.** Prompt-injection defence is input fencing plus scope and budget
middleware; there is no model-side guarantee. Agent evaluation (`tests/agent_eval/`,
CI job `agent-eval`) covers the **deterministic** components only — MITRE
keyword mapper, triage classifier, severity scorer — against golden datasets
with aggregate-metric thresholds, and makes no LLM calls (#382 v1). Evaluation
of live-LLM behaviour on investigation transcripts is not implemented.

---

## What is deliberately absent

* No accreditation, ATO, certification or third-party attestation — none held,
  none pursued.
* No FIPS-validated cryptographic module claim.
* No artifact signing / SLSA provenance.
* No database-level row security or append-only audit storage.
* No evaluation of live-LLM agent behaviour (the existing eval suite is
  deterministic-only — see §11).
* No control implemented solely to satisfy a framework. Every row above
  predates this document; the document only maps what was already there.
