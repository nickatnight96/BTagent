# Phase 6 — Proactive Threat Hunting: Implementation Design

Engineering design for the nine Phase 6 hunting features ([#112](https://github.com/nickatnight96/BTagent/issues/112)–[#121](https://github.com/nickatnight96/BTagent/issues/121)). See the [roadmap](ROADMAP.md#v060----phase-6-proactive-threat-hunting) for the feature catalogue and the [strategy issue (#98)](https://github.com/nickatnight96/BTagent/issues/98) for positioning.

**Build target: Hybrid.** Engine-ready Pydantic schemas + pure-logic cores live in `shared/btagent_shared/`; execution is wired through the existing `DefensivePlugin` + `TaskManager` + service/API runtime. This ships on proven infrastructure now while keeping logic dependency-free so it migrates cleanly into the `engine/` Node/Middleware runtime (per [#101](https://github.com/nickatnight96/BTagent/issues/101)) later.

All MCP connectors are currently mocks (`BTAGENT_MOCK_CONNECTORS=true`). Every feature is buildable and testable against mocks; real-API behaviour arrives with the Phase 4 connector work.

---

## Architectural approach (applies to every feature)

Three layers per feature, in dependency order:

1. **`shared/btagent_shared/types/hunt_*.py`** — Pydantic v2 models with zero heavy deps (the `shared` package is "zero heavy deps" by policy). These are the engine-portable contracts.
2. **`shared/btagent_shared/hunt/`** (new subpackage) — pure-logic cores: clustering, scoring, sigma-compile wrappers, baseline math, correlation. Pure functions / small classes; no DB, LLM, or network. Reusable as engine `Node.run` bodies later.
3. **Runtime wiring** — the side-effectful shell:
   - **Agent side**: `agents/btagent_agents/plugins/hunter/` — a `DefensivePlugin` exposing LangChain tools that call the pure-logic cores + MCP connectors.
   - **Backend side**: `services/hunt_*.py` (take `AsyncSession` first arg, `db.add`/`db.flush`, no commit, no event emit), `api/v1/hunt_*.py` routers (`Depends(get_db)`, `Depends(get_current_user)`, `user.require_permission(...)`, org-scoped queries), models in `db/models_hunt.py`.
   - **Scheduling**: recurring hunts run via a new **arq**-backed scheduler (shared foundation); one-shot hunts run via the existing `TaskManager` asyncio tasks.

### Conventions (verified against the codebase)
- **IDs**: `generate_id("<prefix>")` from `btagent_shared.utils.ids` → prefixed ULIDs. New prefixes: `hpack_`, `hrule_`, `hrun_`, `hfnd_`, `hclu_`, `supp_`, `bent_`, `bprof_`, `bout_`, `idnt_`, `cid_`, `awl_`, `emul_`, `wsig_`, `ddraft_`, `pinj_`, `shag_`.
- **DB models**: SQLAlchemy 2.0 `Mapped`/`mapped_column`, `Base` from `db/models.py`, `org_id` FK with `DEFAULT_ORG_ID`, `JSONB` for flexible blobs, explicit `Index(...)` in `__table_args__`, `created_at`/`updated_at` via `utcnow`. New file `db/models_hunt.py` (mirrors the `models_knowledge.py`/`models_playbook.py` split).
- **Migrations**: `backend/migrations/versions/000N_*.py` with `revision`/`down_revision` chain. Next free numbers start at `0008`. Generate via `make db-revision msg="..."`, then hand-edit.
- **RBAC**: add hunt permissions to the permission map (`backend/btagent_backend/auth/`); enforce with `user.require_permission("hunt:...")`. Reuse the `assert_can_access_*` org-scoping helpers.
- **Events**: extend `EventType` in `shared/btagent_shared/types/events.py`; emit via `RedisEmitter.emit(EventType.X, **payload)` (channel `btagent:events:{id}`). New types: `HUNT_STARTED`, `HUNT_RULE_FIRED`, `HUNT_FINDING_CREATED`, `HUNT_BASELINE_UPDATED`, `HUNT_VALIDATION_RESULT`, `HUNT_PATTERN_SURFACED`.
- **Services don't emit events** — emission happens in the agent hook layer or API handler, matching `knowledge_service.py`.
- **Tests**: `pytest` `asyncio_mode=auto`; backend uses `sqlite+aiosqlite://` in-memory + `client`/`sample_user`/`db` fixtures; agents use `agents/tests/conftest.py`. Markers: `@pytest.mark.asyncio`, `@pytest.mark.parametrize`, `smoke`.
- **Frontend**: React 19 + Zustand + React Router; views under `frontend/src/views/<Name>/`, registered in `frontend/src/router.tsx`. All hunt views are gated on the [#97](https://github.com/nickatnight96/BTagent/issues/97) UX refresh (see Risks).

---

## Shared foundations (Wave 0, built once)

### F0.1 — `HuntFinding` contract (issue #119 core; everything emits into it)
- `shared/btagent_shared/types/hunt_finding.py`: `HuntFinding`, `HuntFindingCluster`, `SuppressionRule`, `HuntFindingState`, `HuntSource`.
- `db/models_hunt.py`: `HuntFindingRow`, `HuntFindingClusterRow`, `SuppressionRuleRow`.
- Migration `0008_hunt_findings`.
- Consumed by #112 / #114 / #116 / #117 / #121.

### F0.2 — arq scheduler (shared infra; #112 + recurring hunts depend on it)
- Add `arq` to `backend/pyproject.toml` (Redis-backed; Redis already deployed).
- `backend/btagent_backend/scheduler/` — arq `WorkerSettings`, job functions, cron registration. New process roles `btagent-scheduler` + `btagent-worker` (same image, different `CMD`); `infra/` compose + Helm entries.
- Pure scheduling-policy logic (cron parse, next-run calc) in `shared/btagent_shared/hunt/schedule.py`.
- Per [#101](https://github.com/nickatnight96/BTagent/issues/101) Pattern 4: canonical job-state in Postgres so a worker restart resumes.

### F0.3 — Hunt RBAC + event types + base hunt types
- Permissions: `hunt:view`, `hunt:create`, `hunt:execute`, `hunt:triage`, `hunt:suppress`, `hunt:promote`, `huntpack:manage`, `detection:draft`, `validation:run`.
- `shared/btagent_shared/types/hunt.py`: `HuntDomain` (`sigma|behavioral|identity|cloud|cross_investigation|agentic`), `HuntScope`, `NoiseProfile`.
- New `EventType` members (above).

### F0.4 — `shared/btagent_shared/hunt/` subpackage skeleton

---

## Per-feature implementation

Legend: **Types** (shared) · **Logic** (shared, pure) · **Data** (DB) · **Runtime** (plugin/service/API) · **FE** (frontend) · **Tests** · **Deps**.

### #119 — Hunt Triage Agent *(Wave 0 — keystone)*
- **Types**: `hunt_finding.py` (F0.1).
- **Logic** `hunt/triage.py`: `cluster_findings(findings)` (deterministic LSH-bucket on `(technique, entity-shape, observable-shape)`; HDBSCAN later), `applies(suppression, finding)`, `suppression_is_overbroad(rule, evidence)`.
- **Data**: `HuntFindingRow`, `HuntFindingClusterRow`, `SuppressionRuleRow` (migration 0008).
- **Runtime**: `services/hunt_triage_service.py` (`record_finding`, `recluster`, `suppress`, `promote_to_investigation` → reuses existing investigation creation, carries evidence chain + IOCs + MITRE map); `api/v1/hunt_findings.py` (`GET /hunt/findings`, `POST /hunt/findings/{id}/suppress`, `POST /hunt/findings/promote`, `GET /hunt/suppressions`); stale-suppression re-confirmation arq cron.
- **FE** `views/HuntTriage/`: clustered inbox, bulk suppress/promote, rationale capture.
- **Tests**: cluster reduction, suppression apply + audit, promote seeds investigation, harmful-suppression flip; pure-fn unit tests.
- **Deps**: F0.1 only. **Build first.**

### #112 — Hunt Pack Runner *(Wave 1)*
- **Types** `hunt_pack.py`: `HuntPackManifest`, `HuntRule`, `HuntSchedule`, `HuntRun`, `NoiseProfile`.
- **Logic** `hunt/sigma.py` (thin `pysigma` wrapper, pure given backend pipeline) + `hunt/schedule.py`.
- **Data**: `HuntPackRow`, `HuntRuleRow`, `HuntRunRow` (migration `0009_hunt_packs`).
- **Runtime**: `plugins/hunter/sigma_compiler.py` + `runner.py`; tools `compile_pack`, `run_pack`, `compute_noise_baseline`; scheduled via arq cron; emits findings into #119; `services/hunt_pack_service.py` + `api/v1/hunt_packs.py`.
- **FE** `views/HuntPacks/`: pack list, per-rule status grid, tuning surface.
- **Tests**: sigma transpile goldens (≥80% of sample SigmaHQ set × 4 backends), scheduler resume, finding-emission integration.
- **Deps**: F0.1, F0.2; new `pysigma` + `pySigma-backend-{splunk,kusto,elasticsearch,crowdstrike}`.

### #114 — Behavioral Hunter *(Wave 1)*
- **Types** `hunt_behavioral.py`: `BehavioralEntity`, `BehavioralProfile`, `BehavioralOutlier`.
- **Logic** `hunt/behavioral.py`: `score_outlier(event_vec, profile)` (cosine + frequency floor).
- **Data**: `behavioral_entities`, `behavioral_profiles` (pgvector, follows `knowledge_chunks`), `behavioral_outliers` (migration `0010_behavioral`).
- **Runtime**: reuse `embedding_service.py`; `services/behavioral_service.py` (baseline-build arq cron + outlier detect); `hunter/` tools `build_baseline`, `detect_outliers`, `classify_intent` (Haiku→Sonnet); promotions → #119.
- **FE** `views/BehavioralHunts/`: entity drift dashboard, outlier triage.
- **Tests**: synthetic LotL → outlier + intent; baseline persistence; cost guard.
- **Deps**: F0.1, F0.2, EDR MCP (mock OK). No new pip deps.

### #113 — CTI → Detection pipeline *(Wave 2)*
- **Types** `detection_engineer.py`: `IntelArtifact`, `DetectionDraft`, `HistoricalValidationResult`, `DetectionRepo`.
- **Logic** `hunt/detection.py`: TTP-set dedupe, edit-distance scoring.
- **Data**: `intel_artifacts`, `detection_drafts`, `detection_repos` (migration `0011_detection_engineer`).
- **Runtime**: new plugin `plugins/detection_engineer/` (engineer persona); nodes CTIExtractor → DataSourceMatcher → RuleDrafter → HistoricalValidator → PRComposer; Git MCP (#100 follow-on); **HITL mandatory** before PR; reuses STIX service, Knowledge RAG, MITRE mapper, #112 sigma compiler, query generator.
- **FE** `views/DetectionEngineer/`: intel inbox, drafting split-view, accept/edit/reject → PR.
- **Tests**: APT29 report → ≥3 drafts; STIX→PR golden (mock Git MCP); CTI-REALM scorecard harness.
- **Deps**: F0.1, #112 sigma compiler, Git MCP (#100), HITL hook (exists).

### #118 — Detection Validation Agent *(Wave 2)*
- **Types** `validation.py`: `EmulationExercise`, `EmulationResult`, `RuleFiring`, `CoverageDelta`.
- **Logic** `hunt/coverage.py`: `compute_delta(expected, fired)` (set math + latency/severity scoring).
- **Data**: `emulation_exercises`, `emulation_results` (migration `0012_validation`).
- **Runtime**: new MCP servers `atomic_red_team_mcp.py`, `caldera_mcp.py` (sandbox-only enforced via connector manifest `blast_radius` + ScopeEnforcement hook); ValidationOrchestrator subgraph (trigger → observe → score → report); miss → #113 ticket, late/wrong-severity → #112 tuning, pass → update MITRE coverage map.
- **FE** `views/PurpleTeam/`: emulation scheduler, result replay, coverage-delta heatmap over MITRE matrix.
- **Tests**: T1059.001 atomic → 2/3 rules fire within SLA (mock SIEM), sandbox-refusal audit, post-merge auto-validate.
- **Deps**: F0.1, F0.2, ART + Caldera MCP (#100), ScopeEnforcement hook (exists).

### #116 — Identity Hunt Agent *(Wave 3 — gated on #100 Tier 1)*
- **Types** `identity_hunt.py`: `IdentityEntity`, `OAuthGrant`, `IdentityHuntPack`.
- **Logic** `hunt/identity.py`: OAuth-grant transitive closure, impossible-travel geo-velocity, dormant-app detection.
- **Data**: `identity_entities`, `oauth_grants` (migration `0013_identity_hunt`).
- **Runtime**: `hunter/packs/identity/` (≥10 packs) on #112 runner; MITRE mapper enriched (T1078/T1098/T1556/T1539/T1550); confirmed hit → Investigation + revoke-playbook proposal (HITL).
- **FE** `views/IdentityHunts/`: token-lifecycle timeline, OAuth-grant graph, consent surfacing.
- **Tests**: OAuth-replay, dormant-app, promote-with-revoke; ≥10 packs vs recorded Okta/Entra fixtures.
- **Deps**: **blocking** #100 Tier 1 Okta + Entra + Google Workspace; F0.1, F0.2, #112.

### #117 — Cloud Control-Plane Hunter *(Wave 3 — gated on #100 Tier 1/2)*
- **Types** `cloud_hunt.py`: `CloudIdentity`, `AgenticWorkload`, `CloudHuntPack`.
- **Logic** `hunt/cloud.py`: STS-role transitive-closure, managed-vs-shadow classification.
- **Data**: `cloud_identities`, `agentic_workloads` (migration `0014_cloud_hunt`).
- **Runtime**: `hunter/packs/cloud/` (≥15 packs incl. shadow-agent/shadow-MCP discovery); shadow-agent → governance workflow, IAM/STS → IR; shares shadow-discovery with #121.
- **FE** `views/CloudHunts/`: control-plane timeline, IAM role-graph, agentic-workload matrix.
- **Tests**: STS-chain + shadow-Bedrock, CloudTrail-tamper, shadow-MCP via DNS+inventory; ≥15 packs.
- **Deps**: **blocking** #100 Tier 1 CloudTrail+GuardDuty, Tier 2 GCP/Azure; F0.1, F0.2, #112.

### #120 — Cross-Investigation Pattern Hunter *(Wave 2 — no new connectors)*
- **Types** `pattern_hunt.py`: `WeakSignal`, `WeakSignalCluster`, `PatternHuntProposal`.
- **Logic** `hunt/patterns.py`: `rank = frequency × recency × cross_investigation_diversity`.
- **Data**: `weak_signals`, `weak_signal_clusters`, `pattern_hunt_proposals` (migration `0015_pattern_hunt`).
- **Runtime**: `services/pattern_hunter_service.py` walks closed investigations via Knowledge RAG; arq weekly cron; proposals → `HuntInput` for the #99 Hunter plugin.
- **FE** `views/PatternInsights/`: ranked patterns + score breakdown, drill to source cases, "Propose a hunt".
- **Tests**: planted cross-case pattern surfaces top-3, diversity weighting, dismiss down-weights.
- **Deps**: F0.1, F0.2, Knowledge service + corpus (exist).

### #121 — Agentic-AI Misuse Hunter *(Wave 3)*
- **Types** `agentic_risk.py`: `PromptInjectionFinding`, `ShadowAgent`, `AgentIdentityDrift`.
- **Logic** `hunt/agentic.py`: OWASP-LLM01 heuristic matchers; shared shadow-discovery with #117.
- **Data**: `prompt_injection_findings`, `shadow_agents`, `agent_identity_drift` (migration `0016_agentic_risk`).
- **Runtime**: `hunter/packs/agentic/`; prompt-injection classifier over LangFuse/OTEL traces (LLM-judge); shadow-MCP discovery (DNS+process+Cloud Run inv); agent-identity drift (Entra Agent ID / Bedrock AgentCore — #100 Tier 2).
- **FE** `views/AgenticRisk/`: injection timeline, shadow-agent inventory, identity drift.
- **Tests**: 10 injection fixtures → ≥8 caught ≤2 FP; shadow-MCP discovery; identity-drift flag.
- **Deps**: F0.1, F0.2, LLM observability (exists), #100 Tier 2 connectors; shares logic with #117.

---

## Dependency graph & sequencing

```
WAVE 0  (no new deps — build first)
  F0.1 HuntFinding contract ─┐
  F0.3 RBAC/events/base types │→ #119 Hunt Triage (keystone)
  F0.4 hunt/ subpackage      ─┘

WAVE 1  (adds arq + pysigma)
  F0.2 arq scheduler ──▶ #112 Hunt Pack Runner ──┐
                          #114 Behavioral Hunter ─┴─▶ emit into #119

WAVE 2  (closes det-eng loop + corpus mining)
  #112 sigma ──▶ #113 CTI→Detection ◀──▶ #118 Validation
  Knowledge RAG ──▶ #120 Cross-Investigation

WAVE 3  (gated on #100 connectors)
  #100 Tier1 ──▶ #116 Identity   ─┐
  #100 Tier1/2 ─▶ #117 Cloud      ─┼─▶ emit into #119
  #100 Tier2 ──▶ #121 Agentic     ─┘  (#121 shares shadow-discovery w/ #117)
```

**Recommended PR sequence** (each a reviewable unit):
1. **PR-A**: F0.1 + F0.3 + F0.4 + #119 (HuntFinding foundation + triage). No new deps.
2. **PR-B**: F0.2 arq scheduler (standalone infra + one trivial cron, e.g. the stale-suppression sweep from #119).
3. **PR-C**: #112 Hunt Pack Runner.
4. **PR-D**: #114 Behavioral Hunter.
5. **PR-E**: #120 Cross-Investigation (no connector deps).
6. **PR-F / PR-G**: #113 + #118 (det-eng loop; can split).
7. **PR-H / I / J**: #116 / #117 / #121 as their #100 connector deps land.

---

## Testing strategy
- **Unit (pure logic)**: `shared/btagent_shared/hunt/*` tested in isolation — fast, no DB/LLM. This is where the hybrid approach pays off.
- **Backend**: `backend/tests/test_hunt_*.py` using in-memory `sqlite+aiosqlite` + `client`/`db`/`sample_user` fixtures; assert RBAC denials, org-scoping, migration round-trips.
- **Agents**: `agents/tests/test_*` for sigma transpile goldens, intent classification, pack execution against mock MCP.
- **UAT**: extend `tests/uat/` with hunt acceptance flows (per each issue's Acceptance section).
- **Eval**: DeepEval golden datasets for LLM steps in `tests/agent_eval/`.
- **E2E**: Playwright specs under `tests/e2e/specs/hunt/` once FE views land (gated on #97).
- Commands: `make test-backend`, `make test-agents`, `make db-revision msg=...`, `make db-migrate`, `make lint`, `make uat`, `make eval`, `make e2e`.

---

## Risks & open questions
1. **#97 UX-refresh dependency**: every `views/*` deliverable assumes the design-system refresh. Backend/agent/shared layers are unblocked regardless.
2. **arq introduction** (#101 Pattern 4): adds `scheduler`/`worker` process roles. Decide: adopt now vs. interim `TaskManager` asyncio cron.
3. **pysigma backend coverage**: CrowdStrike may lack a maintained backend → file upstream / degrade to 3 backends, don't fork.
4. **Connector gating (Wave 3)**: #116/#117/#121 can't reach acceptance without #100 Tier 1/2 real connectors; until then they ship against recorded mock fixtures.
5. **Migration numbering**: assumes `0008`–`0016` are free; verify against in-flight branches (e.g. #86) before generating.
6. **Engine migration debt**: hybrid keeps logic portable, but the eventual move to `engine/` Node/Middleware (#101 Sprint 2/3) is separate work, not tracked here.

---

## Out of scope
- Real connector API implementations (Phase 4 / #100).
- The `engine/` migration of compiler/MCP/hooks (#101 Sprint 2/3).
- Multi-tenancy, IOC graph DB, TAXII feeds (Phase 5 / #98 v0.5).
