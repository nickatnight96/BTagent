# BTagent Deployment Plan

The plan of record for getting BTagent into production and for sequencing the
remaining feature work. It has two halves:

1. **Deployment blockers** — concrete, verified gaps that mean a real
   production deploy would *not* currently succeed. These are the must-fix
   items before any go-live.
2. **Remaining roadmap** — the production-hardening and feature work
   (`docs/ROADMAP.md` v0.4 → Phase 6) that constitutes "the rest" of what ships.

Each blocker is scoped to be ownable as a single follow-up PR. This document
started life as a plan only; blockers that have since been fixed are marked
**RESOLVED** with a pointer to the code that closed them, so the status here
matches the tree rather than the moment it was written.

> Issue references (`#NN`) come from [`ROADMAP.md`](ROADMAP.md) and
> [`PHASE6_THREAT_HUNTING_PLAN.md`](PHASE6_THREAT_HUNTING_PLAN.md), which cite
> them directly.

---

## Status at a glance

| Blocker | Severity | Status |
|---------|----------|--------|
| B1 — backend image missing engine + agents | Critical | **RESOLVED** — `Dockerfile.backend` installs all four packages in dependency order |
| B2 — nothing builds version-tagged images | Critical | **RESOLVED** — `.github/workflows/release.yml` builds + pushes semver-tagged images on `v*` |
| B3 — no migration runs on deploy | Critical | **RESOLVED** — Helm `templates/migrate-job.yaml` (pre-install/pre-upgrade hook) *and* a `migrate` one-shot in both compose files |
| B4 — chart has no scheduler Deployment | High | **RESOLVED** — scheduler Deployment in `templates/deployment.yaml`, gated on `scheduler.enabled` |
| B5 — no admin bootstrap path | High | **RESOLVED** — `bt create-admin` inside the image, plus `make db-reset-admin` on a host |
| B6 — staging is manual-only | Medium | **OPEN** — needs a staging cluster + `KUBE_CONFIG_STAGING` |
| B7 — hardening documented, not default | Medium | **PARTIAL** — security headers and the CORS start-up assertion now ship by default; TLS termination is still manual |

## Why the deploy path used to break

The chart, Terraform, and deploy workflows all existed and read as complete —
but following the documented release path (`git tag v* → deploy-prod.yml`) hit
four independent failures. All four are now closed; the diagram is kept as the
record of what was wrong and what each fix has to keep true.

```mermaid
flowchart TD
    tag["git tag v1.0.0 → deploy-prod.yml"] --> val["validate job:<br/>docker manifest inspect btagent-*:v1.0.0"]
    val -->|"B2 FIXED: release.yml builds<br/>semver-tagged images on v* tags"| deploy["helm upgrade --atomic"]
    deploy --> pod["backend / scheduler pods start"]
    pod -->|"B1 FIXED: image installs<br/>shared → engine → agents → backend"| ok1["imports resolve"]
    deploy -->|"B3 FIXED: pre-install migrate Job<br/>(compose: migrate one-shot)"| ok2["schema is at head first"]
    deploy -->|"B4 FIXED: scheduler Deployment<br/>in the chart"| ok3["arq cron jobs run"]
```

---

## Section 1 — Deployment blockers (must-fix before go-live)

Severity legend: **Critical** = deploy fails or app crashes · **High** =
deploys but a core capability is silently dead or operators are locked out ·
**Medium** = operational / hardening gap.

### B1 — Production backend image is missing the agent engine *(Critical)* — **RESOLVED**

> **Fixed.** `infra/docker/Dockerfile.backend` now copies and installs all four
> workspace packages in dependency order (`shared → engine → agents →
> backend`), each with its source COPY'd before its editable install. A single
> shared image still backs both `backend` and `scheduler`. The description
> below is the original diagnosis.

**Symptom.** The backend (and scheduler) container crashes on first import of
any code path that touches the agent engine.

**Root cause.** `infra/docker/Dockerfile.backend` installs only `shared` and
`backend`:

```dockerfile
RUN cd shared && uv pip install --system -e .
...
RUN cd backend && uv pip install --system -e .
COPY agents/pyproject.toml backend/...   # copied, never installed
# engine/ is never copied or installed at all
```

But the backend imports the engine and agents packages:

| Importer | Imports |
|----------|---------|
| `backend/btagent_backend/services/{task_manager,report_service,playbook_service}.py`, `scheduler/jobs.py` | `btagent_agents` |
| `backend/btagent_backend/ws/engine_event_adapter.py`, `db/models_workflow.py` | `btagent_engine` |
| `agents/btagent_agents/orchestrator/*`, `middleware/llm_router.py` | `btagent_engine` |

`backend/pyproject.toml` only declares `btagent-shared` as a workspace dep, so
installing `backend` does **not** pull in `agents`/`engine`, and the agents'
heavy runtime deps (`langgraph`, `litellm`, `pysigma*`) are never installed.

This is invisible in CI because CI installs all four packages editable
(`ci.yml` install steps) and never runs the actual Docker image. The same image
backs the `scheduler` service in `docker-compose.yml`
(`command: ["arq", "btagent_backend.scheduler.worker.WorkerSettings"]`), so the
scheduler is broken in exactly the same way.

**Fix.** In the builder stage, install in workspace dependency order
`shared → engine → agents → backend` (mirroring the order used throughout
`ci.yml`) and `COPY engine/btagent_engine engine/btagent_engine` so the engine
source ships. Confirm a single shared image (backend + scheduler) is acceptable
versus splitting into separate backend/agent images; note the image-size
increase from the LangGraph/LiteLLM/pysigma dependency tree.

**Verify.** `docker build -f infra/docker/Dockerfile.backend -t btagent-backend:test .`
then `docker run --rm btagent-backend:test python -c "import btagent_backend, btagent_agents, btagent_engine"`.

### B2 — Nothing builds version-tagged images for production *(Critical)* — **RESOLVED**

> **Fixed** via option (a): `.github/workflows/release.yml` triggers on `v*`
> tags and builds + pushes semver-tagged backend and frontend images, ordered
> before the deploy, so `deploy-prod.yml`'s `docker manifest inspect` finds the
> artifact it validates.

**Symptom.** `deploy-prod.yml` fails immediately at the `validate` job with
"image not found" for the tag being released.

**Root cause.** `deploy-prod.yml` triggers on `push: tags: ["v*"]` and the
`validate` job runs `docker manifest inspect <image>:<tag>` before deploying.
The only job that builds and pushes images — `build-images` in `ci.yml` —
- runs only on **push to `main`**,
- tags images **by commit SHA only** (`type=sha,prefix=`), and
- is gated behind `if: ... vars.ENABLE_IMAGE_BUILD == 'true'`.

So no artifact named `ghcr.io/.../btagent-backend:v1.0.0` is ever produced.

**Fix (choose one, document the choice).**
- **(a) Release workflow.** Add `.github/workflows/release.yml` triggered on
  `v*` tags that builds + pushes semver-tagged images, ordered *before* the
  deploy. Cleanest separation of "build release artifact" from "deploy".
- **(b) Extend `build-images`.** Add `type=semver,pattern={{version}}` /
  `type=ref,event=tag` to the metadata step and a `push: tags: ["v*"]` trigger,
  removing or keeping the `ENABLE_IMAGE_BUILD` gate as desired.

Either way, ensure the image tag the deploy resolves (`needs.validate.outputs.version`)
matches what was pushed.

**Verify.** Push a throwaway `v0.0.0-rc1` tag to a fork; confirm the build runs
and `docker manifest inspect` in `validate` passes.

### B3 — No database migration runs on deploy *(Critical)* — **RESOLVED**

> **Fixed on both deploy paths.**
> *Kubernetes:* `infra/helm/btagent/templates/migrate-job.yaml` — a
> `pre-install,pre-upgrade` hook Job at `hook-weight: 5` running
> `sh -c "cd backend && alembic upgrade head"`.
> *Docker Compose:* a `migrate` one-shot service in both
> `infra/docker-compose.yml` and `infra/docker-compose.airgap.yml`, which
> `backend` and `scheduler` depend on with
> `condition: service_completed_successfully`. Migration is therefore no longer
> an easily-skipped runbook step on compose — it cannot be skipped at all.
> `cd backend` is load-bearing in both: the image WORKDIR is `/app` but
> `alembic.ini` lives at `/app/backend`.

**Symptom.** A fresh cluster boots the backend against an empty/unmigrated
schema; existing clusters run new code against an old schema.

**Root cause.** None of `deploy-staging.yml`, `deploy-prod.yml`, or the Helm
templates run `alembic upgrade head`. The chart ships only
configmap / secret / deployment / service / ingress / hpa / pdb /
networkpolicy / serviceaccount templates — no migration Job or init container.
`DEPLOYMENT.md` describes an init container as something the chart "can include"
(it does not).

**Fix.** Add a Helm `pre-install,pre-upgrade` **hook Job**
(`templates/migrate-job.yaml`) that runs `alembic upgrade head` from the backend
image, with `helm.sh/hook-weight` so it completes before the rollout. Because
prod deploys use `--atomic`, a failed migration then rolls the release back
cleanly. For Docker Compose, make the existing `make db-migrate` step explicit
in the deploy runbook (it is currently easy to skip).

**Verify.** `helm template ... | grep -A30 'kind: Job'` shows the hook;
a clean-namespace `helm install` brings the schema up before pods go Ready.

### B4 — Helm chart has no scheduler/worker Deployment *(High)* — **RESOLVED**

> **Fixed.** `infra/helm/btagent/templates/deployment.yaml` renders a scheduler
> Deployment (gated on `scheduler.enabled`, same image as the backend,
> `command: ["arq", "btagent_backend.scheduler.worker.WorkerSettings"]`, same
> config/secret `envFrom`). The compose scheduler now also gets a healthcheck
> that actually applies to a worker (`arq --check`) instead of inheriting the
> image's HTTP one.

**Symptom.** In Kubernetes, all scheduled/background work silently never runs:
Phase 6 scheduled hunts (#112), behavioral baseline builds (#114), and the
stale-suppression re-confirmation sweep (#119).

**Root cause.** `docker-compose.yml` defines a `scheduler` service, but the Helm
`templates/deployment.yaml` ships only `backend` and `frontend` Deployments.
There is no arq worker workload in the chart.

**Fix.** Add a scheduler Deployment to the chart (same image as backend,
`command: ["arq", "btagent_backend.scheduler.worker.WorkerSettings"]`,
`envFrom` the same config/secret), with `replicaCount`/`resources` values
entries. Mirror the compose definition. Keep it a single replica (or add a
leader-election note) so cron jobs don't double-fire.

**Verify.** `helm template` renders the scheduler Deployment; in a test cluster
`kubectl logs deploy/btagent-scheduler` shows arq registering its cron jobs.

### B5 — No admin bootstrap path; `make db-seed` locks you out *(High)* — **RESOLVED**

> **Fixed.** `bt create-admin` (`backend/btagent_backend/cli/admin.py`) is an
> idempotent create-or-reset that reads `BTAGENT_SEED_ADMIN_PASSWORD`, never
> prints it, and exits 1 outside test mode when it is unset. It ships **inside
> the backend image**, so it is the bootstrap path for container-only and
> air-gapped installs where `infra/scripts/reset-admin-password.py` (host repo
> + virtualenv) cannot run; that script now delegates to the same function so
> the two cannot diverge. `DEPLOYMENT.md` no longer recommends `make db-seed`
> for production.

**Symptom.** After a prod `make db-seed`, no one can log in — the admin password
is random and never surfaced.

**Root cause.** `infra/scripts/seed-data.py` (SEC-002 fix) correctly generates a
random admin password in non-test mode and (correctly) does not print it, but
ships no retrieval/reset path — the code comment points operators at an "admin
CLI" that does not exist. Yet `DEPLOYMENT.md` step 5 still instructs
`make db-seed` for production.

**Fix.** Add a deterministic bootstrap: read an admin password from
`BTAGENT_SEED_ADMIN_PASSWORD` (fail loudly if unset in prod) **or** ship a
`create-admin` / `reset-password` management command. Update the prod runbook to
use it and to stop recommending `make db-seed` (which also seeds a sample
investigation) for production.

**Verify.** `BTAGENT_SEED_ADMIN_PASSWORD=… python infra/scripts/seed-data.py`
then log in via `/api/v1/auth/login` with that password.

### B6 — Staging is manual-only; no staging cluster wired *(Medium)*

**Root cause.** `deploy-staging.yml`'s `push: branches: [main]` trigger is
commented out ("Manual trigger only until staging cluster is configured") and it
depends on `secrets.KUBE_CONFIG_STAGING`.

**Fix / track.** Provision the staging cluster (Terraform already models EKS),
set the `KUBE_CONFIG_STAGING` environment secret, then re-enable the
`main`-push trigger so every merge continuously deploys to staging.

### B7 — Production hardening is documented but not default *(Medium)*

**Root cause.** `DEPLOYMENT.md` described the prod nginx config
(HSTS / CSP / X-Frame-Options), restricted CORS, and external-secrets, but these
were manual steps; the shipped defaults were dev-grade (wildcard CORS, plain
nginx). See also `ROADMAP.md` "Known Limitations" (CORS, seed data).

**Status — closed.** All three are now properties of the shipped artifacts
rather than instructions:

- **nginx / security headers.** The frontend image and `infra/nginx/nginx.conf`
  emit HSTS, CSP (with `frame-ancestors`), `X-Frame-Options`,
  `X-Content-Type-Options` and `Referrer-Policy` by default, and the backend's
  `SecurityHeadersMiddleware` sets the same baseline so the posture survives a
  deploy with no nginx in front. Pinned by the Playwright `@nginx` specs.
- **CORS.** The backend refuses to start under `BTAGENT_ENV=prod` when
  `BTAGENT_CORS_ORIGINS` is unset, a wildcard, or a localhost origin.
- **external-secrets.** The chart renders the `ExternalSecret` itself
  (`externalSecrets.enabled`, `infra/helm/btagent/templates/externalsecret.yaml`),
  targeting the same `<fullname>-secret` every workload already mounts, and
  suppresses its own `secretEnv` Secret so the two cannot overwrite each other.
  Guarded by `backend/tests/test_helm_external_secrets.py`.

TLS termination (certs + the 443 `server` block) remains deliberately manual —
it needs a certificate that only the operator of a given deployment has.

---

## Section 2 — Production readiness (ROADMAP v0.4 "Known Limitations")

These don't block a deploy from *standing up*, but block running it for real.
Prioritized; each links to its `ROADMAP.md` v0.4 entry.

Still open:

| Priority | Item | Why it matters | Roadmap |
|----------|------|----------------|---------|
| P0 | **Real SIEM/CTI connectors (#100)** | All 27 registered MCP connectors are mock-first (`BTAGENT_MOCK_CONNECTORS`, default on) and every live path raises `NotImplementedError`; with mocks the product returns canned data. | v0.4 "Real Connector Implementations" |
| P2 | **Perf: query/index tuning, caching, bundle splitting** | High-concurrency readiness. Some index work has landed (see `migrations/versions/0010_perf_indexes.py`); caching and bundle splitting have not been measured. | v0.4 "Performance Optimization" |

Closed since this table was written — each verified against the code, not
assumed, and pinned by `backend/tests/test_roadmap_limitations.py`:

| Priority | Item | Where it landed |
|----------|------|-----------------|
| ~~P0~~ | **JWT revocation + refresh rotation** | `auth/revocation.py` (per-user epoch + family revocation), `auth/jwt.py` (`fid` rotation with reuse detection), `POST /auth/revoke/{user_id}` |
| ~~P1~~ | **Hardened CORS default** | `main.py` — explicit method/header allow-lists; prod startup refuses a wildcard or localhost origin |
| ~~P1~~ | **Deep health checks + graceful shutdown** | `api/v1/health.py` `/health/ready` checks DB, Redis, S3 and the revocation store concurrently; `lifespan` drains in-flight work on SIGTERM |
| ~~P2~~ | **SSO (SAML 2.0 / OIDC), MFA (TOTP)** | `auth/saml.py`, `auth/oidc.py`, `api/v1/sso.py`, `api/v1/mfa.py` |
| ~~P2~~ | **PDF report export** | `GET /reports/investigations/{id}/export?format=pdf` via `services/report_pdf.py` |

---

## Section 3 — Remaining roadmap features ("the issues")

### Phase 6 — Proactive Threat Hunting (#112–#121)

Condensed from [`PHASE6_THREAT_HUNTING_PLAN.md`](PHASE6_THREAT_HUNTING_PLAN.md).
The keystone is the shared `HuntFinding` contract (#119) — every hunt source
emits into it. Cross-cutting dependencies: the **arq scheduler** (#101, also
needed by B4) and **real connectors** (#100, also P0 above).

```
WAVE 0  (no new deps)   F0.1 HuntFinding + F0.3 RBAC/events + F0.4 hunt/ pkg → #119 Hunt Triage (keystone)
WAVE 1  (+arq, +pysigma) #112 Hunt Pack Runner · #114 Behavioral Hunter        → emit into #119
WAVE 2  (det-eng loop)   #113 CTI→Detection ⇄ #118 Validation · #120 Cross-Investigation
WAVE 3  (gated on #100)  #116 Identity · #117 Cloud · #121 Agentic-AI Misuse    → emit into #119
```

Recommended PR sequence (each a reviewable unit): **PR-A** F0.1+F0.3+F0.4+#119 →
**PR-B** arq scheduler (#101) → **PR-C** #112 → **PR-D** #114 → **PR-E** #120 →
**PR-F/G** #113+#118 → **PR-H/I/J** #116/#117/#121 as their #100 connectors land.

> Dependency note: PR-B (arq scheduler) and blocker **B4** (scheduler in the
> Helm chart) are the same infrastructure — land them together so scheduled
> hunts actually run in production.

### Phase 5 — Enterprise (after Phase 6 foundations)

Multi-tenancy (org-scoped isolation, per-tenant RBAC/quotas), STIX/TAXII 2.1
feed ingestion, Neo4j IOC relationship graph, cross-investigation learning,
compliance reporting. See `ROADMAP.md` v0.5.

---

## Section 4 — Sequencing & Definition of Done

### Recommended order

```
B1 → B2 → B3            deploy succeeds and the app starts (critical path)
   ↓
B4 + B5 (+ PR-B #101)   scheduler runs in K8s; an admin can log in
   ↓
B6 + B7                 continuous staging deploys; hardened defaults
   ↓
v0.4 P0/P1              real connectors, JWT revocation, deep health, CORS
   ↓
Phase 6 Waves 0→3       hunting features (PR-A … PR-J)
   ↓
Phase 5                 enterprise
```

### Definition of Done — first production deploy

- [x] **B1** Backend image imports `btagent_agents` + `btagent_engine` (and runs).
- [x] **B2** Tagging `vX.Y.Z` builds + pushes versioned backend/frontend images.
- [x] **B3** `helm install/upgrade` runs `alembic upgrade head` before rollout;
      `docker compose up` does the same via the `migrate` one-shot.
- [x] **B4** Scheduler Deployment runs in-cluster; arq cron jobs register.
- [x] **B5** Admin can log in via a documented, non-leaking bootstrap
      (`bt create-admin`).
- [ ] **B6** Staging cluster wired; merges to `main` deploy to staging.
- [x] **B7** Prod nginx (HSTS/CSP), restricted CORS, external-secrets in place.
      (TLS termination stays manual — see B7 above.)
- [ ] `BTAGENT_MOCK_CONNECTORS=false` with at least one real connector (#100 P0).
- [ ] Prod smoke test (`/api/health`) green; PG backup CronJob scheduled.

---

## Section 5 — Verification (per blocker, for the follow-up PRs)

| Blocker | Verification |
|---------|--------------|
| B1 | `docker build -f infra/docker/Dockerfile.backend .` then `docker run --rm <img> python -c "import btagent_backend, btagent_agents, btagent_engine"`. |
| B2 | Push `v0.0.0-rc1` to a fork; confirm build runs and `deploy-prod.yml` `validate` (`docker manifest inspect`) passes. |
| B3 | `helm template infra/helm/btagent \| grep -A30 'kind: Job'`; clean-namespace install brings schema up before pods Ready. On compose: `docker compose -f infra/docker-compose.yml up -d` then `docker compose ps -a` shows `migrate` `Exited (0)` before `backend` started. |
| B4 | `helm template` renders the scheduler Deployment; `kubectl logs deploy/btagent-scheduler` shows arq cron registration. On compose: `docker compose ps` shows `scheduler` healthy. |
| B5 | `docker compose exec -e BTAGENT_SEED_ADMIN_PASSWORD=… backend bt create-admin`, then `POST /api/v1/auth/login` with that password returns 200. Running it with the variable unset must exit 1. |
| B6 | Merge to `main` triggers `deploy-staging.yml`; staging smoke test green. |
| B7 | `curl -I https://<host>` shows HSTS/CSP/X-Frame-Options; cross-origin request from a non-allowed origin is rejected. |
