# Air-Gapped / Offline Deployment

**Sovereign Pack (#502).** A documented, reproducible BTagent install that runs
with **zero egress** and can be evidenced to a reviewer.

This is a packaging and verification guide, not a new feature. BTagent already
has no hard cloud dependency: every connector is mock-first, LLM routing
supports a local Ollama/vLLM endpoint, secrets resolve through indirection
rather than being baked in, and the audit chain and RBAC are self-contained.
What this document adds is the *procedure* and the *evidence*.

> **Scope note.** Nothing here pursues or claims any accreditation. It gives an
> operator a repeatable offline install and gives a reviewer artifacts to look
> at. Control-to-framework mapping lives in
> [`docs/compliance/controls-mapping.md`](../compliance/controls-mapping.md).

---

## 1. What "zero egress" means here — and what it does not

**The claim.** In the default posture — `BTAGENT_MOCK_CONNECTORS=true`, a
local or mock LLM, and a local embedding provider — the application makes no
outbound network calls.

**The evidence.** [`backend/tests/test_zero_egress.py`](../../backend/tests/test_zero_egress.py),
which runs on every CI push. It instruments `socket`, `httpx`, `aiohttp` and
`urllib` (see [`backend/tests/egress_guard.py`](../../backend/tests/egress_guard.py))
so that any non-loopback destination raises, then exercises an investigation
create through the real route stack, a connector query on both connector tiers,
a CTI enrichment lookup, an embedding call (provider factory, `/knowledge`
ingest, and #482 semantic memory), and a reasoning call. Two canary tests
assert the instrumentation still bites — including one that points *real
product code* (the hosted OpenAI embedding provider) off-box and requires it to
be blocked — so the suite cannot rot into a vacuous pass.

**What that test does not prove:**

| Not covered | Why it matters |
|---|---|
| Anything outside the Python process | A sidecar, a base-image entrypoint, a package post-install hook or a native extension opening its own socket is invisible to it. |
| Code paths the test does not walk | It proves the exercised paths are clean. Unwalked code is unproven. |
| Non-default postures | It says nothing about a deployment that opts into live connectors or a hosted LLM. That is an operator decision. |
| Container, host and network layers | It is evidence about the *application*, not about the node. |

**Therefore: enforce egress at the network layer regardless.** The application
test is corroborating evidence, not the control. The control is
`networkPolicy.allowInternetEgress=false` (Kubernetes) plus a host/perimeter
deny rule. If you take one thing from this document, take that.

---

## 2. Bundle and transfer

Everything is assembled on the connected side, verified on arrival, and
installed offline.

### 2.1 Build the bundle (connected side)

```bash
# Optional: download the CI 'sbom-cyclonedx' artifact into ./sbom first so the
# component inventory travels with the bundle.
infra/scripts/airgap-bundle.sh ./btagent-airgap-bundle
```

[`infra/scripts/airgap-bundle.sh`](../../infra/scripts/airgap-bundle.sh):

1. pulls every container image and resolves it to its **registry digest**
   (`repo@sha256:…`) — the local image ID is deliberately *not* used, because
   it is a config-blob hash the far side cannot pull by;
2. `docker save`s the layers into `images/btagent-images.tar`;
3. copies the offline deployment assets (compose file, env template, nginx
   config, Helm chart, this guide);
4. writes `images.env` (ready to paste into `.env.airgap`) and a `MANIFEST.txt`
   carrying the digests, the git commit, and SHA-256 checksums of every file.

The script refuses to continue if an image has no registry digest — a
locally-built image that was never pushed cannot be verified downstream, and
silently bundling one would defeat the point.

### 2.2 Add what the script deliberately does not fetch

This repository does **not** vendor large model binaries, and the script does
not download them. Add them by hand:

```
btagent-airgap-bundle/
├── images/btagent-images.tar
├── images.env                     # digest-pinned refs
├── deploy/                        # compose + helm + nginx + this guide
├── sbom/                          # CycloneDX, from CI
├── models/                        # you add this — see §4
└── reference/                     # you add this — see §5
```

Re-generate the checksum section of `MANIFEST.txt` after adding them.

### 2.3 Verify and load (offline side)

```bash
cd btagent-airgap-bundle
shasum -a 256 -c <(grep -A10000 'File checksums' MANIFEST.txt | tail -n +2)

docker load -i images/btagent-images.tar

# Re-tag / push into the enclave registry if you run Kubernetes.
```

Confirm the digests you loaded match `images.env` before going further —
that check is the whole reason the bundle records them.

---

## 3. Install

### 3.1 Docker Compose

[`infra/docker-compose.airgap.yml`](../../infra/docker-compose.airgap.yml) is a
**standalone** stack, not an overlay on `docker-compose.yml`. That is
deliberate: the dev compose file carries `build:` stanzas, and an overlay that
leaves them in place will rebuild from source — pulling base images — the
moment a local layer is missing. The air-gap stack is `image:`-only and every
ref comes from the env file, so a half-filled env file fails loudly instead of
starting something whose provenance you cannot state.

```bash
cd infra
cp .env.airgap.example .env.airgap
# paste the IMAGE_* lines from the bundle's images.env, fill every REPLACE_ME
docker compose -f docker-compose.airgap.yml --env-file .env.airgap up -d
```

Then run migrations and bootstrap the first admin:

```bash
docker compose -f docker-compose.airgap.yml --env-file .env.airgap \
  exec backend alembic upgrade head

# The admin password comes from BTAGENT_SEED_ADMIN_PASSWORD; outside test mode
# the seed refuses to invent one rather than minting an unrecoverable secret.
# See backend/btagent_backend/auth/bootstrap.py.
```

Compose networks do not confine the host, and this stack publishes ports, so
`internal: true` is not used and is not claimed. Confining the host is a host
firewall / perimeter job.

### 3.2 Kubernetes (Helm)

[`infra/helm/btagent/values-airgap.yaml`](../../infra/helm/btagent/values-airgap.yaml):

```bash
helm upgrade --install btagent infra/helm/btagent \
  -f infra/helm/btagent/values-airgap.yaml \
  --set image.digest=sha256:<backend-digest> \
  --set frontendImage.digest=sha256:<frontend-digest>
```

Two chart capabilities were added for this and both default to the previous
behaviour, so connected installs are unchanged:

* **`image.digest` / `frontendImage.digest`** — when set, the image ref becomes
  `repository@sha256:…` instead of `repository:tag`, for the backend
  Deployment, the frontend Deployment, the scheduler Deployment and the
  migration Job. Empty by default.
* **`networkPolicy.allowInternetEgress`** — `true` by default (hosted LLM
  providers and live connectors need it). Setting it to `false` **removes the
  `0.0.0.0/0` TCP/443 egress rule entirely**, leaving the backend with DNS plus
  in-namespace PostgreSQL / Redis / model-server traffic. `networkPolicy.extraBackendEgress`
  appends rules for an in-enclave service outside the release namespace.

The stock chart's ingress annotations request an ACME cluster issuer, which
cannot work without egress. `values-airgap.yaml` drops it; terminate TLS with a
certificate issued by the enclave CA and pre-create the referenced secret.

### 3.3 What changes when you enable live connectors

`BTAGENT_MOCK_CONNECTORS=true` is the shipped posture and the one the
zero-egress test verifies. Setting it to `false` is a deliberate step, taken
only after every connector you intend to use is bound to a system **inside**
the enclave. What changes:

* **Programmatic connectors** (`agents/btagent_agents/mcp/servers/*`, most of
  `engine/btagent_engine/integrations/*`) raise `NotImplementedError` on their
  live paths. They fail loudly rather than silently returning fixtures — so a
  half-migrated install is obvious, not subtly wrong.
* **Declarative connectors** (`engine/btagent_engine/integrations/_declarative.py`)
  add a second gate: with mocks off, a capability whose routing spec has
  `live_egress_approved=false` still raises `NotImplementedError`.
  `DeclarativeRunner._select_sender()` is the single place that decides, so
  there is one thing to audit rather than one per connector.
* **Manifest policy still applies.** `ConnectorPolicyMiddleware`
  (`engine/btagent_engine/middleware/connector_policy.py`) enforces the
  capability's declared `tlp_egress` ceiling and `hitl_required` flag before
  dispatch, for declarative and programmatic capabilities alike.
* **Embeddings change too.** `mock_connectors=True` short-circuits the
  embedding factory *before* it looks at `embedding_provider` — so turning
  mocks off is also what makes your configured local embedding model take
  effect. Read §4.2 before you do it.
* **Re-run the verification checklist** (§7). The zero-egress test asserts the
  *default* posture; it does not certify yours.

---

## 4. Local models — LLM and embeddings

### 4.1 The embedding model is not optional

Two features degrade or fail without a working embedding provider:

* **RAG knowledge search** — `/knowledge/ingest` and `/knowledge/query`
  (`backend/btagent_backend/services/knowledge_service.py`), and
* **#482 semantic memory recall** — `MemoryService.recall_semantic`
  (`backend/btagent_backend/services/memory_service.py`).

### 4.2 `MockEmbeddingService` must not be relied on in production

`MockEmbeddingService` (`backend/btagent_backend/services/embedding_service.py`)
generates a deterministic vector by expanding a SHA-256 hash of the input text.
It is stable and dependency-free, which makes it excellent for tests — and
worthless for retrieval, because hash expansion carries **no semantic
relationship** between similar texts. Knowledge search and semantic recall will
return confidently-ranked nonsense.

It can be selected three ways. Know all three:

1. `mock_connectors=True` (`BTAGENT_MOCK_CONNECTORS=true`) — the factory
   returns the mock unconditionally, *before* looking at
   `embedding_provider`. **This is the trap**: the air-gapped default posture
   sets exactly this flag, so an install that stops at "mocks on, no egress,
   done" silently ships mock embeddings.
2. `embedding_provider=openai` with no API key, in `env` `dev` or `test` — the
   factory logs a warning and falls back to the mock.
3. Explicit construction in tests.

Outside `dev`/`test` with mocks off and no key, the factory raises
`EmbeddingProviderError` and the route returns 503 — it does not fall back.

**Verify which provider you actually got.** The backend logs the choice at
startup/first use (`Using Ollama embedding service: …` / `Using mock embedding
service`), and every service exposes `provider_name`. If your production log
says `mock`, retrieval is not working no matter how good the results look.

### 4.3 Configure a real local embedding model

```bash
BTAGENT_EMBEDDING_PROVIDER=ollama
BTAGENT_EMBEDDING_MODEL=nomic-embed-text     # REQUIRED — see below
BTAGENT_OLLAMA_BASE_URL=http://ollama:11434
```

> **Both keys, every time.** `Settings.embedding_model` defaults to
> `text-embedding-3-small`, an OpenAI model name. Because the factory reads
> that attribute for the Ollama branch too, setting only
> `BTAGENT_EMBEDDING_PROVIDER=ollama` hands `text-embedding-3-small` to your
> local server and every embed call fails. This is a real sharp edge; it is
> called out rather than papered over.

Dimensions: the vector columns are 1536-wide (`EMBEDDING_DIM`).
`OllamaEmbeddingService` zero-pads shorter vectors (e.g. `nomic-embed-text` at
768) and truncates longer ones. Zero-padding both sides of a comparison leaves
cosine ranking unchanged, so a smaller local model is usable — but **do not
change models after ingest without re-embedding**: vectors from two different
models are not comparable, and mixed-model stores rank badly with no error.

### 4.4 Seed the model weights offline

`ollama pull` needs the internet, so pull on the connected side and carry the
volume:

```bash
# Connected side
docker run -d --name ollama-seed -v ollama-seed-data:/root/.ollama ollama/ollama
docker exec ollama-seed ollama pull llama3.3
docker exec ollama-seed ollama pull nomic-embed-text
docker run --rm -v ollama-seed-data:/data -v "$PWD:/out" alpine \
  tar czf /out/models/ollama-models.tar.gz -C /data .

# Offline side, before first start of the stack
docker volume create infra_ollama-data
docker run --rm -v infra_ollama-data:/data -v "$PWD/models:/in" alpine \
  tar xzf /in/ollama-models.tar.gz -C /data
```

Model licences are the operator's responsibility. This repository vendors no
weights.

### 4.5 Enabling the local LLM — and a limitation to plan around

Set `BTAGENT_MOCK_LLM=false` to register the LiteLLM-backed client
(`backend/btagent_backend/main.py`). The flag is fail-safe: only the literal
string `false` enables it, so a typo or empty value leaves the mock on and
cannot cause egress.

Two things to know before you flip it:

* **The Ollama base URL used for chat completions is not read from settings.**
  `LiteLLMClient` constructs `TLPAwareLLMRouter()` with no arguments, and that
  router's `ollama_base_url` defaults to `http://localhost:11434`
  (`agents/btagent_agents/llm/router.py`). `BTAGENT_OLLAMA_BASE_URL` is honoured
  by the *embedding* service but not by this path. Until that is wired,
  arrange for the model server to be reachable at `localhost:11434` from the
  backend container — e.g. co-locate it in the same pod/network namespace, or
  publish it there. Verify with a real completion; do not assume.
* **Provider routing is by static preference, not by credential availability.**
  `TLPAwareLLMRouter.resolve` picks the first provider in the allow-list for the
  request's TLP. For `TLP.RED` and `TLP.AMBER_STRICT` that list is Ollama-first
  (RED is Ollama-*only*), which is what you want. For `TLP.GREEN` the list
  starts with Anthropic, so a GREEN request resolves to a hosted provider and
  then **fails** with no credentials — it does not silently fall back to
  Ollama, and it does not silently succeed either. In an enclave, either
  classify work at `AMBER_STRICT`/`RED`, or pass `preferred_provider="ollama"`
  (honoured whenever Ollama is in the allow-list for that TLP, which excludes
  plain `AMBER`). There is currently no single "local providers only" switch;
  see *Known gaps*.

---

## 5. Offline reference data

### 5.1 MITRE ATT&CK

Keyword-based ATT&CK mapping works with no data files at all — the technique
set is embedded in `engine/btagent_engine/data/mitre_mapper.py`. The full
matrix (tactics / techniques / groups tables, coverage analysis, Navigator
export) is loaded from a vendored STIX bundle.

**Refresh procedure:**

1. On the connected side, download the ATT&CK Enterprise STIX 2.1 bundle
   (`enterprise-attack.json`) from the MITRE CTI distribution, record its
   SHA-256, and add it to the transfer bundle under `reference/`.
2. Offline, place it at **`backend/btagent_backend/data/enterprise-attack.json`**
   inside the backend container or on a mounted volume. (The route's 404
   message says "backend/data/" — the path the code actually resolves is
   `btagent_backend/data/`; trust the code.)
3. Call the admin-only reload:

   ```bash
   curl -X POST https://<host>/api/v1/mitre/seed \
     -H "Authorization: Bearer <admin token>"
   ```

   Requires the `mitre:seed` permission (admin). The response reports upserted
   tactic / technique / group counts. The loader upserts, so re-running is
   safe and is the normal way to apply a new ATT&CK release.
4. Record the bundle version and SHA-256 in your change log — the version of
   ATT&CK an assessment was run against is part of the assessment.

Cadence: MITRE ships roughly twice a year. Refresh on their release, not on a
calendar.

### 5.2 STIX / IOC exchange

IOC import and export are file-based and need no network:

* `POST /api/v1/iocs/import` (STIX bundle in the JSON body) and
  `POST /api/v1/iocs/import/stix` (file upload) — parse a STIX 2.1 bundle into
  IOCs;
* `GET /api/v1/iocs/export?investigation_id=…&tlp_level=…` — emit a bundle.

Export is TLP-gated: the shared baseline blocks TLP:RED outright, and the
org-policy guard can further deny an export the baseline would have allowed
(`backend/btagent_backend/services/tlp_egress_guard.py`). Both run inside the
enclave; "egress" there means *out of the investigation context*, which is a
classification control, not a network one.

---

## 6. Dependency manifest and SBOM

Python dependencies are pinned per workspace package (`shared/`, `engine/`,
`agents/`, `backend/`); the frontend is pinned by `frontend/package-lock.json`
and installed with `npm ci`.

CI job **`sbom`** (`.github/workflows/ci.yml`) produces CycloneDX 1.5 documents
for both trees and uploads them as the `sbom-cyclonedx` artifact (30-day
retention):

* `sbom/btagent-python.cdx.json` — generated with `cyclonedx-py environment`,
  so it reflects the actual installed interpreter environment rather than the
  declared dependency ranges;
* `sbom/btagent-frontend.cdx.json` — generated with `@cyclonedx/cyclonedx-npm`
  over the full installed tree (build-time dependencies included, because a
  supply-chain review of an offline bundle cares about what built the bundle as
  much as what runs in it).

The job is **non-blocking**: SBOM tooling breaks on new interpreter/npm
releases far more often than the code does, and a flaky inventory generator
should not gate merges. It is still real — a verify step fails loudly (with a
step annotation) when a document is missing or has zero components, so a
silently-broken generator is visible rather than invisible.

Download the artifact and carry it in the bundle: inside the enclave you
cannot run `pip download` or `npm audit`, so the inventory has to be generated
on the connected side.

---

## 7. Verification checklist

Run these on the installed system and keep the output.

| # | Check | How |
|---|---|---|
| 1 | Zero-egress test passes on the shipped commit | `pytest backend/tests/test_zero_egress.py -v` |
| 2 | Images match the bundle manifest | `docker image inspect --format '{{index .RepoDigests 0}}' <image>` vs `images.env` |
| 3 | Network policy denies internet egress | `kubectl get networkpolicy <release>-backend -o yaml` — no `0.0.0.0/0` rule |
| 4 | Embedding provider is **not** mock | Backend log line at first embed; must not say `mock` |
| 5 | LLM completion works locally | Run one reasoning task end to end with `BTAGENT_MOCK_LLM=false` |
| 6 | ATT&CK matrix loaded | `GET /api/v1/mitre/techniques` returns a populated matrix |
| 7 | Audit chain verifies | `GET /api/v1/audit/verify` (admin) |
| 8 | No hosted-provider credentials present | Grep the rendered env / secret for `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, … |
| 9 | Perimeter denies egress | From the host: attempt an outbound connection and confirm it fails |

Checks 1–8 are about the application. Check 9 is the one that actually holds
the line.

---

## 8. Known gaps

Stated plainly, because a deployment guide that hides its sharp edges is worse
than none.

* **No single "local providers only" switch.** TLP-based routing gets you there
  for `RED`/`AMBER_STRICT`; `GREEN` and `WHITE` still list hosted providers
  first and fail (loudly) without credentials.
* **`BTAGENT_OLLAMA_BASE_URL` is not honoured by the chat-completion path** —
  only by embeddings. See §4.5.
* **`mock_connectors=True` overrides the embedding provider**, so the default
  air-gapped posture selects mock embeddings unless you deliberately turn
  connector mocks off after wiring in-enclave connectors. See §4.2.
* **The MITRE seed 404 message names the wrong directory** (`backend/data/`
  rather than `btagent_backend/data/`).
* **Model weights are not vendored** and never will be in this repository.
* **No accreditation is claimed or pursued.** See
  [`docs/compliance/controls-mapping.md`](../compliance/controls-mapping.md)
  for what the platform actually implements.
