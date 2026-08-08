"""Zero-egress verification for the default (sovereign) posture — #502.

The Sovereign Pack's central claim is that BTagent, in its default posture,
runs with **no outbound network calls** — which is what makes an air-gapped
install possible at all. This module makes that claim executable so it cannot
rot silently.

The posture under test
----------------------
* ``BTAGENT_MOCK_CONNECTORS=true`` — every SIEM/EDR/CTI connector serves
  deterministic fixtures; the live paths raise ``NotImplementedError`` before
  building any client.
* ``BTAGENT_MOCK_LLM=true`` — the engine's ``LLMCallNode`` echoes locally
  instead of dialling a provider. (An air-gapped install substitutes a
  *local* Ollama/vLLM endpoint on loopback; the guard treats loopback as
  in-enclave and permits it, so both shapes pass.)
* Embeddings resolve through ``get_embedding_service``, which under
  ``mock_connectors=True`` returns the deterministic ``MockEmbeddingService``.
  See ``docs/deployment/air-gap.md`` — production installs must configure a
  **real local** embedding model, not this mock.

What is asserted
----------------
Each exercise runs inside :class:`~tests.egress_guard.EgressGuard`, which
patches ``socket``, ``httpx``, ``aiohttp`` and ``urllib`` and refuses any
destination that is not loopback. Coverage here:

1. an investigation create through the real FastAPI route stack;
2. a connector query on both connector tiers — the agents-side MCP server
   (``splunk_search``) and an engine integration node (GreyNoise);
3. an enrichment lookup (VirusTotal IP/hash nodes);
4. an embedding call, three ways: the provider factory, the ``/knowledge``
   ingest+query route, and #482 semantic memory record/recall;
5. a reasoning (LLM) call through the engine node.

What it does NOT prove — stated plainly
---------------------------------------
* **Process-local only.** It sees this Python process. A sidecar container, a
  base-image entrypoint, a package post-install hook or a native extension
  opening its own socket is invisible to it. Network-policy enforcement at the
  cluster/host layer remains the real control; this is evidence about the
  application, not about the node.
* **Path-local only.** It proves the paths exercised above make no egress.
  Code these tests never walk is unproven by them.
* **Default posture only.** It says nothing about a deployment that opts into
  live connectors or a hosted LLM — that is an operator decision, and the
  air-gap guide's whole point is not to make it.
* It does not verify TLS, certificate pinning, or DNS configuration.

The two canary tests below assert the guard *fires* on a deliberate outbound
call. If a refactor ever neuters the patching, they go red rather than letting
every other test in this file pass vacuously.
"""

from __future__ import annotations

import socket

import pytest
import pytest_asyncio
from btagent_shared.types.config import TLP, ModelTier
from btagent_shared.utils.ids import generate_id
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.config import get_settings
from btagent_backend.db.models import OrganizationRow, UserRow
from tests.egress_guard import EgressGuard, EgressViolation, is_loopback_host

_PASSWORD = "Sovereign-P@ss-502!"


# --------------------------------------------------------------------------- #
# Posture fixture
# --------------------------------------------------------------------------- #


@pytest.fixture()
def sovereign_posture(monkeypatch):
    """Put the process into the documented default (air-gapped) posture.

    Set explicitly rather than relied upon implicitly: ``Settings.mock_connectors``
    defaults to ``False`` (production-safe — a prod box must never silently
    serve fixtures), while the engine/agents connector tier reads
    ``BTAGENT_MOCK_CONNECTORS`` with a ``true`` default. The sovereign posture
    is the one where the env var is set, so the test sets it. No product
    default is changed by this fixture.
    """
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    monkeypatch.setenv("BTAGENT_EMBEDDING_PROVIDER", "ollama")
    monkeypatch.setenv("BTAGENT_OPENAI_API_KEY", "")
    get_settings.cache_clear()
    try:
        yield get_settings()
    finally:
        # monkeypatch restores the env; clear again so the cached Settings
        # returns to the suite-wide baseline for every later test.
        get_settings.cache_clear()


@pytest_asyncio.fixture()
async def sovereign_org(db_session: AsyncSession) -> dict:
    """A dedicated org + admin, so nothing here collides with the shared DB."""
    org_id = generate_id("org")
    db_session.add(OrganizationRow(id=org_id, name=org_id.replace("_", "-")))
    await db_session.commit()

    suffix = generate_id("usr").split("_", 1)[1]
    user = UserRow(
        id=generate_id("usr"),
        org_id=org_id,
        username=f"sovereign_{suffix}",
        email=f"sovereign_{suffix}@btagent.test",
        password_hash=hash_password(_PASSWORD),
        role="admin",
    )
    db_session.add(user)
    await db_session.commit()

    token = create_token_pair(user.id, user.username, user.role, org_id=org_id).access_token
    return {"org_id": org_id, "user": user, "headers": {"Authorization": f"Bearer {token}"}}


# --------------------------------------------------------------------------- #
# Canaries — the guard must actually bite
# --------------------------------------------------------------------------- #


def test_guard_blocks_a_raw_socket_to_a_public_address():
    """A deliberate off-box TCP connect is refused at the socket layer."""
    with EgressGuard() as guard:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(EgressViolation):
                # TEST-NET-3 (RFC 5737) — documentation range, never routed.
                sock.connect(("203.0.113.10", 443))
        finally:
            sock.close()
    assert guard.violations, "guard recorded no violation for a public-address connect"


async def test_guard_blocks_httpx_and_dns_for_an_external_host():
    """An external HTTP call is refused before the request leaves httpx, and a
    bare DNS lookup for an external name is refused too (a resolver query is
    itself egress)."""
    import httpx

    with EgressGuard() as guard:
        async with httpx.AsyncClient() as external:
            with pytest.raises(EgressViolation):
                await external.get("https://example.invalid/v1/models")

        with pytest.raises(EgressViolation):
            socket.getaddrinfo("example.invalid", 443)

    layers = {v.layer for v in guard.violations}
    assert "httpx.AsyncClient.send" in layers
    assert "socket.getaddrinfo" in layers


async def test_guard_catches_real_product_code_that_would_egress():
    """The strongest anti-rot check: point *real* product code off-box and the
    guard must catch it.

    ``OpenAIEmbeddingService`` is the hosted-provider branch of the embedding
    factory — precisely the thing an air-gapped install must not select. Under
    the guard its outbound POST is refused, which proves the instrumentation
    sits on the path this codebase actually uses rather than on a synthetic one.
    """
    from btagent_backend.services.embedding_service import OpenAIEmbeddingService

    with EgressGuard() as guard:
        with pytest.raises(EgressViolation):
            await OpenAIEmbeddingService(api_key="sk-not-a-real-key").generate_embeddings(
                ["would this leave the enclave?"]
            )

    assert any("api.openai.com" in v.target for v in guard.violations)


def test_guard_permits_loopback():
    """Loopback is in-enclave (local PostgreSQL / Redis / Ollama) and allowed."""
    assert is_loopback_host("127.0.0.1")
    assert is_loopback_host("::1")
    assert is_loopback_host("localhost")
    assert not is_loopback_host("api.openai.com")
    assert not is_loopback_host("192.0.2.7")
    # A non-loopback name is not assumed local just because it looks internal.
    assert not is_loopback_host("btagent.internal")


# --------------------------------------------------------------------------- #
# 1. Investigation create — full route stack
# --------------------------------------------------------------------------- #


async def test_investigation_create_makes_no_outbound_calls(
    client: AsyncClient, sovereign_posture, sovereign_org: dict
):
    with EgressGuard() as guard:
        resp = await client.post(
            "/api/v1/investigations",
            headers=sovereign_org["headers"],
            json={
                "title": "Air-gapped triage smoke",
                "description": "Zero-egress verification case.",
                "severity": "medium",
                "tlp_level": "green",
            },
        )
        assert resp.status_code == 201, resp.text

        listing = await client.get("/api/v1/investigations", headers=sovereign_org["headers"])
        assert listing.status_code == 200, listing.text

    guard.assert_no_egress()


# --------------------------------------------------------------------------- #
# 2. Connector query — both connector tiers
# --------------------------------------------------------------------------- #


async def test_mcp_connector_query_makes_no_outbound_calls(sovereign_posture):
    """agents-tier MCP server (Splunk) serves fixtures with no socket use."""
    from btagent_agents.mcp.servers.splunk_mcp import SplunkMCPServer

    server = SplunkMCPServer()
    with EgressGuard() as guard:
        results = await server.splunk_search("index=network | head 5")
        alerts = await server.splunk_get_alerts(5)

    guard.assert_no_egress()
    assert results, "mock connector returned nothing — exercise did not run"
    assert alerts, "mock connector returned nothing — exercise did not run"


async def test_engine_connector_node_makes_no_outbound_calls(sovereign_posture):
    """engine-tier integration node (GreyNoise) serves fixtures locally."""
    from btagent_engine import NodeContext, Runner
    from btagent_engine.integrations.greynoise import (
        GreyNoiseLookupIPInput,
        GreyNoiseLookupIPNode,
    )

    ctx = NodeContext(run_id="r_egress", org_id="org_default", investigation_id="inv_egress")
    with EgressGuard() as guard:
        out = await Runner().execute(
            GreyNoiseLookupIPNode(), GreyNoiseLookupIPInput(ip="185.220.101.42"), ctx
        )

    guard.assert_no_egress()
    assert out.seen is True


# --------------------------------------------------------------------------- #
# 3. Enrichment
# --------------------------------------------------------------------------- #


async def test_enrichment_lookup_makes_no_outbound_calls(sovereign_posture):
    """CTI enrichment (VirusTotal IP + hash) stays in-process under mocks."""
    from btagent_engine import NodeContext, Runner
    from btagent_engine.integrations.virustotal import (
        VirusTotalHashLookupInput,
        VirusTotalHashLookupNode,
        VirusTotalIPLookupInput,
        VirusTotalIPLookupNode,
    )

    ctx = NodeContext(run_id="r_enrich", org_id="org_default", investigation_id="inv_egress")
    runner = Runner()
    with EgressGuard() as guard:
        ip_out = await runner.execute(
            VirusTotalIPLookupNode(), VirusTotalIPLookupInput(ip="185.220.101.42"), ctx
        )
        hash_out = await runner.execute(
            VirusTotalHashLookupNode(),
            VirusTotalHashLookupInput(hash="44d88612fea8a8f36de82e1278abb02f"),
            ctx,
        )

    guard.assert_no_egress()
    assert ip_out is not None and hash_out is not None


# --------------------------------------------------------------------------- #
# 4. Embeddings — factory, RAG route, semantic memory (#482)
# --------------------------------------------------------------------------- #


async def test_embedding_factory_makes_no_outbound_calls(sovereign_posture):
    """``mock_connectors=True`` resolves to the deterministic local embedder."""
    from btagent_backend.services.embedding_service import (
        MockEmbeddingService,
        get_embedding_service,
    )

    class _MockPosture:
        mock_connectors = True
        embedding_provider = "ollama"
        embedding_model = "nomic-embed-text"
        ollama_base_url = "http://localhost:11434"
        openai_api_key = ""
        env = "test"

    with EgressGuard() as guard:
        svc = get_embedding_service(_MockPosture())
        vectors = await svc.generate_embeddings(["lateral movement via psexec"])

    guard.assert_no_egress()
    assert isinstance(svc, MockEmbeddingService)
    assert len(vectors) == 1 and len(vectors[0]) == 1536


async def test_knowledge_ingest_makes_no_outbound_calls(
    client: AsyncClient, sovereign_posture, sovereign_org: dict
):
    """The RAG write path (chunk → embed → store) never leaves the box.

    Exercised through the real route wiring, including the lazily-built
    embedding provider — the same code a production install runs, with the
    provider pointed at a local model instead of a hosted API.

    Scope note: the *read* half (``POST /knowledge/query``) is not exercised
    here because ``KnowledgeService.hybrid_search`` issues pgvector operators
    (``<=>``) that the SQLite unit-test database cannot parse. The query-side
    embedding call is covered instead by
    ``test_embedding_factory_makes_no_outbound_calls``, which drives the same
    provider with query text.
    """
    with EgressGuard() as guard:
        ingest = await client.post(
            "/api/v1/knowledge/ingest",
            headers=sovereign_org["headers"],
            json={
                "title": "Offline runbook",
                "content": "Contain the host, collect volatile memory, then image the disk.",
                "source_type": "runbook",
            },
        )
        assert ingest.status_code in (200, 201), ingest.text

        listing = await client.get("/api/v1/knowledge/documents", headers=sovereign_org["headers"])
        assert listing.status_code == 200, listing.text

    guard.assert_no_egress()


async def test_semantic_memory_makes_no_outbound_calls(
    db_session: AsyncSession, sovereign_posture, sovereign_org: dict
):
    """#482 record + semantic recall embed locally.

    ``MemoryService._embed`` swallows provider failures by design (an embedding
    is an optimisation, never a write barrier), so a blocked outbound call
    would degrade silently rather than raise. That is exactly why
    ``assert_no_egress`` re-checks the recorded ledger afterwards.
    """
    from btagent_backend.services.embedding_service import get_embedding_service
    from btagent_backend.services.memory_service import MemoryService

    svc = MemoryService(embedding_factory=lambda: get_embedding_service(sovereign_posture))

    with EgressGuard() as guard:
        row = await svc.record_memory(
            db_session,
            org_id=sovereign_org["org_id"],
            kind="observation",
            subject="host-alpha",
            content="Beaconing to an internal jump box every 300s.",
            tlp_level=TLP.GREEN,
        )
        await db_session.commit()
        recalled = await svc.recall_semantic(
            db_session, sovereign_org["org_id"], "beaconing behaviour", limit=5
        )

    guard.assert_no_egress()
    assert row.id
    assert any(r.id == row.id for r in recalled)


# --------------------------------------------------------------------------- #
# 5. Reasoning / LLM call
# --------------------------------------------------------------------------- #


async def test_llm_call_makes_no_outbound_calls(sovereign_posture):
    """The engine's reasoning node resolves locally under ``BTAGENT_MOCK_LLM``.

    An air-gapped install instead registers a LiteLLM client pointed at a
    loopback Ollama/vLLM endpoint; the guard permits loopback, so the posture
    documented in ``docs/deployment/air-gap.md`` passes this same assertion.
    """
    from btagent_engine import NodeContext
    from btagent_engine.integrations.llm_call import LLMCallInput, LLMCallNode

    ctx = NodeContext(run_id="r_llm_egress", org_id="org_default")
    with EgressGuard() as guard:
        out = await LLMCallNode().run(
            LLMCallInput(messages=[{"role": "user", "content": "summarise this alert"}]),
            ctx,
        )

    guard.assert_no_egress()
    assert out.text.startswith("[mock-llm]")


# --------------------------------------------------------------------------- #
# 6. Local-LLM-only posture (#506)
# --------------------------------------------------------------------------- #


def test_local_llm_only_posture_never_resolves_a_hosted_provider():
    """``BTAGENT_LOCAL_LLM_ONLY=true`` keeps *every* TLP level off the cloud.

    The mock-LLM posture above passes because nothing dials out at all. This
    covers the *next* posture an enclave adopts — ``BTAGENT_MOCK_LLM=false``
    with a local model server — where the old static-preference routing would
    have resolved a GREEN request to Anthropic. ``Settings`` is built directly
    (rather than via the env) so the assertion is about the wiring the lifespan
    uses, and only ``resolve`` runs inside the guard: it is the decision that
    must never name a hosted provider.
    """
    from btagent_agents.llm.router import LOCAL_PROVIDERS, RoutingError

    from btagent_backend.config import Settings
    from btagent_backend.main import build_live_llm_client

    router = build_live_llm_client(
        Settings(local_llm_only=True, ollama_base_url="http://localhost:11434")
    ).router
    assert router.local_only is True

    refused: list[TLP] = []
    with EgressGuard() as guard:
        for tlp in TLP:
            try:
                provider, _ = router.resolve(tlp, ModelTier.STANDARD)
            except RoutingError:
                refused.append(tlp)  # fail closed: refused, not downgraded
                continue
            assert provider in LOCAL_PROVIDERS, f"{tlp} resolved to hosted provider {provider}"

    guard.assert_no_egress()
    # Every TLP rung authorises local inference (the router's AMBER rung used
    # to omit Ollama — a drift bug against the classification hook's ladder,
    # pinned by agents/tests/test_router_hook_tlp_drift.py). Local-only must
    # therefore have no dead zone: a refusal here means a rung lost its local
    # provider again, which would push an enclave operator toward turning the
    # restriction *off* to get work through.
    assert refused == []
