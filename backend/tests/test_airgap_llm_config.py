"""Backend half of the #506 local-LLM / air-gap config fixes.

Three defects, documented in ``docs/deployment/air-gap.md`` rather than fixed
when #502 surfaced them:

(A) the configured Ollama base URL never reached chat completions, because the
    lifespan built ``LiteLLMClient()`` with no arguments;
(B) there was no explicit "local providers only" switch -- offline correctness
    rested on cloud credentials merely being absent;
(C) the MITRE seed 404 named ``backend/data/``, a directory that does not
    exist, while the route resolves ``backend/btagent_backend/data/``.

Routing behaviour itself is pinned in ``agents/tests/test_llm_router_airgap.py``
(that is where the router lives). What is asserted here is the *backend* side:
the settings exist with a fail-safe default, the lifespan threads them into the
client, and the seed error text tells the truth.

No egress: nothing here calls a provider.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from btagent_backend.api.v1.mitre import _DEFAULT_STIX_PATH, _STIX_DIR_HINT
from btagent_backend.config import Settings
from btagent_backend.main import build_live_llm_client
from tests.helpers import auth_header

# --------------------------------------------------------------------------- #
# (A) + (B) settings exist, default safely, and reach the router
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _clean_llm_env(monkeypatch):
    """Isolate from ambient config so a "default" assertion means the default."""
    monkeypatch.delenv("BTAGENT_LOCAL_LLM_ONLY", raising=False)
    monkeypatch.delenv("BTAGENT_OLLAMA_BASE_URL", raising=False)


def test_local_llm_only_defaults_off():
    """Default OFF, so connected deployments keep today's routing."""
    assert Settings().local_llm_only is False


def test_local_llm_only_reads_its_env_var(monkeypatch):
    monkeypatch.setenv("BTAGENT_LOCAL_LLM_ONLY", "true")
    assert Settings().local_llm_only is True


def test_live_client_uses_the_configured_ollama_base_url():
    """(A) the real call site: the base URL must reach the chat router.

    ``Settings`` is constructed directly (not ``get_settings()``) so the
    assertion is about the wiring, not about whatever the test process has in
    its environment.
    """
    settings = Settings(ollama_base_url="http://ollama.enclave.local:11434")
    client = build_live_llm_client(settings)
    assert client.router.ollama_base_url == "http://ollama.enclave.local:11434"


def test_live_client_uses_the_configured_local_only_switch():
    """(B) the switch is honoured, and OFF stays OFF."""
    assert build_live_llm_client(Settings(local_llm_only=True)).router.local_only is True
    assert build_live_llm_client(Settings(local_llm_only=False)).router.local_only is False


def test_live_client_default_ollama_base_url_is_loopback():
    """An operator who sets nothing gets the documented loopback default."""
    assert build_live_llm_client(Settings()).router.ollama_base_url == "http://localhost:11434"


# --------------------------------------------------------------------------- #
# (C) the MITRE seed 404 names the directory the code actually resolves
# --------------------------------------------------------------------------- #


def test_seed_hint_matches_the_resolved_directory():
    """The hint is derived from the resolved path, so it cannot drift again."""
    assert _STIX_DIR_HINT == "backend/btagent_backend/data/"
    assert str(_DEFAULT_STIX_PATH.parent).endswith(_STIX_DIR_HINT.rstrip("/"))
    assert _DEFAULT_STIX_PATH.name == "enterprise-attack.json"


async def test_seed_404_message_names_the_real_path(client: AsyncClient, admin_token: str):
    """The bundle is not vendored, so the 404 branch is the live one here.

    Asserting on the rendered response (not just the constant) is the point:
    the defect was in the operator-facing text at exactly the moment they are
    troubleshooting an offline data refresh.
    """
    if _DEFAULT_STIX_PATH.exists():  # pragma: no cover - only if a bundle is dropped in
        pytest.skip("STIX bundle present; the 404 branch is unreachable")

    resp = await client.post("/api/v1/mitre/seed", headers=auth_header(admin_token))
    assert resp.status_code == 404, resp.text

    detail = resp.json()["detail"]
    assert "backend/btagent_backend/data/" in detail
    # The old, misleading directory must be gone.
    assert "in backend/data/" not in detail
    assert str(_DEFAULT_STIX_PATH) in detail
