"""Unit tests for the Git MCP connector (#113 back half, slice 3).

Mock-first like the SIEM/identity connectors: the mock path validates inputs
exactly as a live provider would (empty/duplicate files rejected), records
PRs in an inspectable ledger, and returns a deterministic commit fingerprint.
Live mode refuses without a resolvable repo token; the token never leaks
into repr/logs; the connector registers with lazy discovery.
"""

from __future__ import annotations

import pytest

from btagent_agents.mcp.servers.git_mcp import (
    MOCK_PR_LEDGER,
    GitMCPServer,
    _redact_secret,
    _slugify_branch,
)

_FILES = [
    {"path": "rules/t1071.001/malicious_c2_ip.yml", "content": "title: C2 IP\n"},
    {"path": "rules/t1566.002/phishing_domain.yml", "content": "title: Phish\n"},
]


@pytest.fixture(autouse=True)
def _clean_ledger() -> None:
    MOCK_PR_LEDGER.clear()


class TestMockOpenPR:
    async def test_open_pr_returns_envelope_and_records_ledger(self) -> None:
        server = GitMCPServer(mock_mode=True)
        out = await server.git_open_detection_pr(
            "Detections/CTI 2026-07-15", "detections: 2 rules", "body", _FILES
        )
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["branch"] == "detections/cti-2026-07-15"
        assert out["pr_url"].endswith("/pull/1")
        assert out["files_written"] == [f["path"] for f in _FILES]
        assert len(MOCK_PR_LEDGER) == 1
        assert MOCK_PR_LEDGER[0]["title"] == "detections: 2 rules"

    async def test_commit_fingerprint_is_deterministic(self) -> None:
        server = GitMCPServer(mock_mode=True)
        a = await server.git_open_detection_pr("b", "t", "", _FILES)
        b = await server.git_open_detection_pr("b", "t", "", _FILES)
        assert a["commit"] == b["commit"]
        assert a["pr_number"] != b["pr_number"]

    async def test_empty_files_rejected(self) -> None:
        server = GitMCPServer(mock_mode=True)
        with pytest.raises(ValueError, match="at least one rule file"):
            await server.git_open_detection_pr("b", "t", "", [])

    async def test_duplicate_paths_rejected(self) -> None:
        server = GitMCPServer(mock_mode=True)
        dup = [_FILES[0], dict(_FILES[0])]
        with pytest.raises(ValueError, match="Duplicate file path"):
            await server.git_open_detection_pr("b", "t", "", dup)

    async def test_empty_content_rejected(self) -> None:
        server = GitMCPServer(mock_mode=True)
        with pytest.raises(ValueError, match="non-empty path and content"):
            await server.git_open_detection_pr(
                "b", "t", "", [{"path": "rules/x.yml", "content": "  "}]
            )


class TestLiveModeAndSecrets:
    async def test_live_mode_without_token_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_GIT_TOKEN", raising=False)
        server = GitMCPServer(mock_mode=False, token_ref="${env:BTAGENT_GIT_TOKEN}")
        with pytest.raises(NotImplementedError):
            await server.git_open_detection_pr("b", "t", "", _FILES)

    def test_repr_omits_token(self) -> None:
        server = GitMCPServer(mock_mode=False, token_ref="${env:BTAGENT_GIT_TOKEN}")
        assert "token" not in repr(server).lower() or "ref" in repr(server).lower()

    def test_redact_secret(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        out = _redact_secret("ghp_0123456789abcdefghij")
        assert out.startswith("[redacted:git-token:")
        assert "ghp_0123456789" not in out

    def test_construction_does_not_resolve_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[str] = []
        monkeypatch.setattr(
            "btagent_agents.mcp.servers.git_mcp.resolve_secret",
            lambda ref: calls.append(ref) or "",
        )
        GitMCPServer(mock_mode=False)
        assert calls == []


class TestBranchSlug:
    def test_slugify(self) -> None:
        assert _slugify_branch("Detections/CTI July!") == "detections/cti-july"
        assert _slugify_branch("///") == "detection-update"


def test_git_server_registered_in_discovery() -> None:
    from btagent_agents.mcp import discovery

    discovery._ensure_servers_loaded()
    assert "git" in discovery._SERVER_CLASSES
    meta = GitMCPServer(mock_mode=True).get_tool_metadata()
    assert [m["name"] for m in meta] == ["git_open_detection_pr"]
    assert meta[0]["server_id"] == "git"
