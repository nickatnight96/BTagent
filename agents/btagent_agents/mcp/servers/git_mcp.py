"""Git MCP server connector — detection-repo PR surface (#113 back half, slice 3).

Wraps the single write operation the CTI → Detection pipeline needs: open a
pull request against the org's detection-rule repository carrying one or
more accepted Sigma rules. Deliberately high-level — branch + commit + PR in
one call — because the composer never needs the primitives separately, and a
single call keeps the blast radius reviewable.

Design notes
------------
* **Mock-first.** Defaults to ``BTAGENT_MOCK_CONNECTORS=true``. Mock mode
  records the operation in an in-memory ledger (exposed for tests as
  :data:`MOCK_PR_LEDGER`) and returns a deterministic envelope. Live mode is
  a guarded placeholder until the live-rollout PR (real GitHub/GitLab API).
* **HITL discipline.** This connector is only ever invoked by the backend
  composer, which consumes *accepted* proposals (a one-shot human decision)
  behind a senior-analyst permission — the mandatory-HITL requirement from
  issue #113. The connector itself never decides what ships.
* **Secret hygiene.** The repo token is resolved lazily via
  ``${secret:…}`` refs, never logged, and never present in ``repr()``.
* **Circuit breaker + pooling** via the shared
  :class:`btagent_agents.mcp.registry.MCPConnectionRegistry` (same as the
  SIEM/identity connectors).
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from datetime import UTC, datetime
from typing import Any

from btagent_shared.utils.secrets import resolve_secret
from langchain_core.tools import tool

logger = logging.getLogger("btagent.mcp.servers.git")

MOCK_MODE: bool = os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"

# In-memory ledger of mock PRs — inspectable by tests, reset via clear().
MOCK_PR_LEDGER: list[dict[str, Any]] = []

_BRANCH_SAFE = re.compile(r"[^a-z0-9._/-]+")


def _slugify_branch(name: str) -> str:
    """Normalise a proposed branch name to a git-safe slug."""
    slug = _BRANCH_SAFE.sub("-", name.strip().lower()).strip("-/")
    return slug or "detection-update"


def _redact_secret(secret: str) -> str:
    """Safe-to-log fingerprint of the repo token; never the raw value."""
    if not secret or len(secret) < 12:
        return "[redacted]"
    return f"[redacted:git-token:…{secret[-4:]}]"


class GitMCPServer:
    """Detection-repo Git connector with mock and real modes.

    The mock path is what CI exercises; it validates inputs the same way a
    live path would (non-empty files, unique paths) so composer bugs surface
    in tests rather than against a real repo.
    """

    server_id: str = "git"

    DEFAULT_REPO_REF: str = "${env:BTAGENT_DETECTION_REPO}"
    DEFAULT_TOKEN_REF: str = "${secret:vault:git/detection_repo_token}"

    def __init__(
        self,
        *,
        mock_mode: bool | None = None,
        repo_ref: str | None = None,
        token_ref: str | None = None,
    ) -> None:
        self.mock_mode: bool = mock_mode if mock_mode is not None else MOCK_MODE
        self._repo_ref: str = repo_ref or self.DEFAULT_REPO_REF
        self._token_ref: str = token_ref or self.DEFAULT_TOKEN_REF

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"GitMCPServer(server_id={self.server_id!r}, mock_mode={self.mock_mode!r})"

    # ----- lazy secret resolution -----

    def _get_token(self) -> str:
        resolved: str = resolve_secret(self._token_ref)
        return resolved

    def _get_repo(self) -> str:
        resolved: str = resolve_secret(self._repo_ref)
        return resolved or "example-org/detection-rules"

    # ----- tool -----

    async def git_open_detection_pr(
        self,
        branch: str,
        title: str,
        body: str,
        files: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Open a detection-rule pull request (branch + commit + PR in one call).

        Args:
            branch: Proposed branch name (normalised to a git-safe slug).
            title: PR title.
            body: PR body (markdown).
            files: ``[{"path": ..., "content": ...}, ...]`` — the rule files.

        Returns:
            Envelope with the branch, a deterministic commit fingerprint,
            and the PR URL.

        Raises:
            ValueError: empty file list, empty path/content, or duplicate
                paths — the same rejections a live git provider would give.
        """
        if not files:
            raise ValueError("A detection PR needs at least one rule file")
        seen: set[str] = set()
        for f in files:
            path = (f.get("path") or "").strip()
            if not path or not (f.get("content") or "").strip():
                raise ValueError("Every PR file needs a non-empty path and content")
            if path in seen:
                raise ValueError(f"Duplicate file path in PR: {path}")
            seen.add(path)

        if self.mock_mode:
            return self._mock_open_pr(branch, title, body, files)
        return await self._real_open_pr(branch, title, body, files)

    # ----- mock implementation -----

    def _mock_open_pr(
        self,
        branch: str,
        title: str,
        body: str,
        files: list[dict[str, str]],
    ) -> dict[str, Any]:
        repo = self._get_repo()
        slug = _slugify_branch(branch)
        # Deterministic fingerprint over the file set — stable across reruns
        # so tests (and idempotency checks upstream) can rely on it.
        digest = hashlib.sha256(
            "\n".join(f"{f['path']}\n{f['content']}" for f in files).encode()
        ).hexdigest()[:12]
        pr_number = len(MOCK_PR_LEDGER) + 1
        entry = {
            "repo": repo,
            "branch": slug,
            "title": title,
            "body": body,
            "files": files,
            "commit": digest,
            "pr_number": pr_number,
            "opened_at": datetime.now(UTC).isoformat(),
        }
        MOCK_PR_LEDGER.append(entry)
        logger.info(
            "git(mock): opened detection PR #%d on %s (branch=%s files=%d)",
            pr_number,
            repo,
            slug,
            len(files),
        )
        return {
            "status": "success",
            "is_mock": True,
            "repo": repo,
            "branch": slug,
            "commit": digest,
            "pr_number": pr_number,
            "pr_url": f"https://git.example.com/{repo}/pull/{pr_number}",
            "files_written": [f["path"] for f in files],
        }

    # ----- real implementation (placeholder, fail-safe) -----

    async def _real_open_pr(
        self,
        branch: str,
        title: str,
        body: str,
        files: list[dict[str, str]],
    ) -> dict[str, Any]:
        token = self._get_token()
        if not token or token.startswith("<unresolved:"):
            logger.warning("git: live-mode PR refused — no repo token (%s)", _redact_secret(token))
            raise NotImplementedError(
                "Git live mode requires a resolvable detection-repo token "
                "(wire ${secret:vault:git/detection_repo_token})."
            )
        raise NotImplementedError("Git live open_detection_pr not yet implemented")

    # ----- tool metadata -----

    def get_tool_metadata(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "git_open_detection_pr",
                "description": (
                    "Open a pull request against the detection-rule repository "
                    "carrying one or more accepted Sigma rules (branch + commit "
                    "+ PR in one call). Only invoked after human acceptance."
                ),
                "server_id": self.server_id,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "branch": {"type": "string", "description": "Proposed branch name"},
                        "title": {"type": "string", "description": "PR title"},
                        "body": {"type": "string", "description": "PR body (markdown)"},
                        "files": {
                            "type": "array",
                            "description": "Rule files: [{path, content}]",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "path": {"type": "string"},
                                    "content": {"type": "string"},
                                },
                                "required": ["path", "content"],
                            },
                        },
                    },
                    "required": ["branch", "title", "body", "files"],
                },
            }
        ]


# ---------------------------------------------------------------------------
# Module-level LangChain tool instance (parity with sibling connectors)
# ---------------------------------------------------------------------------
_server = GitMCPServer()


@tool
async def git_open_detection_pr(
    branch: str,
    title: str,
    body: str,
    files: list[dict[str, str]],
) -> dict[str, Any]:
    """Open a detection-rule pull request (branch + commit + PR in one call).

    Args:
        branch: Proposed branch name.
        title: PR title.
        body: PR body (markdown).
        files: Rule files as [{path, content}].
    """
    return await _server.git_open_detection_pr(branch, title, body, files)
