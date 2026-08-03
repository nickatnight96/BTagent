"""Fencing untrusted content into LLM prompts — the single implementation.

CLAUDE.md requires every piece of external data interpolated into an agent
prompt to be wrapped in ``<external-data>`` tags. Wrapping alone is not a
defence: the payload is attacker-influenced (alert bodies, CTI reports, log
lines, TAXII objects), so a literal ``</external-data>`` inside it closes the
fence early and everything after it is read as trusted instruction. That was
GH #373.

The fix is to neutralise embedded fence sentinels *before* interpolation. This
module is the one place that happens. It lives in ``btagent_shared`` because
that is the only tier importable from engine, agents, and backend alike —
previous copies diverged precisely because each tier re-implemented it locally,
and three of the newer copies never received the #373 hardening at all.

**Do not re-implement this.** ``test_prompt_fence.py`` fails if a new
hand-rolled fence appears in the tree.

Two halves, not one
-------------------

That guard scans ``*.py``, so it only covers fences built in Python. Workflow
and orchestrator templates fence in YAML — ``content:
"<external-data>{{ alert_text }}</external-data>"`` — and those were invisible
to it while the renderer substituted values verbatim, which reopened #373 on
the template path (#560). The second half of this control therefore lives in
``btagent_engine.runtime.templating``, which runs :func:`neutralize_sentinels`
over every substituted value. Wrapping (here) and substitution (there) are the
only two ways untrusted text reaches a fence; both are now closed.
"""

from __future__ import annotations

import re

# Fence tags that must never appear "live" inside a payload. Matching is
# case-insensitive, tolerates stray inner whitespace, and — unlike the original
# #373 fix — also catches attribute-bearing forms such as
# ``<external-data foo="1">``, which a model may well read as a fence boundary.
_TAG_NAMES = ("external-data", "agent-memory", "knowledge-context")

_SENTINEL_RES: dict[str, re.Pattern[str]] = {
    name: re.compile(rf"<\s*/?\s*{re.escape(name)}\b[^>]*>", re.IGNORECASE) for name in _TAG_NAMES
}

# Any fence tag, used when neutralising a payload destined for one fence
# against *all* known fence names — a memory block that smuggles an
# ``</external-data>`` is just as dangerous as one that smuggles its own tag.
_ANY_SENTINEL_RE = re.compile(
    r"<\s*/?\s*(?:" + "|".join(re.escape(n) for n in _TAG_NAMES) + r")\b[^>]*>",
    re.IGNORECASE,
)


def neutralize_sentinels(text: str) -> str:
    """HTML-escape the angle brackets of any embedded fence tag.

    ``</external-data>`` becomes ``&lt;/external-data&gt;``: still legible to a
    human reading the transcript, but no longer a tag the model can treat as a
    boundary.
    """
    return _ANY_SENTINEL_RE.sub(
        lambda m: m.group(0).replace("<", "&lt;").replace(">", "&gt;"), text
    )


def wrap_fenced(text: str, tag: str) -> str:
    """Fence untrusted ``text`` inside ``<tag>`` after neutralising sentinels."""
    if tag not in _SENTINEL_RES:
        raise ValueError(
            f"unknown fence tag {tag!r}; add it to _TAG_NAMES so payloads are "
            "neutralised against it too"
        )
    return f"<{tag}>\n{neutralize_sentinels(text)}\n</{tag}>"


def wrap_external_data(text: str) -> str:
    """Fence untrusted external text for an LLM prompt (the common case)."""
    return wrap_fenced(text, "external-data")


__all__ = ["neutralize_sentinels", "wrap_external_data", "wrap_fenced"]
