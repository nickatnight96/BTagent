"""The TLP → LLM-provider allow-list is a monotonic ladder with no holes.

``TLP_ALLOWED_PROVIDERS`` decides which model providers may see data at each
classification level. It is the confidentiality boundary for every LLM call the
agent makes: ``llm_router`` consults it and raises ``TLPViolation`` on a
mismatch.

A table like this has one structural property worth asserting, and it is not
"the values are right" — it is that the levels **relate** correctly. As
classification relaxes, the permitted set may only widen. If a provider is
trusted with TLP:RED data it is necessarily trusted with TLP:GREEN data, so a
provider present at a stricter level and absent at a looser one is a hole, not
a policy.

There was exactly one such hole. ``TLP.AMBER`` omitted Ollama while the
stricter ``RED`` and ``AMBER_STRICT`` and the looser ``GREEN`` and ``WHITE``
all permitted it:

    RED           {ollama}
    AMBER_STRICT  {ollama, bedrock}
    AMBER         {anthropic, bedrock, vertex_ai}      <- ollama missing
    GREEN         {anthropic, openai, bedrock, vertex_ai, ollama}
    WHITE         {… , azure, ollama}

Ollama is local inference: the data never leaves the deployment, which is
precisely why TLP:RED permits nothing else. So the effect of the omission was
backwards — an org running AMBER investigations on a local model was refused
and pushed onto a *cloud* provider. The rung looks like it was written as "the
cloud providers acceptable at AMBER" and simply did not carry the local one
down from the stricter tiers.

Also pinned here: the two named constants actually drive the table. They were
defined, named as though they were the policy (``_TRUSTED_CLOUD_PROVIDERS`` —
"safe for TLP:AMBER_STRICT and below"), and referenced nowhere, while the table
inlined the same values. Editing them to tighten policy would have changed
nothing at all.
"""

from __future__ import annotations

import inspect

import pytest
from btagent_shared.types.config import TLP, ModelProvider

from btagent_agents.hooks import classification_hook as hook
from btagent_agents.hooks.classification_hook import (
    TLP_ALLOWED_PROVIDERS,
    is_provider_allowed,
)

#: Strictest first. Each level must permit a superset of the one before it.
_LADDER: tuple[TLP, ...] = (
    TLP.RED,
    TLP.AMBER_STRICT,
    TLP.AMBER,
    TLP.GREEN,
    TLP.WHITE,
)


def test_the_ladder_covers_every_tlp_level():
    """A level missing from the ladder would not be checked by the tests below."""
    assert set(_LADDER) == set(TLP), (
        "TLP gained or lost a level; update _LADDER (strictest first) so the "
        "monotonicity check still spans the whole scale"
    )


def test_every_tlp_level_has_a_routing_rule():
    """Fail-closed is safe, but a missing rule means that level cannot run at all."""
    missing = sorted(level.value for level in TLP if level not in TLP_ALLOWED_PROVIDERS)
    assert not missing, (
        f"TLP levels with no provider rule: {missing}. is_provider_allowed fails "
        "closed, so these refuse every provider — no LLM call at that "
        "classification would succeed."
    )


@pytest.mark.parametrize(
    ("stricter", "looser"),
    # Adjacent pairs: (RED, AMBER_STRICT), (AMBER_STRICT, AMBER), … The lengths
    # differ by one by construction, so `strict` must stay off here.
    list(zip(_LADDER, _LADDER[1:], strict=False)),
    ids=lambda level: level.value if isinstance(level, TLP) else str(level),
)
def test_relaxing_classification_only_widens_the_allow_list(stricter: TLP, looser: TLP):
    """The invariant that catches a dropped rung.

    A provider trusted with more-sensitive data must stay trusted with
    less-sensitive data. Anything else is an accident of how the rung was
    written, not a confidentiality decision.
    """
    lost = sorted(TLP_ALLOWED_PROVIDERS[stricter] - TLP_ALLOWED_PROVIDERS[looser])
    assert not lost, (
        f"{looser.value} forbids providers that the stricter {stricter.value} "
        f"allows: {lost}. Relaxing classification must never narrow the set — "
        "that pushes data toward a less private destination."
    )


def test_local_inference_is_allowed_at_every_level():
    """Local providers never leave the deployment, so no level may exclude them."""
    for level in TLP:
        for provider in hook._LOCAL_PROVIDERS:
            assert is_provider_allowed(level, provider), (
                f"{provider} is local inference but is refused at {level.value}"
            )


def test_strictest_level_permits_local_inference_only():
    """Guard the guard: monotonicity alone is satisfied by permitting everything.

    Without this, widening every rung to the full provider list would pass the
    ladder check while destroying the boundary it exists to enforce.
    """
    assert TLP_ALLOWED_PROVIDERS[TLP.RED] == hook._LOCAL_PROVIDERS
    assert ModelProvider.OPENAI not in TLP_ALLOWED_PROVIDERS[TLP.RED]
    assert ModelProvider.ANTHROPIC not in TLP_ALLOWED_PROVIDERS[TLP.RED]


def test_no_level_permits_an_unknown_provider():
    known = {p.value for p in ModelProvider}
    for level, allowed in TLP_ALLOWED_PROVIDERS.items():
        unknown = sorted(set(allowed) - known)
        assert not unknown, f"{level.value} permits providers that do not exist: {unknown}"


def test_an_unmapped_tlp_refuses_every_provider():
    """Fail-closed, asserted rather than assumed."""

    class _Unmapped(str):
        pass

    for provider in (p.value for p in ModelProvider):
        assert is_provider_allowed(_Unmapped("not_a_tlp"), provider) is False


def test_the_named_constants_actually_drive_the_table():
    """They described the policy while driving nothing — the trap this closes.

    ``_LOCAL_PROVIDERS`` and ``_TRUSTED_CLOUD_PROVIDERS`` were defined, named as
    though they were authoritative, and referenced nowhere; the table inlined
    the same values. Tightening a constant would have read as a policy change
    and had no effect. The source check is deliberate: equal *values* would pass
    even if the table went back to inlining them.
    """
    source = inspect.getsource(hook)
    table_src = source.split("TLP_ALLOWED_PROVIDERS", 1)[1].split("def is_provider_allowed", 1)[0]
    for name in ("_LOCAL_PROVIDERS", "_TRUSTED_CLOUD_PROVIDERS"):
        assert name in table_src, (
            f"{name} is no longer referenced by TLP_ALLOWED_PROVIDERS. Either "
            "wire it back in or delete it — a named constant that describes the "
            "policy without driving it invites a silent no-op edit."
        )
