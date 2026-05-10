"""Context cascade tests: per-layer behaviour + end-to-end orchestration."""

from __future__ import annotations

from btagent_engine.context import (
    COMPRESS_THRESHOLD,
    EXTERNALIZE_THRESHOLD,
    ContextLayer,
    apply_cascade,
    estimate_message_tokens,
    layer0_externalize,
    layer1_compress,
    layer2_prune,
    layer3_summarize,
    make_artifact_ref,
)

# --------------------------------------------------------------------------- #
# Layer 0: externalisation / artifact refs
# --------------------------------------------------------------------------- #


def test_artifact_ref_hash_is_deterministic():
    """Same content => same ref. Different content => different ref."""
    a1 = make_artifact_ref("abc" * 1000)
    a2 = make_artifact_ref("abc" * 1000)
    a3 = make_artifact_ref("def" * 1000)
    assert a1.ref == a2.ref
    assert a1.sha256 == a2.sha256
    assert a1.ref != a3.ref
    assert a1.sha256 != a3.sha256
    # Format invariant
    assert a1.ref.startswith("artifact:")
    assert len(a1.sha256) == 64


def test_layer0_externalises_only_large_tool_messages():
    big = "X" * (EXTERNALIZE_THRESHOLD + 100)
    small = "Y" * 50
    msgs = [
        {"role": "system", "content": big},  # not a tool, must stay
        {"role": "user", "content": big},  # not a tool, must stay
        {"role": "tool", "name": "splunk", "content": big},  # externalise
        {"role": "tool", "name": "vt", "content": small},  # too small, stay
    ]
    out, artifacts = layer0_externalize(msgs)
    assert len(artifacts) == 1
    assert artifacts[0].tool_name == "splunk"
    # The system + user messages were NOT touched
    assert out[0]["content"] == big
    assert out[1]["content"] == big
    # The tool message has been replaced with a marker referencing the artifact
    assert artifacts[0].ref in out[2]["content"]
    # Small tool message untouched
    assert out[3]["content"] == small


# --------------------------------------------------------------------------- #
# Layer 1: compression bounds
# --------------------------------------------------------------------------- #


def test_layer1_compress_keeps_output_within_threshold():
    big = "Z" * (COMPRESS_THRESHOLD + 5000)
    msgs = [
        {"role": "tool", "name": "splunk", "content": big},
        {"role": "user", "content": big},  # untouched: not a tool
    ]
    out = layer1_compress(msgs)
    # Tool message squeezed
    tool_bytes = len(out[0]["content"].encode("utf-8"))
    assert tool_bytes <= COMPRESS_THRESHOLD + len(
        "\n\n[... truncated -- full output in artifact store ...]"
    )
    # User message untouched
    assert out[1]["content"] == big


def test_layer1_json_array_sampling():
    """A long JSON array gets sampled rather than truncated mid-way."""
    import json

    array = list(range(1000))
    msg = {"role": "tool", "name": "ip_lookup", "content": json.dumps(array)}
    out = layer1_compress([msg])
    content = out[0]["content"]
    # Sample marker present
    assert "sampled" in content
    # And the kept items form valid JSON prefix
    assert content.startswith("[")


# --------------------------------------------------------------------------- #
# Layer 2: prune ordering
# --------------------------------------------------------------------------- #


def test_layer2_prune_preserves_first_and_last():
    msgs = [{"role": "system", "content": "sys"}]
    msgs += [{"role": "user", "content": f"u{i}"} for i in range(20)]
    msgs += [{"role": "assistant", "content": "final"}]
    out = layer2_prune(msgs, keep_first=2, keep_last=3)
    assert out[0]["content"] == "sys"
    assert out[1]["content"] == "u0"
    # Marker in the middle
    assert out[2]["role"] == "system"
    assert "pruned" in out[2]["content"].lower()
    # And the last 3 are preserved at the tail
    assert [m["content"] for m in out[-3:]] == ["u18", "u19", "final"]


def test_layer2_prune_is_noop_when_under_threshold():
    msgs = [{"role": "user", "content": f"u{i}"} for i in range(4)]
    out = layer2_prune(msgs, keep_first=2, keep_last=3)
    assert out == msgs


# --------------------------------------------------------------------------- #
# Layer 3: summarize fallback
# --------------------------------------------------------------------------- #


async def test_layer3_summarize_calls_summarizer_and_keeps_tail():
    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "msg-a"},
        {"role": "assistant", "content": "msg-b"},
        {"role": "user", "content": "msg-c"},
        {"role": "assistant", "content": "msg-d"},
        {"role": "user", "content": "msg-e"},
    ]

    seen: list[list[dict]] = []

    def summarizer(prefix: list[dict]) -> str:
        seen.append(prefix)
        return "ALL-SUMMED"

    out = await layer3_summarize(msgs, summarizer, keep_last=2)
    # Summary message present in the second slot (after preserved system msg).
    assert out[0]["role"] == "system"
    assert out[0]["content"] == "sys"
    assert "ALL-SUMMED" in out[1]["content"]
    # Tail of 2 preserved at the end
    assert [m["content"] for m in out[-2:]] == ["msg-d", "msg-e"]
    # Summarizer was given the prefix
    assert len(seen) == 1
    assert seen[0] == msgs[:-2]


async def test_layer3_summarize_supports_async_summarizer():
    msgs = [{"role": "user", "content": f"m{i}"} for i in range(5)]

    async def summarizer(prefix):
        return f"async-summary-of-{len(prefix)}"

    out = await layer3_summarize(msgs, summarizer, keep_last=2)
    assert "async-summary-of-3" in out[0]["content"]


# --------------------------------------------------------------------------- #
# End-to-end cascade
# --------------------------------------------------------------------------- #


async def test_apply_cascade_no_op_when_under_budget():
    msgs = [{"role": "user", "content": "small"}]
    result = await apply_cascade(msgs, max_tokens=1_000_000)
    assert result.fits_budget is True
    assert result.layers_applied == []
    assert result.messages == msgs
    assert result.artifacts == []


async def test_apply_cascade_reduces_too_big_input_progressively():
    """End-to-end: an over-budget transcript triggers layers in order."""
    big = "X" * (EXTERNALIZE_THRESHOLD * 2)
    msgs: list[dict] = [{"role": "system", "content": "sys"}]
    # 5 large tool messages -- way over any sensible budget
    for i in range(5):
        msgs.append({"role": "tool", "name": f"t{i}", "content": big})
    msgs.append({"role": "user", "content": "final"})

    pre_est = estimate_message_tokens(msgs)
    assert pre_est > 1000  # sanity: input is genuinely huge

    # Tight budget so externalisation alone is enough.
    result = await apply_cascade(msgs, max_tokens=200)
    assert ContextLayer.EXTERNALIZE in result.layers_applied
    assert result.fits_budget is True
    # All 5 tool messages externalised
    assert len(result.artifacts) == 5
    # And the budget is now under the cap
    assert result.final_token_estimate <= 200


async def test_apply_cascade_falls_through_to_summarizer():
    """If externalise/compress/prune don't make it fit, summariser kicks in."""
    msgs = [{"role": "system", "content": "sys"}]
    # 30 user messages, each large enough that prune still leaves a lot.
    msgs += [{"role": "user", "content": "Y" * 200} for _ in range(30)]
    msgs.append({"role": "assistant", "content": "tail"})

    summarizer_calls = []

    def summarizer(prefix):
        summarizer_calls.append(len(prefix))
        return "S"

    result = await apply_cascade(
        msgs,
        max_tokens=10,  # impossibly tight: forces all the way to layer 3
        summarizer=summarizer,
    )
    assert ContextLayer.SUMMARIZE in result.layers_applied
    assert len(summarizer_calls) == 1


async def test_apply_cascade_returns_unfit_when_no_summarizer_provided():
    """Without a summariser, the cascade may end up still over budget."""
    msgs = [{"role": "user", "content": "Y" * 20_000}]
    result = await apply_cascade(msgs, max_tokens=10)
    # No summarizer => cannot apply layer 3 => still over budget
    assert ContextLayer.SUMMARIZE not in result.layers_applied
    assert result.fits_budget is False
