"""Tests for the enrichment.dedup_iocs Node.

Audit-fix coverage: the legacy dedup tool was case-sensitive on the
key, so ``DOMAIN.COM`` and ``domain.com`` did not collapse. The first
test below pins the corrected behaviour so it cannot regress."""

from __future__ import annotations

from btagent_engine import NodeContext, NodeRegistry, Runner
from btagent_engine.enrichment import (
    DedupIOCsInput,
    DedupIOCsNode,
    DedupIOCsOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_dedup", org_id="org_default", investigation_id="inv_t")


# ---------------------------------------------------------------------------
# Audit-fix: case-insensitive domain merge.
# ---------------------------------------------------------------------------


async def test_dedup_collapses_case_variant_domains() -> None:
    out: DedupIOCsOutput = await Runner().execute(
        DedupIOCsNode(),
        DedupIOCsInput(
            iocs=[
                {"type": "domain", "value": "Evil.Example.COM"},
                {"type": "domain", "value": "evil.example.com"},
                {"type": "domain", "value": "EVIL.EXAMPLE.COM."},
            ]
        ),
        _ctx(),
    )
    assert len(out.iocs) == 1
    assert out.iocs[0]["value"] == "evil.example.com"
    assert out.duplicates_removed == 2


# ---------------------------------------------------------------------------
# IP canonicalisation.
# ---------------------------------------------------------------------------


async def test_dedup_canonicalises_leading_zero_ip_variants() -> None:
    out = await Runner().execute(
        DedupIOCsNode(),
        DedupIOCsInput(
            iocs=[
                {"type": "ipv4", "value": "010.000.000.001"},
                {"type": "ipv4", "value": "10.0.0.1"},
            ]
        ),
        _ctx(),
    )
    assert len(out.iocs) == 1
    assert out.iocs[0]["value"] == "10.0.0.1"
    assert out.duplicates_removed == 1


async def test_dedup_canonicalises_ipv6_compressed_and_full() -> None:
    out = await Runner().execute(
        DedupIOCsNode(),
        DedupIOCsInput(
            iocs=[
                {"type": "ipv6", "value": "2001:0db8:0000:0000:0000:0000:0000:0001"},
                {"type": "ipv6", "value": "2001:db8::1"},
            ]
        ),
        _ctx(),
    )
    assert len(out.iocs) == 1
    assert out.duplicates_removed == 1


# ---------------------------------------------------------------------------
# Confidence merge: max wins.
# ---------------------------------------------------------------------------


async def test_dedup_keeps_max_confidence_on_merge() -> None:
    out = await Runner().execute(
        DedupIOCsNode(),
        DedupIOCsInput(
            iocs=[
                {"type": "domain", "value": "evil.io", "confidence": 0.3},
                {"type": "domain", "value": "EVIL.io", "confidence": 0.9},
                {"type": "domain", "value": "evil.io", "confidence": 0.5},
            ]
        ),
        _ctx(),
    )
    assert len(out.iocs) == 1
    assert out.iocs[0]["confidence"] == 0.9


# ---------------------------------------------------------------------------
# Tag union on merge.
# ---------------------------------------------------------------------------


async def test_dedup_unions_tags_on_merge() -> None:
    out = await Runner().execute(
        DedupIOCsNode(),
        DedupIOCsInput(
            iocs=[
                {"type": "domain", "value": "evil.io", "tags": ["c2", "phishing"]},
                {"type": "domain", "value": "EVIL.IO", "tags": ["phishing", "ransomware"]},
            ]
        ),
        _ctx(),
    )
    assert len(out.iocs) == 1
    assert set(out.iocs[0]["tags"]) == {"c2", "phishing", "ransomware"}


# ---------------------------------------------------------------------------
# first_seen: earliest wins.
# ---------------------------------------------------------------------------


async def test_dedup_keeps_earliest_first_seen_on_merge() -> None:
    out = await Runner().execute(
        DedupIOCsNode(),
        DedupIOCsInput(
            iocs=[
                {"type": "domain", "value": "evil.io", "first_seen": "2026-04-01T00:00:00Z"},
                {"type": "domain", "value": "evil.io", "first_seen": "2025-11-15T00:00:00Z"},
            ]
        ),
        _ctx(),
    )
    assert len(out.iocs) == 1
    assert out.iocs[0]["first_seen"] == "2025-11-15T00:00:00Z"


# ---------------------------------------------------------------------------
# duplicates_removed accounting.
# ---------------------------------------------------------------------------


async def test_dedup_removed_count_is_input_minus_output() -> None:
    inputs = [
        {"type": "domain", "value": "a.com"},
        {"type": "domain", "value": "A.COM"},
        {"type": "domain", "value": "b.com"},
        {"type": "ipv4", "value": "1.1.1.1"},
        {"type": "ipv4", "value": "001.001.001.001"},
    ]
    out = await Runner().execute(
        DedupIOCsNode(),
        DedupIOCsInput(iocs=inputs),
        _ctx(),
    )
    # 3 distinct canonical groups: a.com, b.com, 1.1.1.1
    assert len(out.iocs) == 3
    assert out.duplicates_removed == len(inputs) - len(out.iocs)
    assert out.duplicates_removed == 2


# ---------------------------------------------------------------------------
# URL: host case folded, path case preserved.
# ---------------------------------------------------------------------------


async def test_dedup_url_lowers_host_keeps_path_case() -> None:
    out = await Runner().execute(
        DedupIOCsNode(),
        DedupIOCsInput(
            iocs=[
                {"type": "url", "value": "HTTPS://Evil.Example.COM/Admin/Login"},
                {"type": "url", "value": "https://evil.example.com/Admin/Login"},
            ]
        ),
        _ctx(),
    )
    assert len(out.iocs) == 1
    assert out.iocs[0]["value"] == "https://evil.example.com/Admin/Login"


# ---------------------------------------------------------------------------
# Hashes + emails lower-cased.
# ---------------------------------------------------------------------------


async def test_dedup_hash_case_collapses() -> None:
    out = await Runner().execute(
        DedupIOCsNode(),
        DedupIOCsInput(
            iocs=[
                {"type": "hash_md5", "value": "D41D8CD98F00B204E9800998ECF8427E"},
                {"type": "hash_md5", "value": "d41d8cd98f00b204e9800998ecf8427e"},
            ]
        ),
        _ctx(),
    )
    assert len(out.iocs) == 1
    assert out.duplicates_removed == 1


def test_dedup_iocs_node_is_registered() -> None:
    assert NodeRegistry.get("enrichment.dedup_iocs") is DedupIOCsNode
