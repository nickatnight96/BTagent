"""Tests for the enrichment.extract_iocs Node."""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext, NodeRegistry, Runner
from btagent_engine.enrichment import (
    ExtractedIOC,
    ExtractIOCsInput,
    ExtractIOCsNode,
    ExtractIOCsOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_extract", org_id="org_default", investigation_id="inv_t")


# ---------------------------------------------------------------------------
# Pattern coverage -- one positive example per type.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected_type", "expected_value"),
    [
        ("Connection from 8.8.8.8 to corp", "ipv4", "8.8.8.8"),
        ("v6 route 2001:db8::1 logged", "ipv6", "2001:db8::1"),
        (
            "payload at https://evil.example.com/x.bin downloaded",
            "url",
            "https://evil.example.com/x.bin",
        ),
        ("phishing pointed at evil-payload.top earlier", "domain", "evil-payload.top"),
        (
            "md5 d41d8cd98f00b204e9800998ecf8427e seen on host",
            "hash_md5",
            "d41d8cd98f00b204e9800998ecf8427e",
        ),
        (
            "sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709 from sandbox",
            "hash_sha1",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        ),
        (
            "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 alert",
            "hash_sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        ("contact attacker@evil.io for ransom", "email", "attacker@evil.io"),
        (
            "dropper landed at C:\\Users\\joe\\AppData\\evil.exe",
            "file_path_windows",
            "C:\\Users\\joe\\AppData\\evil.exe",
        ),
        (
            "linux backdoor at /var/tmp/.cache/x.so observed",
            "file_path_unix",
            "/var/tmp/.cache/x.so",
        ),
    ],
)
async def test_extract_each_pattern_type_matches(
    text: str, expected_type: str, expected_value: str
) -> None:
    out: ExtractIOCsOutput = await Runner().execute(
        ExtractIOCsNode(),
        ExtractIOCsInput(text=text),
        _ctx(),
    )
    types_values = {(i.type, i.value) for i in out.iocs}
    assert (expected_type, expected_value) in types_values


# ---------------------------------------------------------------------------
# Defang refanging
# ---------------------------------------------------------------------------


async def test_extract_defanged_ip_is_matched() -> None:
    out = await Runner().execute(
        ExtractIOCsNode(),
        ExtractIOCsInput(text="C2 at 185[.]220[.]101[.]42 reaching out"),
        _ctx(),
    )
    assert any(i.type == "ipv4" and i.value == "185.220.101.42" for i in out.iocs)


async def test_extract_defanged_url_with_hxxp_is_matched() -> None:
    out = await Runner().execute(
        ExtractIOCsNode(),
        ExtractIOCsInput(text="dropper hxxps://bad[.]example[.]com/x found"),
        _ctx(),
    )
    assert any(i.type == "url" and i.value.startswith("https://bad.example.com/") for i in out.iocs)


# ---------------------------------------------------------------------------
# RFC-1918 skip semantics
# ---------------------------------------------------------------------------


async def test_extract_skips_rfc_1918_when_no_explicit_ip_filter() -> None:
    out = await Runner().execute(
        ExtractIOCsNode(),
        ExtractIOCsInput(text="internal hop 10.0.0.5 then 192.168.1.1 then 172.16.4.4"),
        _ctx(),
    )
    assert not any(i.type == "ipv4" for i in out.iocs)


async def test_extract_includes_rfc_1918_when_ip_filter_explicit() -> None:
    out = await Runner().execute(
        ExtractIOCsNode(),
        ExtractIOCsInput(
            text="internal hop 10.0.0.5 then public 8.8.8.8",
            types=["ip"],
        ),
        _ctx(),
    )
    values = {i.value for i in out.iocs if i.type == "ipv4"}
    assert "10.0.0.5" in values
    assert "8.8.8.8" in values


# ---------------------------------------------------------------------------
# Within-call dedup
# ---------------------------------------------------------------------------


async def test_extract_dedups_repeated_ioc_within_single_call() -> None:
    out = await Runner().execute(
        ExtractIOCsNode(),
        ExtractIOCsInput(text="8.8.8.8 then 8.8.8.8 then 8.8.8.8 again"),
        _ctx(),
    )
    ipv4s = [i for i in out.iocs if i.type == "ipv4" and i.value == "8.8.8.8"]
    assert len(ipv4s) == 1
    # First-occurrence wins -> offset is the position of the very first one.
    assert ipv4s[0].first_offset == 0


# ---------------------------------------------------------------------------
# by_type integrity
# ---------------------------------------------------------------------------


async def test_extract_by_type_count_equals_iocs_length() -> None:
    text = (
        "C2 8.8.8.8 phishing https://evil.io/p attacker@evil.io "
        "hash d41d8cd98f00b204e9800998ecf8427e"
    )
    out = await Runner().execute(
        ExtractIOCsNode(),
        ExtractIOCsInput(text=text),
        _ctx(),
    )
    assert sum(out.by_type.values()) == len(out.iocs)
    # Sanity: we expect at least 4 distinct types here.
    assert len(out.by_type) >= 4


# ---------------------------------------------------------------------------
# Output is well-formed Pydantic.
# ---------------------------------------------------------------------------


async def test_extract_output_objects_are_extracted_ioc_models() -> None:
    out = await Runner().execute(
        ExtractIOCsNode(),
        ExtractIOCsInput(text="C2 8.8.8.8"),
        _ctx(),
    )
    assert all(isinstance(i, ExtractedIOC) for i in out.iocs)


def test_extract_node_is_registered() -> None:
    assert NodeRegistry.get("enrichment.extract_iocs") is ExtractIOCsNode
