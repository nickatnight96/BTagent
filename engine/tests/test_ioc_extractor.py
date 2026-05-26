"""Tests for IOCExtractorNode (UC-2.2, #105)."""

from __future__ import annotations

from btagent_engine import NodeContext
from btagent_engine.data import IOCExtractorInput, IOCExtractorNode
from btagent_shared.types.enums import IOCType


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_ioc", org_id="org_test")


async def _extract(text: str):
    out = await IOCExtractorNode().run(IOCExtractorInput(text=text), _ctx())
    return out


def _values(out, t: IOCType):
    return [i.value for i in out.iocs if i.type == t]


async def test_extracts_each_ioc_type():
    text = (
        "APT99 used 185.220.101.42 and evil-c2.example to host "
        "https://evil-c2.example/payload.bin. "
        "MD5 d41d8cd98f00b204e9800998ecf8427e, "
        "SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709, "
        "SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. "
        "Contact attacker@evil-c2.example. Exploited CVE-2026-12345."
    )
    out = await _extract(text)
    assert "185.220.101.42" in _values(out, IOCType.IP)
    assert "evil-c2.example" in _values(out, IOCType.DOMAIN)
    assert any("payload.bin" in u for u in _values(out, IOCType.URL))
    assert "d41d8cd98f00b204e9800998ecf8427e" in _values(out, IOCType.HASH_MD5)
    assert "da39a3ee5e6b4b0d3255bfef95601890afd80709" in _values(out, IOCType.HASH_SHA1)
    assert (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        in _values(out, IOCType.HASH_SHA256)
    )
    assert "attacker@evil-c2.example" in _values(out, IOCType.EMAIL)
    assert "CVE-2026-12345" in _values(out, IOCType.CVE)


async def test_defanged_indicators_normalized():
    text = "Beacon to hxxps://evil[.]com/c2 from 10[.]0[.]0[.]5, mail user(at)evil[.]com"
    out = await _extract(text)
    assert any(i.was_defanged for i in out.iocs)
    assert "10.0.0.5" in _values(out, IOCType.IP)
    assert any("evil.com" in u for u in _values(out, IOCType.URL))
    assert "user@evil.com" in _values(out, IOCType.EMAIL)


async def test_url_host_not_double_counted_as_domain():
    text = "Visit https://only-in-url.example/x — nothing else here."
    out = await _extract(text)
    # only-in-url.example appears only inside the URL -> not a standalone domain
    assert _values(out, IOCType.DOMAIN) == []
    assert len(_values(out, IOCType.URL)) == 1


async def test_dedup_counts_duplicates():
    text = "1.2.3.4 1.2.3.4 1.2.3.4"
    out = await _extract(text)
    assert _values(out, IOCType.IP) == ["1.2.3.4"]
    assert out.deduped_count == 2


async def test_file_extension_not_treated_as_domain():
    text = "The dropper payload.exe and script invoke.ps1 were observed."
    out = await _extract(text)
    assert "payload.exe" not in _values(out, IOCType.DOMAIN)
    assert "invoke.ps1" not in _values(out, IOCType.DOMAIN)


async def test_empty_text():
    out = await _extract("")
    assert out.iocs == []
