"""Tests for IOCExtractorNode (UC-2.2, #105)."""

from __future__ import annotations

from btagent_shared.types.enums import IOCType

from btagent_engine import NodeContext
from btagent_engine.data import IOCExtractorInput, IOCExtractorNode


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
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in _values(
        out, IOCType.HASH_SHA256
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


# --- YARA rule extraction (UC-2.2, #105) ----------------------------------- #

_YARA_RULE = """rule EvilDropper : trojan
{
    meta:
        description = "Detects the Evil dropper"
    strings:
        $a = "evil-c2.example"
        $hex = { 6A 40 68 00 30 00 00 }
    condition:
        $a or $hex
}"""


async def test_extracts_yara_rule_alongside_iocs():
    text = (
        "Advisory AA26-001: infra 185.220.101.42, C2 evil-c2.example. "
        "Deploy the detection rule below:\n\n" + _YARA_RULE
    )
    out = await _extract(text)
    assert len(out.yara_rules) == 1
    rule = out.yara_rules[0]
    assert rule.name == "EvilDropper"
    # Brace-balanced: the hex-string braces don't close the block early.
    assert "$hex = { 6A 40 68 00 30 00 00 }" in rule.rule
    assert rule.rule.strip().endswith("}")
    assert "condition:" in rule.rule
    # Indicators still surface alongside the rule.
    assert "185.220.101.42" in _values(out, IOCType.IP)


async def test_yara_requires_condition_section():
    """A bare ``rule <name> { ... }`` with no condition is not a YARA rule."""
    text = "The firewall rule Blocklist { deny all } was applied at the edge."
    out = await _extract(text)
    assert out.yara_rules == []


async def test_yara_brace_inside_string_literal_does_not_terminate_block():
    text = (
        "rule BraceInString {\n"
        "    strings:\n"
        '        $s = "literal close brace } here"\n'
        "    condition:\n"
        "        $s\n"
        "}"
    )
    out = await _extract(text)
    assert len(out.yara_rules) == 1
    assert out.yara_rules[0].name == "BraceInString"
    assert out.yara_rules[0].rule.strip().endswith("}")
    assert "literal close brace } here" in out.yara_rules[0].rule


async def test_multiple_yara_rules_extracted():
    text = _YARA_RULE + "\n\n" + _YARA_RULE.replace("EvilDropper", "SecondStage")
    out = await _extract(text)
    assert sorted(r.name for r in out.yara_rules) == ["EvilDropper", "SecondStage"]


async def test_no_yara_rules_when_absent():
    out = await _extract("Prose about 1.2.3.4 and evil.example, no detections here.")
    assert out.yara_rules == []
