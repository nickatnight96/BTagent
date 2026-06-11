"""Golden tests for the Sigma -> 4-backend transpiler (#112).

The goldens assert load-bearing query fragments (table / source / index
mapping and field comparisons) rather than full strings, so a cosmetic
upstream pySigma formatting change doesn't break the suite while a field- or
table-mapping regression still does.
"""

from __future__ import annotations

import pytest

from btagent_engine.hunting import (
    SUPPORTED_BACKENDS,
    SigmaTranspileError,
    UnsupportedSigmaRuleError,
    load_builtin_pack,
    transpile,
)

_PACK = load_builtin_pack("windows_baseline")
_RULES = {r.file: r for r in _PACK.rules}


def _yaml(file: str) -> str:
    return _RULES[file].sigma_yaml


# --- per-backend goldens for the shipped example rules ---


def test_encoded_powershell_splunk_spl():
    spl = transpile(_yaml("encoded_powershell.yml"), "splunk")
    assert 'Image IN ("*\\\\powershell.exe", "*\\\\pwsh.exe")' in spl
    assert "-EncodedCommand" in spl
    assert "CommandLine IN" in spl


def test_encoded_powershell_sentinel_kql_uses_xdr_table():
    kql = transpile(_yaml("encoded_powershell.yml"), "sentinel")
    assert kql.startswith("DeviceProcessEvents")  # Advanced Hunting table mapping
    assert "| where" in kql
    assert 'FolderPath endswith "\\\\powershell.exe"' in kql
    assert "ProcessCommandLine contains" in kql


def test_encoded_powershell_elastic_lucene_uses_ecs_fields():
    lucene = transpile(_yaml("encoded_powershell.yml"), "elastic")
    assert "process.executable:" in lucene  # ECS mapping, not raw Sysmon Image
    assert "process.command_line:" in lucene
    assert "powershell.exe" in lucene


def test_encoded_powershell_crowdstrike_logscale():
    cs = transpile(_yaml("encoded_powershell.yml"), "crowdstrike")
    assert "#event_simpleName=/^ProcessRollup2$/i" in cs  # Falcon telemetry mapping
    assert "ImageFileName=" in cs
    assert "CommandLine=" in cs


def test_failed_logon_splunk_maps_security_source_and_eventcode():
    spl = transpile(_yaml("failed_logon_spray.yml"), "splunk")
    assert 'source="WinEventLog:Security"' in spl  # windows pipeline source mapping
    assert "EventCode=4625" in spl  # EventID -> EventCode
    assert "LogonType=3" in spl


def test_failed_logon_sentinel_maps_logon_table():
    kql = transpile(_yaml("failed_logon_spray.yml"), "sentinel")
    assert kql.startswith("DeviceLogonEvents")
    assert "LogonType == 3" in kql


def test_failed_logon_elastic_maps_winlog_channel():
    lucene = transpile(_yaml("failed_logon_spray.yml"), "elastic")
    assert "winlog.channel:Security" in lucene
    assert "event.code:4625" in lucene


def test_certutil_and_mshta_transpile_keep_cli_markers():
    for file, marker in (
        ("certutil_remote_download.yml", "urlcache"),
        ("mshta_remote_script.yml", "javascript"),
    ):
        for backend in SUPPORTED_BACKENDS:
            query = transpile(_yaml(file), backend)
            assert marker in query, f"{file} on {backend} lost {marker!r}"


def test_every_example_rule_transpiles_on_every_backend():
    for rule in _PACK.rules:
        for backend in SUPPORTED_BACKENDS:
            assert transpile(rule.sigma_yaml, backend).strip()


# --- error contract ---


def test_invalid_yaml_raises_transpile_error():
    with pytest.raises(SigmaTranspileError, match="invalid Sigma rule"):
        transpile("title: [unclosed\n", "splunk")


def test_non_sigma_yaml_raises_transpile_error():
    with pytest.raises(SigmaTranspileError, match="invalid Sigma rule"):
        transpile("just: a\nplain: mapping\n", "splunk")


_DEPRECATED_PIPE_RULE = """\
title: Deprecated Aggregation Rule
id: 00000000-0000-4000-8000-0000000000aa
logsource:
  product: windows
  service: security
detection:
  sel1:
    EventID: 4624
  sel2:
    EventID: 4625
  condition: sel1 | near sel2
level: medium
"""


def test_unsupported_sigma_construct_raises_typed_error():
    with pytest.raises(UnsupportedSigmaRuleError):
        transpile(_DEPRECATED_PIPE_RULE, "splunk")


def test_unsupported_error_is_a_transpile_error_with_backend():
    with pytest.raises(SigmaTranspileError) as excinfo:
        transpile(_DEPRECATED_PIPE_RULE, "sentinel")
    assert excinfo.value.backend == "sentinel"
    assert excinfo.value.reason


_XDR_UNMAPPED_FIELD_RULE = """\
title: Field With No XDR Mapping
id: 00000000-0000-4000-8000-0000000000ab
logsource:
  product: windows
  service: security
detection:
  sel:
    EventID: 4625
    SubStatus: '0xC000006A'
  condition: sel
level: medium
"""


def test_backend_specific_unmapped_field_is_unsupported_only_there():
    # SubStatus has no DeviceLogonEvents column in the XDR pipeline...
    with pytest.raises(UnsupportedSigmaRuleError):
        transpile(_XDR_UNMAPPED_FIELD_RULE, "sentinel")
    # ...but the same rule is expressible on Splunk.
    assert "SubStatus" in transpile(_XDR_UNMAPPED_FIELD_RULE, "splunk")


def test_unknown_backend_raises_value_error():
    with pytest.raises(ValueError, match="unknown backend"):
        transpile(_yaml("encoded_powershell.yml"), "qradar")  # type: ignore[arg-type]


# --- backend init failure isolation (Codex #198 P2) -----------------------


def test_transpile_wraps_backend_init_failure_in_sigma_transpile_error(monkeypatch):
    """A backend factory that fails to initialise (e.g. missing pySigma
    plugin) must surface as ``SigmaTranspileError`` so the per-rule catch
    in the pack runner isolates it instead of killing the whole pack."""
    import importlib

    transpile_mod = importlib.import_module("btagent_engine.hunting.transpile")
    SigmaTranspileError = transpile_mod.SigmaTranspileError
    transpile = transpile_mod.transpile

    def _boom() -> object:
        raise RuntimeError("missing plugin")

    monkeypatch.setitem(transpile_mod._BACKEND_FACTORIES, "splunk", _boom)
    # Force a re-init by busting the cache for this backend.
    transpile_mod._backend_cache.pop("splunk", None)

    rule_yaml = (
        "title: x\n"
        "logsource: {category: process_creation, product: windows}\n"
        "detection:\n"
        "  selection: {Image|endswith: 'a.exe'}\n"
        "  condition: selection\n"
    )

    with pytest.raises(SigmaTranspileError) as exc_info:
        transpile(rule_yaml, "splunk")
    assert "backend init failed" in str(exc_info.value)
