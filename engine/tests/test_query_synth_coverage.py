"""Golden coverage test for the QuerySynth curated template library (#99).

The acceptance bar for #99 is *breadth*: curated, backend-native hunt queries
for the ATT&CK techniques the rest of the product actually references, not a
handful of demo templates with a generic fallback behind them.

These assertions are deliberately exact so the numbers can't silently
regress. If you add curated templates, bump the constants below in the same
commit — that is the point of the test. If you *remove* coverage, the test
fails and you have to say so out loud in review.

Also enforced here (structure, not just count):

* every executable query terminates in its backend's result cap
  (SPL/Falcon ``| head N``, KQL ``| take N``, ES|QL ``| LIMIT N``) — the
  anti-SIEM-DoS invariant the node's docstring promises;
* every backend dialect looks like itself (KQL has no ``index=``, SPL has
  no ``FROM``, Sigma is a rule);
* ``TECHNIQUE_NAMES`` stays key-for-key in sync with ``QUERY_LIBRARY``;
* the generic placeholder still fires for uncovered techniques.
"""

from __future__ import annotations

import re

import pytest
from btagent_shared.types.hunt import Backend

from btagent_engine import NodeContext
from btagent_engine.reasoning.query_synth import QuerySynthInput, QuerySynthNode
from btagent_engine.reasoning.query_templates import (
    QUERY_LIBRARY,
    TECHNIQUE_NAMES,
    curated_counts,
    curated_technique_ids,
    lookup_template,
)

# --------------------------------------------------------------------------- #
# The golden numbers.
# --------------------------------------------------------------------------- #

# Total techniques with at least one curated backend template.
EXPECTED_TOTAL_TECHNIQUES = 73

# Per-backend curated technique counts. Gaps are deliberate and honest:
#   * crowdstrike is lower because Falcon has no mail-flow, no cloud
#     control-plane and no Kubernetes-audit telemetry — those techniques fall
#     through to the generic placeholder rather than pretending to be covered;
#   * defender is 0 — Defender advanced-hunting shares KQL with Sentinel but
#     has its own table set, so it is intentionally left to the fallback until
#     someone validates the tables;
#   * sigma is 72 (T1195 has no single sensible logsource).
EXPECTED_PER_BACKEND: dict[Backend, int] = {
    Backend.SPLUNK: 73,
    Backend.SENTINEL: 73,
    Backend.ELASTIC: 73,
    Backend.CROWDSTRIKE: 54,
    Backend.SIGMA: 72,
    Backend.DEFENDER: 0,
}

# The four executable backends #99 targets + how each one caps result volume.
_RESULT_CAPS: dict[Backend, re.Pattern[str]] = {
    Backend.SPLUNK: re.compile(r"\|\s*head\s+\d+\s*$", re.IGNORECASE),
    Backend.CROWDSTRIKE: re.compile(r"\|\s*head\s+\d+\s*$", re.IGNORECASE),
    Backend.SENTINEL: re.compile(r"\|\s*take\s+\d+\s*$", re.IGNORECASE),
    Backend.ELASTIC: re.compile(r"\|\s*LIMIT\s+\d+\s*$"),
}

# A cross-section of the highest-value techniques the packs / MITRE mapper /
# detection proposals reference. Every one of these must be curated on all
# four executable backends — this is the "breadth where it matters" check
# that a pure count can't make.
_CORE_FOUR_BACKEND_TECHNIQUES = [
    "T1003.001",  # LSASS dumping
    "T1021.001",  # RDP lateral movement
    "T1027",  # obfuscated command lines
    "T1047",  # WMI execution
    "T1053.005",  # scheduled tasks
    "T1055",  # process injection
    "T1059.001",  # PowerShell
    "T1059.003",  # cmd.exe
    "T1071.001",  # HTTP C2 beaconing
    "T1071.004",  # DNS tunnelling
    "T1078",  # valid accounts
    "T1105",  # ingress tool transfer
    "T1110",  # brute force
    "T1486",  # ransomware
    "T1490",  # inhibit system recovery
    "T1505.003",  # web shell
    "T1547.001",  # run-key persistence
    "T1562.001",  # impair defenses
]

_EXECUTABLE_BACKENDS = [
    Backend.SPLUNK,
    Backend.SENTINEL,
    Backend.ELASTIC,
    Backend.CROWDSTRIKE,
]


# --------------------------------------------------------------------------- #
# Counts
# --------------------------------------------------------------------------- #


def test_total_curated_technique_count():
    assert len(QUERY_LIBRARY) == EXPECTED_TOTAL_TECHNIQUES
    assert len(curated_technique_ids()) == EXPECTED_TOTAL_TECHNIQUES


def test_curated_technique_count_per_backend():
    assert curated_counts() == EXPECTED_PER_BACKEND


@pytest.mark.parametrize("backend", _EXECUTABLE_BACKENDS)
def test_each_executable_backend_has_broad_coverage(backend: Backend):
    """Floor check independent of the exact golden numbers above."""
    assert len(curated_technique_ids(backend)) >= 50


def test_technique_ids_are_wellformed():
    bad = [t for t in QUERY_LIBRARY if not re.fullmatch(r"T\d{4}(\.\d{3})?", t)]
    assert bad == [], f"malformed technique ids: {bad}"


def test_technique_names_do_not_drift_from_library():
    assert set(TECHNIQUE_NAMES) == set(QUERY_LIBRARY)
    assert all(name.strip() for name in TECHNIQUE_NAMES.values())


def test_core_techniques_cover_all_four_executable_backends():
    gaps = {
        ttp: [b.value for b in _EXECUTABLE_BACKENDS if b not in QUERY_LIBRARY.get(ttp, {})]
        for ttp in _CORE_FOUR_BACKEND_TECHNIQUES
    }
    assert {t: g for t, g in gaps.items() if g} == {}


def test_coverage_spans_the_attack_lifecycle():
    """Breadth means tactics, not just a pile of execution techniques."""
    tactic_probes = {
        "initial-access": ["T1190", "T1566.001"],
        "execution": ["T1059.001", "T1047"],
        "persistence": ["T1547.001", "T1505.003"],
        "privilege-escalation": ["T1068", "T1548.002"],
        "defense-evasion": ["T1027", "T1562.001"],
        "credential-access": ["T1003.001", "T1558.003"],
        "discovery": ["T1046", "T1087.002"],
        "lateral-movement": ["T1021.001", "T1021.002"],
        "collection": ["T1114", "T1560"],
        "command-and-control": ["T1071.001", "T1090.003"],
        "exfiltration": ["T1041", "T1567.002"],
        "impact": ["T1486", "T1490"],
    }
    missing = {
        tactic: [t for t in probes if t not in QUERY_LIBRARY]
        for tactic, probes in tactic_probes.items()
    }
    assert {k: v for k, v in missing.items() if v} == {}


# --------------------------------------------------------------------------- #
# Structure / syntax plausibility
# --------------------------------------------------------------------------- #


def test_every_executable_query_is_result_capped():
    offenders = []
    for ttp, per_backend in QUERY_LIBRARY.items():
        for backend, query in per_backend.items():
            pattern = _RESULT_CAPS.get(backend)
            if pattern is not None and not pattern.search(query.strip()):
                offenders.append((ttp, backend.value))
    assert offenders == [], f"uncapped curated queries: {offenders}"


def test_queries_are_substantive_not_placeholders():
    offenders = []
    for ttp, per_backend in QUERY_LIBRARY.items():
        for backend, query in per_backend.items():
            if len(query.strip()) < 40 or "TODO" in query:
                offenders.append((ttp, backend.value))
    assert offenders == [], f"placeholder-looking curated queries: {offenders}"


def test_backend_dialects_look_native():
    """Cheap syntax smell test — a KQL query that says ``index=`` is SPL."""
    offenders = []
    for ttp, per_backend in QUERY_LIBRARY.items():
        for backend, query in per_backend.items():
            if backend == Backend.SPLUNK and not query.lstrip().startswith("index="):
                offenders.append((ttp, "splunk-no-index"))
            if backend == Backend.SENTINEL and "index=" in query:
                offenders.append((ttp, "kql-has-spl"))
            if backend == Backend.ELASTIC and not query.lstrip().startswith("FROM "):
                offenders.append((ttp, "esql-no-from"))
            if backend == Backend.CROWDSTRIKE and "event_simpleName" not in query:
                offenders.append((ttp, "falcon-no-event"))
            if backend == Backend.SIGMA and not query.startswith("title:"):
                offenders.append((ttp, "sigma-no-title"))
    assert offenders == [], f"dialect smells: {offenders}"


def test_sigma_rules_carry_a_detection_block():
    offenders = [
        ttp
        for ttp, per_backend in QUERY_LIBRARY.items()
        if Backend.SIGMA in per_backend
        and (
            "logsource:" not in per_backend[Backend.SIGMA]
            or "condition:" not in per_backend[Backend.SIGMA]
        )
    ]
    assert offenders == [], f"sigma rules missing logsource/condition: {offenders}"


# --------------------------------------------------------------------------- #
# Lookup semantics + the preserved generic fallback
# --------------------------------------------------------------------------- #


def test_exact_lookup_beats_parent_inheritance():
    # Both T1078 and T1078.004 are curated -> the sub-technique wins.
    query, source = lookup_template("T1078.004", Backend.SPLUNK)
    assert source == "T1078.004"
    assert query == QUERY_LIBRARY["T1078.004"][Backend.SPLUNK]


def test_uncurated_subtechnique_inherits_parent():
    # T1110.001 (password guessing) has no entry of its own; T1110 does.
    assert "T1110.001" not in QUERY_LIBRARY
    query, source = lookup_template("T1110.001", Backend.SPLUNK)
    assert source == "T1110"
    assert query == QUERY_LIBRARY["T1110"][Backend.SPLUNK]


def test_lookup_returns_none_for_uncovered_technique():
    assert lookup_template("T9999.999", Backend.SPLUNK) is None
    # Curated technique, backend with an honest gap (no Falcon mail telemetry).
    assert lookup_template("T1566.001", Backend.CROWDSTRIKE) is None


async def test_generic_fallback_still_fires_for_uncovered_technique():
    out = await QuerySynthNode().run(
        QuerySynthInput(ttp_id="T9999.999", backends=_EXECUTABLE_BACKENDS),
        NodeContext(run_id="r_qs_cov", org_id="org_test"),
    )
    for backend in _EXECUTABLE_BACKENDS:
        assert "TODO" in out.queries[backend].query
        assert "refine" in out.queries[backend].notes.lower()


async def test_curated_technique_emits_named_curated_note():
    out = await QuerySynthNode().run(
        QuerySynthInput(ttp_id="T1003.001", backends=[Backend.SENTINEL]),
        NodeContext(run_id="r_qs_cov", org_id="org_test"),
    )
    note = out.queries[Backend.SENTINEL].notes
    assert "curated" in note.lower()
    assert "LSASS" in note
    assert "TODO" not in out.queries[Backend.SENTINEL].query


async def test_inherited_template_says_so_in_the_notes():
    out = await QuerySynthNode().run(
        QuerySynthInput(ttp_id="T1110.001", backends=[Backend.SPLUNK]),
        NodeContext(run_id="r_qs_cov", org_id="org_test"),
    )
    note = out.queries[Backend.SPLUNK].notes
    assert "inherited" in note.lower()
    assert "T1110" in note


async def test_node_emits_curated_queries_for_every_covered_technique():
    """End-to-end: no curated technique regresses into the generic path."""
    ctx = NodeContext(run_id="r_qs_cov", org_id="org_test")
    node = QuerySynthNode()
    offenders = []
    for ttp, per_backend in QUERY_LIBRARY.items():
        backends = sorted(per_backend, key=lambda b: b.value)
        out = await node.run(QuerySynthInput(ttp_id=ttp, backends=backends), ctx)
        for backend in backends:
            if out.queries[backend].query != per_backend[backend]:
                offenders.append((ttp, backend.value))
    assert offenders == []
