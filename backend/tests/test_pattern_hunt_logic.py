"""Unit tests for the dependency-free Cross-Investigation Pattern Hunter logic (#120).

Pins the load-bearing ranking contract — cross-investigation diversity must
dominate raw occurrence frequency — plus extraction, the cluster→HuntInput
proposal transform, and a deterministic golden scenario of ~50 seeded closed
investigations spanning 3 underlying APT patterns (all 3 must land in top-N,
the planted pattern in the top-3). No DB, embedding service, or LLM.
"""

from datetime import UTC, datetime, timedelta

import pytest
from btagent_shared.hunt import pattern
from btagent_shared.hunt.pattern import (
    ClosedInvestigationRecord,
    ObservedIOC,
    WeakSignalClusterer,
    WeakSignalExtractor,
)
from btagent_shared.types.pattern_hunt import WeakSignal, WeakSignalKind

NOW = datetime(2026, 6, 18, tzinfo=UTC)


def _ws(
    *,
    value: str,
    kind: WeakSignalKind = WeakSignalKind.IOC,
    distinct: int,
    refs: list[str] | None = None,
    last_seen: datetime = NOW,
) -> WeakSignal:
    refs = refs if refs is not None else [f"inv_{i}" for i in range(distinct)]
    return WeakSignal(
        id=f"ws_{value}",
        kind=kind,
        value=value,
        first_seen=last_seen - timedelta(days=1),
        last_seen=last_seen,
        investigation_refs=refs,
        distinct_investigation_count=distinct,
    )


# --------------------------------------------------------------------------- #
# THE acceptance criterion: 5 unrelated > 5-in-1
# --------------------------------------------------------------------------- #


def test_five_unrelated_investigations_outrank_five_in_one():
    """A signal in 5 *unrelated* investigations must rank ABOVE a signal with
    5 occurrences in 1 investigation. This is the core #120 contract."""
    spread = _ws(value="spread", distinct=5, refs=[f"inv_{i}" for i in range(5)])
    # concentrated: many occurrences, but all inside a single investigation.
    concentrated = _ws(value="concentrated", distinct=5, refs=["inv_single"])
    # NOTE: distinct_investigation_count here is the occurrence count *within*
    # one case (the worst-case adversarial input). Diversity in score_cluster
    # is keyed on the distinct ref *set*, so concentrated has diversity 1.
    spread_score = pattern.score_cluster([spread], now=NOW)
    concentrated_score = pattern.score_cluster([concentrated], now=NOW)
    assert spread_score > concentrated_score


def test_diversity_dominates_frequency_helper():
    # The pinned guarantee, exercised directly across a range of magnitudes.
    assert pattern.diversity_dominates_frequency(
        spread_distinct_investigations=5, concentrated_occurrences=5, now=NOW
    )
    # Even a heavily-hammered single case (50 occurrences) loses to 5 spread.
    assert pattern.diversity_dominates_frequency(
        spread_distinct_investigations=5, concentrated_occurrences=50, now=NOW
    )
    # And 3 unrelated beats 20-in-1.
    assert pattern.diversity_dominates_frequency(
        spread_distinct_investigations=3, concentrated_occurrences=20, now=NOW
    )


def test_diversity_factor_is_superlinear():
    # squared → 5 distinct is 25x a single, not 5x.
    assert pattern.diversity_factor(5) == 25.0
    assert pattern.diversity_factor(1) == 1.0
    assert pattern.diversity_factor(0) == 0.0


def test_frequency_factor_saturates():
    # log1p → 50 occurrences is ~2.2x the score of 5, not 10x.
    f5 = pattern.frequency_factor(5)
    f50 = pattern.frequency_factor(50)
    assert f50 / f5 < 2.5


def test_recency_factor_decays_and_floors():
    assert pattern.recency_factor(NOW, now=NOW) == pytest.approx(1.0)
    half = pattern.recency_factor(NOW - timedelta(days=90), now=NOW)
    assert half == pytest.approx(0.5, abs=0.01)
    ancient = pattern.recency_factor(NOW - timedelta(days=3650), now=NOW)
    assert ancient == pytest.approx(0.05, abs=1e-6)  # floored


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #


def test_extractor_dedupes_and_counts_distinct_investigations():
    records = [
        ClosedInvestigationRecord(
            investigation_id="inv_a",
            closed_at=NOW,
            iocs=[ObservedIOC(type="ip", value="1.2.3.4")],
        ),
        ClosedInvestigationRecord(
            investigation_id="inv_b",
            closed_at=NOW,
            iocs=[ObservedIOC(type="ip", value="1.2.3.4")],
        ),
    ]
    signals = WeakSignalExtractor().extract(records)
    ip = next(s for s in signals if s.kind is WeakSignalKind.IOC and s.value == "1.2.3.4")
    assert ip.distinct_investigation_count == 2
    assert set(ip.investigation_refs) == {"inv_a", "inv_b"}


def test_extractor_pulls_tld_from_domainish_iocs():
    records = [
        ClosedInvestigationRecord(
            investigation_id="inv_a",
            closed_at=NOW,
            iocs=[ObservedIOC(type="domain", value="login.evil-corp.com")],
        ),
        ClosedInvestigationRecord(
            investigation_id="inv_b",
            closed_at=NOW,
            iocs=[ObservedIOC(type="url", value="https://mail.evil-corp.com/x")],
        ),
    ]
    signals = WeakSignalExtractor().extract(records)
    tld = next(s for s in signals if s.kind is WeakSignalKind.TLD)
    assert tld.value == "evil-corp.com"
    assert tld.distinct_investigation_count == 2


def test_extract_tld_handles_email_url_and_www():
    assert pattern.extract_tld("user@sub.bad.net") == "bad.net"
    assert pattern.extract_tld("http://www.bad.net/path?q=1") == "bad.net"
    assert pattern.extract_tld("bad.net") == "bad.net"
    assert pattern.extract_tld("localhost") == ""


def test_extractor_normalizes_asn_prefix():
    records = [
        ClosedInvestigationRecord(investigation_id="inv_a", closed_at=NOW, asns=["AS12345"]),
        ClosedInvestigationRecord(investigation_id="inv_b", closed_at=NOW, asns=["12345"]),
    ]
    signals = WeakSignalExtractor().extract(records)
    asn = next(s for s in signals if s.kind is WeakSignalKind.ASN)
    assert asn.value == "12345"
    assert asn.distinct_investigation_count == 2


def test_extractor_drops_short_cmdline_fragments():
    records = [
        ClosedInvestigationRecord(
            investigation_id="inv_a",
            closed_at=NOW,
            cmdline_fragments=["ab", "powershell -enc"],
        )
    ]
    signals = WeakSignalExtractor().extract(records)
    cmd_values = {s.value for s in signals if s.kind is WeakSignalKind.CMDLINE_FRAGMENT}
    assert "ab" not in cmd_values
    assert "powershell -enc" in cmd_values


# --------------------------------------------------------------------------- #
# Clustering threshold
# --------------------------------------------------------------------------- #


def test_clusterer_requires_min_distinct_investigations():
    single = _ws(value="onlyonce", distinct=1, refs=["inv_x"])
    spread = _ws(value="spread", distinct=3, refs=["inv_1", "inv_2", "inv_3"])
    clusters = WeakSignalClusterer().cluster([single, spread], now=NOW)
    ids = {c.id for c in clusters}
    assert any("spread" in cid for cid in ids)
    assert not any("onlyonce" in cid for cid in ids)


def test_clusterer_sorts_by_score_desc():
    low = _ws(value="low", distinct=2, refs=["inv_1", "inv_2"])
    high = _ws(value="high", distinct=8, refs=[f"inv_{i}" for i in range(8)])
    clusters = WeakSignalClusterer().cluster([low, high], now=NOW)
    assert clusters[0].members[0].value == "high"
    assert clusters[0].score > clusters[1].score


# --------------------------------------------------------------------------- #
# Cluster -> HuntInput proposal
# --------------------------------------------------------------------------- #


def test_cluster_to_hunt_input_is_non_empty_for_ioc():
    cluster = WeakSignalClusterer().cluster([_ws(value="9.9.9.9", distinct=3)], now=NOW)[0]
    hi = pattern.cluster_to_hunt_input(cluster, initiated_by="tester")
    assert hi.initiated_by == "tester"
    assert len(hi.iocs) == 1
    assert hi.iocs[0].value == "9.9.9.9"
    # at least one of (adversaries, ttps, iocs) non-empty
    assert hi.iocs or hi.ttps or hi.adversaries


def test_cluster_to_hunt_input_maps_technique_to_ttps():
    sig = _ws(value="t1059.001", kind=WeakSignalKind.TECHNIQUE, distinct=4)
    cluster = WeakSignalClusterer().cluster([sig], now=NOW)[0]
    hi = pattern.cluster_to_hunt_input(cluster, initiated_by="tester")
    assert hi.ttps == ["T1059.001"]
    assert hi.iocs == []


def test_cluster_to_hunt_input_tld_becomes_domain_ioc():
    sig = _ws(value="evil-corp.com", kind=WeakSignalKind.TLD, distinct=5)
    cluster = WeakSignalClusterer().cluster([sig], now=NOW)[0]
    hi = pattern.cluster_to_hunt_input(cluster, initiated_by="tester")
    assert len(hi.iocs) == 1
    assert hi.iocs[0].type.value == "domain"


def test_cluster_to_hunt_input_rejects_empty_cluster():
    from btagent_shared.types.pattern_hunt import WeakSignalCluster

    empty = WeakSignalCluster(id="wsc_empty", members=[], score=0.0)
    with pytest.raises(ValueError, match="empty cluster"):
        pattern.cluster_to_hunt_input(empty, initiated_by="tester")


# --------------------------------------------------------------------------- #
# Finding 3 (Codex #208 P1): exact-IOC signals preserve their original type
# --------------------------------------------------------------------------- #


def test_ip_signal_yields_ip_ioc_and_maps_in_hypothesis_gen():
    """An IP IOC recurring across cases must keep IOCType.IP through to the
    proposal, so the hypothesis generator's default-TTP map can pick it up
    (rather than flattening to OTHER → zero hypotheses)."""
    from btagent_shared.types.enums import IOCType

    records = [
        ClosedInvestigationRecord(
            investigation_id="inv_a",
            closed_at=NOW,
            iocs=[ObservedIOC(type="ip", value="203.0.113.7")],
        ),
        ClosedInvestigationRecord(
            investigation_id="inv_b",
            closed_at=NOW,
            iocs=[ObservedIOC(type="ip", value="203.0.113.7")],
        ),
    ]
    signals = WeakSignalExtractor().extract(records)
    ip_sig = next(s for s in signals if s.kind is WeakSignalKind.IOC and s.value == "203.0.113.7")
    assert ip_sig.ioc_type == "ip"

    cluster = WeakSignalClusterer().cluster([ip_sig], now=NOW)[0]
    hi = pattern.cluster_to_hunt_input(cluster, initiated_by="tester")
    assert len(hi.iocs) == 1
    assert hi.iocs[0].type is IOCType.IP

    # And hypothesis_gen's default-TTP map has an entry for "ip", so a proposal
    # built from this IOC can produce a non-empty hypothesis list / runbook.
    from btagent_engine.reasoning.hypothesis_gen import _IOC_TYPE_DEFAULT_TTP

    assert hi.iocs[0].type.value in _IOC_TYPE_DEFAULT_TTP


def test_common_ioc_types_survive_unknown_falls_back_to_other():
    from btagent_shared.types.enums import IOCType

    cases = [
        ("ip", IOCType.IP),
        ("url", IOCType.URL),
        ("hash_sha256", IOCType.HASH_SHA256),
        ("email", IOCType.EMAIL),
        ("cve", IOCType.CVE),
        ("file_path", IOCType.FILE_PATH),
        # genuinely unknown / unset -> OTHER
        ("totally_made_up", IOCType.OTHER),
    ]
    for raw_type, expected in cases:
        records = [
            ClosedInvestigationRecord(
                investigation_id=f"inv_{raw_type}_{i}",
                closed_at=NOW,
                iocs=[ObservedIOC(type=raw_type, value=f"val-{raw_type}")],
            )
            for i in range(2)
        ]
        signals = WeakSignalExtractor().extract(records)
        sig = next(s for s in signals if s.kind is WeakSignalKind.IOC)
        cluster = WeakSignalClusterer().cluster([sig], now=NOW)[0]
        hi = pattern.cluster_to_hunt_input(cluster, initiated_by="t")
        assert hi.iocs[0].type is expected, raw_type


# --------------------------------------------------------------------------- #
# Finding 2 (Codex #208 P1): cluster ids are collision-resistant
# --------------------------------------------------------------------------- #


def test_distinct_values_collapsing_to_same_slug_get_distinct_cluster_ids():
    """`a.b` and `a-b` both slug to `a-b`; the appended content hash must keep
    their cluster ids (and signal/ioc ids) distinct so neither proposal
    silently overwrites the other on the (org_id, cluster_id) unique key."""
    dotted = _ws(value="a.b", distinct=3)
    dashed = _ws(value="a-b", distinct=3)
    clusters = WeakSignalClusterer().cluster([dotted, dashed], now=NOW)
    ids = [c.id for c in clusters]
    assert len(ids) == len(set(ids)), ids
    # Both still carry the readable slug prefix for humans.
    assert all(cid.startswith("wsc_ioc_a-b_") for cid in ids), ids


def test_cluster_id_is_deterministic_across_runs():
    sig = _ws(value="a.b", distinct=3)
    run1 = WeakSignalClusterer().cluster([sig], now=NOW)[0].id
    run2 = WeakSignalClusterer().cluster([sig], now=NOW)[0].id
    assert run1 == run2

    # Long values sharing a 48-char slug prefix also stay distinct.
    long_a = _ws(value="x" * 60 + "-aaa", distinct=2)
    long_b = _ws(value="x" * 60 + "-bbb", distinct=2)
    c = WeakSignalClusterer().cluster([long_a, long_b], now=NOW)
    assert c[0].id != c[1].id


# --------------------------------------------------------------------------- #
# Golden scenario: ~50 closed investigations, 3 APT patterns
# --------------------------------------------------------------------------- #


def _build_golden_corpus() -> list[ClosedInvestigationRecord]:
    """50 closed investigations seeded with 3 planted cross-case APT patterns.

    * APT-A ("apex"): a single C2 domain reused across many UNRELATED cases —
      the strongest cross-case signal (planted to land top-3).
    * APT-B ("bishop"): a shared ATT&CK technique recurring across cases.
    * APT-C ("crane"): a reused ASN across a handful of cases.

    Everything else is per-case noise (unique IOCs that touch exactly one
    investigation) so the planted patterns must rise above background.
    """
    records: list[ClosedInvestigationRecord] = []
    base = datetime(2026, 1, 1, tzinfo=UTC)

    # APT-A: c2 domain in 18 unrelated investigations (inv 0..17).
    # APT-B: technique T1566.001 in 12 investigations (inv 10..21).
    # APT-C: ASN 64500 in 6 investigations (inv 30..35).
    for i in range(50):
        closed = base + timedelta(days=i)
        iocs = [
            # per-case noise: unique IP touching only this one case.
            ObservedIOC(type="ip", value=f"10.0.{i}.1"),
        ]
        techniques: list[str] = []
        asns: list[str] = []

        if i < 18:
            iocs.append(ObservedIOC(type="domain", value=f"node{i}.apex-c2.net"))
        if 10 <= i < 22:
            techniques.append("T1566.001")
        if 30 <= i < 36:
            asns.append("AS64500")

        records.append(
            ClosedInvestigationRecord(
                investigation_id=f"inv_{i:02d}",
                closed_at=closed,
                iocs=iocs,
                techniques=techniques,
                asns=asns,
            )
        )
    return records


def test_golden_three_apt_patterns_all_in_top_n():
    records = _build_golden_corpus()
    signals = WeakSignalExtractor().extract(records)
    clusters = WeakSignalClusterer().cluster(signals, now=NOW, top_n=10)

    # All three planted patterns must surface in top-N.
    top_n_signature = [(c.members[0].kind, c.members[0].value) for c in clusters]

    apt_a = (WeakSignalKind.TLD, "apex-c2.net")
    apt_b = (WeakSignalKind.TECHNIQUE, "t1566.001")
    apt_c = (WeakSignalKind.ASN, "64500")

    assert apt_a in top_n_signature, f"APT-A missing from top-N: {top_n_signature}"
    assert apt_b in top_n_signature, f"APT-B missing from top-N: {top_n_signature}"
    assert apt_c in top_n_signature, f"APT-C missing from top-N: {top_n_signature}"

    # The strongest planted pattern (APT-A, 18 unrelated cases) lands top-3.
    top_3 = top_n_signature[:3]
    assert apt_a in top_3, f"APT-A (strongest) not in top-3: {top_3}"

    # Per-case noise (single-investigation IPs) must NOT crowd the top-N.
    noise_in_top = [s for s in top_n_signature if s[0] is WeakSignalKind.IOC]
    # the only IOC-kind signals are the noise IPs (each touches one case), so
    # the min-distinct=2 threshold should have excluded them all.
    assert noise_in_top == [], f"per-case noise leaked into top-N: {noise_in_top}"


def test_golden_is_deterministic():
    records = _build_golden_corpus()
    run1 = WeakSignalClusterer().cluster(WeakSignalExtractor().extract(records), now=NOW, top_n=10)
    run2 = WeakSignalClusterer().cluster(WeakSignalExtractor().extract(records), now=NOW, top_n=10)
    assert [(c.id, c.score) for c in run1] == [(c.id, c.score) for c in run2]
