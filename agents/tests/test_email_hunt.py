"""Golden tests for the email-security hunt-finding mapper (email vertical, slice 1).

All tests are deterministic, pure-logic (no network / LLM / DB): they exercise
``btagent_shared.hunt.email`` over the dict shape the phishing-triage correlator
returns, and verify the end-to-end flow correlator → findings by feeding the
real ``correlate_email_threats`` output straight into the mapper.

Matrix:
  T1  priority → severity + confidence mapping (all four rungs).
  T2  technique set: base T1566; click adds T1566.002; malware adds T1566.001.
  T3  entities: recipient + sender become clustering keys.
  T4  observables: url + internet_message_id become pivot artifacts.
  T5  source/domain stamped EMAIL_SECURITY / EMAIL; evidence carries the raw
      incident.
  T6  quarantine + click incident titles are shaped for their kind.
  T7  ordering preserved (critical-first) and empty input → no findings.
  T8  end-to-end: correlate_email_threats output maps cleanly to findings.
"""

from __future__ import annotations

from btagent_shared.hunt.email import (
    phishing_incident_to_finding,
    phishing_incidents_to_findings,
)
from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt import HuntDomain, HuntSource

from btagent_agents.plugins.triage.tools.phishing_correlator import correlate_email_threats


def _incident(**overrides) -> dict:
    base = {
        "kind": "message",
        "priority": "high",
        "recipient": "cfo@acme.example",
        "internet_message_id": "<msg-1@acme.example>",
        "subject": "Invoice overdue",
        "sender": "attacker@bad.example",
        "verdict": "high_confidence_phish",
        "delivery_action": "delivered",
        "clicked": False,
        "rationale": "why",
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------- #
# T1 — priority → severity + confidence
# --------------------------------------------------------------------------- #


class TestSeverityConfidence:
    def test_all_priority_rungs(self) -> None:
        expected = {
            "critical": (Severity.CRITICAL, 0.95),
            "high": (Severity.HIGH, 0.8),
            "medium": (Severity.MEDIUM, 0.6),
            "low": (Severity.LOW, 0.45),
        }
        for priority, (sev, conf) in expected.items():
            f = phishing_incident_to_finding(_incident(priority=priority))
            assert f.severity == sev
            assert f.confidence == conf

    def test_unknown_priority_defaults_medium(self) -> None:
        f = phishing_incident_to_finding(_incident(priority="weird"))
        assert f.severity == Severity.MEDIUM
        assert f.confidence == 0.6


# --------------------------------------------------------------------------- #
# T2 — technique set
# --------------------------------------------------------------------------- #


class TestTechniques:
    def test_base_phishing_technique(self) -> None:
        f = phishing_incident_to_finding(_incident())
        assert f.technique_ids == ["T1566"]

    def test_click_adds_link_technique(self) -> None:
        f = phishing_incident_to_finding(_incident(clicked=True))
        assert "T1566.002" in f.technique_ids

    def test_click_kind_adds_link_technique(self) -> None:
        f = phishing_incident_to_finding(_incident(kind="click", clicked=True))
        assert "T1566.002" in f.technique_ids

    def test_malware_adds_attachment_technique(self) -> None:
        f = phishing_incident_to_finding(_incident(verdict="malware"))
        assert "T1566.001" in f.technique_ids


# --------------------------------------------------------------------------- #
# T3 / T4 — entities + observables
# --------------------------------------------------------------------------- #


class TestEntitiesObservables:
    def test_recipient_and_sender_entities(self) -> None:
        f = phishing_incident_to_finding(_incident())
        kinds = {(e.kind, e.value) for e in f.entities}
        assert ("email_recipient", "cfo@acme.example") in kinds
        assert ("email_sender", "attacker@bad.example") in kinds

    def test_missing_sender_omitted(self) -> None:
        f = phishing_incident_to_finding(_incident(sender=""))
        assert all(e.kind != "email_sender" for e in f.entities)

    def test_url_and_message_id_observables(self) -> None:
        f = phishing_incident_to_finding(
            _incident(kind="click", url="https://bad.example/pay", clicked=True)
        )
        obs = {(o.type, o.value) for o in f.observables}
        assert ("url", "https://bad.example/pay") in obs
        assert ("email_message_id", "<msg-1@acme.example>") in obs

    def test_no_url_when_absent(self) -> None:
        f = phishing_incident_to_finding(_incident())
        assert all(o.type != "url" for o in f.observables)


# --------------------------------------------------------------------------- #
# T5 — source/domain/evidence
# --------------------------------------------------------------------------- #


class TestProvenance:
    def test_source_and_domain_stamped(self) -> None:
        f = phishing_incident_to_finding(_incident())
        assert f.source == HuntSource.EMAIL_SECURITY
        assert f.domain == HuntDomain.EMAIL

    def test_evidence_carries_raw_incident(self) -> None:
        inc = _incident()
        f = phishing_incident_to_finding(inc)
        assert f.evidence["phishing_incident"] == inc
        assert f.description == "why"


# --------------------------------------------------------------------------- #
# T6 — kind-specific titles
# --------------------------------------------------------------------------- #


class TestTitles:
    def test_click_title(self) -> None:
        f = phishing_incident_to_finding(_incident(kind="click", verdict="phish"))
        assert "Malicious URL click" in f.title

    def test_quarantine_title(self) -> None:
        f = phishing_incident_to_finding(
            _incident(kind="quarantine", verdict="phish", release_status="needs_review")
        )
        assert "Quarantined" in f.title and "awaiting review" in f.title

    def test_delivered_message_title(self) -> None:
        f = phishing_incident_to_finding(_incident(delivery_action="delivered", clicked=True))
        assert "delivered" in f.title and "clicked" in f.title


# --------------------------------------------------------------------------- #
# T7 — ordering + empty
# --------------------------------------------------------------------------- #


class TestBatch:
    def test_ordering_preserved(self) -> None:
        correlation = {
            "incidents": [
                _incident(priority="critical", recipient="a@x.com"),
                _incident(priority="low", recipient="b@x.com"),
            ]
        }
        findings = phishing_incidents_to_findings(correlation)
        assert [f.severity for f in findings] == [Severity.CRITICAL, Severity.LOW]

    def test_empty_correlation_no_findings(self) -> None:
        assert phishing_incidents_to_findings({}) == []
        assert phishing_incidents_to_findings({"incidents": []}) == []


# --------------------------------------------------------------------------- #
# T8 — end-to-end from the real correlator
# --------------------------------------------------------------------------- #


class TestEndToEndFromCorrelator:
    def test_correlator_output_maps_cleanly(self) -> None:
        # A malicious message delivered and clicked → the correlator's critical
        # active-incident; the mapper turns it into a CRITICAL email finding.
        messages = [
            {
                "internet_message_id": "<m1@acme.example>",
                "recipient": "cfo@acme.example",
                "sender": "attacker@bad.example",
                "subject": "wire",
                "verdict": "high_confidence_phish",
                "delivery_action": "delivered",
            }
        ]
        clicks = [
            {
                "internet_message_id": "<m1@acme.example>",
                "recipient": "cfo@acme.example",
                "verdict": "high_confidence_phish",
                "disposition": "permitted",
                "url": "https://bad.example/pay",
            }
        ]
        correlation = correlate_email_threats(messages, clicks)
        findings = phishing_incidents_to_findings(correlation)
        assert findings
        top = findings[0]
        assert top.severity == Severity.CRITICAL
        assert top.source == HuntSource.EMAIL_SECURITY
        assert "T1566.002" in top.technique_ids  # clicked → link technique
        # The critical incident is the delivered-and-clicked *message*; it
        # carries the message-id (the click's url lives on standalone clicks).
        assert any(o.type == "email_message_id" for o in top.observables)
