"""#103 demo-scenario acceptance tests — the four demos, end-to-end over the API.

The NightWing catalog (#103) defines four demo-ready scenarios, each chaining
multiple use cases. Its definition-of-done requires an E2E acceptance test per
scenario in ``tests/uat/``; this file is that. Every step drives the real HTTP
API against the mock-mode stack (BTAGENT_MOCK_LLM / BTAGENT_MOCK_CONNECTORS),
so the flows are deterministic and run in the CI UAT job.

Run with: pytest tests/uat/test_demo_scenarios.py -v
Requires: backend on localhost:8000, postgres + redis up, seeded personas.

HITL note: Demo 3 asserts the cross-cutting requirement directly — an
unapproved containment execution is REFUSED with a durable audit id, because
"the agent proposes; the analyst decides" is enforced by the platform, not by
prompt text.
"""

from __future__ import annotations

import time

import httpx
import pytest

BASE = "http://localhost:8000"


@pytest.fixture(scope="module")
def client():
    return httpx.Client(base_url=BASE, timeout=30)


@pytest.fixture(scope="module")
def admin_headers(client):
    r = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "admin"}
    )
    assert r.status_code == 200, f"Admin login failed: {r.text}"
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ── Demo 1 — Hypothesis-Driven Hunt (UC-1.1 / 1.2 / 4.1 / 5.2) ──────────────


class TestDemo1HypothesisDrivenHunt:
    """'Hunt for suspicious PowerShell (T1059.001)…' → plan with per-backend
    queries and an executable runbook."""

    def test_ttp_to_plan_with_queries_and_runbook(self, client, admin_headers):
        r = client.post(
            "/api/v1/hunts/plan",
            headers=admin_headers,
            json={"ttps": ["T1059.001"], "adversaries": []},
        )
        assert r.status_code == 200, r.text
        plan = r.json()

        # The agent mapped the TTP into at least one hypothesis…
        assert plan["hypotheses"], "plan produced no hypotheses"
        # …and a runbook entry for the technique with executable queries.
        entries = plan["ttp_entries"]
        assert entries, "plan produced no TTP runbook entries"
        techniques = {e["ttp_id"] for e in entries}
        assert "T1059.001" in techniques
        # ``queries`` is a per-backend mapping (backend name -> Query).
        queried = [e for e in entries if e.get("queries")]
        assert queried, "no runbook entry carries per-backend queries"
        backends = {backend for e in queried for backend in e["queries"]}
        assert backends, "queries carry no backend names"

    def test_plan_is_persisted_and_listable(self, client, admin_headers):
        r = client.post(
            "/api/v1/hunts/plan",
            headers=admin_headers,
            json={"ttps": ["T1059.001"]},
        )
        assert r.status_code == 200, r.text
        plan_id = r.json()["id"]

        got = client.get(f"/api/v1/hunts/plans/{plan_id}", headers=admin_headers)
        assert got.status_code == 200, got.text
        assert got.json()["id"] == plan_id


# ── Demo 2 — Intel-Driven Hunt (UC-2.1 / 2.2 / 4.3) ─────────────────────────


ADVISORY = """\
CISA Advisory AA26-999A: Threat actors were observed delivering payloads from
hxxp://malicious-cdn[.]example[.]com/stage2.ps1 and beaconing to 203.0.113.77.
Post-exploitation used encoded PowerShell (T1059.001) and scheduled tasks
(T1053.005) for persistence. A dropped binary carried SHA-256
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
"""


class TestDemo2IntelDrivenHunt:
    """Paste an advisory → extracted IOCs/TTPs → persisted Sigma proposals →
    historical validation against the mock backends."""

    def test_advisory_text_to_validated_proposal(self, client, admin_headers):
        tag = f"uat-demo2-{int(time.time())}"
        r = client.post(
            "/api/v1/cti/propose-detections",
            headers=admin_headers,
            json={"report_text": ADVISORY, "report_name": tag},
            timeout=60,
        )
        assert r.status_code == 200, r.text
        proposals = r.json()["proposals"]
        assert proposals, "no proposals extracted from the advisory text"

        # Proposals were persisted into the review queue.
        listing = client.get(
            "/api/v1/cti/proposals?page_size=200", headers=admin_headers
        )
        assert listing.status_code == 200, listing.text
        rows = listing.json()["items"]
        assert rows, "proposal store is empty after propose-detections"

        # Validate the newest proposal over historical telemetry (mock
        # connectors; 90-day default window per #113).
        row_id = rows[0]["id"]
        v = client.post(
            f"/api/v1/cti/proposals/{row_id}/validate",
            headers=admin_headers,
            json={},
            timeout=120,
        )
        assert v.status_code == 200, v.text
        validation = v.json()["validation"]
        assert validation is not None
        assert validation["verdict"] in {"matched", "clean", "error"}


# ── Demo 3 — Alert Triage to Containment (UC-3.1 / 3.2 / 2.3) ───────────────


class TestDemo3TriageToContainment:
    """Alert → classification → dual-path response plan → containment that is
    REFUSED without explicit approval (the platform-enforced HITL gate)."""

    def test_triage_classifies_the_alert(self, client, admin_headers):
        r = client.post(
            "/api/v1/triage",
            headers=admin_headers,
            json={
                "title": "Multiple failed logons followed by success for admin",
                "description": "20 failed logons then success from a new ASN.",
                "source": "splunk",
                "severity": "high",
                "entities": {"user": ["admin"], "ip": ["203.0.113.77"]},
            },
        )
        assert r.status_code == 200, r.text
        result = r.json()
        assert result["typed_intent"], "triage produced no typed intent"
        assert result["disposition"], "triage produced no disposition"
        assert result["proposed_severity"], "triage proposed no severity"

    def test_response_plan_and_hitl_refusal(self, client, admin_headers):
        plan = client.post(
            "/api/v1/response-plan",
            headers=admin_headers,
            json={
                "typed_intent": "malware_detected",
                "severity": "high",
                "entities": {"host": ["web-01"], "ip": ["203.0.113.77"]},
            },
        )
        assert plan.status_code == 200, plan.text
        steps = plan.json()["plan"]["tactical_steps"]
        assert steps, "response plan produced no tactical steps"

        # Cross-cutting HITL requirement: executing a step WITHOUT approval
        # must be refused — and the refusal itself must be durably audited.
        step = steps[0]
        refusal = client.post(
            "/api/v1/containment/execute/response-action",
            headers=admin_headers,
            json={
                "action_id": step.get("id") or "uat-demo3-step",
                "action_type": step.get("action_type") or "isolate_host",
                "connector": step.get("connector") or "crowdstrike",
                "target": "web-01",
                "description": "UAT demo 3 unapproved execution attempt",
                "approved": False,
            },
        )
        assert refusal.status_code in (400, 403), (
            f"unapproved containment was not refused: {refusal.status_code} {refusal.text}"
        )
        detail = refusal.json()["detail"]
        assert detail["outcome"] == "denied"
        assert detail.get("audit_id"), "refusal was not written to the audit ledger"


# ── Demo 4 — Incident to Report (UC-5.2 / 6.1 / 6.2 / 7.1) ──────────────────


class TestDemo4IncidentToReport:
    """Investigation → executive + CISA-format reporting → verifiable audit
    lineage for the whole trail.

    The report plugin's case-data source is still the fixed-id mock store
    (#109 gap), while the API route org-scope-checks the real DB — so the
    demo seeds a DB row with the mock store's case id (``inv_mock_001``)
    through the test-gated seed route, making both gates pass the way a
    wired #109 would.
    """

    @pytest.fixture(scope="class")
    def investigation_id(self, client, admin_headers):
        r = client.post(
            "/api/v1/investigations/test/seed",
            headers=admin_headers,
            json={
                "id": "inv_mock_001",
                "title": "Phishing Campaign Targeting Finance Department",
                "description": "Phishing alert escalated for the reporting demo.",
                "severity": "high",
            },
        )
        assert r.status_code == 201, r.text
        return r.json()["id"]

    def test_generate_executive_and_cisa_reports(
        self, client, admin_headers, investigation_id
    ):
        for template in ("executive_briefing", "cisa_incident"):
            r = client.post(
                "/api/v1/reports/generate",
                headers=admin_headers,
                json={"investigation_id": investigation_id, "template": template},
                timeout=60,
            )
            assert r.status_code == 200, f"{template}: {r.text}"
            body = r.json()
            sections = body.get("sections") or {}
            assert sections, f"{template} produced no sections"
            assert all(str(v).strip() for v in sections.values()), (
                f"{template} produced an empty section"
            )

    def test_coordination_summary_draft(self, client, admin_headers, investigation_id):
        r = client.post(
            "/api/v1/reports/summarize",
            headers=admin_headers,
            json={"investigation_ids": [investigation_id], "format": "cisa"},
            timeout=60,
        )
        assert r.status_code == 200, r.text

    def test_audit_chain_verifies(self, client, admin_headers):
        r = client.get("/api/v1/audit/verify", headers=admin_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body.get("valid") is True, f"audit chain failed verification: {body}"
