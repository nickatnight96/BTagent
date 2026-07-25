"""Tests for the shift-handover narrative composer (#108 UC-5.1).

Pure-function coverage of ``compose_handover_narrative`` (quiet shift,
section rendering, severity ordering, bullet caps, watch-items) plus one
API-level check that ``GET /api/v1/handover`` carries the brief.
"""

from datetime import UTC, datetime

from conftest import auth_header

from btagent_backend.services.handover_narrative import compose_handover_narrative


def _summary(**overrides):
    base = {
        "window_hours": 8,
        "window_start": datetime.now(UTC),
        "generated_at": datetime.now(UTC),
        "headline": "",
        "investigations": [],
        "open_by_severity": {},
        "findings_by_severity": {},
        "findings_untriaged": 0,
    }
    base.update(overrides)
    return base


def _case(title: str, *, is_new: bool = True, severity: str = "high", status: str = "pending"):
    return {
        "id": "inv_x",
        "title": title,
        "severity": severity,
        "status": status,
        "is_new": is_new,
        "updated_at": datetime.now(UTC),
    }


def test_quiet_shift_is_a_single_line():
    narrative = compose_handover_narrative(_summary())
    assert narrative.startswith("Quiet shift:")
    assert "\n" not in narrative


def test_active_shift_sections_and_watch_items():
    narrative = compose_handover_narrative(
        _summary(
            investigations=[
                _case("Phishing wave", is_new=True, severity="high", status="investigating"),
                _case("Old beacon case", is_new=False, severity="medium", status="paused"),
            ],
            open_by_severity={"high": 2, "critical": 1},
            findings_by_severity={"medium": 3, "critical": 2},
            findings_untriaged=4,
        )
    )
    lines = narrative.splitlines()
    assert lines[0] == "Shift brief — last 8h:"
    assert "New cases (1):" in lines
    assert "  - [high] Phishing wave (investigating)" in lines
    assert "Updated cases (1):" in lines
    assert "  - [medium] Old beacon case (paused)" in lines
    # Severity buckets render in canonical order (critical before medium/high).
    assert "Hunt findings: 5 landed (2 critical, 3 medium); 4 untriaged." in lines
    assert "Open backlog: 3 case(s) — 1 critical, 2 high." in lines
    # Watch-items: untriaged first, then critical, then high.
    assert lines[-1] == (
        "Watch first: triage the 4 untriaged finding(s); "
        "1 critical case(s) still open; 2 high-severity case(s) still open."
    )


def test_bullets_are_capped():
    cases = [_case(f"Case {n}") for n in range(7)]
    narrative = compose_handover_narrative(_summary(investigations=cases))
    assert narrative.count("  - [high]") == 5
    assert "… and 2 more" in narrative


async def test_handover_api_exposes_narrative(client, analyst_token):
    inv = await client.post(
        "/api/v1/investigations",
        headers=auth_header(analyst_token),
        json={
            "title": "Narrative Test — token replay",
            "description": "seeded by test_handover_narrative",
            "severity": "high",
        },
    )
    assert inv.status_code in (200, 201), inv.text

    resp = await client.get("/api/v1/handover", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    narrative = resp.json()["narrative"]
    assert narrative.startswith("Shift brief — last 8h:")
    assert "Narrative Test — token replay" in narrative
