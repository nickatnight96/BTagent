"""Tests for the richer detection-repo PR body (#113 "do both" — Task C).

The composer's Markdown body now carries, per shipped rule:

* an **evidence-chain SHA-256** of the exact rule body being shipped,
* an **intel-source citation** (source STIX indicator id + bundle id),
* a **validation hit-count** line (telemetry verdict + total hits), and
* a **draft-vs-final note** — whether an analyst edited the rule before it
  shipped (the migration-free path: the edited "final" text rides in on the
  in-memory request, never a new DB column).

These are pure-function assertions over ``_pr_body`` / ``build_pr_files`` — no
DB session, so no shared-DB isolation concerns.
"""

from __future__ import annotations

import hashlib

from btagent_backend.db.models_cti import DetectionProposalRow
from btagent_backend.services.cti_detection_service import _pr_body, build_pr_files


def _row(
    *,
    row_id: str,
    title: str,
    sigma_yaml: str,
    source_stix_id: str,
    bundle_id: str | None,
    technique_ids: list[str],
    validation: dict | None,
    confidence: float = 0.85,
) -> DetectionProposalRow:
    return DetectionProposalRow(
        id=row_id,
        org_id="org_prbody_test",
        proposal_id="prop_x",
        source_stix_id=source_stix_id,
        bundle_id=bundle_id,
        title=title,
        sigma_yaml=sigma_yaml,
        technique_ids=technique_ids,
        confidence=confidence,
        validation=validation,
    )


_SIGMA_A = "title: Rule A\ndetection:\n  selection:\n    x: 1\n  condition: selection\n"
_SIGMA_B = "title: Rule B\ndetection:\n  selection:\n    y: 2\n  condition: selection\n"


def _rows() -> list[DetectionProposalRow]:
    return [
        _row(
            row_id="dprop_aaa111",
            title="C2 Beacon Detection",
            sigma_yaml=_SIGMA_A,
            source_stix_id="indicator--1111",
            bundle_id="bundle--abc",
            technique_ids=["T1071.001"],
            validation={"verdict": "matched", "total_hits": 7},
        ),
        _row(
            row_id="dprop_bbb222",
            title="Phishing Domain Detection",
            sigma_yaml=_SIGMA_B,
            source_stix_id="indicator--2222",
            bundle_id="bundle--abc",
            technique_ids=["T1566.002"],
            validation=None,
        ),
    ]


def test_pr_body_includes_evidence_sha256() -> None:
    rows = _rows()
    body = _pr_body(rows)
    expected_a = hashlib.sha256(_SIGMA_A.encode("utf-8")).hexdigest()
    expected_b = hashlib.sha256(_SIGMA_B.encode("utf-8")).hexdigest()
    assert expected_a in body
    assert expected_b in body
    assert "Rule evidence SHA-256" in body


def test_pr_body_cites_intel_source() -> None:
    body = _pr_body(_rows())
    assert "indicator--1111" in body
    assert "indicator--2222" in body
    assert "bundle--abc" in body
    assert "Intel source" in body


def test_pr_body_reports_validation_hit_counts() -> None:
    body = _pr_body(_rows())
    # Validated row: verdict + explicit hit count.
    assert "matched" in body
    assert "7 hit(s)" in body
    # Unvalidated row: honest "no validation run" note (not a fake 0 hits).
    assert "no validation run recorded" in body
    # Summary table carries a Hits column with the count and an em-dash.
    assert "| Hits |" in body


def test_pr_body_draft_vs_final_unchanged_by_default() -> None:
    body = _pr_body(_rows())
    assert "unchanged from draft" in body
    assert "edited from draft" not in body


def test_pr_body_draft_vs_final_flags_edits() -> None:
    rows = _rows()
    edited_yaml = _SIGMA_A.replace("Rule A", "Rule A (analyst-tuned)")
    final = {rows[0].id: edited_yaml}
    body = _pr_body(rows, final_yaml_by_row=final)

    assert "edited from draft before shipping" in body
    # The evidence SHA is computed over the *shipped* (edited) body, not the draft.
    assert hashlib.sha256(edited_yaml.encode("utf-8")).hexdigest() in body
    assert hashlib.sha256(_SIGMA_A.encode("utf-8")).hexdigest() not in body
    # The untouched second rule is still reported as unchanged.
    assert "unchanged from draft" in body


def test_build_pr_files_ships_final_override() -> None:
    rows = _rows()
    edited_yaml = _SIGMA_A.replace("Rule A", "Rule A v2")
    files = build_pr_files(rows, final_yaml_by_row={rows[0].id: edited_yaml})
    by_content = [f["content"] for f in files]
    assert edited_yaml in by_content
    assert _SIGMA_A not in by_content
    # The un-overridden rule still ships its stored draft.
    assert _SIGMA_B in by_content


def test_build_pr_files_defaults_to_stored_draft() -> None:
    rows = _rows()
    files = build_pr_files(rows)
    contents = {f["content"] for f in files}
    assert contents == {_SIGMA_A, _SIGMA_B}
    # Deterministic technique-first layout.
    assert all(f["path"].startswith("rules/t") for f in files)
