"""The chart has three ways to supply secrets, and they must not collide.

1. ``existingSecret`` — a Secret the operator created and manages.
2. ``externalSecrets.enabled`` — the External Secrets Operator syncs one.
3. neither — the chart renders ``<fullname>-secret`` from ``secretEnv``.

The failure this file exists to prevent is a naming one, and it has already
happened once. ``DEPLOYMENT.md`` told operators to run
``--set secretEnv.existingSecret=btagent-secrets``, which the chart did not
understand: ``--set`` simply added a map entry called ``existingSecret``, so
the rendered Secret held that one meaningless key, none of the real
credentials, and the Secret the operator had created was mounted by nothing.
The backend came up with no ``BTAGENT_DATABASE_URL``. That was the *primary
documented install path*.

So the property under test is: **every workload resolves the Secret name the
same way, through one helper.** A consumer that hardcodes
``<fullname>-secret`` keeps working in the default mode and silently mounts
the wrong object under ``existingSecret`` — which is precisely the shape of
bug a text-only test misses, so the name resolution is exercised by rendering
the helper for each mode rather than grepping for it.

There is no ``helm`` binary in CI (see ``test_helm_backup_cronjob.py`` for the
same constraint), so ``_resolve_secret_name`` reimplements the helper's logic
and is pinned against the template source by
``test_the_stub_matches_the_shipped_helper``. That coupling is the honest weak
point of this file and is called out rather than hidden.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_CHART = Path(__file__).resolve().parents[2] / "infra" / "helm" / "btagent"
_TEMPLATES = _CHART / "templates"
_VALUES = _CHART / "values.yaml"

_SECRET_REF_NAME = re.compile(r"secretRef:\s*\n\s*name:\s*(?P<name>.+)")
_HELPER_CALL = '{{ include "btagent.secretName" . }}'


@pytest.fixture(scope="module")
def values() -> dict:
    return yaml.safe_load(_VALUES.read_text(encoding="utf-8"))


def _resolve_secret_name(*, fullname: str, existing_secret: str) -> str:
    """What `btagent.secretName` renders to. Kept honest by the test below."""
    return existing_secret or f"{fullname}-secret"


def test_the_stub_matches_the_shipped_helper():
    """Guard the guard: if the helper's logic changes, this file must too."""
    helpers = (_TEMPLATES / "_helpers.tpl").read_text(encoding="utf-8")
    assert '{{- define "btagent.secretName" -}}' in helpers, "the helper is gone"
    body = helpers.split('{{- define "btagent.secretName" -}}', 1)[1].split("{{- end }}", 1)[0]
    assert ".Values.existingSecret" in body
    assert 'printf "%s-secret" (include "btagent.fullname" .)' in body, (
        "the fallback name changed; _resolve_secret_name above is now wrong"
    )


# ---------------------------------------------------------------------------
# One resolution path for every consumer.
# ---------------------------------------------------------------------------


def test_every_workload_resolves_the_name_through_the_helper():
    """A hardcoded name works in the default mode and breaks under existingSecret."""
    offenders: list[str] = []
    for template in sorted(_TEMPLATES.glob("*.yaml")):
        src = template.read_text(encoding="utf-8")
        for match in _SECRET_REF_NAME.finditer(src):
            name = match.group("name").strip()
            if name != _HELPER_CALL:
                offenders.append(f"{template.name}: {name}")
    assert not offenders, (
        "workload(s) mount a Secret name not resolved through btagent.secretName:\n  "
        + "\n  ".join(offenders)
    )


def test_at_least_the_known_consumers_are_covered():
    """Vacuity check — the regex must actually be finding the four consumers."""
    found = {
        t.name
        for t in _TEMPLATES.glob("*.yaml")
        if _SECRET_REF_NAME.search(t.read_text(encoding="utf-8"))
    }
    assert {"deployment.yaml", "migrate-job.yaml", "backup-cronjob.yaml"} <= found, (
        f"expected the backend/scheduler, migrate and backup workloads; found {found}"
    )


@pytest.mark.parametrize(
    "existing_secret,expected",
    [
        ("", "btagent-secret"),
        ("btagent-secrets", "btagent-secrets"),
        ("corp-managed-db-creds", "corp-managed-db-creds"),
    ],
    ids=["default", "operator-supplied", "arbitrary-name"],
)
def test_name_resolution_for_each_mode(existing_secret: str, expected: str):
    assert _resolve_secret_name(fullname="btagent", existing_secret=existing_secret) == expected


def test_external_secret_target_uses_the_same_helper():
    """Otherwise the operator syncs a Secret the workloads do not mount."""
    src = (_TEMPLATES / "externalsecret.yaml").read_text(encoding="utf-8")
    assert re.search(r"target:\s*\n(?:\s*#.*\n)*\s*name:\s*" + re.escape(_HELPER_CALL), src)


# ---------------------------------------------------------------------------
# Defaults and mutual exclusion.
# ---------------------------------------------------------------------------


def test_existing_secret_defaults_to_empty(values: dict):
    """Defaulting to a name would point every install at someone else's Secret."""
    assert values["existingSecret"] == ""


def test_chart_secret_is_suppressed_by_either_other_source():
    guard = (_TEMPLATES / "secret.yaml").read_text(encoding="utf-8").lstrip().split("\n", 1)[0]
    assert "not .Values.externalSecrets.enabled" in guard
    assert "not .Values.existingSecret" in guard


def test_the_two_managed_sources_are_refused_together():
    """`existingSecret` says "I own it"; externalSecrets says "ESO owns it"."""
    src = (_TEMPLATES / "validate.yaml").read_text(encoding="utf-8")
    assert "mutually exclusive" in src
    assert "fail" in src


def test_literal_secret_env_alongside_existing_secret_fails_the_render():
    """The silent-ignore trap, same shape as the externalSecrets one.

    This check cannot live in secret.yaml — that template is not rendered when
    `existingSecret` is set, so a guard there could never fire. It lives in
    validate.yaml, which always renders.
    """
    src = (_TEMPLATES / "validate.yaml").read_text(encoding="utf-8")
    assert re.search(r"if \.Values\.existingSecret", src)
    assert re.search(r"range \$key, \$value := \.Values\.secretEnv", src)
    secret_src = (_TEMPLATES / "secret.yaml").read_text(encoding="utf-8")
    assert "not .Values.existingSecret" in secret_src.split("\n", 1)[0], (
        "if secret.yaml ever renders under existingSecret, move the guard back into it"
    )


def test_validate_template_emits_no_manifest():
    """It must be checks only — a stray document would be applied to the cluster.

    `{{- /* ... */ -}}` blocks are stripped first: their contents are Go
    template comments and render to nothing, so counting them as emitted YAML
    would flag the explanation rather than any real output.
    """
    src = (_TEMPLATES / "validate.yaml").read_text(encoding="utf-8")
    stripped = re.sub(r"\{\{-?\s*/\*.*?\*/\s*-?\}\}", "", src, flags=re.S)
    emitting = [
        line
        for line in stripped.splitlines()
        if line.strip() and not line.lstrip().startswith("{{")
    ]
    assert not emitting, f"validate.yaml would emit YAML: {emitting}"


@pytest.mark.parametrize(
    "template", ["_helpers.tpl", "validate.yaml", "secret.yaml", "externalsecret.yaml"]
)
def test_template_blocks_are_balanced(template: str):
    """A stray or missing `{{- end }}` breaks the render for every install."""
    src = (_TEMPLATES / template).read_text(encoding="utf-8")
    kws = re.findall(r"\{\{-?\s*(if|range|with|define|block|end)\b", src)
    opens = sum(1 for k in kws if k != "end")
    closes = sum(1 for k in kws if k == "end")
    assert opens == closes, f"{template}: {opens} opener(s) vs {closes} end(s)"
