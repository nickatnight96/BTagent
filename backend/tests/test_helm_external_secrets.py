"""External Secrets Operator support is in the chart, and cannot collide with it.

EPIC-8's B7 lists "external-secrets in place" as a production-readiness item.
Until now the only thing the repo offered was a hand-written manifest pasted
into ``docs/DEPLOYMENT.md`` — and that manifest targeted a Secret named
``btagent-secrets`` while every workload in the chart mounts
``<fullname>-secret``. Following the docs produced a perfectly healthy
ExternalSecret syncing a Secret that nothing read, and a backend that came up
with no ``BTAGENT_DATABASE_URL``.

So the property this file exists to hold is a naming one: **the ExternalSecret
target must be the same name every consumer already mounts.** That is asserted
against the consumers themselves (scanned out of the templates) rather than
against a literal, so adding a workload with a different ``secretRef`` fails
here instead of at 3am.

The second property is mutual exclusion. ``secret.yaml`` and
``externalsecret.yaml`` produce an object of the *same name* by design; if both
ever render, Helm rewrites the Secret from ``secretEnv`` on every upgrade and
the operator writes the real values back on its next reconcile, so which
credentials a pod sees depends on when it happened to start.

There is no ``helm`` binary in CI, so — as in ``test_helm_backup_cronjob.py``
— the chart is validated by reading the shipped YAML. Templates carrying Go
templating are asserted on source text. That is weaker than a rendered-manifest
test and is said plainly rather than dressed up.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_CHART = Path(__file__).resolve().parents[2] / "infra" / "helm" / "btagent"
_TEMPLATES = _CHART / "templates"
_VALUES = _CHART / "values.yaml"
_EXTERNAL_SECRET = _TEMPLATES / "externalsecret.yaml"
_SECRET = _TEMPLATES / "secret.yaml"
_DOCS = Path(__file__).resolve().parents[2] / "docs" / "DEPLOYMENT.md"

# `secretRef:` followed (within a couple of lines) by the name it mounts.
_SECRET_REF = re.compile(r"secretRef:\s*\n\s*name:\s*(?P<name>.+)")
# Openers/closers of Go template blocks, for a balance check.
_BLOCK = re.compile(r"\{\{-?\s*(?P<kw>if|range|with|define|block|end)\b")


@pytest.fixture(scope="module")
def values() -> dict:
    return yaml.safe_load(_VALUES.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def es_src() -> str:
    return _EXTERNAL_SECRET.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def secret_src() -> str:
    return _SECRET.read_text(encoding="utf-8")


def _mounted_secret_names() -> set[str]:
    """Every Secret name the chart's workloads mount via `envFrom.secretRef`."""
    names: set[str] = set()
    for template in _TEMPLATES.glob("*.yaml"):
        for match in _SECRET_REF.finditer(template.read_text(encoding="utf-8")):
            names.add(match.group("name").strip())
    return names


def test_external_secret_template_is_shipped():
    assert _EXTERNAL_SECRET.is_file(), (
        "EPIC-8 B7 requires chart-native external-secrets support, not a manifest in the docs"
    )


def test_target_name_is_the_name_every_workload_actually_mounts(es_src: str):
    """The bug the docs shipped: syncing a Secret nothing reads.

    Adding a workload that mounts some *other* Secret name fails here, because
    the target would then satisfy only some of its consumers.
    """
    mounted = _mounted_secret_names()
    assert mounted, "no envFrom.secretRef found in the chart — the scan regex has drifted"
    assert len(mounted) == 1, (
        f"workloads mount more than one Secret name ({sorted(mounted)}); the ExternalSecret "
        "can only target one of them, so the others would go unpopulated"
    )
    target = mounted.pop()
    # `(?!\S)` matters: without it, a target of `<fullname>-secrets` would match
    # as a prefix of the expected `<fullname>-secret` and the test would pass on
    # exactly the typo it exists to catch.
    assert re.search(
        r"target:\s*\n(?:\s*#.*\n)*\s*name:\s*" + re.escape(target) + r"(?!\S)",
        es_src,
    ), f"ExternalSecret target must be {target!r} — the name the workloads mount"


def test_chart_secret_and_external_secret_are_mutually_exclusive(es_src: str, secret_src: str):
    """Both rendering means Helm and the operator overwrite each other.

    Asserted as a property of the guard rather than its exact text: the
    chart's Secret must be suppressed whenever the operator owns one. The
    guard also covers `existingSecret` (a third source), which is why this
    no longer pins the literal opening line.
    """
    assert es_src.lstrip().startswith("{{- if .Values.externalSecrets.enabled -}}")

    guard = secret_src.lstrip().split("\n", 1)[0]
    assert guard.startswith("{{- if "), f"secret.yaml is not guarded at all: {guard!r}"
    assert "not .Values.externalSecrets.enabled" in guard, (
        f"secret.yaml renders even when the operator owns the Secret: {guard!r}"
    )
    assert "not .Values.existingSecret" in guard, (
        f"secret.yaml renders even when the user supplied their own Secret: {guard!r}"
    )


@pytest.mark.parametrize("template", [_EXTERNAL_SECRET, _SECRET])
def test_template_blocks_are_balanced(template: Path):
    """A stray or missing `{{- end }}` breaks the render for every install."""
    keywords = [m.group("kw") for m in _BLOCK.finditer(template.read_text(encoding="utf-8"))]
    opens = sum(1 for k in keywords if k != "end")
    closes = sum(1 for k in keywords if k == "end")
    assert opens == closes, f"{template.name}: {opens} block opener(s) vs {closes} end(s)"


def test_external_secrets_is_disabled_by_default(values: dict):
    """Enabling it without a SecretStore is a failed install, so it cannot default on."""
    assert values["externalSecrets"]["enabled"] is False


def test_no_secret_store_is_assumed(values: dict):
    """Shipping a default store name would point installs at someone else's backend."""
    assert values["externalSecrets"]["secretStoreRef"]["name"] == ""
    assert values["externalSecrets"]["secretStoreRef"]["kind"] in {
        "SecretStore",
        "ClusterSecretStore",
    }


def test_no_remote_keys_are_assumed(values: dict):
    """Defaults must not guess at key paths in the operator's backend."""
    assert values["externalSecrets"]["data"] == {}
    assert values["externalSecrets"]["dataFrom"] == []


def test_deletion_policy_retains_the_secret(values: dict):
    """`Delete` would remove the Secret out from under running pods."""
    assert values["externalSecrets"]["target"]["deletionPolicy"] == "Retain"


def test_api_version_is_an_external_secrets_crd(values: dict):
    assert values["externalSecrets"]["apiVersion"].startswith("external-secrets.io/")


def test_missing_store_fails_the_render(es_src: str):
    """Better a template error than an ExternalSecret referencing store ""."""
    assert "secretStoreRef.name is empty" in es_src
    assert "fail" in es_src


def test_empty_mapping_fails_the_render(es_src: str):
    """No data and no dataFrom syncs an empty Secret; the backend then has no DSN."""
    assert "neither externalSecrets.data nor externalSecrets.dataFrom" in es_src


def test_literal_secret_env_alongside_external_secrets_fails_the_render(es_src: str):
    """The silent-ignore trap.

    With external-secrets on, `secretEnv` is not rendered at all. A credential
    left there does nothing — while still sitting in plaintext in values.
    """
    assert "secretEnv" in es_src
    assert re.search(r"range\s+\$key,\s*\$value\s*:=\s*\.Values\.secretEnv", es_src)


def test_secret_env_keys_are_valid_external_secret_keys(values: dict):
    """`secretEnv` keys double as ESO `secretKey`s in the documented mapping.

    ESO validates secretKey against `[-._a-zA-Z0-9]+`; a key that is fine as a
    Helm map entry but rejected there would fail only on the cluster.
    """
    for key in values["secretEnv"]:
        assert re.fullmatch(r"[-._a-zA-Z0-9]+", key), f"invalid ExternalSecret secretKey: {key!r}"


def test_migrate_job_ordering_is_addressed(es_src: str):
    """The migrate Job reads the Secret as a pre-install hook at weight 5.

    The ExternalSecret has to be created ahead of it, or a fresh install runs
    migrations against a Secret that does not exist yet.
    """
    weight = re.search(r'"helm\.sh/hook-weight":\s*"(-?\d+)"', es_src)
    assert weight is not None, "ExternalSecret is not ordered ahead of the migrate Job"
    assert int(weight.group(1)) < 5


def test_docs_do_not_hand_out_a_target_name_nothing_mounts():
    """The original defect, kept closed.

    docs/DEPLOYMENT.md's external-secrets section must not tell operators to
    sync a Secret name no workload in the chart reads.
    """
    if not _DOCS.is_file():
        pytest.skip("docs/DEPLOYMENT.md not present")
    text = _DOCS.read_text(encoding="utf-8")
    start = text.find("External Secrets Operator")
    if start == -1:
        pytest.skip("no external-secrets section in the deployment docs")
    section = text[start : start + 3000]
    for match in re.finditer(r"target:\s*\n\s*name:\s*(?P<name>\S+)", section):
        assert match.group("name") in {"btagent-secret", "btagent-backend-secret"}, (
            f"docs sync a Secret named {match.group('name')!r}, which no workload mounts; "
            "the chart's consumers all use <fullname>-secret"
        )
