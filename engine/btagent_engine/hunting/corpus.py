"""External Sigma corpus (SigmaHQ layout) -> hunt pack importer (#112).

The #112 runner, the per-org pack store and the transpiler all existed, but
there was no way to get a *large external rule corpus* in: the only packs that
could ever run were the handful shipped under
``btagent_engine/hunting/packs/``. This module is that path — point it at a
checkout (or an unpacked release) of a SigmaHQ-layout rule tree and it produces
a normal :class:`~btagent_engine.hunting.pack.HuntPack` that the *existing*
loader, runner and per-org store handle with no special cases.

Layout it accepts
-----------------

SigmaHQ ships rules as a nested tree, not a flat pack directory::

    <root>/
      rules/windows/process_creation/proc_creation_win_certutil_encode.yml
      rules/linux/process_creation/proc_creation_lnx_curl_pipe_shell.yml
      rules-threat-hunting/windows/.../*.yml
      deprecated/...            # skipped (see DEFAULT_SKIP_DIRS)

:func:`iter_sigma_rule_files` walks that tree; ``<root>`` may equally be a
single flat directory of ``*.yml`` rules, so "an external Sigma rule
directory/pack" in either shape works.

Skip-with-reason, never abort
-----------------------------

A ~1000-rule community corpus *will* contain rules this platform cannot use:
unparseable YAML, rules with no title, rules using constructs no connected
backend can express (pipe-aggregations, correlation rules), and — across
merged trees — duplicate rule ids. Importing must not be all-or-nothing, so
each rule is judged on its own and the failures are **recorded, not raised**:

* ``parse``     — not valid YAML / not a mapping / no title / fails the
  :class:`HuntPackRule` contract.
* ``transpile`` — parsed fine, but transpiled to **none** of the requested
  backends. A rule that transpiles to at least one backend is installed (the
  runner already records per-backend errors at run time), so a Windows-only
  rule is not thrown away just because the Falcon pipeline rejects it.
* ``duplicate`` — a rule id already claimed by an earlier file (``load_pack``
  refuses duplicate ids, so they must be resolved at import time).

Every skip carries a human-readable ``reason``; :attr:`CorpusImport.skipped`
is what the CLI prints and what :func:`write_pack_dir` persists next to the
pack as ``install_report.json``.

Transpile coverage
------------------

:func:`transpile_coverage` measures, per backend, what fraction of a rule set
transpiles. It is the same computation the importer uses to decide skips, and
the metric the vendored-fixture test asserts on so coverage cannot silently
regress.

Zero network: this module only ever reads a local directory. Downloading the
SigmaHQ catalog is explicitly out of scope (deferred) — an operator clones or
unpacks it, then points ``bt huntpack install`` at the path.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.hunting.pack import (
    HuntPack,
    HuntPackRule,
    PackLoadError,
    deterministic_id,
    load_pack,
    rule_from_file,
)
from btagent_engine.hunting.transpile import (
    SUPPORTED_BACKENDS,
    SigmaBackendName,
    SigmaTranspileError,
    transpile,
)

logger = logging.getLogger("btagent.engine.hunting.corpus")

# Directories never walked for rules. ``deprecated``/``unsupported`` are
# SigmaHQ's own graveyards (rules kept for history, not for detection);
# ``tests``/``.github``/``.git`` are repo scaffolding.
DEFAULT_SKIP_DIRS: frozenset[str] = frozenset(
    {".git", ".github", "__pycache__", "deprecated", "node_modules", "tests", "unsupported"}
)

_RULE_SUFFIXES = (".yml", ".yaml")

# Slug used for a pack directory name / install key: lowercase, no separators
# that could escape the install root.
_SLUG_RE = re.compile(r"[^a-z0-9]+")

SkipStage = Literal["parse", "transpile", "duplicate"]


def slugify(value: str, *, fallback: str = "pack") -> str:
    """``"SigmaHQ core rules"`` -> ``"sigmahq_core_rules"`` (safe as a dir name)."""
    slug = _SLUG_RE.sub("_", value.strip().lower()).strip("_")
    return (slug or fallback)[:64]


class RuleSkip(BaseModel):
    """One rule the import declined, and why."""

    model_config = ConfigDict(extra="forbid")

    file: str = Field(..., description="Path relative to the corpus root.")
    stage: SkipStage
    reason: str = Field(..., description="Human-readable cause, safe to show an operator.")
    rule_id: str | None = None
    title: str | None = None


class RuleTranspile(BaseModel):
    """Per-backend transpile outcome for one parsed rule."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    file: str
    title: str = ""
    # Backends the rule transpiled to, and the error text for those it didn't.
    ok: list[str] = Field(default_factory=list)
    errors: dict[str, str] = Field(default_factory=dict)

    @property
    def any_ok(self) -> bool:
        return bool(self.ok)


class BackendCoverage(BaseModel):
    """How much of a rule set one backend can express."""

    model_config = ConfigDict(extra="forbid")

    backend: str
    total: int = 0
    ok: int = 0

    @property
    def failed(self) -> int:
        return max(self.total - self.ok, 0)

    @property
    def rate(self) -> float:
        """Fraction in ``[0, 1]``; ``0.0`` for an empty rule set."""
        return (self.ok / self.total) if self.total else 0.0


class CorpusImport(BaseModel):
    """The result of importing an external Sigma corpus."""

    model_config = ConfigDict(extra="forbid")

    pack: HuntPack
    source: str = Field(..., description="Corpus root the rules were read from.")
    scanned: int = Field(0, description="Rule files found under the root.")
    backends: list[str] = Field(default_factory=list)
    skipped: list[RuleSkip] = Field(default_factory=list)
    transpiled: list[RuleTranspile] = Field(
        default_factory=list, description="Per-rule, per-backend transpile outcomes (parsed rules)."
    )

    @property
    def installed(self) -> int:
        return len(self.pack.rules)

    def coverage(self) -> dict[str, BackendCoverage]:
        """Per-backend transpile coverage over the rules that parsed."""
        out = {b: BackendCoverage(backend=b, total=len(self.transpiled)) for b in self.backends}
        for report in self.transpiled:
            for backend in report.ok:
                if backend in out:
                    out[backend].ok += 1
        return out

    def skip_reasons(self) -> dict[str, int]:
        """``{stage: count}`` rollup, for a one-line CLI summary."""
        counts: dict[str, int] = {}
        for skip in self.skipped:
            counts[skip.stage] = counts.get(skip.stage, 0) + 1
        return counts


def iter_sigma_rule_files(
    root: Path | str, *, skip_dirs: Iterable[str] = DEFAULT_SKIP_DIRS
) -> list[Path]:
    """Every candidate Sigma rule file under ``root``, sorted, deterministically.

    Walks nested SigmaHQ trees and flat directories alike. Directories in
    ``skip_dirs`` (and any dot-directory) are pruned, as are dot-files and
    SigmaHQ's ``*_test.yml`` scaffolding files.
    """
    root = Path(root)
    if not root.is_dir():
        raise PackLoadError(f"not a directory: {root}")

    skip = {d.lower() for d in skip_dirs}
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _RULE_SUFFIXES:
            continue
        rel = path.relative_to(root)
        parts = rel.parts[:-1]
        if any(p.lower() in skip or p.startswith(".") for p in parts):
            continue
        if path.name.startswith("."):
            continue
        found.append(path)
    return found


def _rule_slug(rel: Path) -> str:
    """``windows/process_creation/foo.yml`` -> ``windows_process_creation_foo.yml``.

    The imported pack is a *flat* ``rules/`` directory, so the nested corpus
    path is folded into the filename; that keeps two same-named rules from
    different categories from colliding.
    """
    stem = "_".join([*rel.parts[:-1], rel.stem])
    return f"{slugify(stem, fallback='rule')[:120]}.yml"


def transpile_coverage(
    rules: Sequence[HuntPackRule],
    backends: Sequence[str] = SUPPORTED_BACKENDS,
    *,
    transpile_fn: Any = None,
) -> tuple[dict[str, BackendCoverage], list[RuleTranspile]]:
    """Measure what fraction of ``rules`` each backend can express.

    Returns ``({backend: BackendCoverage}, [RuleTranspile])`` — the rollup the
    fixture test asserts on plus the per-rule detail the importer turns into
    skip reasons. ``transpile_fn`` is injectable for tests that must not pay
    for pySigma; it defaults to :func:`btagent_engine.hunting.transpile`.
    """
    fn = transpile_fn or transpile
    backend_list = [str(b) for b in backends]
    reports: list[RuleTranspile] = []

    for rule in rules:
        report = RuleTranspile(rule_id=rule.id, file=rule.file or "", title=rule.title)
        for backend in backend_list:
            try:
                query = fn(rule.sigma_yaml, backend)
            except SigmaTranspileError as exc:
                report.errors[backend] = exc.reason[:500]
                continue
            except Exception as exc:  # a backend plugin blowing up is that backend's problem
                report.errors[backend] = f"{type(exc).__name__}: {exc}"[:500]
                continue
            if not str(query or "").strip():
                report.errors[backend] = "backend produced no query"
                continue
            report.ok.append(backend)
        reports.append(report)

    coverage = {b: BackendCoverage(backend=b, total=len(reports)) for b in backend_list}
    for report in reports:
        for backend in report.ok:
            coverage[backend].ok += 1
    return coverage, reports


def import_sigma_corpus(
    root: Path | str,
    *,
    name: str | None = None,
    version: str = "1.0.0",
    description: str = "",
    pack_id: str | None = None,
    backends: Sequence[str] = SUPPORTED_BACKENDS,
    check_transpile: bool = True,
    max_rules: int | None = None,
    transpile_fn: Any = None,
) -> CorpusImport:
    """Import a SigmaHQ-layout rule tree as a :class:`HuntPack`.

    Parses every rule file under ``root``, records which ones transpile per
    backend, and drops (with a reason) the ones that cannot be parsed, cannot
    be transpiled by *any* requested backend, or duplicate an earlier rule id.
    Nothing is written to disk — see :func:`write_pack_dir`.

    ``check_transpile=False`` imports parse-only (no pySigma cost); the
    resulting :attr:`CorpusImport.transpiled` is then empty and no rule is
    skipped for transpile reasons.
    """
    root = Path(root)
    paths = iter_sigma_rule_files(root)
    if max_rules is not None:
        paths = paths[:max_rules]

    pack_name = (name or root.name or "sigma-corpus")[:200]
    resolved_pack_id = (pack_id or deterministic_id("hpack", pack_name, version))[:200]

    skipped: list[RuleSkip] = []
    parsed: list[HuntPackRule] = []
    seen_ids: dict[str, str] = {}
    # rule id -> corpus-relative source path, so a later (transpile-stage) skip
    # still names the file the operator has on disk, not the flattened slug.
    source_by_id: dict[str, str] = {}

    for path in paths:
        rel = path.relative_to(root)
        try:
            rule = rule_from_file(path, {}, pack_id=resolved_pack_id)
        except (PackLoadError, ValueError) as exc:
            skipped.append(RuleSkip(file=str(rel), stage="parse", reason=str(exc)[:500]))
            continue
        except OSError as exc:  # unreadable file / bad encoding
            skipped.append(
                RuleSkip(file=str(rel), stage="parse", reason=f"unreadable: {exc}"[:500])
            )
            continue

        if rule.id in seen_ids:
            skipped.append(
                RuleSkip(
                    file=str(rel),
                    stage="duplicate",
                    reason=f"rule id {rule.id} already imported from {seen_ids[rule.id]}",
                    rule_id=rule.id,
                    title=rule.title,
                )
            )
            continue
        seen_ids[rule.id] = str(rel)
        source_by_id[rule.id] = str(rel)
        # Flatten the corpus path into the pack's flat rules/ filename.
        parsed.append(rule.model_copy(update={"file": _rule_slug(rel)}))

    reports: list[RuleTranspile] = []
    kept = parsed
    if check_transpile and parsed:
        _, reports = transpile_coverage(parsed, backends, transpile_fn=transpile_fn)
        by_id = {r.rule_id: r for r in reports}
        kept = []
        for rule in parsed:
            report = by_id.get(rule.id)
            if report is not None and not report.any_ok:
                worst = "; ".join(f"{b}: {e}" for b, e in sorted(report.errors.items()))
                skipped.append(
                    RuleSkip(
                        file=source_by_id.get(rule.id, rule.file or rule.id),
                        stage="transpile",
                        reason=f"no supported backend could express this rule ({worst})"[:500],
                        rule_id=rule.id,
                        title=rule.title,
                    )
                )
                continue
            kept.append(rule)

    pack = HuntPack(
        id=resolved_pack_id,
        name=pack_name,
        version=version,
        description=description or f"Imported from external Sigma corpus {root.name!r}.",
        rules=kept,
    )
    result = CorpusImport(
        pack=pack,
        source=str(root),
        scanned=len(paths),
        backends=[str(b) for b in backends],
        skipped=skipped,
        transpiled=reports,
    )
    logger.info(
        "sigma corpus imported: source=%s scanned=%d installed=%d skipped=%d (%s)",
        root,
        result.scanned,
        result.installed,
        len(result.skipped),
        result.skip_reasons(),
    )
    return result


def _manifest(result: CorpusImport) -> dict[str, Any]:
    """The ``pack.yaml`` mapping for an imported corpus.

    Per-rule entries carry the transpile record (``transpiles`` /
    ``transpile_errors``) alongside the metadata the loader reads. The loader
    ignores keys it does not know, so the record is durable documentation of
    *which rules work on which backend* without a schema change.
    """
    pack = result.pack
    by_id = {r.rule_id: r for r in result.transpiled}
    rules: list[dict[str, Any]] = []
    for rule in pack.rules:
        entry: dict[str, Any] = {"file": rule.file, "enabled": rule.enabled}
        if rule.mitre_techniques:
            entry["mitre_techniques"] = list(rule.mitre_techniques)
        if rule.notes:
            entry["notes"] = rule.notes
        report = by_id.get(rule.id)
        if report is not None:
            entry["transpiles"] = sorted(report.ok)
            if report.errors:
                entry["transpile_errors"] = dict(sorted(report.errors.items()))
        rules.append(entry)
    return {
        "id": pack.id,
        "name": pack.name,
        "version": pack.version,
        "description": pack.description,
        "source": result.source,
        "imported_at": datetime.now(UTC).isoformat(),
        "rules": rules,
    }


def install_report(result: CorpusImport) -> dict[str, Any]:
    """The JSON install report: counts, per-backend coverage, every skip."""
    coverage = result.coverage()
    return {
        "pack_id": result.pack.id,
        "pack_name": result.pack.name,
        "version": result.pack.version,
        "source": result.source,
        "imported_at": datetime.now(UTC).isoformat(),
        "scanned": result.scanned,
        "installed": result.installed,
        "skipped_count": len(result.skipped),
        "skip_reasons": result.skip_reasons(),
        "backends": list(result.backends),
        "coverage": {
            b: {"ok": c.ok, "total": c.total, "rate": round(c.rate, 4)} for b, c in coverage.items()
        },
        "skipped": [s.model_dump() for s in result.skipped],
    }


def write_pack_dir(result: CorpusImport, dest: Path | str, *, overwrite: bool = False) -> Path:
    """Materialise an imported corpus as a loadable pack directory.

    Writes ``pack.yaml`` + ``rules/*.yml`` (verbatim Sigma) + an
    ``install_report.json``, then **loads the result back** through
    :func:`~btagent_engine.hunting.pack.load_pack` so a directory that the
    runner could not read never survives an install.

    Refuses to clobber an existing pack unless ``overwrite`` — reinstalling an
    updated corpus replaces the rule set wholesale, so stale rule files from a
    previous import are removed first.
    """
    dest = Path(dest)
    if dest.exists():
        if not overwrite:
            raise PackLoadError(f"pack directory already exists: {dest}")
        for stale in (dest / "rules").glob("*"):
            if stale.is_file():
                stale.unlink()
    if not result.pack.rules:
        raise PackLoadError("refusing to install a pack with no usable rules")

    rules_dir = dest / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    for rule in result.pack.rules:
        (rules_dir / str(rule.file)).write_text(rule.sigma_yaml, encoding="utf-8")

    (dest / "pack.yaml").write_text(
        yaml.safe_dump(_manifest(result), sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    (dest / "install_report.json").write_text(
        json.dumps(install_report(result), indent=2, sort_keys=False),
        encoding="utf-8",
    )

    # Round-trip: an install that the pack loader cannot read is a failed install.
    load_pack(dest)
    return dest


__all__ = [
    "DEFAULT_SKIP_DIRS",
    "BackendCoverage",
    "CorpusImport",
    "RuleSkip",
    "RuleTranspile",
    "SigmaBackendName",
    "import_sigma_corpus",
    "install_report",
    "iter_sigma_rule_files",
    "slugify",
    "transpile_coverage",
    "write_pack_dir",
]
