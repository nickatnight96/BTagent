"""Sigma -> per-backend query transpiler (#112 Hunt Pack Runner).

Thin wrapper over pySigma + the upstream ``pySigma-backend-*`` packages —
Sigma->query translation is a solved problem and we deliberately do not
re-implement it (mirrors ``agents/btagent_agents/plugins/hunter/
sigma_compiler.py``, which is the MCP-tool flavour of the same wrapper).

Public API::

    transpile(rule_yaml, backend) -> str

raising :class:`SigmaTranspileError` (malformed rule / backend failure) or
its subclass :class:`UnsupportedSigmaRuleError` (the rule uses a construct
pySigma or the target backend cannot express — deprecated pipe-aggregations,
fields the backend's pipeline has no mapping for, ...).

Each backend is paired with the processing pipeline that makes its output
actually runnable on that platform:

* ``splunk``      -> SplunkBackend + ``splunk_windows_pipeline`` (Windows
  source/EventCode mapping, e.g. ``source="WinEventLog:Security"``).
* ``sentinel``    -> KustoBackend + ``microsoft_xdr_pipeline`` (Advanced
  Hunting tables — ``DeviceProcessEvents | where ...`` — queryable from a
  Sentinel workspace with the Defender XDR connector).
* ``elastic``     -> LuceneBackend + ``ecs_windows`` (ECS field names, e.g.
  ``process.command_line``, matching Elastic Agent / winlogbeat data).
* ``crowdstrike`` -> LogScaleBackend + ``crowdstrike_falcon_pipeline``
  (Falcon LogScale / event-search syntax over ProcessRollup2 telemetry).

pySigma imports are kept lazy so importing :mod:`btagent_engine.hunting`
does not pull the sigma stack onto every engine consumer's import path.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Literal, get_args

if TYPE_CHECKING:
    from sigma.conversion.base import Backend as PySigmaBackend

SigmaBackendName = Literal["splunk", "sentinel", "elastic", "crowdstrike"]

SUPPORTED_BACKENDS: tuple[SigmaBackendName, ...] = get_args(SigmaBackendName)


class SigmaTranspileError(Exception):
    """A Sigma rule failed to transpile for a backend."""

    def __init__(self, backend: str, reason: str) -> None:
        self.backend = backend
        self.reason = reason
        super().__init__(f"Sigma transpile failed for {backend}: {reason}")


class UnsupportedSigmaRuleError(SigmaTranspileError):
    """The rule uses a Sigma feature this backend (or pySigma) cannot express.

    Distinct from a malformed rule: the YAML is valid Sigma, but e.g. uses the
    deprecated ``| count() ...`` pipe-aggregation syntax, or references fields
    the backend pipeline has no mapping for on that platform.
    """


def _make_splunk() -> PySigmaBackend:
    from sigma.backends.splunk import SplunkBackend
    from sigma.pipelines.splunk import splunk_windows_pipeline

    return SplunkBackend(splunk_windows_pipeline())


def _make_sentinel() -> PySigmaBackend:
    from sigma.backends.kusto import KustoBackend
    from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline

    return KustoBackend(microsoft_xdr_pipeline())


def _make_elastic() -> PySigmaBackend:
    from sigma.backends.elasticsearch import LuceneBackend
    from sigma.pipelines.elasticsearch import ecs_windows

    return LuceneBackend(ecs_windows())


def _make_crowdstrike() -> PySigmaBackend:
    from sigma.backends.crowdstrike import LogScaleBackend
    from sigma.pipelines.crowdstrike import crowdstrike_falcon_pipeline

    return LogScaleBackend(crowdstrike_falcon_pipeline())


_BACKEND_FACTORIES = {
    "splunk": _make_splunk,
    "sentinel": _make_sentinel,
    "elastic": _make_elastic,
    "crowdstrike": _make_crowdstrike,
}

# pySigma backend/pipeline construction is not free; instances are reusable
# across convert() calls, so build each lazily, once, behind a lock.
_backend_cache: dict[str, PySigmaBackend] = {}
_backend_cache_lock = threading.Lock()


def _get_backend(backend: str) -> PySigmaBackend:
    factory = _BACKEND_FACTORIES.get(backend)
    if factory is None:
        raise ValueError(f"unknown backend {backend!r}; supported: {', '.join(SUPPORTED_BACKENDS)}")
    with _backend_cache_lock:
        instance = _backend_cache.get(backend)
        if instance is None:
            # Codex #198: backend factory failures (missing plugin, pipeline
            # init error) used to escape transpile()'s except blocks and
            # therefore _run_rule_on_backend()'s SigmaTranspileError catch,
            # killing the whole pack instead of being recorded per rule.
            # Wrap as SigmaTranspileError so per-rule isolation holds. The
            # ValueError above stays raw (programmer error, not runtime).
            try:
                instance = factory()
            except Exception as exc:
                raise SigmaTranspileError(backend, f"backend init failed: {exc}") from exc
            _backend_cache[backend] = instance
        return instance


def transpile(rule_yaml: str, backend: SigmaBackendName) -> str:
    """Transpile one canonical Sigma rule (YAML string) to a backend query.

    Raises:
        ValueError: ``backend`` is not one of the four supported names
            (programming error, not a rule problem).
        UnsupportedSigmaRuleError: the rule uses a construct pySigma or the
            target backend cannot express.
        SigmaTranspileError: the YAML is not a valid Sigma rule, or the
            backend failed / produced no query.
    """
    import yaml as _yaml
    from sigma.collection import SigmaCollection
    from sigma.exceptions import (
        SigmaConditionError,
        SigmaError,
        SigmaFeatureNotSupportedByBackendError,
        SigmaTransformationError,
    )

    backend_impl = _get_backend(backend)  # validates the name before parsing

    try:
        collection = SigmaCollection.from_yaml(rule_yaml)
    except (SigmaError, _yaml.YAMLError) as exc:
        raise SigmaTranspileError(backend, f"invalid Sigma rule: {exc}") from exc

    try:
        converted = backend_impl.convert(collection)
    except (
        SigmaConditionError,
        SigmaFeatureNotSupportedByBackendError,
        SigmaTransformationError,
        NotImplementedError,
    ) as exc:
        raise UnsupportedSigmaRuleError(backend, str(exc)) from exc
    except SigmaError as exc:
        raise SigmaTranspileError(backend, str(exc)) from exc

    # Backends disagree on the return shape: most give list[str], LogScale a str.
    queries = [converted] if isinstance(converted, str) else list(converted)
    queries = [q for q in queries if q and str(q).strip()]
    if not queries:
        raise SigmaTranspileError(backend, "backend produced no query")

    # A single rule file yields one query on the common path; a collection
    # that expands to several is OR-joined like the agents-side compiler.
    return str(queries[0]) if len(queries) == 1 else " OR ".join(str(q) for q in queries)
