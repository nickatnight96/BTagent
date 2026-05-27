"""Sigma → multi-backend transpiler for the Hunt Pack Runner (#112).

Thin wrapper over pySigma + the upstream ``pySigma-backend-*`` packages. Given
a canonical SigmaHQ rule (YAML string), produce the equivalent query for each
requested :class:`SiemBackend`. Transpile is per-backend best-effort: a rule
that can't be expressed on one backend still compiles for the others, and the
caller learns which backends failed (so the runner can mark a rule ``ERRORED``
only where appropriate).

Sigma → backend translation is a solved problem; the agentic value is in
prioritisation/tuning/suppression downstream, not in re-implementing this.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from btagent_shared.types.huntpack import SiemBackend

if TYPE_CHECKING:
    from sigma.conversion.base import Backend as PySigmaBackend

logger = logging.getLogger("btagent.hunter.sigma_compiler")


class SigmaCompileError(Exception):
    """Raised when a Sigma rule fails to transpile to a given backend."""

    def __init__(self, backend: SiemBackend, reason: str) -> None:
        self.backend = backend
        super().__init__(f"Sigma transpile failed for {backend.value}: {reason}")


def _load_backends() -> dict[SiemBackend, type[PySigmaBackend]]:
    """Import the available upstream pySigma backend classes.

    Each backend is imported independently so that a missing or incompatible
    upstream ``pySigma-backend-*`` package (e.g. if CrowdStrike support lags a
    pySigma core release) degrades to "that one backend is unavailable" rather
    than taking down the whole compiler. Imported lazily (inside the function)
    to keep the pySigma stack off the module import path.
    """
    specs: list[tuple[SiemBackend, str, str]] = [
        (SiemBackend.SPLUNK, "sigma.backends.splunk", "SplunkBackend"),
        (SiemBackend.ELASTIC, "sigma.backends.elasticsearch", "LuceneBackend"),
        (SiemBackend.SENTINEL, "sigma.backends.kusto", "KustoBackend"),
        (SiemBackend.CROWDSTRIKE, "sigma.backends.crowdstrike", "LogScaleBackend"),
    ]
    backends: dict[SiemBackend, type[PySigmaBackend]] = {}
    for backend, module_path, class_name in specs:
        try:
            module = __import__(module_path, fromlist=[class_name])
            backends[backend] = getattr(module, class_name)
        except Exception as exc:  # missing / incompatible upstream backend
            logger.warning("pySigma backend for %s unavailable: %s", backend.value, exc)
    return backends


class SigmaCompiler:
    """Transpiles canonical Sigma YAML to per-backend query strings."""

    def __init__(self) -> None:
        self._backends = _load_backends()

    @property
    def supported_backends(self) -> list[SiemBackend]:
        return list(self._backends.keys())

    def transpile(
        self,
        sigma_yaml: str,
        backends: list[SiemBackend] | None = None,
    ) -> tuple[dict[SiemBackend, str], dict[SiemBackend, str]]:
        """Transpile one Sigma rule to the requested backends.

        Returns ``(queries, errors)`` where ``queries`` maps each successfully
        compiled backend to its query string and ``errors`` maps each failed
        backend to a human-readable reason. ``backends=None`` targets every
        supported backend.

        A Sigma collection can expand to multiple queries (e.g. correlation
        rules); we join them with the backend's own ``OR`` for the simple
        single-rule case and take the first for others — hunt packs use
        single-condition rules, so this is the common path.
        """
        from sigma.collection import SigmaCollection

        targets = backends or self.supported_backends
        queries: dict[SiemBackend, str] = {}
        errors: dict[SiemBackend, str] = {}

        # Parse once; reuse the collection across backends.
        try:
            collection = SigmaCollection.from_yaml(sigma_yaml)
        except Exception as exc:  # malformed rule — fails for all backends
            reason = f"invalid Sigma YAML: {exc}"
            return {}, {b: reason for b in targets}

        for backend in targets:
            backend_cls = self._backends.get(backend)
            if backend_cls is None:
                errors[backend] = "no upstream pySigma backend available"
                continue
            try:
                result = backend_cls().convert(collection)
                if not result:
                    errors[backend] = "backend produced no query"
                    continue
                queries[backend] = result[0] if len(result) == 1 else " OR ".join(result)
            except Exception as exc:
                logger.debug("Sigma transpile failed for %s: %s", backend.value, exc)
                errors[backend] = str(exc)

        return queries, errors
