"""MITRE ATT&CK keyword-based technique mapper.

Loads keyword-to-technique mappings from the vendored YAML data file and
provides fast, deterministic technique suggestion from alert text, IOC
context, and category strings.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("btagent.mitre.mapper")

_KEYWORDS_PATH = Path(__file__).resolve().parent / "data" / "mitre_keywords.yaml"


@dataclass(frozen=True, slots=True)
class TechniqueSuggestion:
    """A suggested MITRE ATT&CK technique."""

    technique_id: str
    keyword_matched: str
    confidence: float


class MitreMapper:
    """Map alert text to MITRE ATT&CK techniques via keyword matching.

    Loads keyword mappings from ``mitre_keywords.yaml`` once and caches them
    for the lifetime of the instance.
    """

    def __init__(self, keywords_path: Path | None = None) -> None:
        self._keywords: list[dict[str, Any]] = []
        self._loaded = False
        self._path = keywords_path or _KEYWORDS_PATH

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def suggest_techniques(
        self,
        text: str,
        *,
        max_results: int = 10,
        min_confidence: float = 0.0,
    ) -> list[TechniqueSuggestion]:
        """Scan *text* for keywords and return matching MITRE techniques.

        Parameters
        ----------
        text : str
            Alert text, IOC context, or category string to scan.
        max_results : int
            Maximum number of suggestions to return, sorted by confidence
            descending.
        min_confidence : float
            Minimum confidence threshold for inclusion.

        Returns
        -------
        list[TechniqueSuggestion]
            Matching techniques, highest confidence first.
        """
        self._ensure_loaded()
        if not text:
            return []

        lower = text.lower()
        seen_techniques: dict[str, TechniqueSuggestion] = {}

        for entry in self._keywords:
            keyword = entry.get("keyword", "")
            technique_id = entry.get("technique_id", "")
            confidence = float(entry.get("confidence", 0.0))

            if not keyword or not technique_id:
                continue
            if confidence < min_confidence:
                continue

            if keyword in lower:
                existing = seen_techniques.get(technique_id)
                if existing is None or confidence > existing.confidence:
                    seen_techniques[technique_id] = TechniqueSuggestion(
                        technique_id=technique_id,
                        keyword_matched=keyword,
                        confidence=confidence,
                    )

        results = sorted(
            seen_techniques.values(),
            key=lambda s: s.confidence,
            reverse=True,
        )
        return results[:max_results]

    def suggest_for_iocs(
        self,
        iocs: list[dict[str, Any]],
        *,
        max_results: int = 10,
    ) -> list[TechniqueSuggestion]:
        """Suggest techniques based on a list of IOC dicts.

        Scans IOC type, value, and context fields for keyword matches.
        """
        parts: list[str] = []
        for ioc in iocs:
            parts.append(ioc.get("type", ""))
            parts.append(ioc.get("value", ""))
            parts.append(ioc.get("context", ""))
        combined = " ".join(parts)
        return self.suggest_techniques(combined, max_results=max_results)

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    def _ensure_loaded(self) -> None:
        """Lazy-load the keyword YAML file on first use."""
        if self._loaded:
            return
        try:
            if self._path.exists():
                raw = yaml.safe_load(self._path.read_text())
                if isinstance(raw, list):
                    self._keywords = raw
                    logger.info(
                        "Loaded %d MITRE keyword mappings from %s",
                        len(self._keywords),
                        self._path,
                    )
                else:
                    logger.warning("MITRE keywords file is not a list: %s", self._path)
            else:
                logger.warning("MITRE keywords file not found: %s", self._path)
        except Exception:
            logger.exception("Failed to load MITRE keywords from %s", self._path)
        self._loaded = True
