"""STIX TLP marking-definition mapping — the single source of truth.

Two incompatible generations of TLP marking definitions exist in the wild and a
feed may emit either:

* **TLP 1.0** — the four marking-definition objects written into the STIX 2.1
  specification itself (WHITE / GREEN / AMBER / RED). Deprecated by FIRST in
  2022 but still emitted by older feeds and archived bundles.
* **TLP 2.0** — the current FIRST standard (CLEAR / GREEN / AMBER /
  AMBER+STRICT / RED), which most commercial and ISAC TAXII 2.1 servers emit
  today. It is also the *only* generation that can express AMBER+STRICT.

Recognising just one generation fails **open**: an unmatched marking falls back
to the caller's default (historically ``green``), so a TLP:RED indicator from a
modern feed would be ingested as shareable and the RED egress gate would never
engage. Both generations are therefore accepted on import.

On export we emit TLP 2.0 (see ``EXPORT_MARKING_VERSION``). TLP 1.0 has no
AMBER+STRICT marking at all, so emitting 1.0 would silently downgrade an
``amber_strict`` IOC to plain AMBER — a classification downgrade on egress.
"""

from __future__ import annotations

from typing import Any

from btagent_shared.types.config import TLP

# TLP 1.0 — the marking definitions embedded in the STIX 2.1 spec (deprecated).
TLP_V1_MARKINGS: dict[str, TLP] = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": TLP.WHITE,
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": TLP.GREEN,
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": TLP.AMBER,
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": TLP.RED,
}

# TLP 2.0 — the current FIRST standard. WHITE was renamed CLEAR; AMBER+STRICT
# is new and has no TLP 1.0 equivalent.
TLP_V2_MARKINGS: dict[str, TLP] = {
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487": TLP.WHITE,  # CLEAR
    "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb": TLP.GREEN,
    "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421": TLP.AMBER,
    "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003": TLP.AMBER_STRICT,
    "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1": TLP.RED,
}

# Import accepts either generation.
MARKING_REF_TO_TLP: dict[str, TLP] = {**TLP_V1_MARKINGS, **TLP_V2_MARKINGS}

# Export emits this generation. Switch to "1.0" only for a consumer that cannot
# parse TLP 2.0 — doing so makes ``amber_strict`` inexpressible, and
# ``tlp_to_marking_ref`` will refuse it rather than silently downgrade.
EXPORT_MARKING_VERSION = "2.0"

_TLP_TO_V2_REF: dict[TLP, str] = {tlp: ref for ref, tlp in TLP_V2_MARKINGS.items()}
_TLP_TO_V1_REF: dict[TLP, str] = {tlp: ref for ref, tlp in TLP_V1_MARKINGS.items()}

# Most-restrictive-first. A bundle may carry several markings; the effective
# classification is the strictest one present, never the first one iterated.
_RESTRICTIVENESS: tuple[TLP, ...] = (
    TLP.RED,
    TLP.AMBER_STRICT,
    TLP.AMBER,
    TLP.GREEN,
    TLP.WHITE,
)


def marking_refs_to_tlp(marking_refs: list[str] | None) -> TLP | None:
    """Resolve STIX ``object_marking_refs`` to the strictest TLP present.

    Returns ``None`` when no recognised TLP marking is present, so the caller
    decides the default explicitly rather than inheriting one from iteration
    order.
    """
    if not marking_refs:
        return None
    found = {MARKING_REF_TO_TLP[ref] for ref in marking_refs if ref in MARKING_REF_TO_TLP}
    if not found:
        return None
    for level in _RESTRICTIVENESS:
        if level in found:
            return level
    return None


def tlp_to_marking_ref(tlp: TLP | str, version: str | None = None) -> str | None:
    """Return the marking-definition id to stamp on an exported object.

    Returns ``None`` for a level the requested generation cannot express, so
    callers omit the marking rather than emit a weaker one.
    """
    level = TLP(tlp)
    table = _TLP_TO_V1_REF if (version or EXPORT_MARKING_VERSION) == "1.0" else _TLP_TO_V2_REF
    return table.get(level)


def bundle_has_red_marking(bundle: dict[str, Any]) -> bool:
    """Return True if any object in the bundle is marked TLP:RED (either generation)."""
    for obj in bundle.get("objects", []):
        if marking_refs_to_tlp(obj.get("object_marking_refs", [])) is TLP.RED:
            return True
    return False
