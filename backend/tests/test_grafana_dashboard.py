"""The operations dashboard only charts metrics the app actually exports.

The #103 outcome-metrics surface is the provisioned Grafana dashboard at
``infra/grafana/provisioning/dashboards/btagent-operations.json``. A dashboard
is the easiest artifact in the repo to rot silently: rename a metric in
``observability/metrics.py`` and every panel goes permanently blank with no
test noticing. This guard ties the two together:

* every ``btagent_*`` series a panel queries must be a sample family the
  Prometheus registry really exposes (as scraped — prometheus_client appends
  ``_total`` to counters and expands histograms into ``_bucket``/``_sum``/
  ``_count``, so the guard collects the registry rather than trusting the
  constructor names);
* every metric declared in ``metrics.py`` must appear on the dashboard — an
  unplotted metric is unmeasured "outcome" (#103's word) and either belongs
  on a panel or shouldn't exist.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_DASHBOARD = (
    Path(__file__).resolve().parent.parent.parent
    / "infra"
    / "grafana"
    / "provisioning"
    / "dashboards"
    / "btagent-operations.json"
)

_METRIC_RE = re.compile(r"\bbtagent_[a-z0-9_]+\b")


def _dashboard_exprs() -> list[str]:
    doc = json.loads(_DASHBOARD.read_text())
    exprs: list[str] = []
    for panel in doc.get("panels", []):
        for target in panel.get("targets", []) or []:
            if target.get("expr"):
                exprs.append(target["expr"])
    return exprs


def _exposed_sample_names() -> set[str]:
    """Sample-family names as Prometheus scrapes them from the live registry."""
    # Importing the module registers everything on the default REGISTRY.
    from prometheus_client import REGISTRY

    import btagent_backend.observability.metrics  # noqa: F401

    names: set[str] = set()
    for family in REGISTRY.collect():
        if not family.name.startswith("btagent_"):
            continue
        if family.type == "counter":
            names.add(f"{family.name}_total")
        elif family.type == "histogram":
            names.update({f"{family.name}_bucket", f"{family.name}_sum", f"{family.name}_count"})
        else:
            names.add(family.name)
    return names


def test_dashboard_parses_and_has_panels():
    doc = json.loads(_DASHBOARD.read_text())
    assert doc["uid"] == "btagent-operations"
    exprs = _dashboard_exprs()
    assert len(exprs) >= 10, "dashboard lost its panels"


def test_every_charted_series_is_exported():
    exposed = _exposed_sample_names()
    charted = {m for expr in _dashboard_exprs() for m in _METRIC_RE.findall(expr)}
    unknown = sorted(charted - exposed)
    assert not unknown, (
        "These dashboard series are not exported by observability/metrics.py "
        f"(panel would render blank forever): {unknown}\nExported: {sorted(exposed)}"
    )


def test_every_exported_metric_is_charted():
    exposed = _exposed_sample_names()
    charted_text = "\n".join(_dashboard_exprs())
    # A histogram counts as charted if any of its expansions appears.
    unplotted = sorted(name for name in exposed if name not in charted_text)
    # _sum/_count are legitimate leftovers when the histogram is charted via
    # _bucket percentiles.
    unplotted = [
        n
        for n in unplotted
        if not (
            (n.endswith("_sum") or n.endswith("_count"))
            and n.rsplit("_", 1)[0] + "_bucket" in charted_text
        )
    ]
    assert not unplotted, (
        "These exported metrics appear on no dashboard panel — an unmeasured "
        f"outcome metric (#103): {unplotted}"
    )
