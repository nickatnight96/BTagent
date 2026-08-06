"""Every request body the API binds rejects fields it does not declare.

Pydantic v2 defaults to ``extra='ignore'``. A request model without
``extra="forbid"`` therefore accepts an unknown field, drops it, and returns
success — the caller cannot tell the difference between "you sent it and I
used it" and "you misspelled it and I ignored you".

That is the #586 failure mode (FastAPI discards an unknown *query* parameter
without a word) on a larger and more dangerous surface, because request bodies
carry the fields that govern classification:

    CreateInvestigationRequest(title="t", tlpp_level="red", sevrity="critical")
    -> severity=medium, tlp_level=green

A misspelled ``tlp_level`` creates the investigation at TLP:GREEN instead of
the RED that was asked for. Nothing raises, nothing logs, and the case is
routed to cloud LLMs it should never have reached. Four of the sixty-three
``*Request`` models under ``api/v1`` set ``extra="forbid"`` before this guard;
the rest were all one typo away from that.

``test_api_query_param_parity``'s docstring used to claim request bodies were
*not* exposed to this, "because Pydantic does reject unknown fields when
configured to". The conditional was carrying the whole claim and it was wrong
in practice — almost nothing was so configured. That sentence is corrected
there, and this file is what makes the corrected version true.

What is checked
---------------
Every class in ``backend/btagent_backend/api/v1/*.py`` whose name ends in
``Request`` and which subclasses ``BaseModel`` must declare
``extra="forbid"`` — directly, or by inheriting a base that does.

What is NOT checked, so a pass isn't read as more than it is
------------------------------------------------------------
* **Nested models.** A field typed as another ``BaseModel`` is only strict if
  *that* model is too. The scan is by class name, so a nested model called
  ``FooPayload`` rather than ``FooRequest`` is invisible to it.
* **Bodies that are not models.** A route taking ``dict[str, Any]`` accepts
  anything by construction; no model means nothing to tighten.
* **Response models.** Only inbound bodies are in scope — ``extra`` on a
  response shape has no bearing on what a caller can smuggle in.
* **Semantics.** A field that is declared, spelled right, and wrong for the
  situation is a different problem entirely.
"""

from __future__ import annotations

import ast
from functools import lru_cache
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_API_DIR = _REPO / "backend" / "btagent_backend" / "api" / "v1"

#: ``"module.ClassName" -> why it may accept undeclared fields.``
#:
#: Ships empty. The bar is high because the failure mode is silence: an entry
#: here says "a caller may misspell a field on this model and get a 2xx".
#: "It has no security-relevant fields" is not a reason — the next field added
#: to it might, and nothing would re-open the question.
FORBID_EXEMPT: dict[str, str] = {}

# A scan this simple could match nothing and pass. Set below the real count at
# the time of writing (63) so ordinary additions do not trip it.
_MIN_REQUEST_MODELS = 45


@lru_cache(maxsize=1)
def _request_models() -> dict[str, bool]:
    """``{"module.ClassName": declares_forbid}`` for every ``*Request`` model.

    ``declares_forbid`` is true when the class body assigns ``model_config``
    with ``extra="forbid"``. Read from the AST rather than by importing so a
    module that needs settings or a database to import is still covered.
    """
    found: dict[str, bool] = {}
    for path in sorted(_API_DIR.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or not node.name.endswith("Request"):
                continue
            if not any(
                isinstance(base, ast.Name) and base.id == "BaseModel" for base in node.bases
            ):
                continue
            found[f"{path.stem}.{node.name}"] = _declares_forbid(node)
    return found


def _declares_forbid(node: ast.ClassDef) -> bool:
    """True when the class body sets ``model_config = ConfigDict(extra="forbid")``."""
    for stmt in node.body:
        targets = (
            stmt.targets
            if isinstance(stmt, ast.Assign)
            else [stmt.target]
            if isinstance(stmt, ast.AnnAssign)
            else []
        )
        if not any(isinstance(t, ast.Name) and t.id == "model_config" for t in targets):
            continue
        value = stmt.value
        if not isinstance(value, ast.Call):
            continue
        for kw in value.keywords:
            if (
                kw.arg == "extra"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value == "forbid"
            ):
                return True
    return False


def test_the_scan_finds_a_realistic_number_of_models():
    """Guard the guard: an empty scan would make the check below vacuous."""
    models = _request_models()
    assert len(models) >= _MIN_REQUEST_MODELS, f"only found {len(models)} *Request models"


def test_the_scan_reads_forbid_correctly():
    """Pin one model end to end, so a parser returning junk cannot pass.

    ``CreateInvestigationRequest`` is the one whose silent drop of a misspelled
    ``tlp_level`` motivated this file, so it is the one worth pinning.
    """
    models = _request_models()
    assert models.get("investigations.CreateInvestigationRequest") is True


def test_every_request_model_forbids_undeclared_fields():
    """The ratchet: a new request model must reject what it does not declare."""
    permissive = sorted(
        name
        for name, forbids in _request_models().items()
        if not forbids and name not in FORBID_EXEMPT
    )
    assert not permissive, (
        "These request models silently accept and drop undeclared fields:\n  "
        + "\n  ".join(permissive)
        + '\n\nAdd `model_config = ConfigDict(extra="forbid")`. Without it a '
        "caller who misspells a field gets a 2xx and the model's default — "
        "which for tlp_level means the case is created at GREEN instead of the "
        "RED that was asked for (#586's failure mode, on request bodies)."
    )


def test_exemption_list_only_holds_live_models():
    """The exemption list may only shrink."""
    models = _request_models()

    stale = sorted(set(FORBID_EXEMPT) - set(models))
    assert not stale, (
        f"FORBID_EXEMPT names models that no longer exist: {stale}. "
        "Remove them — a ratchet's exemption list may only shrink."
    )

    now_strict = sorted(name for name in FORBID_EXEMPT if models.get(name))
    assert not now_strict, (
        f"FORBID_EXEMPT names models that now forbid extras: {now_strict}. "
        "The exemption is obsolete; delete it."
    )
