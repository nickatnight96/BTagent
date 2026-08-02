"""WebSocket wire-contract test — the anti-drift chokepoint.

Why this file exists
--------------------

Before this test, the frontend and the backend each had a *self-consistent*
test suite pinning its own side of a contract the two did not actually share:

* the browser decoded envelopes as ``event_id`` / ``event_type`` / ``payload``
  while the hub forwards ``EventEnvelope.model_dump_json()`` verbatim, which is
  ``id`` / ``type`` / ``data`` (no aliases) — so every event decoded to
  all-``undefined``;
* the browser put ``message`` / ``checkpoint_id`` / ``approved`` at the frame's
  TOP level while ``ClientMessage`` only reads them out of ``data`` — and
  Pydantic silently ignores the extras, so ``msg.data`` was ``{}``;
* the frontend's ``EventType`` enum had members (``hitl_requested``,
  ``message_complete``, ``status_changed``, ``timeline_entry``,
  ``hunt_finding_updated``) that no Python enum member has ever emitted.

Both suites were green throughout. The only thing that catches that class of
bug is a test that exercises the REAL serialization on both sides against one
shared artifact. That artifact is
``frontend/src/types/ws-contract.fixture.json``:

* THIS test re-derives the contract from the live Python types and asserts the
  checked-in fixture matches — so a Python-side change that isn't propagated
  fails here.
* ``frontend/src/__tests__/wsContract.test.ts`` asserts
  ``frontend/src/types/events.generated.ts`` matches the same fixture, and
  round-trips the fixture's real ``model_dump_json()`` payload through the real
  ``WebSocketClient`` — so a TypeScript-side change that isn't propagated fails
  there.

Regenerating after an INTENTIONAL protocol change::

    BTAGENT_REGEN_WS_CONTRACT=1 pytest backend/tests/test_ws_contract.py

then review + commit the regenerated fixture and ``events.generated.ts``
together.
"""

from __future__ import annotations

import json
import os
import pathlib

import pytest
from btagent_shared.types.events import EventEnvelope, EventType

from btagent_backend.ws.protocol import (
    ClientMessage,
    ClientMessageType,
    ServerMessage,
    ServerMessageType,
)

# backend/tests/test_ws_contract.py -> repo root
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURE_PATH = _REPO_ROOT / "frontend" / "src" / "types" / "ws-contract.fixture.json"
GENERATED_TS_PATH = _REPO_ROOT / "frontend" / "src" / "types" / "events.generated.ts"

# Deterministic sample values so the fixture is stable across regenerations.
_SAMPLE_EVENT_ID = "evt_01CONTRACTSAMPLE0000000000"
_SAMPLE_INV_ID = "inv_01CONTRACTSAMPLE0000000000"
_SAMPLE_TRACE_ID = "trace_01CONTRACTSAMPLE000000000"
_SAMPLE_TIMESTAMP = "2026-07-31T00:00:00+00:00"


# --------------------------------------------------------------------------- #
# Canonical contract builder (also the generator)
# --------------------------------------------------------------------------- #


def build_contract() -> dict:
    """Derive the whole wire contract from the LIVE Python types.

    Uses real serialization (``model_dump_json``) rather than a hand-written
    literal, so the fixture can never describe a shape Pydantic doesn't
    actually emit.
    """
    sample = EventEnvelope(
        type=EventType.OUTPUT_CHUNK,
        id=_SAMPLE_EVENT_ID,
        investigation_id=_SAMPLE_INV_ID,
        parent_id=None,
        trace_id=_SAMPLE_TRACE_ID,
        timestamp=_SAMPLE_TIMESTAMP,
        data={"text": "hello", "index": 1},
    )
    client_sample = ClientMessage(
        type=ClientMessageType.CHAT,
        investigation_id=_SAMPLE_INV_ID,
        data={"message": "what happened?"},
    )
    return {
        "_comment": (
            "GENERATED — do not hand-edit. Source of truth: "
            "shared/btagent_shared/types/events.py + "
            "backend/btagent_backend/ws/protocol.py. Regenerate with "
            "BTAGENT_REGEN_WS_CONTRACT=1 pytest backend/tests/test_ws_contract.py"
        ),
        "envelope_fields": list(EventEnvelope.model_fields.keys()),
        "event_types": {m.name: m.value for m in EventType},
        "sample_envelope_json": sample.model_dump_json(),
        "client_message_fields": list(ClientMessage.model_fields.keys()),
        "client_message_types": {m.name: m.value for m in ClientMessageType},
        "client_message_sample_json": client_sample.model_dump_json(),
        "server_message_types": {m.name: m.value for m in ServerMessageType},
    }


_TS_HEADER = """/**
 * GENERATED FILE — do not hand-edit.
 *
 * Mirrors the Python wire contract:
 *   - `EventType`     <- shared/btagent_shared/types/events.py :: EventType
 *   - `EventEnvelope` <- shared/btagent_shared/types/events.py :: EventEnvelope
 *                        (exactly `EventEnvelope.model_dump_json()` — the hub
 *                        forwards that JSON verbatim, with NO aliasing)
 *   - `ClientMessageType` / `ClientMessage`
 *                     <- backend/btagent_backend/ws/protocol.py
 *
 * Drift is a test failure, in BOTH directions:
 *   - backend/tests/test_ws_contract.py re-derives the contract from the live
 *     Python types and diffs it against ws-contract.fixture.json;
 *   - frontend/src/__tests__/wsContract.test.ts diffs THIS file against that
 *     same fixture and round-trips a real `model_dump_json()` payload through
 *     the real WebSocketClient.
 *
 * To change the protocol: edit the Python types, then regenerate with
 *   BTAGENT_REGEN_WS_CONTRACT=1 pytest backend/tests/test_ws_contract.py
 * and commit the regenerated fixture + this file together.
 */

"""


def build_generated_ts(contract: dict) -> str:
    """Emit the TypeScript mirror of the contract."""
    lines: list[str] = [_TS_HEADER, "export enum EventType {"]
    for name, value in contract["event_types"].items():
        lines.append(f'  {name} = "{value}",')
    lines += ["}", "", "export enum ClientMessageType {"]
    for name, value in contract["client_message_types"].items():
        lines.append(f'  {name} = "{value}",')
    lines += ["}", "", "export enum ServerMessageType {"]
    for name, value in contract["server_message_types"].items():
        lines.append(f'  {name} = "{value}",')
    lines += [
        "}",
        "",
        "/**",
        " * The exact JSON the hub puts on the wire — `EventEnvelope.model_dump_json()`.",
        " * Field names are the Python attribute names (no aliases): `id`, `type`,",
        " * `data` — NOT `event_id` / `event_type` / `payload`.",
        " */",
        "export interface EventEnvelope {",
        "  type: EventType;",
        "  id: string;",
        "  investigation_id: string;",
        "  parent_id: string | null;",
        "  trace_id: string | null;",
        "  timestamp: string;",
        "  data: Record<string, unknown>;",
        "}",
        "",
        "/**",
        " * Browser -> server frame. Pydantic IGNORES unknown top-level keys, so every",
        " * payload field MUST be nested under `data` or it is silently dropped.",
        " */",
        "export interface ClientMessage {",
        "  type: ClientMessageType;",
        "  investigation_id?: string | null;",
        "  data?: Record<string, unknown>;",
        "}",
        "",
    ]
    return "\n".join(lines)


def _regenerate() -> dict:
    contract = build_contract()
    FIXTURE_PATH.write_text(json.dumps(contract, indent=2) + "\n")
    GENERATED_TS_PATH.write_text(build_generated_ts(contract))
    return contract


if os.environ.get("BTAGENT_REGEN_WS_CONTRACT"):
    _regenerate()


@pytest.fixture(scope="module")
def fixture_contract() -> dict:
    assert FIXTURE_PATH.exists(), f"missing WS contract fixture at {FIXTURE_PATH}"
    return json.loads(FIXTURE_PATH.read_text())


# --------------------------------------------------------------------------- #
# 1. The checked-in fixture matches the live Python types
# --------------------------------------------------------------------------- #


def test_fixture_matches_live_python_types(fixture_contract: dict) -> None:
    """The single anti-drift assertion for the whole server->client contract."""
    assert fixture_contract == build_contract(), (
        "WS contract drift: the Python types changed but "
        "frontend/src/types/ws-contract.fixture.json was not regenerated. Run\n"
        "  BTAGENT_REGEN_WS_CONTRACT=1 pytest backend/tests/test_ws_contract.py\n"
        "and commit the regenerated fixture AND "
        "frontend/src/types/events.generated.ts together."
    )


def test_generated_ts_matches_live_python_types(fixture_contract: dict) -> None:
    """events.generated.ts is byte-identical to what the live types emit."""
    assert GENERATED_TS_PATH.exists(), f"missing generated TS at {GENERATED_TS_PATH}"
    assert GENERATED_TS_PATH.read_text() == build_generated_ts(build_contract()), (
        "frontend/src/types/events.generated.ts is stale. Regenerate with\n"
        "  BTAGENT_REGEN_WS_CONTRACT=1 pytest backend/tests/test_ws_contract.py"
    )


# --------------------------------------------------------------------------- #
# 2. Real serialization: server -> client
# --------------------------------------------------------------------------- #


def test_envelope_wire_keys_are_unaliased_python_names() -> None:
    """The wire keys are ``id``/``type``/``data`` — NOT event_id/event_type/payload.

    This is the exact defect the frontend decoder used to have. Pinning the
    literal key set here means any future ``alias=`` / ``serialization_alias=``
    on EventEnvelope trips a test instead of silently blanking every event in
    the browser.
    """
    raw = EventEnvelope(
        type=EventType.THINKING,
        investigation_id="inv_x",
        data={"model": "haiku"},
    ).model_dump_json()
    payload = json.loads(raw)

    assert set(payload) == {
        "type",
        "id",
        "investigation_id",
        "parent_id",
        "trace_id",
        "timestamp",
        "data",
    }
    # The aliased names the browser used to read must NOT exist.
    for absent in ("event_id", "event_type", "payload"):
        assert absent not in payload

    assert payload["type"] == "thinking"
    assert payload["data"] == {"model": "haiku"}


def test_every_event_type_survives_a_real_serialization_round_trip() -> None:
    """Each EventType serializes to its literal string and parses back."""
    for event_type in EventType:
        raw = EventEnvelope(
            type=event_type,
            investigation_id="inv_x",
            data={"k": "v"},
        ).model_dump_json()
        assert json.loads(raw)["type"] == event_type.value
        assert EventEnvelope.model_validate_json(raw).type is event_type


def test_server_message_wrapper_shape() -> None:
    """Protocol-level frames are ``{type, data}`` — the browser branches on type."""
    payload = json.loads(ServerMessage(type=ServerMessageType.PONG, data={}).model_dump_json())
    assert payload == {"type": "pong", "data": {}}


# --------------------------------------------------------------------------- #
# 3. Real serialization: client -> server
# --------------------------------------------------------------------------- #


def test_flat_client_frames_lose_their_payload() -> None:
    """Pin the failure mode so nobody "fixes" the client back to a flat frame.

    The old browser client sent ``{type, investigation_id, message}``. Pydantic
    ignores the unknown top-level key, so the server saw ``data == {}`` and the
    chat message never reached the engine. That is not an error the server can
    report — which is exactly why it has to be pinned on this side.
    """
    flat_chat = json.dumps(
        {"type": "chat", "investigation_id": "inv_1", "message": "what happened?"}
    )
    assert ClientMessage.model_validate_json(flat_chat).data == {}

    flat_hitl = json.dumps(
        {
            "type": "hitl_response",
            "investigation_id": "inv_1",
            "checkpoint_id": "cp_1",
            "approved": True,
            "comment": "ok",
        }
    )
    assert ClientMessage.model_validate_json(flat_hitl).data == {}


def test_nested_client_frames_carry_their_payload(fixture_contract: dict) -> None:
    """The shape the browser client now sends parses with its payload intact."""
    chat = ClientMessage.model_validate_json(fixture_contract["client_message_sample_json"])
    assert chat.type is ClientMessageType.CHAT
    assert chat.data == {"message": "what happened?"}

    hitl = ClientMessage.model_validate_json(
        json.dumps(
            {
                "type": "hitl_response",
                "investigation_id": "inv_1",
                "data": {"checkpoint_id": "cp_1", "approved": True, "comment": "ok"},
            }
        )
    )
    assert hitl.data == {"checkpoint_id": "cp_1", "approved": True, "comment": "ok"}


def test_ping_is_a_valid_client_message_type() -> None:
    """The heartbeat frame the browser sends must PARSE, not produce an ERROR.

    The client has always sent ``{"type": "ping"}`` every 30s; until ``PING``
    existed on ``ClientMessageType`` the server answered each one with an error
    frame that then flowed through the browser's handler chain as junk.
    """
    msg = ClientMessage.model_validate_json(json.dumps({"type": "ping"}))
    assert msg.type is ClientMessageType.PING
    assert msg.investigation_id is None


def test_subscribe_frame_shape() -> None:
    """D3: the browser must be able to subscribe to a non-global channel."""
    msg = ClientMessage.model_validate_json(
        json.dumps({"type": "subscribe", "investigation_id": "inv_1"})
    )
    assert msg.type is ClientMessageType.SUBSCRIBE
    assert msg.investigation_id == "inv_1"
