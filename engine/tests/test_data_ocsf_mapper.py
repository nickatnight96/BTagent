"""Tests for OCSFMapperNode (UC-1.2 semantic layer, #104)."""

from __future__ import annotations

from datetime import UTC, timezone

import pytest

from btagent_engine import NodeContext
from btagent_engine.data import (
    OCSFMapperInput,
    OCSFMapperNode,
    UnknownConnectorError,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_map", org_id="org_test")


async def test_splunk_flat_field_normalized():
    out = await OCSFMapperNode().run(
        OCSFMapperInput(
            connector="splunk",
            raw_events=[
                {
                    "_time": "2026-05-21T09:14:03+00:00",
                    "src_ip": "10.0.0.5",
                    "dest_ip": "8.8.8.8",
                    "user": "alice",
                    "action": "allowed",
                }
            ],
        ),
        _ctx(),
    )
    assert len(out.events) == 1
    e = out.events[0]
    assert e.source_ip == "10.0.0.5"
    assert e.dest_ip == "8.8.8.8"
    assert e.user == "alice"
    assert e.action == "allowed"
    assert e.source_connector == "splunk"


async def test_elastic_nested_field_normalized():
    out = await OCSFMapperNode().run(
        OCSFMapperInput(
            connector="elastic",
            raw_events=[
                {
                    "@timestamp": "2026-05-21T09:20:11.000Z",
                    "source": {"ip": "10.0.0.5"},
                    "destination": {"ip": "8.8.8.8"},
                    "user": {"name": "alice"},
                }
            ],
        ),
        _ctx(),
    )
    e = out.events[0]
    # Nested source.ip -> canonical source_ip (same field as Splunk's src_ip)
    assert e.source_ip == "10.0.0.5"
    assert e.dest_ip == "8.8.8.8"
    assert e.user == "alice"


async def test_timestamps_normalized_to_utc():
    out = await OCSFMapperNode().run(
        OCSFMapperInput(
            connector="splunk",
            raw_events=[{"_time": "2026-05-21T09:14:03+05:00", "src_ip": "1.1.1.1"}],
        ),
        _ctx(),
    )
    ts = out.events[0].timestamp
    assert ts.tzinfo is not None
    assert ts.utcoffset() == UTC.utcoffset(None)
    # 09:14:03+05:00 -> 04:14:03Z
    assert ts.hour == 4


async def test_epoch_timestamp_parsed():
    out = await OCSFMapperNode().run(
        OCSFMapperInput(
            connector="crowdstrike",
            raw_events=[{"timestamp": 1747818843, "ComputerName": "H1", "UserName": "u1"}],
        ),
        _ctx(),
    )
    assert out.events[0].timestamp.tzinfo is not None
    assert out.events[0].host == "H1"


async def test_empty_events_yield_empty_output():
    out = await OCSFMapperNode().run(OCSFMapperInput(connector="splunk", raw_events=[]), _ctx())
    assert out.events == []


async def test_unknown_connector_raises():
    with pytest.raises(UnknownConnectorError):
        await OCSFMapperNode().run(
            OCSFMapperInput(connector="nonexistent", raw_events=[{}]), _ctx()
        )


async def test_raw_event_preserved_for_lineage():
    raw = {"_time": "2026-05-21T09:14:03+00:00", "src_ip": "1.1.1.1", "extra": "kept"}
    out = await OCSFMapperNode().run(OCSFMapperInput(connector="splunk", raw_events=[raw]), _ctx())
    assert out.events[0].raw_event == raw
    assert out.events[0].raw_ref.connector == "splunk"
