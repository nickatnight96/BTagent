"""Re-export EventType from shared for convenience within the agents package."""

from btagent_shared.types.events import EventEnvelope, EventType

__all__ = ["EventEnvelope", "EventType"]
