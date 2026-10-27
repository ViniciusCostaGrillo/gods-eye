"""Event-driven pipeline envelopes (CloudEvents 1.0 spec) and async EventBus."""

from collections import defaultdict
from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from godseye.domain.enums import EventType
from godseye.domain.models import new_id, utc_now_iso


class CloudEvent(BaseModel):
    """CloudEvents 1.0 specification envelope (api-integration skill)."""

    model_config = ConfigDict(extra="forbid")

    specversion: str = Field(default="1.0")
    type: str
    source: str = Field(default="/godseye-orchestrator")
    id: str = Field(default_factory=new_id)
    time: str = Field(default_factory=utc_now_iso)
    datacontenttype: str = Field(default="application/json")
    correlation_id: str = Field(default_factory=new_id)
    data: dict[str, Any] = Field(default_factory=dict)


EventHandler = Callable[[CloudEvent], Awaitable[None]]


class EventBus:
    """Asynchronous pub/sub event bus for decoupled OSINT pipeline orchestration."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[EventHandler]] = defaultdict(list)
        self._history: list[CloudEvent] = []

    def subscribe(self, event_type: EventType | str, handler: EventHandler) -> None:
        """Subscribe an async handler to an event type."""
        key = str(event_type)
        self._subscribers[key].append(handler)

    async def publish(
        self,
        event_type: EventType | str,
        data: dict[str, Any],
        source: str = "/godseye-core",
        correlation_id: str | None = None,
    ) -> CloudEvent:
        """Publish an event to all registered subscribers."""
        event = CloudEvent(
            type=str(event_type),
            source=source,
            correlation_id=correlation_id or new_id(),
            data=data,
        )
        self._history.append(event)
        if len(self._history) > 1000:
            self._history = self._history[-1000:]

        for handler in self._subscribers.get(str(event_type), []):
            await handler(event)
        for wildcard_handler in self._subscribers.get("*", []):
            await wildcard_handler(event)
        return event

    @property
    def history(self) -> list[CloudEvent]:
        """Return recent published CloudEvents."""
        return list(self._history)
