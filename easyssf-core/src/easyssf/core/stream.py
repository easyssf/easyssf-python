"""Event stream configuration and status (SSF 1.0, section 8.1)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from . import event_types
from .claims import Claims, audiences, object_member, string_member, strings
from .delivery import POLL_URI, PUSH_URI

__all__ = ["StreamConfiguration", "StreamStatus", "StreamStatusValue"]


class StreamStatusValue:
    """Stream statuses (SSF 1.0, section 8.1.2); an open set."""

    ENABLED: Final = "enabled"
    """The stream delivers events."""
    PAUSED: Final = "paused"
    """The stream holds events back and delivers them when enabled again."""
    DISABLED: Final = "disabled"
    """The stream delivers no events and drops them."""


class StreamConfiguration:
    """The configuration of an event stream (SSF 1.0, section 8.1.1), as sent to and returned by
    the transmitter."""

    __slots__ = ("_claims",)

    def __init__(self, claims: Claims | None = None) -> None:
        self._claims: Claims = {} if claims is None else claims

    @classmethod
    def push(
        cls,
        endpoint_url: str,
        authorization_header: str = "",
        events_requested: Sequence[str] = (),
        description: str = "",
    ) -> StreamConfiguration:
        """A stream the transmitter pushes events to.

        ``endpoint_url`` is the push endpoint of the receiver as the transmitter reaches it,
        ``authorization_header`` the ``Authorization`` header the transmitter has to send (``""``
        for none), ``events_requested`` the requested event types (alias or URI).
        """
        delivery: Claims = {"method": PUSH_URI, "endpoint_url": endpoint_url}
        if authorization_header:
            delivery["authorization_header"] = authorization_header
        return cls._new(delivery, events_requested, description)

    @classmethod
    def poll(cls, events_requested: Sequence[str] = (), description: str = "") -> StreamConfiguration:
        """A stream the receiver polls events from."""
        return cls._new({"method": POLL_URI}, events_requested, description)

    @classmethod
    def _new(cls, delivery: Claims, events_requested: Sequence[str], description: str) -> StreamConfiguration:
        claims: Claims = {
            "delivery": delivery,
            "events_requested": [event_types.resolve(event) for event in events_requested],
        }
        if description:
            claims["description"] = description
        return cls(claims)

    @property
    def claims(self) -> Claims:
        """The members of the stream configuration."""
        return self._claims

    @property
    def stream_id(self) -> str:
        """The ``stream_id``, ``""`` if the transmitter has not assigned one."""
        return string_member(self._claims, "stream_id")

    @property
    def issuer(self) -> str:
        """The ``iss``, the issuer of the SETs of this stream."""
        return string_member(self._claims, "iss")

    @property
    def audience(self) -> list[str]:
        """The audiences of the SETs of this stream, empty if unknown."""
        return audiences(self._claims.get("aud"))

    @property
    def events_supported(self) -> list[str]:
        """The ``events_supported`` of the transmitter."""
        return strings(self._claims.get("events_supported"))

    @property
    def events_requested(self) -> list[str]:
        """The ``events_requested`` by the receiver."""
        return strings(self._claims.get("events_requested"))

    @property
    def events_delivered(self) -> list[str]:
        """The ``events_delivered`` on this stream."""
        return strings(self._claims.get("events_delivered"))

    @property
    def description(self) -> str:
        """The ``description``."""
        return string_member(self._claims, "description")

    @property
    def delivery_method_uri(self) -> str:
        """The identifier of the delivery method, see :attr:`DeliveryMethod.uri`."""
        return string_member(object_member(self._claims, "delivery"), "method")

    @property
    def delivery_endpoint_url(self) -> str:
        """The push endpoint of the receiver or the poll endpoint of the transmitter, ``""`` if absent."""
        return string_member(object_member(self._claims, "delivery"), "endpoint_url")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, StreamConfiguration) and other._claims == self._claims

    def __hash__(self) -> int:
        return id(self)

    def __repr__(self) -> str:
        return f"StreamConfiguration({self._claims!r})"


@dataclass(frozen=True, slots=True)
class StreamStatus:
    """The status of an event stream (SSF 1.0, section 8.1.2)."""

    stream_id: str
    """The identifier of the stream."""
    status: str
    """``enabled``, ``paused`` or ``disabled``, see :class:`StreamStatusValue`."""
    reason: str = ""
    """Why the stream has that status, ``""`` if the transmitter gave none."""
