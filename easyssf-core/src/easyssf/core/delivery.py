"""How SETs get from the transmitter to the receiver."""

from __future__ import annotations

from enum import Enum
from typing import Final

__all__ = ["POLL_URI", "PUSH_URI", "DeliveryMethod"]

PUSH_URI: Final = "urn:ietf:rfc:8935"
"""Identifies push delivery in a stream configuration."""
POLL_URI: Final = "urn:ietf:rfc:8936"
"""Identifies poll delivery in a stream configuration."""


class DeliveryMethod(Enum):
    """How SETs get from the transmitter to the receiver."""

    PUSH = "push"
    """The transmitter sends SETs to an endpoint of the receiver (RFC 8935)."""
    POLL = "poll"
    """The receiver fetches SETs from an endpoint of the transmitter (RFC 8936)."""

    @property
    def uri(self) -> str:
        """The identifier of the delivery method in a stream configuration."""
        return PUSH_URI if self is DeliveryMethod.PUSH else POLL_URI

    @classmethod
    def from_uri(cls, uri: str) -> DeliveryMethod | None:
        """The delivery method with the given identifier, ``None`` for any other string."""
        if uri == PUSH_URI:
            return cls.PUSH
        if uri == POLL_URI:
            return cls.POLL
        return None

    @classmethod
    def from_name(cls, name: str) -> DeliveryMethod | None:
        """The delivery method by its lowercase name as used in configuration, ``None`` otherwise."""
        try:
            return cls(name.strip().lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """The lowercase name, for logs and metric tags: ``push`` or ``poll``."""
        return self.value
