"""What the receiver records about its work: the ``Metrics`` protocol under the Java names, the
outcomes of a received SET, and ``NoopMetrics`` that records nothing."""

from __future__ import annotations

from datetime import timedelta
from typing import Final, Protocol

from easyssf.core import DeliveryMethod

__all__ = ["Metrics", "NoopMetrics", "SetOutcome"]


class SetOutcome:
    """What happened to a received SET, the tag of the ``easyssf.receiver.sets`` metric."""

    HANDLED: Final = "handled"
    """The SET was verified and handled."""
    DUPLICATE: Final = "duplicate"
    """The SET was processed before and has been skipped."""
    IN_PROGRESS: Final = "in-progress"
    """The SET is being handled by another instance and has been left for a redelivery."""
    INVALID: Final = "invalid"
    """The SET was rejected."""
    UNAVAILABLE: Final = "unavailable"
    """The SET could not be verified because the transmitter was unavailable."""
    FAILED: Final = "failed"
    """A handler failed, the SET is expected to be delivered again."""
    UNAUTHENTICATED: Final = "unauthenticated"
    """A push request did not carry the expected authorization."""


class Metrics(Protocol):
    """Records what the receiver does, under the Java names: ``easyssf.receiver.sets`` (a counter
    of received SETs by transmitter, delivery and outcome), ``easyssf.receiver.events`` (a
    counter of handled events by transmitter, event type and delivery), ``easyssf.receiver.poll``
    (a histogram of the duration of poll requests by transmitter and outcome) and
    ``easyssf.receiver.poll.pending-acks`` (a gauge of the acknowledgements a poller owes).

    Implement it over OpenTelemetry or Prometheus, subclassing :class:`NoopMetrics` for the
    methods you do not record. The methods are sync: they only record, they never wait.
    """

    def set_received(self, transmitter: str, delivery: DeliveryMethod, outcome: str) -> None:
        """Counts a received SET by transmitter (``""`` if unknown), delivery and
        :class:`SetOutcome`."""
        ...

    def event_handled(self, transmitter: str, event_type: str, delivery: DeliveryMethod) -> None:
        """Counts a handled event by transmitter, event type URI and delivery."""
        ...

    def poll_completed(self, transmitter: str, duration: timedelta, success: bool) -> None:
        """Records a poll request to the transmitter and whether it answered it."""
        ...

    def pending_acks_changed(self, transmitter: str, pending_acks: int) -> None:
        """Records the number of acknowledgements and error reports a poller owes its
        transmitter, for a gauge."""
        ...


class NoopMetrics:
    """Records nothing. Subclass it in a :class:`Metrics` implementation to record only some of
    the metrics."""

    def set_received(self, transmitter: str, delivery: DeliveryMethod, outcome: str) -> None:
        """Records nothing."""

    def event_handled(self, transmitter: str, event_type: str, delivery: DeliveryMethod) -> None:
        """Records nothing."""

    def poll_completed(self, transmitter: str, duration: timedelta, success: bool) -> None:
        """Records nothing."""

    def pending_acks_changed(self, transmitter: str, pending_acks: int) -> None:
        """Records nothing."""
