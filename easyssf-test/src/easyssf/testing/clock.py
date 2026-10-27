"""A clock moved by hand, for tests of time-dependent behaviour."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

__all__ = ["ManualClock"]


class ManualClock:
    """A clock that only moves when a test moves it; a ``Clock`` for stores and pollers.

    Example:
        >>> clock = ManualClock()
        >>> store = InMemoryJtiDedupStore(100, timedelta(minutes=5), clock)
        >>> clock.advance(timedelta(minutes=6))
    """

    def __init__(self, now: datetime | None = None) -> None:
        self._now = now if now is not None else datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        """The current time of the clock."""
        return self._now

    @property
    def now(self) -> datetime:
        """The current time of the clock."""
        return self._now

    def advance(self, delta: timedelta) -> datetime:
        """Moves the clock forward by ``delta`` and returns the new time."""
        self._now += delta
        return self._now

    def set(self, now: datetime) -> None:
        """Sets the clock to the given time."""
        self._now = now
