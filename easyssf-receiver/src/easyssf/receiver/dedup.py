"""De-duplication of SETs by ``jti``: the ``JtiDedupStore`` protocol and its in-memory
implementation. A SET is claimed before its handlers run, so that a redelivery of a handled SET
is skipped and a SET another instance is handling is left alone."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Final, Protocol

from easyssf.core import EventToken

from .errors import Clock, system_clock

__all__ = [
    "DEFAULT_DEDUP_LEASE",
    "InMemoryJtiDedupStore",
    "JtiClaim",
    "JtiClaimState",
    "JtiDedupStore",
]

DEFAULT_DEDUP_LEASE: Final = timedelta(seconds=60)
"""The lease of a claim by default: 60 seconds."""


class JtiClaimState(Enum):
    """What a store knows about a SET when it is claimed."""

    GRANTED = "granted"
    """Not seen before, or abandoned by a crashed instance: the caller handles the SET."""
    IN_PROGRESS = "in-progress"
    """Another instance is handling the SET right now: neither handle nor acknowledge it."""
    PROCESSED = "processed"
    """The SET was handled before: acknowledge it, do not handle it again."""


@dataclass(frozen=True, slots=True)
class JtiClaim:
    """The answer of a :class:`JtiDedupStore` to a claim and, for a granted claim, the token that
    fences it against a later take-over of the same SET."""

    state: JtiClaimState
    """What the store knows about the SET."""
    token: int = 0
    """A value the store chooses for a granted claim, for example the time of the claim."""

    @property
    def is_granted(self) -> bool:
        """Whether the claim was granted: the caller handles the SET."""
        return self.state is JtiClaimState.GRANTED


class JtiDedupStore(Protocol):
    """Remembers which SETs were processed, so that a redelivery of a handled SET is skipped and
    a SET another instance is handling is left alone. It does not make handling exactly once: an
    instance that dies after a handler ran and before :meth:`processed` hands the SET to the next
    instance after the lease, which is why handlers are idempotent. Implement it to back it with
    a shared or durable store.

    A SET is claimed before its handlers run and marked processed once they succeeded. In
    between it is in progress: another instance of the application that receives the same SET
    then neither handles nor acknowledges it, and leaves it to the transmitter's redelivery. An
    instance that crashes mid-processing leaves the claim behind, so a claim older than the
    store's lease counts as abandoned and the next instance takes the SET over.

    A granted claim carries a token that fences it: :meth:`processed`, :meth:`forget` and
    :meth:`renew` only act on the claim with that token. An instance whose handlers outlived the
    lease therefore neither completes nor deletes the claim of the instance that took the SET
    over; the SET belongs to the new holder, and :meth:`processed` returns ``False`` so that the
    late instance does not acknowledge the SET either: the acknowledgement is the new holder's,
    with the record of the success. An instance whose handlers may run longer than the lease
    renews its claim meanwhile.

    A failure of the store raises; the processor reports it as a ``StoreError``.
    """

    async def claim(self, token: EventToken) -> JtiClaim:
        """Atomically records that the caller is about to handle the SET, unless it was handled
        before or is being handled by another instance."""
        ...

    async def processed(self, token: EventToken, claim: JtiClaim) -> bool:
        """Records that the handlers of a claimed SET succeeded and returns ``True``. Does nothing
        and returns ``False`` if the claim was taken over meanwhile, because the handlers outlived
        the lease: the SET then belongs to the instance that took it over, and the caller leaves
        it to that instance to acknowledge."""
        ...

    async def forget(self, token: EventToken, claim: JtiClaim) -> None:
        """Forgets the given SET again, because handling it failed and it is expected to be
        delivered once more. Does nothing if the claim was taken over meanwhile."""
        ...

    async def renew(self, token: EventToken, claim: JtiClaim) -> JtiClaim | None:
        """Extends the claim of a SET whose handlers are still running: its age starts over, so
        it does not count as abandoned after the lease. Returns the claim to use from now on, as
        a store may give a renewed claim a new token, or ``None`` if the claim was taken over,
        the SET then belongs to the instance that took it over. A store that does not renew
        returns the claim as it is, which leaves the lease as the bound for the handlers."""
        ...


class _KnownState(Enum):
    IN_PROGRESS = 1
    PROCESSED = 2


@dataclass(slots=True)
class _Known:
    state: _KnownState
    since: datetime
    token: int

    def holds(self, claim: JtiClaim) -> bool:
        return self.state is _KnownState.IN_PROGRESS and self.token == claim.token


class InMemoryJtiDedupStore:
    """A :class:`JtiDedupStore` that remembers a bounded number of SETs in memory, evicting the
    oldest first. Its content is lost on restart and not shared between instances, so the
    in-progress state only matters when the same SET arrives twice while a handler of this
    instance still runs.

    The methods do not await anything, so they are atomic on the event loop; the store is not
    meant to be shared between threads.

    Args:
        capacity: how many SETs to remember, at least one.
        lease: how long a claim is held, :data:`DEFAULT_DEDUP_LEASE` if not positive; longer
            than the longest handler.
        clock: the clock that measures the age of a claim, the system clock by default.
    """

    def __init__(self, capacity: int, lease: timedelta | None = None, clock: Clock | None = None) -> None:
        self._capacity = max(1, capacity)
        self._lease = lease if lease is not None and lease > timedelta(0) else DEFAULT_DEDUP_LEASE
        self._clock = clock if clock is not None else system_clock
        self._entries: OrderedDict[str, _Known] = OrderedDict()  # oldest first
        self._next_token = 0

    def __len__(self) -> int:
        """The number of SETs remembered."""
        return len(self._entries)

    def _put(self, key: str, state: _KnownState, token: int) -> None:
        self._entries.pop(key, None)
        self._entries[key] = _Known(state, self._clock(), token)
        while len(self._entries) > self._capacity:
            self._entries.popitem(last=False)

    def _grant(self, key: str) -> JtiClaim:
        self._next_token += 1
        self._put(key, _KnownState.IN_PROGRESS, self._next_token)
        return JtiClaim(JtiClaimState.GRANTED, self._next_token)

    async def claim(self, token: EventToken) -> JtiClaim:
        """Grants the claim unless the SET was processed or is in progress within the lease; an
        abandoned claim is taken over, with a token of its own."""
        key = token.idempotency_key
        existing = self._entries.get(key)
        if existing is None:
            return self._grant(key)
        if existing.state is _KnownState.PROCESSED:
            return JtiClaim(JtiClaimState.PROCESSED)
        if existing.since + self._lease <= self._clock():
            # abandoned: taken over, with a token of its own
            return self._grant(key)
        return JtiClaim(JtiClaimState.IN_PROGRESS)

    async def processed(self, token: EventToken, claim: JtiClaim) -> bool:
        """Records the success of the claim unless it was taken over; an evicted claim is
        recorded anyway."""
        key = token.idempotency_key
        existing = self._entries.get(key)
        # the claim may have been evicted meanwhile: record the success anyway
        if existing is None or existing.holds(claim):
            self._put(key, _KnownState.PROCESSED, claim.token)
            return True
        return False

    async def forget(self, token: EventToken, claim: JtiClaim) -> None:
        """Forgets the SET if the claim still holds it."""
        key = token.idempotency_key
        existing = self._entries.get(key)
        if existing is not None and existing.holds(claim):
            del self._entries[key]

    async def renew(self, token: EventToken, claim: JtiClaim) -> JtiClaim | None:
        """Starts the age of the claim over, keeping its token; ``None`` if it was taken over."""
        key = token.idempotency_key
        existing = self._entries.get(key)
        if existing is not None and not existing.holds(claim):
            return None
        # an evicted claim is restored, as processed records it as well
        self._put(key, _KnownState.IN_PROGRESS, claim.token)
        return claim

    def __repr__(self) -> str:
        return f"InMemoryJtiDedupStore(capacity={self._capacity}, lease={self._lease}, size={len(self._entries)})"
