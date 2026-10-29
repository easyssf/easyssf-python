"""Processing of a received SET independent of how it was delivered: verify it, skip it if it
was processed before, hand it to the handlers. The port of ``receiver/processor.go``."""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from typing import TypeAlias

from easyssf.core import MEMBERS, DeliveryMethod, EventToken, EventTypes, event_types

from .dedup import JtiClaim, JtiClaimState, JtiDedupStore
from .errors import ErrorCode, HandlingError, InProgressError, RejectedError, StoreError, TransmitterUnavailableError
from .event import EventContext, Handler, HandlerCallable, as_handler, handler_name
from .metrics import Metrics, NoopMetrics, SetOutcome
from .verifier import Verifier, unverified_issuer

__all__ = [
    "CriticalSubjectMembers",
    "ProcessingOutcome",
    "ProcessingResult",
    "Processor",
    "ProcessorOptions",
    "StreamVerificationCheck",
]

_logger = logging.getLogger("easyssf.receiver")


class ProcessingOutcome(Enum):
    """What happened to a valid SET."""

    HANDLED = "handled"
    """The SET was handled by all handlers."""
    DUPLICATE = "duplicate"
    """The SET was processed before and has been skipped."""

    def __str__(self) -> str:
        """The lowercase name."""
        return self.value


@dataclass(frozen=True, slots=True)
class ProcessingResult:
    """What :meth:`Processor.process` returns for a valid SET: the outcome and the verified token.
    Anything else is raised."""

    outcome: ProcessingOutcome
    """What happened to the SET."""
    token: EventToken
    """The verified SET."""

    @property
    def is_handled(self) -> bool:
        """Whether the SET was handled by all handlers."""
        return self.outcome is ProcessingOutcome.HANDLED

    @property
    def is_duplicate(self) -> bool:
        """Whether the SET was processed before and has been skipped."""
        return self.outcome is ProcessingOutcome.DUPLICATE


StreamVerificationCheck: TypeAlias = Callable[[str], Callable[[EventContext], Awaitable[None] | None] | None]
"""Validates a stream verification event before the handlers see it: looked up by the issuer of
the SET, it gives the check for that issuer, or ``None`` for an issuer without a pending
verification. The check, sync or async, raises a ``RejectedError`` with ``invalid_state`` for an
unexpected state. See ``stream.py``."""

CriticalSubjectMembers: TypeAlias = Callable[[str], Sequence[str]]
"""Looks up the ``critical_subject_members`` a transmitter declares in its metadata, by its
issuer; empty for an unknown issuer."""


@dataclass(frozen=True, slots=True)
class ProcessorOptions:
    """How a :class:`Processor` processes SETs beyond verifying, de-duplicating and handling them.
    The defaults are usable."""

    metrics: Metrics | None = None
    """Records what the processor does. Nothing by default."""
    logger: logging.Logger | None = None
    """Where the processor logs; ``easyssf.receiver`` by default."""
    stream_verifications: StreamVerificationCheck | None = None
    """Validates stream verification events before the handlers see them. Verification events
    are accepted unchecked while this is ``None``."""
    understood_subject_members: Sequence[str] | None = None
    """The members of a complex subject the application interprets. A SET whose subject has a
    member the transmitter declared critical (``critical_subject_members`` of its metadata) that
    is not among them is rejected as ``invalid_request``, as the SSF specification requires
    critical members to be interpreted by the receiver. By default the members
    :class:`~easyssf.core.Subject` gives access to, :data:`easyssf.core.MEMBERS`."""
    critical_subject_members: CriticalSubjectMembers | None = None
    """The ``critical_subject_members`` a transmitter declares in its metadata, by its issuer.
    Nothing is critical while this is ``None``."""
    claim_renewal: timedelta | None = None
    """Renews the claim of a SET at this interval while its handlers run
    (:meth:`~easyssf.receiver.dedup.JtiDedupStore.renew`), so that a handler that runs longer
    than the lease of the dedup store does not lose the SET to another instance; a third of the
    lease is a good interval. ``None`` or zero, the default, turns renewal off: the lease then
    bounds the handlers. A renewal that finds the claim taken over stops, and the result of the
    handlers is not recorded, as without renewal after the lease."""


class Processor:
    """Processes a received SET independent of how it was delivered: verifies it, skips it if it
    was processed before and hands it to the handlers.

    With a :class:`~easyssf.receiver.dedup.JtiDedupStore` the SET is claimed while the handlers
    run. A ``claim_renewal`` keeps the claim alive while a handler runs longer than the store's
    lease; without it the lease bounds the handlers.

    Args:
        verifier: verifies the SETs.
        dedup_store: skips SETs processed before; ``None`` processes duplicates.
        options: how SETs are processed beyond that.
    """

    def __init__(
        self, verifier: Verifier, dedup_store: JtiDedupStore | None = None, options: ProcessorOptions | None = None
    ) -> None:
        self._verifier = verifier
        self._dedup = dedup_store
        self._options = options if options is not None else ProcessorOptions()
        self._handlers: list[Handler] = []
        self._metrics: Metrics = self._options.metrics if self._options.metrics is not None else NoopMetrics()
        self._log = self._options.logger if self._options.logger is not None else _logger
        self._understood: Sequence[str] = (
            self._options.understood_subject_members
            if self._options.understood_subject_members is not None
            else MEMBERS
        )

    @property
    def verifier(self) -> Verifier:
        """The verifier of the SETs."""
        return self._verifier

    @property
    def dedup_store(self) -> JtiDedupStore | None:
        """The dedup store, ``None`` if duplicates are processed."""
        return self._dedup

    @property
    def options(self) -> ProcessorOptions:
        """How SETs are processed."""
        return self._options

    @property
    def metrics(self) -> Metrics:
        """Where the processor records what it does."""
        return self._metrics

    @property
    def logger(self) -> logging.Logger:
        """Where the processor logs."""
        return self._log

    @property
    def handlers(self) -> list[Handler]:
        """The handlers, in the order they are called; a copy."""
        return list(self._handlers)

    def add_handler(self, *handlers: Handler | HandlerCallable) -> Processor:
        """Adds handlers; every handler is called, in order, for every verified SET. A sync or
        async callable is wrapped with :func:`~easyssf.receiver.event.as_handler`."""
        self._handlers.extend(as_handler(handler) for handler in handlers)
        return self

    @property
    def handler_count(self) -> int:
        """The number of handlers."""
        return len(self._handlers)

    async def process(self, encoded_set: str, delivery: DeliveryMethod) -> ProcessingResult:
        """Verifies and handles the given SET, in JWS compact serialization.

        Raises:
            RejectedError: the SET is invalid, with the error code of RFC 8935.
            TransmitterUnavailableError: the keys could not be obtained; deliver the SET again.
            InProgressError: another instance is handling the SET; deliver it again. Also when
                the claim of this instance was taken over while its handlers ran, because they
                outlived the lease: the handlers may have succeeded here, but the SET belongs to
                the instance that took it over, which records and acknowledges it. Acknowledging
                it here as well would let a failure there go unnoticed by the transmitter.
            HandlingError: a handler failed; every handler ran, the SET is forgotten and expected
                to be delivered again.
            StoreError: the dedup store failed.
        """
        unverified = unverified_issuer(encoded_set)
        try:
            token = await self._verify(encoded_set)
        except TransmitterUnavailableError:
            self._metrics.set_received(unverified, delivery, SetOutcome.UNAVAILABLE)
            raise
        except Exception:
            self._metrics.set_received(unverified, delivery, SetOutcome.INVALID)
            raise
        issuer = token.issuer
        event = EventContext(token, delivery)
        claim = JtiClaim(JtiClaimState.GRANTED)
        if self._dedup is not None:
            try:
                claim = await self._dedup.claim(token)
            except Exception as error:
                raise StoreError(error) from error
            if claim.state is JtiClaimState.PROCESSED:
                self._log.debug(
                    "Skipping SET, it was processed before", extra={"jti": token.jti, "transmitter": issuer}
                )
                self._metrics.set_received(issuer, delivery, SetOutcome.DUPLICATE)
                return ProcessingResult(ProcessingOutcome.DUPLICATE, token)
            if claim.state is JtiClaimState.IN_PROGRESS:
                self._log.debug(
                    "Leaving SET for a redelivery, another instance is handling it",
                    extra={"jti": token.jti, "transmitter": issuer},
                )
                self._metrics.set_received(issuer, delivery, SetOutcome.IN_PROGRESS)
                raise InProgressError()
        aliases = [event_types.alias_of(event_type) for event_type in event.event_types]
        self._log.debug(
            "Received SET",
            extra={"jti": token.jti, "transmitter": issuer, "delivery": str(delivery), "events": aliases},
        )
        if event.has_event(EventTypes.SSF_STREAM_VERIFICATION):
            self._log.info("Received stream verification event", extra={"transmitter": issuer, "jti": token.jti})

        renewal = self._start_renewal(token, claim)
        # every handler runs, also after one failed: a failing handler must not keep the others
        # from reacting to the event
        failed = 0
        first: tuple[str, Exception] | None = None
        try:
            for handler in self._handlers:
                try:
                    await handler.handle(event)
                except Exception as error:  # a handler's failure is the processor's to report
                    name = handler_name(handler)
                    self._log.error(
                        "An event handler failed",
                        exc_info=error,
                        extra={"jti": token.jti, "transmitter": issuer, "handler": name},
                    )
                    failed += 1
                    if first is None:
                        first = (name, error)
        finally:
            # the claim as last renewed; a taken-over one no longer belongs to this instance, so
            # the outcome of the handlers is neither recorded nor acknowledged
            claim, owned = await renewal.stop()

        if first is not None:
            if self._dedup is not None and owned:
                try:
                    await self._dedup.forget(token, claim)
                except Exception as error:
                    raise StoreError(error) from error
            self._metrics.set_received(issuer, delivery, SetOutcome.FAILED)
            raise HandlingError(first[0], first[1], failed)
        if self._dedup is not None:
            # the success is the new holder's to record and to acknowledge once the claim was
            # taken over, whether a renewal noticed or only processed does: a claim may be lost
            # between the last renewal and the record of the success
            recorded = False
            if owned:
                try:
                    recorded = await self._dedup.processed(token, claim)
                except Exception as error:
                    raise StoreError(error) from error
            if recorded is False:
                self._log.warning(
                    "Leaving SET for a redelivery, its claim was taken over by another instance while the handlers "
                    "ran; they outlived the dedup lease",
                    extra={"jti": token.jti, "transmitter": issuer},
                )
                self._metrics.set_received(issuer, delivery, SetOutcome.IN_PROGRESS)
                raise InProgressError()
        self._metrics.set_received(issuer, delivery, SetOutcome.HANDLED)
        for event_type in event.event_types:
            self._metrics.event_handled(issuer, event_type, delivery)
        return ProcessingResult(ProcessingOutcome.HANDLED, token)

    async def _verify(self, encoded_set: str) -> EventToken:
        token = await self._verifier.verify(encoded_set)
        event = EventContext(token, DeliveryMethod.PUSH)
        if self._options.stream_verifications is not None:
            check = self._options.stream_verifications(token.issuer)
            if check is not None:
                outcome = check(event)
                if inspect.isawaitable(outcome):
                    await outcome
        self._check_critical_subject_members(event)
        return token

    def _check_critical_subject_members(self, event: EventContext) -> None:
        if self._options.critical_subject_members is None:
            return
        critical = self._options.critical_subject_members(event.event_token.issuer)
        if not critical:
            return
        present = event.subject.member_names
        not_understood = [member for member in critical if member in present and member not in self._understood]
        if not_understood:
            raise RejectedError(
                ErrorCode.INVALID_REQUEST,
                f"The subject has the members {not_understood} which the transmitter declared critical "
                "and this receiver does not understand",
            )

    def _start_renewal(self, token: EventToken, claim: JtiClaim) -> _ClaimRenewal:
        renewal = _ClaimRenewal(claim, owned=claim.is_granted or self._dedup is None)
        interval = self._options.claim_renewal
        if self._dedup is None or not claim.is_granted or interval is None or interval <= timedelta(0):
            return renewal
        renewal.task = asyncio.create_task(
            self._renew(self._dedup, token, renewal, interval.total_seconds()),
            name=f"easyssf-claim-renewal-{token.jti}",
        )
        return renewal

    async def _renew(self, dedup: JtiDedupStore, token: EventToken, renewal: _ClaimRenewal, interval: float) -> None:
        while True:
            await asyncio.sleep(interval)
            try:
                renewed = await dedup.renew(token, renewal.claim)
            except Exception as error:  # a failed renewal is tried again
                self._log.warning("Could not renew the claim of a SET: %s", error, extra={"jti": token.jti})
                continue
            if renewed is None:
                self._log.warning(
                    "The claim of a SET was taken over by another instance while its handlers ran",
                    extra={"jti": token.jti},
                )
                renewal.owned = False
                return
            renewal.claim = renewed

    def __repr__(self) -> str:
        return f"Processor(verifier={self._verifier!r}, handlers={len(self._handlers)})"


class _ClaimRenewal:
    """Renews a claim in the background while the handlers run."""

    __slots__ = ("claim", "owned", "task")

    def __init__(self, claim: JtiClaim, owned: bool) -> None:
        self.claim = claim
        self.owned = owned
        self.task: asyncio.Task[None] | None = None

    async def stop(self) -> tuple[JtiClaim, bool]:
        """Ends the renewal and returns the claim as last renewed and whether it is still owned."""
        if self.task is not None:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                # the renewal's own cancellation; a cancellation of the caller is raised again
                current = asyncio.current_task()
                if current is not None and current.cancelling():
                    raise
            self.task = None
        return self.claim, self.owned
