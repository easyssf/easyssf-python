"""Poll delivery (RFC 8936): the poller and the acknowledgements it owes the transmitter; a port
of ``receiver/poll.go`` of the Go port and of ``org.easyssf.receiver.poll``.

A :class:`Poller` fetches SETs from the poll endpoint of the stream, hands them to the
:class:`~easyssf.receiver.processor.Processor` and acknowledges them with the next request. The
acknowledgements wait in a :class:`PollAckStore` until a request carried them, so that a SET the
transmitter was never told about is delivered again.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any, Final, Protocol, TypeAlias

import httpx

from easyssf.core import Claims, DeliveryMethod, object_member

from .authorizer import Authorizer, BearerToken, Endpoint, RetryOptions
from .config import PollConfig
from .errors import Clock, EasyssfError, InProgressError, RejectedError, system_clock
from .metrics import Metrics, NoopMetrics
from .processor import Processor
from .transmitter import LONG_POLL_MARGIN, HttpResponse, TokenProvider, UriPolicy, exchange

__all__ = [
    "InMemoryPollAckStore",
    "PendingAck",
    "PollAckStore",
    "PollEndpoint",
    "PollError",
    "Poller",
    "PollerOptions",
    "default_poller_options",
    "fixed_poll_endpoint",
]

_log: Final = logging.getLogger("easyssf.receiver.poll")

_MAX_REQUESTS_PER_POLL: Final = 100
"""How many requests one poll sends at most while the transmitter reports ``moreAvailable``."""
_MIN_HOLD: Final = timedelta(seconds=1)
"""A long poll that comes back empty faster than this was not held: the transmitter does not
support long polling, and the poller waits the interval before the next request."""


@dataclass(frozen=True, slots=True)
class PendingAck:
    """What the poller owes the transmitter for a SET it fetched (RFC 8936, section 2.2): an
    acknowledgement that the SET was received and handled, or an error that it was rejected,
    which goes into the ``setErrs`` member of the next poll request. Build one with :meth:`ack`
    or :meth:`ack_error`."""

    jti: str
    """The identifier of the SET."""
    error: str = ""
    """The error code of a rejected SET (``invalid_request``, ...), ``""`` for an
    acknowledgement."""
    description: str = ""
    """Describes the error."""

    @classmethod
    def ack(cls, jti: str) -> PendingAck:
        """The acknowledgement of a handled SET."""
        return cls(jti)

    @classmethod
    def ack_error(cls, jti: str, code: str, description: str) -> PendingAck:
        """The report of a rejected SET."""
        return cls(jti, code, description)

    @property
    def is_error(self) -> bool:
        """Whether this reports an error rather than acknowledging the SET."""
        return self.error != ""


class PollAckStore(Protocol):
    """Keeps the acknowledgements and error reports the poller owes a transmitter until a poll
    request has carried them (RFC 8936, section 2.4: they ride on the next request). The
    :class:`InMemoryPollAckStore` loses them when the application stops, so a SET handled but not
    yet acknowledged is delivered again after a restart and skipped as a duplicate. A durable
    implementation, such as the store of ``easyssf-receiver-sqlalchemy``, acknowledges it with the
    first poll after the restart instead.

    Entries are kept per transmitter, identified by its issuer, because a ``jti`` is only unique
    per issuer and a store may serve several transmitters.
    """

    async def record(self, issuer: str, ack: PendingAck) -> None:
        """Records an acknowledgement or error report. Recording the same ``jti`` again does
        nothing."""
        ...

    async def pending(self, issuer: str, limit: int) -> list[PendingAck]:
        """Lists the acknowledgements and error reports waiting for the transmitter, oldest first,
        at most ``limit``; a negative limit lists all."""
        ...

    async def remove(self, issuer: str, jtis: Sequence[str]) -> None:
        """Removes entries the transmitter has received; a ``jti`` that is not waiting is ignored."""
        ...

    async def size(self, issuer: str) -> int:
        """The number of entries waiting for the transmitter."""
        ...


class InMemoryPollAckStore:
    """A :class:`PollAckStore` that keeps the pending acknowledgements in memory, in the order
    they were recorded. Lost when the application stops; the default of the poller. The methods
    do not await anything, so they are atomic on the event loop."""

    __slots__ = ("_pending",)

    def __init__(self) -> None:
        self._pending: dict[str, list[PendingAck]] = {}

    async def record(self, issuer: str, ack: PendingAck) -> None:
        """Records the acknowledgement unless one with its ``jti`` is waiting already."""
        acks = self._pending.setdefault(issuer, [])
        if any(existing.jti == ack.jti for existing in acks):
            return
        acks.append(ack)

    async def pending(self, issuer: str, limit: int) -> list[PendingAck]:
        """The waiting acknowledgements, oldest first, at most ``limit``."""
        acks = self._pending.get(issuer, [])
        if 0 <= limit < len(acks):
            acks = acks[:limit]
        return list(acks)

    async def remove(self, issuer: str, jtis: Sequence[str]) -> None:
        """Removes the acknowledgements with the given ``jti``."""
        removed = set(jtis)
        if issuer in self._pending:
            self._pending[issuer] = [ack for ack in self._pending[issuer] if ack.jti not in removed]

    async def size(self, issuer: str) -> int:
        """The number of waiting acknowledgements."""
        return len(self._pending.get(issuer, []))

    def __repr__(self) -> str:
        sizes = {issuer: len(acks) for issuer, acks in self._pending.items()}
        return f"InMemoryPollAckStore({sizes!r})"


PollEndpoint: TypeAlias = Callable[[], str]
"""Supplies the poll endpoint, ``""`` as long as it is not known: the stream is still being
registered."""


def fixed_poll_endpoint(url: str) -> PollEndpoint:
    """A :data:`PollEndpoint` that is known in advance."""
    return lambda: url


@dataclass(frozen=True, slots=True)
class PollerOptions:
    """How a :class:`Poller` polls. Read when the poller works. Start from
    :func:`default_poller_options` or :meth:`from_config` and ``dataclasses.replace`` what differs."""

    ack_store: PollAckStore | None = None
    """Keeps the acknowledgements until a poll request carried them; an
    :class:`InMemoryPollAckStore` by default."""
    policy: UriPolicy = field(default_factory=UriPolicy)
    """Checks the poll endpoint of the stream and decides which redirects are followed; the strict
    one (https, or http on loopback) by default."""
    max_ack_batch: int = 1000
    """The most acknowledgements and error reports one request carries, the rest goes with the
    next one; 1000 by default."""
    metrics: Metrics | None = None
    """Records the polls. Nothing by default."""
    interval: timedelta = timedelta(seconds=30)
    """The time between two polls, 30 seconds by default. With long polling, the pause after a
    failed request or after a transmitter answered an empty long poll at once."""
    initial_delay: timedelta = timedelta(0)
    """How long :meth:`Poller.start` waits before the first poll, nothing by default."""
    endpoint_retry: timedelta = timedelta(seconds=1)
    """How soon the poller looks again while the poll endpoint of the stream is not known yet,
    one second by default; never longer than the interval."""
    long_polling_hold: timedelta = timedelta(0)
    """Switches to long polling (RFC 8936, section 2.5) when positive: the first request of a poll
    asks the transmitter to hold it until SETs are available (``returnImmediately: false``), and a
    running poller sends the next request as soon as a response was handled. The value is how long
    the transmitter holds a request, part of the agreement with it (section 2.2); the request waits
    that long plus :data:`~easyssf.receiver.transmitter.LONG_POLL_MARGIN` for the response. Zero,
    the default, is short polling."""
    flush_on_stop: bool = True
    """Whether :meth:`Poller.stop` sends the pending acknowledgements with a last request, so that
    the transmitter does not deliver the SETs again after a restart; ``True`` by default."""
    max_events: int = 100
    """The maximum number of SETs fetched with one request, 100 by default."""
    transmitter: str = ""
    """The issuer of the transmitter that is polled, for the metrics and as the key of its
    acknowledgements in the :attr:`ack_store`; the poll endpoint if ``""``."""
    rate_limit_fallback: timedelta = timedelta(0)
    """How long to pause polling after a 429 Too Many Requests without a ``Retry-After`` header;
    zero, the default, polls again at the regular interval."""
    max_pause: timedelta = timedelta(minutes=5)
    """The longest pause a ``Retry-After`` header or the rate limit fallback can cause, 5 minutes
    by default."""
    timeout: timedelta | None = None
    """How long a request that is answered immediately waits for the response;
    :data:`~easyssf.receiver.transmitter.DEFAULT_HTTP_TIMEOUT` if ``None``."""
    clock: Clock = system_clock
    """The clock the pauses the transmitter asks for are measured by."""
    logger: logging.Logger | None = None
    """Where the poller logs; ``easyssf.receiver.poll`` if ``None``."""

    @classmethod
    def from_config(cls, config: PollConfig) -> PollerOptions:
        """The options of a :class:`~easyssf.receiver.config.PollConfig`: the interval, the
        initial delay, the SETs per request, the long polling hold if long polling is on, and the
        rate limit fallback and maximum pause. The rest keeps its default."""
        return replace(
            default_poller_options(),
            interval=config.interval,
            initial_delay=config.initial_delay,
            max_events=config.max_events,
            long_polling_hold=config.long_polling_hold if config.long_polling else timedelta(0),
            rate_limit_fallback=config.rate_limit.fallback_backoff,
            max_pause=config.rate_limit.max_backoff,
        )

    @property
    def is_long_polling(self) -> bool:
        """Whether the options ask for long polling."""
        return self.long_polling_hold > timedelta(0)


def default_poller_options() -> PollerOptions:
    """The defaults: short polling every 30 seconds, 100 SETs and 1000 acknowledgements per
    request, a flush on stop, pauses of at most 5 minutes."""
    return PollerOptions()


class PollError(EasyssfError):
    """A poll request failed.

    Args:
        message: what failed.
        cause: the underlying error, ``None`` if the transmitter answered with an error status.
    """

    def __init__(self, message: str, cause: BaseException | None = None) -> None:
        super().__init__(message)
        self.message = message
        """What failed."""
        self.cause = cause
        """The underlying error, ``None`` if there is none."""
        self.__cause__ = cause

    def __str__(self) -> str:
        """The message, followed by the cause if there is one."""
        if self.cause is not None:
            return f"{self.message}: {self.cause}"
        return self.message


@dataclass(frozen=True, slots=True)
class _PollResult:
    fetched: int = 0
    skipped: bool = False
    endpoint_unknown: bool = False


class Poller:
    """Fetches SETs from the poll endpoint of the transmitter (RFC 8936).

    A SET is acknowledged once it was handled. An invalid SET is reported as an error to the
    transmitter. A SET that could not be handled is neither acknowledged nor reported, the
    transmitter delivers it again with a later poll. Acknowledgements and error reports ride on
    the next poll request (section 2.4) and wait in the :class:`PollAckStore` until that request
    succeeded.

    By default the poller polls at a fixed interval and asks the transmitter to answer right away
    (``returnImmediately: true``, short polling). With long polling
    (:attr:`PollerOptions.long_polling_hold`) it keeps one request outstanding instead. A backlog
    is fetched with immediate requests in both modes.

    Until the poll endpoint of the stream is known, typically because the
    :class:`~easyssf.receiver.stream.StreamRegistrar` is still registering the stream when the
    poller starts, the poller looks again every :attr:`PollerOptions.endpoint_retry` rather than
    waiting the interval. :meth:`wake_up` ends the pause between two polls altogether;
    :meth:`~easyssf.receiver.transmitter.Transmitter.start` arranges for it when the stream is
    registered, so that the first poll follows the registration at once.

    Poll requests are not retried: the poller has its interval, and a 429 or 503 pauses it.

    Args:
        client: the client the transmitter is called with.
        authorizer: authorizes the requests: an :class:`~easyssf.receiver.authorizer.Authorizer`,
            a :class:`~easyssf.receiver.transmitter.TokenProvider` sent as bearer token, or
            ``None`` for no authorization.
        endpoint: supplies the poll endpoint, ``""`` as long as it is not known.
        processor: processes the SETs.
        options: how the poller polls; :func:`default_poller_options` if ``None``.

    Raises:
        ValueError: if an option is out of range: interval, max events, max ack batch, max pause
            and endpoint retry must be positive, the long polling hold not negative.
    """

    def __init__(
        self,
        client: httpx.AsyncClient,
        authorizer: Authorizer | TokenProvider | None,
        endpoint: PollEndpoint,
        processor: Processor,
        options: PollerOptions | None = None,
    ) -> None:
        options = options if options is not None else default_poller_options()
        if (
            options.interval <= timedelta(0)
            or options.max_events <= 0
            or options.max_ack_batch <= 0
            or options.max_pause <= timedelta(0)
            or options.endpoint_retry <= timedelta(0)
        ):
            raise ValueError(
                "PollerOptions interval, max events, max ack batch, max pause and endpoint retry must be positive"
            )
        if options.long_polling_hold < timedelta(0):
            raise ValueError("PollerOptions.long_polling_hold must not be negative")
        self._options = replace(
            options,
            ack_store=options.ack_store if options.ack_store is not None else InMemoryPollAckStore(),
            metrics=options.metrics if options.metrics is not None else NoopMetrics(),
        )
        assert self._options.ack_store is not None and self._options.metrics is not None
        self._store: PollAckStore = self._options.ack_store
        self._metrics: Metrics = self._options.metrics
        self._log = options.logger if options.logger is not None else _log
        self._client = client
        self._authorizer = BearerToken(authorizer)
        self._endpoint = endpoint
        self._processor = processor
        self._polling = asyncio.Lock()  # held while a poll runs
        self._wake = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._paused_until: datetime | None = None
        self._last_poll_at: datetime | None = None
        self._last_successful_poll_at: datetime | None = None
        self._last_poll_error = ""

    @property
    def options(self) -> PollerOptions:
        """How the poller polls, with the defaults filled in."""
        return self._options

    @property
    def is_long_polling(self) -> bool:
        """Whether the poller long polls."""
        return self._options.is_long_polling

    async def start(self) -> None:
        """Starts polling the transmitter in a task of its own: periodically, or with one request
        always outstanding when long polling, until :meth:`stop` is called. Without it, SETs are
        only fetched by calling :meth:`poll_now`. Calling it again while running has no effect;
        once the task ended, :meth:`start` starts it again."""
        if self.is_running:
            return
        self._task = asyncio.create_task(self._run(), name="easyssf-poller")

    async def stop(self) -> None:
        """Stops polling: ends the polling task, cancelling an outstanding long poll, and sends
        the pending acknowledgements with a last request unless :attr:`PollerOptions.flush_on_stop`
        says otherwise. The acknowledgements are sent also when the task ended before."""
        task, self._task = self._task, None
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        if self._options.flush_on_stop:
            await self._flush_acks()

    @property
    def is_running(self) -> bool:
        """Whether the polling task runs."""
        return self._task is not None and not self._task.done()

    def wake_up(self) -> None:
        """Ends the pause between two polls, so that the next poll runs now, on the poller's task
        and with its error handling. Does nothing while the poller is not running;
        :meth:`poll_now` polls on the caller's task regardless."""
        if self.is_running:
            self._wake.set()

    @property
    def last_poll_at(self) -> datetime | None:
        """When the transmitter was last polled, ``None`` if it was not polled yet."""
        return self._last_poll_at

    @property
    def last_successful_poll_at(self) -> datetime | None:
        """When the transmitter was last polled successfully, ``None`` if never."""
        return self._last_successful_poll_at

    @property
    def last_poll_error(self) -> str:
        """Why the last poll failed, ``""`` if it succeeded or none was made yet."""
        return self._last_poll_error

    @property
    def paused_until(self) -> datetime | None:
        """Until when the transmitter asked not to be polled, ``None`` if it did not or the pause
        is over."""
        if self._paused_until is not None and self._paused_until > self._options.clock():
            return self._paused_until
        return None

    async def pending_ack_count(self) -> int:
        """The number of acknowledgements and error reports waiting for the next poll request;
        0 if the store cannot tell."""
        key = self._ack_key()
        if not key:
            return 0
        try:
            return await self._store.size(key)
        except Exception:  # a store that cannot be read owes nothing it can tell of
            return 0

    async def poll_now(self) -> int:
        """Fetches and processes the SETs that are available at the transmitter and acknowledges
        them, with the request answered immediately whether or not long polling is on. One poll
        runs at a time: a call while another is in progress returns right away.

        Returns the number of SETs fetched, 0 as well if the poll endpoint is not known yet, the
        transmitter asked to slow down or a poll is in progress.

        Raises:
            PollError: if a poll request failed.
            UriPolicyError: if the poll endpoint is not acceptable to the policy.
        """
        if self._polling.locked():
            self._log.debug("Not polling, a poll is in progress")
            return 0
        async with self._polling:
            result = await self._poll(False)
        return result.fetched

    async def _run(self) -> None:
        options = self._options
        try:
            if options.initial_delay > timedelta(0):
                await asyncio.sleep(options.initial_delay.total_seconds())
            while True:
                # a wake-up that arrived before this poll is used up by it; one that arrives during
                # the poll ends the pause after it
                self._wake.clear()
                started = time.monotonic()
                result, error = await self._poll_locked()
                pause = options.interval
                if error is not None:
                    self._log.warning("Could not poll the SSF transmitter: %s", error, extra={"error": error})
                elif result.endpoint_unknown:
                    # the stream is still being registered: look again soon
                    pause = min(options.endpoint_retry, options.interval)
                elif result.skipped:
                    pause = self._pause_while_skipped()
                elif self.is_long_polling:
                    held = result.fetched > 0 or time.monotonic() - started >= _MIN_HOLD.total_seconds()
                    if held:
                        pause = timedelta(0)
                if pause > timedelta(0):
                    with contextlib.suppress(TimeoutError):
                        await asyncio.wait_for(self._wake.wait(), pause.total_seconds())
        finally:
            # the task clears its own handle when it ends, so that is_running tells the truth and
            # start works again; not when stop took the handle already
            if self._task is asyncio.current_task():
                self._task = None

    async def _poll_locked(self) -> tuple[_PollResult, Exception | None]:
        if self._polling.locked():
            return _PollResult(skipped=True), None
        async with self._polling:
            try:
                return await self._poll(self.is_long_polling), None
            except Exception as error:  # reported, the next poll tries again
                return _PollResult(), error

    def _pause_while_skipped(self) -> timedelta:
        until = self.paused_until
        if until is not None:
            until_resume = until - self._options.clock()
            if until_resume > self._options.interval:
                return until_resume
        return self._options.interval

    async def _poll(self, hold: bool) -> _PollResult:
        endpoint = self._endpoint()
        if not endpoint:
            self._log.debug("Not polling, the poll endpoint of the SSF stream is not known yet")
            return _PollResult(skipped=True, endpoint_unknown=True)
        # the endpoint of a registered stream comes from the transmitter: checked like a configured
        # one, the receiver's token must not go to http
        self._options.policy.check_endpoint(endpoint, "the poll endpoint of the SSF stream")
        until = self.paused_until
        if until is not None:
            self._log.debug("Not polling, the SSF transmitter asked to wait", extra={"until": until})
            return _PollResult(skipped=True)
        self._last_poll_at = self._options.clock()
        key = self._ack_key_for(endpoint)
        try:
            result = await self._poll_requests(endpoint, key, hold)
        except Exception as error:
            self._last_poll_error = str(error)
            raise
        self._last_successful_poll_at = self._options.clock()
        self._last_poll_error = ""
        return result

    async def _poll_requests(self, endpoint: str, key: str, hold: bool) -> _PollResult:
        fetched = 0
        more_available = True
        request = 0
        while more_available and request < _MAX_REQUESTS_PER_POLL:
            # only the first request of a poll is held, a backlog is fetched right away
            response = await self._request(endpoint, key, self._options.max_events, not (hold and request == 0))
            sets = _sets_of(response)
            for jti, encoded in sets:
                await self._process(key, jti, encoded)
            fetched += len(sets)
            more_available = response.get("moreAvailable") is True and len(sets) > 0
            request += 1
        if not hold and await self._pending_size(key) > 0:
            # acknowledge right away instead of with the next poll; a long poll sends its next
            # request at once anyway
            response = await self._request(endpoint, key, 0, True)
            sets = _sets_of(response)
            for jti, encoded in sets:
                await self._process(key, jti, encoded)
            fetched += len(sets)
        return _PollResult(fetched=fetched)

    async def _pending_size(self, key: str) -> int:
        try:
            return await self._store.size(key)
        except Exception:  # as Go: a store that cannot be read defers to the next poll
            return 0

    async def _process(self, key: str, jti: str, encoded_set: str) -> None:
        ack: PendingAck | None = None
        try:
            await self._processor.process(encoded_set, DeliveryMethod.POLL)
            ack = PendingAck.ack(jti)
        except InProgressError:
            # another instance is on it, the transmitter delivers the SET again
            self._log.debug("Not acknowledging polled SET, another instance is handling it", extra={"jti": jti})
        except Exception as error:  # every failure of a SET is the poller's to report
            rejected = RejectedError.of(error)
            if rejected is not None:
                self._log.warning(
                    "Rejecting polled SET: %s",
                    rejected,
                    extra={"jti": jti, "code": rejected.code, "description": rejected.description},
                )
                ack = PendingAck.ack_error(jti, rejected.code, rejected.description)
            else:
                # not acknowledged, the transmitter delivers the SET again
                self._log.warning("Could not process polled SET: %s", error, extra={"jti": jti, "error": error})
        if ack is None:
            return
        try:
            await self._store.record(key, ack)
        except Exception as error:  # the SET is delivered again
            self._log.warning(
                "Could not record the acknowledgement of the polled SET: %s", error, extra={"jti": jti, "error": error}
            )
        await self._report_pending(key)

    async def _report_pending(self, key: str) -> None:
        try:
            size = await self._store.size(key)
        except Exception:  # nothing to report then
            return
        self._metrics.pending_acks_changed(self._options.transmitter, size)

    async def _request(self, endpoint: str, key: str, max_events: int, return_immediately: bool) -> Claims:
        """Sends one poll request with the pending acknowledgements and returns the parsed
        response body."""
        options = self._options
        try:
            pending = await self._store.pending(key, options.max_ack_batch)
        except Exception as error:
            raise PollError("Could not read the pending acknowledgements", error) from error
        acks: list[str] = []
        errs: dict[str, Claims] = {}
        for ack in pending:
            if ack.is_error:
                report: Claims = {"err": ack.error}
                if ack.description:
                    report["description"] = ack.description
                errs[ack.jti] = report
            else:
                acks.append(ack.jti)
        body: Claims = {"maxEvents": max_events, "returnImmediately": return_immediately}
        if acks:
            body["ack"] = acks
        if errs:
            body["setErrs"] = errs
        timeout = options.timeout
        if not return_immediately and options.is_long_polling:
            timeout = options.long_polling_hold + LONG_POLL_MARGIN
        started = time.monotonic()
        try:
            # not retried: the poller has its interval, and a 429 or 503 pauses it below
            response = await exchange(
                self._client,
                "POST",
                endpoint,
                authorizer=self._authorizer,
                policy=options.policy,
                retry=RetryOptions(),
                timeout=timeout,
                json_body=json.dumps(body, separators=(",", ":")).encode(),
                endpoint=Endpoint.POLL,
            )
        except Exception as error:
            self._metrics.poll_completed(options.transmitter, _since(started), False)
            raise PollError(f"Poll request to {endpoint} failed", error) from error
        if not response.successful:
            self._metrics.poll_completed(options.transmitter, _since(started), False)
            self._pause_if_asked(response)
            raise PollError(f"Poll request to {endpoint} failed with status {response.status}")
        parsed: Claims = {}
        if response.body.strip():
            try:
                value = json.loads(response.body)
            except ValueError as error:
                self._metrics.poll_completed(options.transmitter, _since(started), False)
                raise PollError(f"Poll request to {endpoint} failed: the response is not JSON", error) from error
            if isinstance(value, dict):
                parsed = value
        if pending:
            try:
                await self._store.remove(key, [ack.jti for ack in pending])
            except Exception as error:  # sent again with the next request, the transmitter ignores it
                self._log.warning("Could not remove the delivered acknowledgements: %s", error, extra={"error": error})
            await self._report_pending(key)
        self._metrics.poll_completed(options.transmitter, _since(started), True)
        return parsed

    async def _flush_acks(self) -> None:
        """Sends the pending acknowledgements with a request that asks for no SETs, best effort."""
        endpoint = self._endpoint()
        if not endpoint:
            return
        key = self._ack_key_for(endpoint)
        if await self._pending_size(key) == 0 or self._polling.locked():
            return
        async with self._polling:
            try:
                await self._request(endpoint, key, 0, True)
            except Exception as error:  # best effort
                self._log.debug(
                    "Could not acknowledge the pending SETs before stopping, they are sent with the next poll: %s",
                    error,
                    extra={"error": error},
                )
                return
            self._log.debug("Acknowledged the pending SETs before stopping")

    def _ack_key(self) -> str:
        if self._options.transmitter:
            return self._options.transmitter
        return self._endpoint() or ""

    def _ack_key_for(self, endpoint: str) -> str:
        return self._options.transmitter or endpoint

    def _pause_if_asked(self, response: HttpResponse) -> None:
        """Honours a ``Retry-After`` header in seconds on 429 and 503 (RFC 9110, section 10.2.3),
        and the rate limit fallback on a 429 without one; a date instead of seconds is treated
        like no header."""
        options = self._options
        pause = timedelta(0)
        if response.status in (429, 503):
            value = response.headers.get("Retry-After", "").strip()
            if value.isascii() and value.isdigit():
                pause = timedelta(seconds=int(value))
        if pause == timedelta(0) and response.status == 429:
            pause = options.rate_limit_fallback
        if pause <= timedelta(0):
            return
        pause = min(pause, options.max_pause)
        self._paused_until = options.clock() + pause

    def __repr__(self) -> str:
        mode = "long polling" if self.is_long_polling else "short polling"
        return f"Poller({self._options.transmitter or self._endpoint() or '?'!r}, {mode}, running={self.is_running})"


def _since(started: float) -> timedelta:
    return timedelta(seconds=time.monotonic() - started)


def _sets_of(response: Claims) -> list[tuple[str, str]]:
    """The SETs of a poll response by ``jti``, in the order of their ``jti`` so that the order is
    deterministic."""
    sets = object_member(response, "sets") or {}
    return [(jti, _string_of(sets[jti])) for jti in sorted(sets)]


def _string_of(value: Any) -> str:
    """A JSON value as text: a string as it is, ``None`` as ``""``, anything else as its JSON."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, separators=(",", ":"))
