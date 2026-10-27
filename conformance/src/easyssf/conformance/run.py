"""One test run of the receiver under test and the runner that keeps the current one; the port of
``run.go``.

A :class:`Run` is a receiver assembled by hand from the parts of ``easyssf.receiver`` that creates
its stream at the emulated transmitter, plays the operations of its :class:`~.scenario.Scenario`,
accepts the events the transmitter delivers and deletes the stream once no more arrive. Every run
has its own receiver (keys, access token, de-duplication), since every test of the suite emulates
a new transmitter under the same issuer.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import httpx

from easyssf.core import (
    DeliveryMethod,
    EventToken,
    EventTypes,
    StreamConfiguration,
    StreamStatusValue,
    event_types,
    string_member,
)
from easyssf.receiver import (
    JWK_SET_ACCEPT,
    BearerToken,
    ClientCredentialsOptions,
    ClientCredentialsTokenProvider,
    Endpoint,
    EventContext,
    FixedToken,
    HttpJwkSetSource,
    InMemoryJtiDedupStore,
    IssuerMismatchError,
    JwtVerifier,
    MetadataResolver,
    Poller,
    PollerOptions,
    Processor,
    ProcessorOptions,
    PushHandler,
    PushResponse,
    RejectedError,
    StreamClient,
    StreamVerification,
    TokenProvider,
    TransmitterUnavailableError,
    UriPolicy,
    VerifierOptions,
    get_json,
    unverified_payload,
)

from .receiver_settings import AuthMode, ReceiverSettings
from .scenario import RunStatus, Scenario

__all__ = ["LogEntry", "ReceivedSet", "Run", "RunStatus", "Runner"]

_log: Final = logging.getLogger("easyssf.conformance")
_CALL_TIMEOUT: Final = timedelta(seconds=30)
_DEDUP_CAPACITY: Final = 10_000
_IDLE_POLL: Final = 0.5
_VERIFICATION_POLL: Final = 0.2
_VERIFICATION_ATTEMPTS: Final = 3
_PAUSE: Final = 3.0
_DELETE_TIMEOUT: Final = 30.0


@dataclass(frozen=True, slots=True)
class LogEntry:
    """A line of the log of a run."""

    time: datetime
    message: str

    def to_mapping(self) -> dict[str, Any]:
        """The entry as the API shows it."""
        return {"time": self.time.isoformat(), "message": self.message}


@dataclass(frozen=True, slots=True)
class ReceivedSet:
    """A SET a run received, and what became of it."""

    time: datetime
    jti: str
    events: tuple[str, ...]
    """The aliases of the event types, sorted."""
    outcome: str
    """``accepted``, or ``rejected with <code>: <description>``."""

    def to_mapping(self) -> dict[str, Any]:
        """The SET as the API shows it."""
        return {"time": self.time.isoformat(), "jti": self.jti, "events": list(self.events), "outcome": self.outcome}


class _LazyClientCredentials:
    """Obtains tokens at the token endpoint of the emulated authorization server, which lives
    next to the transmitter (``<issuer>/token``); it is looked up with the first call, so that a
    run can start while the suite is down. A ``TokenProvider`` and ``TokenInvalidator``."""

    def __init__(self, run: Run, client: httpx.AsyncClient) -> None:
        self._run = run
        self._client = client
        self._delegate: ClientCredentialsTokenProvider | None = None

    async def access_token(self) -> str:
        if self._delegate is None:
            metadata = await self._run.metadata_resolver.resolve()
            auth = self._run.settings.auth
            options = ClientCredentialsOptions(
                scopes=tuple(auth.scopes),
                authenticate_with_request_body=auth.authenticate_with_request_body,
                timeout=_CALL_TIMEOUT,
            )
            self._delegate = ClientCredentialsTokenProvider(
                self._client, metadata.issuer + "/token", auth.client_id, auth.client_secret, options
            )
        return await self._delegate.access_token()

    def invalidate(self) -> None:
        if self._delegate is not None:
            self._delegate.invalidate()

    def __repr__(self) -> str:
        return "LazyClientCredentials(...)"


class _RecordingVerifier:
    """Records the SETs the verifier rejects."""

    def __init__(self, run: Run, verifier: JwtVerifier) -> None:
        self._run = run
        self._verifier = verifier

    async def verify(self, encoded_set: str) -> EventToken:
        try:
            return await self._verifier.verify(encoded_set)
        except RejectedError as rejected:
            jti = string_member(unverified_payload(encoded_set), "jti") or "?"
            self._run._record(jti, (), f"rejected with {rejected.code}: {rejected.description}")
            raise


class Run:
    """One test run, see the module documentation. Build it with :meth:`Runner.start`, or directly
    and :meth:`start` it.

    Args:
        id: the id of the run.
        scenario: the scenario to play.
        issuer: the issuer of the emulated transmitter, the test instance of the suite.
        delivery: the delivery method to ask for.
        settings: the settings of the receiver under test.
        client: the client the suite is called with; it has to trust the suite's certificate.
        logger: where the run logs; ``easyssf.conformance`` by default.

    Raises:
        UriPolicyError: if the issuer is not an https URL.
    """

    def __init__(
        self,
        id: str,
        scenario: Scenario,
        issuer: str,
        delivery: DeliveryMethod,
        *,
        settings: ReceiverSettings,
        client: httpx.AsyncClient,
        logger: logging.Logger | None = None,
    ) -> None:
        self._id = id
        self._scenario = scenario
        self._issuer = issuer
        self._delivery = delivery
        self._settings = settings
        self._log = logging.LoggerAdapter(logger if logger is not None else _log, {"run": id})
        self._started_at = datetime.now(tz=UTC)
        self._started_monotonic = time.monotonic()
        self._last_activity = self._started_monotonic
        self._idle_timeout = settings.idle_timeout
        self._status = RunStatus.STARTING
        self._stream: StreamConfiguration | None = None
        self._stream_deleted = False
        self._entries: list[LogEntry] = []
        self._received: list[ReceivedSet] = []
        self._verified = 0
        self._rejected = 0
        self._task: asyncio.Task[None] | None = None

        policy = UriPolicy()
        self._metadata = MetadataResolver(issuer, None, client, policy, self._log.logger, timeout=_CALL_TIMEOUT)
        tokens = self._token_provider(client)
        self._streams = StreamClient(self._metadata, client, BearerToken(tokens), timeout=_CALL_TIMEOUT)
        self._verification = StreamVerification(lambda: self.stream_id, logger=self._log.logger)
        metadata = self._metadata

        async def resolve_jwks_url() -> str:
            resolved = await metadata.resolve()
            if not resolved.jwks_uri:
                raise TransmitterUnavailableError(None, "the transmitter metadata has no jwks_uri")
            return resolved.jwks_uri

        async def fetch_keys(url: str) -> bytes:
            return await get_json(
                client, url, policy=policy, timeout=_CALL_TIMEOUT, accept=JWK_SET_ACCEPT, endpoint=Endpoint.JWKS
            )

        keys = HttpJwkSetSource(client, resolve_jwks_url, timeout=_CALL_TIMEOUT, fetch=fetch_keys)
        # the audience of the stream once it is created, any before
        options = VerifierOptions(expected_audiences_provider=lambda: self._stream.audience if self._stream else ())
        self._verifier = JwtVerifier(issuer, keys, options)
        self._processor = Processor(
            _RecordingVerifier(self, self._verifier),
            InMemoryJtiDedupStore(_DEDUP_CAPACITY),
            ProcessorOptions(logger=self._log.logger, stream_verifications=lambda _issuer: self._check_verification),
        ).add_handler(self._record_handled_set)
        self._push_header = "Bearer " + base64.urlsafe_b64encode(secrets.token_bytes(24)).rstrip(b"=").decode("ascii")
        self._push = PushHandler(self._processor, self._push_header)
        self._poller: Poller | None = None
        if delivery is DeliveryMethod.POLL:
            poller_options = PollerOptions(
                interval=settings.poll_interval,
                endpoint_retry=min(settings.poll_interval, timedelta(seconds=1)),
                transmitter=issuer,
                timeout=_CALL_TIMEOUT,
                logger=self._log.logger,
            )
            self._poller = Poller(client, BearerToken(tokens), self._poll_endpoint, self._processor, poller_options)

    def _token_provider(self, client: httpx.AsyncClient) -> TokenProvider:
        auth = self._settings.auth
        if auth.mode is AuthMode.STATIC:
            return FixedToken(auth.access_token)
        return _LazyClientCredentials(self, client)

    def _poll_endpoint(self) -> str:
        if self._stream is None or self._stream_deleted:
            return ""
        return self._stream.delivery_endpoint_url

    # -- what the run is ------------------------------------------------------------------------------

    @property
    def id(self) -> str:
        """The id of the run."""
        return self._id

    @property
    def scenario(self) -> Scenario:
        """The scenario the run plays."""
        return self._scenario

    @property
    def issuer(self) -> str:
        """The issuer of the emulated transmitter."""
        return self._issuer

    @property
    def delivery(self) -> DeliveryMethod:
        """The delivery method the run asks for."""
        return self._delivery

    @property
    def settings(self) -> ReceiverSettings:
        """The settings of the receiver under test."""
        return self._settings

    @property
    def started_at(self) -> datetime:
        """When the run started."""
        return self._started_at

    @property
    def status(self) -> RunStatus:
        """Where the run stands."""
        return self._status

    @property
    def stream(self) -> StreamConfiguration | None:
        """The stream of the run, ``None`` before it was created."""
        return self._stream

    @property
    def stream_id(self) -> str:
        """The identifier of the stream, ``""`` before it was created."""
        return self._stream.stream_id if self._stream is not None else ""

    @property
    def log(self) -> list[LogEntry]:
        """What the run did so far; a copy."""
        return list(self._entries)

    @property
    def received_sets(self) -> list[ReceivedSet]:
        """The SETs the run received; a copy."""
        return list(self._received)

    @property
    def is_active(self) -> bool:
        """Whether the run is starting or running."""
        return self._status.is_active

    @property
    def push_authorization_header(self) -> str:
        """The ``Authorization`` header the transmitter has to send to the push endpoint for this
        run, registered with the stream."""
        return self._push_header

    @property
    def push_handler(self) -> PushHandler:
        """The push handler of this run; :meth:`push` goes through it."""
        return self._push

    @property
    def metadata_resolver(self) -> MetadataResolver:
        """The metadata of the emulated transmitter."""
        return self._metadata

    @property
    def idle_timeout(self) -> timedelta:
        """How long the run waits for further events before it deletes the stream."""
        return self._idle_timeout

    def set_idle_timeout(self, timeout: timedelta) -> None:
        """Overrides the idle timeout of the settings for this run, before :meth:`start`."""
        self._idle_timeout = timeout

    # -- running --------------------------------------------------------------------------------------

    def start(self) -> None:
        """Starts the run in a task of its own; a second call does nothing."""
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._run(), name=f"easyssf-conformance-run-{self._id}")

    async def stop(self) -> None:
        """Ends the run: the stream is deleted. Returns once the run ended."""
        task = self._task
        if task is None:
            return
        if not task.done():
            task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def wait(self) -> None:
        """Returns once the run ended."""
        task = self._task
        if task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await task

    async def push(self, authorization_header: str | None, body: bytes) -> PushResponse:
        """Handles a SET the transmitter pushed to this run."""
        self._touch()
        return await self._push.handle(authorization_header, body)

    def _touch(self) -> None:
        self._last_activity = time.monotonic()

    async def _run(self) -> None:
        self._status = RunStatus.RUNNING
        try:
            await self._execute()
            final = RunStatus.FINISHED if self._status is RunStatus.RUNNING else self._status
        except asyncio.CancelledError:
            # the cleanup below must not be cancelled with the run
            current = asyncio.current_task()
            if current is not None:
                current.uncancel()
            self._logf("Run stopped")
            final = RunStatus.STOPPED
        except Exception as error:  # the run reports every failure as its outcome
            self._logf(f"Run failed: {error}")
            self._log.error("Conformance run failed", exc_info=error)
            final = RunStatus.FAILED
        if self._poller is not None:
            await self._poller.stop()
        await self._delete_stream()
        # the run stays active until its stream is gone, so that whoever sees it end sees that too
        self._status = final

    async def _execute(self) -> None:
        self._logf(f"Scenario {self._scenario} with {self._delivery} delivery against {self._issuer}")
        metadata = await self._metadata.resolve()
        self._logf(
            f"Transmitter metadata: jwks_uri {metadata.jwks_uri}, "
            f"configuration_endpoint {metadata.configuration_endpoint}"
        )
        desired = self._desired_stream(f"easyssf conformance run {self._id}")
        try:
            stream = await self._streams.create_stream(desired)
        except IssuerMismatchError as mismatch:
            self._logf(f"Refusing the stream: {mismatch}")
            self._stream = mismatch.stream
            await self._delete_stream()
            self._status = RunStatus.REFUSED_STREAM
            return
        self._stream = stream
        self._logf(
            f"Created stream {stream.stream_id}: audience {stream.audience}, delivery {stream.delivery_method_uri} "
            f"{stream.delivery_endpoint_url}, events delivered {_aliases(stream.events_delivered)}"
        )
        if self._poller is not None:
            await self._poller.start()
        if self._scenario is Scenario.CREATE_DELETE:
            return
        read = await self._streams.stream(stream.stream_id)
        self._logf(f"Read stream configuration: events requested {_aliases(read.events_requested)}")
        status = await self._streams.status(stream.stream_id)
        self._logf(f"Read stream status: {status.status}")
        if self._scenario is Scenario.STREAM_MANAGEMENT:
            updated = await self._streams.update_stream(
                stream.stream_id, {"description": desired.description + " (updated)"}
            )
            self._logf(f"Updated stream: description '{updated.description}'")
            replaced = await self._streams.replace_stream(
                stream.stream_id, self._desired_stream(desired.description + " (replaced)")
            )
            self._logf(f"Replaced stream: description '{replaced.description}'")
        await self._verify_stream()
        if self._scenario is Scenario.STATUS_UPDATE:
            paused = await self._streams.update_status(stream.stream_id, StreamStatusValue.PAUSED, "conformance run")
            self._logf(f"Pausing the stream: {paused.status}")
            await asyncio.sleep(_PAUSE)
            enabled = await self._streams.update_status(stream.stream_id, StreamStatusValue.ENABLED, "conformance run")
            self._logf(f"Enabling the stream: {enabled.status}")
        if self._scenario is Scenario.REMOVE_SUBJECT:
            await self._streams.remove_subject(stream.stream_id, self._settings.subject_to_remove)
            self._logf(f"Removed subject {self._settings.subject_to_remove} from the stream")
        idle = self._idle_timeout
        self._logf(f"Accepting events until none arrived for {idle}")
        phase_start = time.monotonic()
        while True:
            await asyncio.sleep(_IDLE_POLL)
            now = time.monotonic()
            latest = max(self._last_activity, phase_start)
            if now - latest > idle.total_seconds():
                self._logf(f"No event for {idle}")
                return
            if now - self._started_monotonic > self._settings.max_duration.total_seconds():
                self._logf("Maximum run duration reached")
                return

    async def _verify_stream(self) -> None:
        """Asks for a verification event and waits for it, requesting again after a rejected one,
        at most three times; without any event it goes on."""
        timeout = self._settings.verification_timeout.total_seconds()
        for _attempt in range(_VERIFICATION_ATTEMPTS):
            verified_before, rejected_before = self._verified, self._rejected
            state = await self._verification.request_verification(self._streams, self.stream_id)
            self._logf(f"Requested stream verification with state {state}")
            deadline = time.monotonic() + timeout
            rejected_again = False
            while time.monotonic() < deadline:
                if self._verified > verified_before:
                    return
                if self._rejected > rejected_before:
                    self._logf("Rejected a verification event, requesting the verification again")
                    rejected_again = True
                    break
                await asyncio.sleep(_VERIFICATION_POLL)
            if not rejected_again:
                self._logf(f"No verification event within {self._settings.verification_timeout}, going on without it")
                return

    def _desired_stream(self, description: str) -> StreamConfiguration:
        if self._delivery is DeliveryMethod.POLL:
            return StreamConfiguration.poll(self._settings.events_requested, description)
        return StreamConfiguration.push(
            self._settings.push_url, self._push_header, self._settings.events_requested, description
        )

    async def _delete_stream(self) -> None:
        stream_id = self.stream_id
        if not stream_id or self._stream_deleted:
            return
        self._stream_deleted = True
        try:
            async with asyncio.timeout(_DELETE_TIMEOUT):
                await self._streams.delete_stream(stream_id)
        except Exception as error:  # reported in the log of the run, the run itself is over
            self._logf(f"Could not delete stream {stream_id}: {error}")
            return
        self._logf(f"Deleted stream {stream_id}")

    # -- what arrives -----------------------------------------------------------------------------------

    def _check_verification(self, event: EventContext) -> None:
        try:
            self._verification.check(event)
        except RejectedError as rejected:
            self._rejected += 1
            self._record(
                event.event_token.jti,
                ("SsfStreamVerification",),
                f"rejected with {rejected.code}: {rejected.description}",
            )
            raise

    async def _record_handled_set(self, event: EventContext) -> None:
        token = event.event_token
        if event.has_event(EventTypes.SSF_STREAM_VERIFICATION):
            payload = event.event(EventTypes.SSF_STREAM_VERIFICATION) or {}
            state = payload.get("state")
            described = f"state {state}" if state is not None else "no state (initiated by the transmitter)"
            self._logf(f"Verification event {token.jti} accepted, {described}")
            self._verified += 1
        self._record(token.jti, tuple(_aliases(event.event_types)), "accepted")

    def _record(self, jti: str, events: tuple[str, ...], outcome: str) -> None:
        self._touch()
        now = datetime.now(tz=UTC)
        self._received.append(ReceivedSet(now, jti, events, outcome))
        self._logf(f"SET {jti} {list(events)}: {outcome}")

    def _logf(self, message: str) -> None:
        self._entries.append(LogEntry(datetime.now(tz=UTC), message))
        self._log.info(message)

    def __repr__(self) -> str:
        return f"Run(id={self._id!r}, scenario={self._scenario}, status={self._status}, stream={self.stream_id!r})"


def _aliases(uris: list[str]) -> list[str]:
    return sorted(event_types.alias_of(uri) for uri in uris)


class Runner:
    """Starts and keeps the current :class:`Run`. There is at most one run at a time, since the
    suite's tests run one after another and the push endpoint belongs to the current run.

    Args:
        settings: the settings of the receiver under test.
        client: the client the suite is called with; it has to trust the suite's certificate.
        logger: where the runs log; ``easyssf.conformance`` by default.
    """

    def __init__(
        self, settings: ReceiverSettings, client: httpx.AsyncClient, logger: logging.Logger | None = None
    ) -> None:
        self._settings = settings
        self._client = client
        self._log = logger
        self._ids = 0
        self._current: Run | None = None

    @property
    def settings(self) -> ReceiverSettings:
        """The settings of the receiver under test."""
        return self._settings

    @property
    def current(self) -> Run | None:
        """The current run, ``None`` if none was started yet."""
        return self._current

    async def start(
        self,
        scenario: Scenario,
        issuer: str = "",
        delivery: DeliveryMethod | None = None,
        idle_timeout: timedelta | None = None,
    ) -> Run:
        """Starts a run, stopping the current one if it is still active. ``issuer`` is the issuer
        of the emulated transmitter, ``""`` for the configured one; ``delivery`` ``None`` for the
        configured one; ``idle_timeout`` ``None`` for the configured one.

        Raises:
            ValueError: if no issuer is given and none is configured, or the issuer is not an
                https URL.
        """
        if not issuer:
            issuer = self._settings.issuer
            if not issuer:
                raise ValueError("the transmitter issuer must be set when no issuer is given for the run")
        if delivery is None:
            delivery = self._settings.delivery
        if self._current is not None and self._current.is_active:
            await self._current.stop()
        self._ids += 1
        run = Run(
            str(self._ids), scenario, issuer, delivery, settings=self._settings, client=self._client, logger=self._log
        )
        if idle_timeout is not None and idle_timeout > timedelta(0):
            run.set_idle_timeout(idle_timeout)
        self._current = run
        run.start()
        return run

    def __repr__(self) -> str:
        return f"Runner(current={self._current!r})"
