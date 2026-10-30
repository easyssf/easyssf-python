"""Stream management (SSF 1.0, section 8.1): the client of the management API, the stream of the
receiver, its registration and the verification events; a port of ``receiver/stream.go`` of the
Go port and of ``org.easyssf.receiver.stream``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import secrets
from collections.abc import Callable
from datetime import timedelta
from enum import Enum
from typing import Any, Final
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from easyssf.core import (
    POLL_URI,
    Claims,
    EventTypes,
    Format,
    StreamConfiguration,
    StreamStatus,
    TransmitterMetadata,
    event_types,
    parse_claims,
    string_member,
)

from .authorizer import Authorizer, BearerToken, Endpoint, RetryOptions
from .errors import EasyssfError, ErrorCode, RejectedError, _find
from .event import EventContext
from .transmitter import MetadataResolver, TokenProvider, UriPolicy, exchange

__all__ = [
    "MAX_STREAM_RETRY_DELAY",
    "IssuerMismatchError",
    "ReceiverStream",
    "StreamClient",
    "StreamError",
    "StreamListener",
    "StreamRegistrar",
    "StreamRegistrarState",
    "StreamVerification",
    "changes_for",
    "has_desired_delivery",
    "has_desired_events",
    "stream_status_of",
]

_log: Final = logging.getLogger("easyssf.receiver.stream")

MAX_STREAM_RETRY_DELAY: Final = timedelta(seconds=30)
"""The longest delay between two attempts to register the stream."""

_DEFAULT_RETRY_DELAY: Final = timedelta(seconds=1)


class StreamError(EasyssfError):
    """A call to the stream management API of the transmitter failed: the transmitter could not
    be called, or answered with an error status.

    Args:
        status: the HTTP status the transmitter answered with, 0 if it did not answer.
        cause: the underlying error, ``None`` if there is none.
        message: what failed.
    """

    def __init__(self, status: int, cause: BaseException | None, message: str) -> None:
        super().__init__(message)
        self.status = status
        """The HTTP status the transmitter answered with, 0 if it did not answer."""
        self.cause = cause
        """The underlying error, ``None`` if there is none."""
        self.message = message
        """What failed."""
        self.__cause__ = cause

    def __str__(self) -> str:
        """The message, followed by the cause if there is one."""
        if self.cause is not None:
            return f"{self.message}: {self.cause}"
        return self.message

    @classmethod
    def of(cls, exc: BaseException | None) -> StreamError | None:
        """The stream error in the given exception or its chain of causes, ``None`` if there is
        none."""
        found = _find(exc, cls)
        return found if isinstance(found, cls) else None


def stream_status_of(exc: BaseException | None) -> int:
    """The HTTP status a failed call to the stream management API was answered with, 0 if ``exc``
    is not a :class:`StreamError` or the transmitter did not answer."""
    error = StreamError.of(exc)
    return error.status if error is not None else 0


class IssuerMismatchError(EasyssfError):
    """The transmitter returned a stream whose issuer is not the issuer the transmitter metadata
    was obtained from (SSF 1.0, section 8.1.1). Such a stream must not be used: its SETs would not
    verify.

    Args:
        expected_issuer: the issuer of the transmitter.
        stream: the stream the transmitter returned, for example to delete it if it was created.
    """

    def __init__(self, expected_issuer: str, stream: StreamConfiguration) -> None:
        super().__init__(expected_issuer, stream)
        self.expected_issuer = expected_issuer
        """The issuer of the transmitter."""
        self.stream = stream
        """The stream the transmitter returned."""

    def __str__(self) -> str:
        """Which stream was returned with which issuer instead of which."""
        return (
            f"The transmitter returned stream {self.stream.stream_id} with the issuer {self.stream.issuer!r} "
            f"instead of {self.expected_issuer!r}"
        )


class StreamClient:
    """Calls the stream management API of one transmitter (SSF 1.0, section 8.1): configuration,
    status, subjects and verification. The endpoints are discovered from the transmitter metadata.
    Every stream configuration the transmitter returns is checked to carry the issuer of the
    metadata before it is accepted (section 8.1.1): the SETs of a stream with another issuer would
    not verify.

    Args:
        metadata_resolver: finds the endpoints.
        client: the client the transmitter is called with.
        authorizer: authorizes the calls: an :class:`~easyssf.receiver.authorizer.Authorizer`, a
            :class:`~easyssf.receiver.transmitter.TokenProvider` sent as bearer token, or ``None``
            for no authorization.
        retry: how a failed call is tried again; not at all by default.
        timeout: how long a call waits for the response;
            :data:`~easyssf.receiver.transmitter.DEFAULT_HTTP_TIMEOUT` if ``None``.
        max_response_size: the largest response read, in bytes;
            :data:`~easyssf.receiver.transmitter.MAX_RESPONSE_SIZE` if ``None``.
        policy: the URI policy the redirects are checked with; the one of the resolver by default.
    """

    def __init__(
        self,
        metadata_resolver: MetadataResolver,
        client: httpx.AsyncClient,
        authorizer: Authorizer | TokenProvider | None = None,
        *,
        retry: RetryOptions | None = None,
        timeout: timedelta | None = None,
        max_response_size: int | None = None,
        policy: UriPolicy | None = None,
    ) -> None:
        self._metadata = metadata_resolver
        self._client = client
        self._authorizer = BearerToken(authorizer)
        self._policy = policy
        self.retry = retry if retry is not None else RetryOptions()
        """How a failed call is tried again."""
        self.timeout = timeout
        """How long a call waits for the response; the default if ``None``."""
        self.max_response_size = max_response_size
        """The largest response read, in bytes; the default if ``None``."""

    @property
    def metadata_resolver(self) -> MetadataResolver:
        """Where the endpoints come from."""
        return self._metadata

    @property
    def authorizer(self) -> Authorizer:
        """What the calls go through."""
        return self._authorizer

    @property
    def policy(self) -> UriPolicy:
        """The URI policy the redirects are checked with."""
        return self._policy if self._policy is not None else self._metadata.policy

    async def streams(self) -> list[StreamConfiguration]:
        """Lists the streams of this receiver (``GET configuration_endpoint``).

        Raises:
            IssuerMismatchError: if a stream has another issuer than the transmitter.
            StreamError: if the call failed.
        """
        endpoint = await self._configuration_endpoint()
        body = await self._exchange("GET", endpoint, None, Endpoint.CONFIGURATION)
        if not body.strip():
            return []
        try:
            parsed = json.loads(body)
        except ValueError as error:
            raise StreamError(0, error, "The transmitter returned an invalid list of streams") from error
        if isinstance(parsed, list):
            return [self._check_issuer(StreamConfiguration(element)) for element in parsed if isinstance(element, dict)]
        if isinstance(parsed, dict):
            return [self._check_issuer(StreamConfiguration(parsed))]
        raise StreamError(0, None, "The transmitter returned an invalid list of streams")

    async def stream(self, stream_id: str) -> StreamConfiguration:
        """Reads the stream with the given identifier (``GET configuration_endpoint?stream_id=``).

        Raises:
            IssuerMismatchError: if the stream has another issuer than the transmitter.
            StreamError: if the call failed.
        """
        endpoint = await self._configuration_endpoint()
        body = await self._exchange("GET", _with_stream_id_query(endpoint, stream_id), None, Endpoint.CONFIGURATION)
        return self._check_issuer(_parse_stream(body))

    async def create_stream(self, stream: StreamConfiguration) -> StreamConfiguration:
        """Creates a stream (``POST configuration_endpoint``), see
        :meth:`~easyssf.core.StreamConfiguration.push` and :meth:`~easyssf.core.StreamConfiguration.poll`.

        Raises:
            IssuerMismatchError: if the transmitter created the stream with another issuer than
                its own; the stream must not be used then.
            StreamError: if the call failed.
        """
        endpoint = await self._configuration_endpoint()
        body = await self._exchange("POST", endpoint, stream.claims, Endpoint.CONFIGURATION)
        return self._check_issuer(_parse_stream(body))

    async def update_stream(self, stream_id: str, changes: Claims) -> StreamConfiguration:
        """Updates the given members of a stream (``PATCH configuration_endpoint``), the others
        are left as they are.

        Raises:
            IssuerMismatchError: if the stream has another issuer than the transmitter.
            StreamError: if the call failed.
        """
        endpoint = await self._configuration_endpoint()
        body = await self._exchange("PATCH", endpoint, _with_stream_id(changes, stream_id), Endpoint.CONFIGURATION)
        return self._check_issuer(_parse_stream(body))

    async def replace_stream(self, stream_id: str, stream: StreamConfiguration) -> StreamConfiguration:
        """Replaces the configuration of a stream (``PUT configuration_endpoint``).

        Raises:
            IssuerMismatchError: if the stream has another issuer than the transmitter.
            StreamError: if the call failed.
        """
        endpoint = await self._configuration_endpoint()
        body = await self._exchange("PUT", endpoint, _with_stream_id(stream.claims, stream_id), Endpoint.CONFIGURATION)
        return self._check_issuer(_parse_stream(body))

    def _check_issuer(self, stream: StreamConfiguration) -> StreamConfiguration:
        """A stream belongs to the transmitter the metadata was obtained from (SSF 1.0, section
        8.1.1, ``iss``); SETs of a stream with another issuer would not verify against that
        transmitter's keys and issuer, so such a stream is refused wherever it comes from."""
        if stream.issuer != self._metadata.issuer:
            raise IssuerMismatchError(self._metadata.issuer, stream)
        return stream

    async def delete_stream(self, stream_id: str) -> None:
        """Deletes a stream (``DELETE configuration_endpoint?stream_id=``)."""
        endpoint = await self._configuration_endpoint()
        await self._exchange("DELETE", _with_stream_id_query(endpoint, stream_id), None, Endpoint.CONFIGURATION)

    async def status(self, stream_id: str) -> StreamStatus:
        """Reads the status of a stream (``GET status_endpoint``)."""
        endpoint = await self._endpoint(lambda m: m.status_endpoint, "status_endpoint")
        body = await self._exchange("GET", _with_stream_id_query(endpoint, stream_id), None, Endpoint.STATUS)
        return _parse_status(body)

    async def update_status(self, stream_id: str, status: str, reason: str = "") -> StreamStatus:
        """Enables, pauses or disables a stream (``POST status_endpoint``): ``status`` is one of
        :class:`~easyssf.core.StreamStatusValue`, ``reason`` optional."""
        endpoint = await self._endpoint(lambda m: m.status_endpoint, "status_endpoint")
        body: Claims = {"status": status}
        if reason:
            body["reason"] = reason
        response = await self._exchange("POST", endpoint, _with_stream_id(body, stream_id), Endpoint.STATUS)
        return _parse_status(response)

    async def add_subject(self, stream_id: str, subject: Claims, verified: bool = False) -> None:
        """Asks the transmitter to send events about the subject (a subject identifier, see
        :mod:`easyssf.core.subjects`); ``verified`` tells whether the receiver has verified the
        subject (``POST add_subject_endpoint``)."""
        endpoint = await self._endpoint(lambda m: m.add_subject_endpoint, "add_subject_endpoint")
        body = _with_stream_id({"subject": subject, "verified": verified}, stream_id)
        await self._exchange("POST", endpoint, body, Endpoint.ADD_SUBJECT)

    async def remove_subject(self, stream_id: str, subject: Claims) -> None:
        """Asks the transmitter to no longer send events about the subject
        (``POST remove_subject_endpoint``)."""
        endpoint = await self._endpoint(lambda m: m.remove_subject_endpoint, "remove_subject_endpoint")
        await self._exchange(
            "POST", endpoint, _with_stream_id({"subject": subject}, stream_id), Endpoint.REMOVE_SUBJECT
        )

    async def request_verification(self, stream_id: str, state: str = "") -> None:
        """Asks the transmitter to send a verification event on the stream
        (``POST verification_endpoint``, SSF 1.0, section 8.1.4.1); ``state``, if not ``""``, is
        echoed in the event."""
        endpoint = await self._endpoint(lambda m: m.verification_endpoint, "verification_endpoint")
        body: Claims = {}
        if state:
            body["state"] = state
        await self._exchange("POST", endpoint, _with_stream_id(body, stream_id), Endpoint.VERIFICATION)

    async def _configuration_endpoint(self) -> str:
        return await self._endpoint(lambda m: m.configuration_endpoint, "configuration_endpoint")

    async def _endpoint(self, endpoint: Callable[[TransmitterMetadata], str], name: str) -> str:
        try:
            metadata = await self._metadata.resolve()
        except Exception as error:
            raise StreamError(0, error, str(error)) from error
        url = endpoint(metadata)
        if not url:
            raise StreamError(0, None, f"The SSF transmitter metadata has no {name}")
        return url

    async def _exchange(self, method: str, url: str, body: Claims | None, endpoint: str) -> bytes:
        """Calls the endpoint and returns the body of a successful response."""
        json_body = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
        try:
            response = await exchange(
                self._client,
                method,
                url,
                authorizer=self._authorizer,
                policy=self.policy,
                retry=self.retry,
                timeout=self.timeout,
                max_response_size=self.max_response_size,
                json_body=json_body,
                endpoint=endpoint,
            )
        except Exception as error:
            raise StreamError(0, error, f"{method} {url} failed") from error
        if not response.successful:
            raise StreamError(
                response.status, None, f"{method} {url} failed with status {response.status}: {response.text}"
            )
        return response.body

    def __repr__(self) -> str:
        return f"StreamClient({self._metadata.issuer!r})"


def _parse_stream(body: bytes) -> StreamConfiguration:
    return StreamConfiguration(_parse_object(body))


def _parse_status(body: bytes) -> StreamStatus:
    claims = _parse_object(body)
    return StreamStatus(
        string_member(claims, "stream_id"), string_member(claims, "status"), string_member(claims, "reason")
    )


def _parse_object(body: bytes) -> Claims:
    try:
        return parse_claims(body)
    except ValueError as error:
        raise StreamError(0, error, "The transmitter returned an invalid response") from error


def _with_stream_id_query(endpoint: str, stream_id: str) -> str:
    parts = urlsplit(endpoint)
    query = [(name, value) for name, value in parse_qsl(parts.query, keep_blank_values=True) if name != "stream_id"]
    query.append(("stream_id", stream_id))
    return urlunsplit(parts._replace(query=urlencode(query)))


def _with_stream_id(body: Claims, stream_id: str) -> Claims:
    with_id: Claims = {"stream_id": stream_id}
    with_id.update(body)
    return with_id


class ReceiverStream:
    """Holds the configuration of the stream this receiver gets its events from, once it is known:
    after the :class:`StreamRegistrar` has registered or looked up the stream at the transmitter."""

    __slots__ = ("_configuration",)

    def __init__(self, configuration: StreamConfiguration | None = None) -> None:
        self._configuration = configuration

    @property
    def configuration(self) -> StreamConfiguration | None:
        """The configuration of the stream, ``None`` as long as it is not known."""
        return self._configuration

    def set_configuration(self, configuration: StreamConfiguration | None) -> None:
        """Sets the configuration once the stream is known."""
        self._configuration = configuration

    @property
    def stream_id(self) -> str:
        """The identifier of the stream, ``""`` as long as it is not known."""
        return self._configuration.stream_id if self._configuration is not None else ""

    @property
    def audience(self) -> list[str]:
        """The audiences of the SETs of the stream, empty as long as they are not known."""
        return self._configuration.audience if self._configuration is not None else []

    @property
    def poll_endpoint_url(self) -> str:
        """The poll endpoint of a stream with poll delivery, ``""`` as long as the stream is not
        known or it is delivered otherwise."""
        configuration = self._configuration
        if configuration is None or configuration.delivery_method_uri != POLL_URI:
            return ""
        return configuration.delivery_endpoint_url

    def __repr__(self) -> str:
        return f"ReceiverStream({self._configuration!r})"


class StreamVerification:
    """Validates stream verification events (SSF 1.0, section 8.1.4.1) and keeps track of the
    verifications this receiver requested.

    A verification event has to be about the stream of the receiver: its ``sub_id`` is an opaque
    identifier with the identifier of the stream. If it echoes a state, that has to be a state the
    receiver sent with a verification request that was not answered yet. An event without state
    was initiated by the transmitter and is accepted.

    Args:
        stream_id_provider: tells the identifier of the stream, ``""`` as long as it is not known;
            the subject of verification events is not checked while it is unknown. ``None`` never
            knows the stream.
        reject_unrequested_state: rejects a verification event with a state when the receiver is
            not waiting for the answer to a verification request. By default such an event is
            accepted, since some transmitters add a state to the verification events they initiate
            themselves.
        logger: where accepted unrequested states are logged; ``easyssf.receiver.stream`` by default.
    """

    def __init__(
        self,
        stream_id_provider: Callable[[], str] | None = None,
        *,
        reject_unrequested_state: bool = False,
        logger: logging.Logger | None = None,
    ) -> None:
        self._stream_id = stream_id_provider if stream_id_provider is not None else _unknown_stream
        self._pending: set[str] = set()
        self.reject_unrequested_state = reject_unrequested_state
        """Rejects a verification event with a state when no verification request is pending."""
        self.logger = logger if logger is not None else _log
        """Where accepted unrequested states are logged."""

    def new_state(self) -> str:
        """Creates a state for a verification request and remembers it until the verification
        event that echoes it arrived."""
        state = secrets.token_hex(16)
        self._pending.add(state)
        return state

    async def request_verification(self, client: StreamClient, stream_id: str) -> str:
        """Asks the transmitter to send a verification event on the stream through ``client``;
        returns the state the verification event has to echo.

        Raises:
            StreamError: if the request failed; the state is forgotten then.
        """
        state = self.new_state()
        try:
            await client.request_verification(stream_id, state)
        except BaseException:
            self._pending.discard(state)
            raise
        return state

    @property
    def is_pending(self) -> bool:
        """Whether a verification request was sent that has not been answered yet."""
        return bool(self._pending)

    def check(self, context: EventContext) -> None:
        """Validates the verification event of a SET, if it has one. The processor calls it for
        every SET of the transmitter.

        Raises:
            RejectedError: with ``invalid_request`` if the event is about another stream, with
                ``invalid_state`` if it echoes a state that is not expected.
        """
        if not context.has_event(EventTypes.SSF_STREAM_VERIFICATION):
            return
        expected = self._stream_id()
        if expected:
            # SSF 1.0 8.1.4.1: the sub_id of a verification event is opaque and names the stream
            subject_id = context.event_token.subject_id
            if string_member(subject_id, "format") != Format.OPAQUE or string_member(subject_id, "id") != expected:
                raise RejectedError(
                    ErrorCode.INVALID_REQUEST, "The verification event is not about the stream of this receiver"
                )
        payload = context.event(EventTypes.SSF_STREAM_VERIFICATION) or {}
        state = _string_of(payload.get("state"))
        if not state:
            return
        if state in self._pending:
            self._pending.discard(state)
            return
        if self._pending or self.reject_unrequested_state:
            raise RejectedError(
                ErrorCode.INVALID_STATE, "The state of the verification event is not the one this receiver sent"
            )
        self.logger.debug("Accepting a verification event with a state although no verification was requested")


def _unknown_stream() -> str:
    return ""


def _string_of(value: Any) -> str:
    """A JSON value as text: a string as it is, ``None`` as ``""``, anything else as its JSON."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, separators=(",", ":"))


class StreamRegistrarState(Enum):
    """Where the registration of a :class:`StreamRegistrar` stands."""

    NOT_STARTED = "not_started"
    """:meth:`StreamRegistrar.start` was not called yet."""
    REGISTERING = "registering"
    """The stream is being looked up or registered, with retries while the transmitter cannot be
    reached."""
    REGISTERED = "registered"
    """The stream is known and matches what the receiver wants."""
    FAILED = "failed"
    """The stream cannot be used, see :attr:`StreamRegistrar.last_error`. Not retried."""

    def __str__(self) -> str:
        """The lowercase name: ``not_started``, ``registering``, ``registered``, ``failed``."""
        return self.value


StreamListener = Callable[[StreamConfiguration], None]
"""Told the stream whenever the registrar registered it."""


class StreamRegistrar:
    """Makes the stream of this receiver known after :meth:`start`, without holding the startup of
    the application up: the transmitter is called in the background and retried until it answers.

    Either looks up a stream that was created at the transmitter by its identifier
    (:meth:`for_existing_stream`), or manages the stream itself (:meth:`for_managed_stream`): it
    reuses the stream the receiver already has at the transmitter, brings it in line with the
    desired configuration, or creates it.

    Listeners (:meth:`add_listener`) learn when the stream is registered;
    :meth:`~easyssf.receiver.transmitter.Transmitter.start` uses that to have the poller fetch right
    away instead of an interval later. Use the constructors.
    """

    def __init__(
        self,
        client: StreamClient,
        stream: ReceiverStream,
        *,
        existing_id: str = "",
        desired: StreamConfiguration | None = None,
        delete_on_shutdown: bool = False,
        initial_retry_delay: timedelta | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._client = client
        self._stream = stream
        self._existing_id = existing_id
        self._desired = desired
        self.delete_on_shutdown = delete_on_shutdown
        """Deletes a stream this receiver manages at the transmitter when it stops."""
        self.initial_retry_delay = initial_retry_delay
        """The delay before the first retry, doubled up to :data:`MAX_STREAM_RETRY_DELAY`; one
        second if ``None``."""
        self.logger = logger if logger is not None else _log
        """Where the registrar logs."""
        self._state = StreamRegistrarState.NOT_STARTED
        self._last_error = ""
        self._listeners: list[StreamListener] = []
        self._task: asyncio.Task[None] | None = None
        # start and stop exclude each other, so that a registration started while stop deletes
        # the stream does not find and adopt the stream being deleted
        self._lifecycle = asyncio.Lock()
        # whether a stream was published since the last stop: the receiver keeps the stream
        # after stop, and stop deletes only one it has not deleted before
        self._published = False

    @classmethod
    def for_existing_stream(
        cls,
        client: StreamClient,
        stream: ReceiverStream,
        stream_id: str,
        *,
        initial_retry_delay: timedelta | None = None,
        logger: logging.Logger | None = None,
    ) -> StreamRegistrar:
        """A registrar that looks up the stream with the given identifier and makes it known
        through ``stream``."""
        return cls(client, stream, existing_id=stream_id, initial_retry_delay=initial_retry_delay, logger=logger)

    @classmethod
    def for_managed_stream(
        cls,
        client: StreamClient,
        stream: ReceiverStream,
        desired: StreamConfiguration,
        *,
        delete_on_shutdown: bool = False,
        initial_retry_delay: timedelta | None = None,
        logger: logging.Logger | None = None,
    ) -> StreamRegistrar:
        """A registrar that discovers, updates or creates the stream the receiver wants
        (:meth:`~easyssf.core.StreamConfiguration.push`, :meth:`~easyssf.core.StreamConfiguration.poll`)
        and makes it known through ``stream``."""
        return cls(
            client,
            stream,
            desired=desired,
            delete_on_shutdown=delete_on_shutdown,
            initial_retry_delay=initial_retry_delay,
            logger=logger,
        )

    @property
    def stream(self) -> ReceiverStream:
        """Where the registered stream is made known."""
        return self._stream

    @property
    def current(self) -> StreamConfiguration | None:
        """The stream as the transmitter last returned it, ``None`` before registration."""
        return self._stream.configuration

    @property
    def manages_stream(self) -> bool:
        """Whether the registrar manages the stream (as opposed to looking an existing one up)."""
        return self._desired is not None

    @property
    def state(self) -> StreamRegistrarState:
        """Where the registration stands."""
        return self._state

    @property
    def last_error(self) -> str:
        """Why the last attempt to look up or register the stream failed, ``""`` if it succeeded
        or none was made yet."""
        return self._last_error

    @property
    def is_running(self) -> bool:
        """Whether the background registration runs."""
        return self._task is not None and not self._task.done()

    def add_listener(self, listener: StreamListener) -> None:
        """Adds a listener that is told whenever :meth:`register` succeeded, on the task that
        registered the stream."""
        self._listeners.append(listener)

    async def start(self) -> None:
        """Starts looking up or registering the stream in the background; returns at once.
        :meth:`stop` ends the retries. Calling it again while running has no effect; once the
        task ended, :meth:`start` starts it again. While :meth:`stop` is under way, it waits for
        it to finish, so that a stream being deleted is not adopted."""
        async with self._lifecycle:
            if self.is_running:
                return
            self._state = StreamRegistrarState.REGISTERING
            self._task = asyncio.create_task(self._register_with_retries(), name="easyssf-stream-registrar")

    async def stop(self) -> None:
        """Stops the background registration and, if :attr:`delete_on_shutdown` says so, deletes a
        stream the receiver manages: the one published since the last :meth:`stop`, not again one
        a previous :meth:`stop` deleted. A registration in flight is cancelled and publishes
        nothing."""
        async with self._lifecycle:
            task, self._task = self._task, None
            if task is not None and not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            published, self._published = self._published, False
            stream_id = self._stream.stream_id
            if self.delete_on_shutdown and self._desired is not None and published and stream_id:
                try:
                    await self._client.delete_stream(stream_id)
                except Exception as error:
                    self.logger.warning("Could not delete SSF stream", extra={"stream": stream_id, "error": error})
                else:
                    self.logger.info("Deleted SSF stream", extra={"stream": stream_id})

    async def _register_with_retries(self) -> None:
        delay = (
            self.initial_retry_delay
            if self.initial_retry_delay and self.initial_retry_delay > timedelta(0)
            else _DEFAULT_RETRY_DELAY
        )
        try:
            while True:
                try:
                    await self.register()
                    return
                except IssuerMismatchError as mismatch:
                    # trying again would only find or create the same stream
                    self.logger.error("Not using the SSF stream", extra={"error": mismatch})
                    self._state, self._last_error = StreamRegistrarState.FAILED, str(mismatch)
                    return
                except Exception as error:
                    self._state, self._last_error = StreamRegistrarState.REGISTERING, str(error)
                    self.logger.warning(
                        "Could not set up the SSF stream, trying again", extra={"retry_in": delay, "error": error}
                    )
                await asyncio.sleep(delay.total_seconds())
                delay = min(delay * 2, MAX_STREAM_RETRY_DELAY)
        finally:
            # the task clears its own handle when it ends, so that is_running tells the truth and
            # start works again; not when stop took the handle already
            if self._task is asyncio.current_task():
                self._task = None

    async def register(self) -> StreamConfiguration:
        """Looks up or registers the stream once, on the caller's task, and makes it known.

        Raises:
            StreamError: if the transmitter could not be called or answered with an error.
            IssuerMismatchError: if the stream has another issuer than the transmitter; a stream
                created on the way is deleted again, an existing one is left alone.
        """
        if self._desired is None:
            stream = await self._client.stream(self._existing_id)
            action = "Using"
        else:
            stream, action = await self._register_managed(self._desired)
        self._stream.set_configuration(stream)
        self._published = True
        self.logger.info(
            action + " SSF stream",
            extra={
                "stream": stream.stream_id,
                "delivery": stream.delivery_method_uri,
                "endpoint": stream.delivery_endpoint_url,
                "events": [event_types.alias_of(event) for event in stream.events_delivered],
                "audience": stream.audience,
            },
        )
        self._state, self._last_error = StreamRegistrarState.REGISTERED, ""
        for listener in list(self._listeners):
            listener(stream)
        return stream

    async def _register_managed(self, desired: StreamConfiguration) -> tuple[StreamConfiguration, str]:
        streams = await self._client.streams()
        for existing in streams:
            if not has_desired_delivery(existing, desired):
                continue
            if has_desired_events(existing, desired):
                return existing, "Using existing"
            return await self._client.update_stream(existing.stream_id, changes_for(desired)), "Updated"
        try:
            return await self._client.create_stream(desired), "Created"
        except IssuerMismatchError as mismatch:
            # the stream was created but must not be used, and trying again would only create
            # another one
            await self._delete_quietly(mismatch.stream.stream_id)
            raise
        except StreamError as error:
            # the transmitter allows a single stream per receiver and it is configured differently
            if error.status == 409 and len(streams) == 1:
                return await self._client.update_stream(streams[0].stream_id, changes_for(desired)), "Updated"
            raise

    async def _delete_quietly(self, stream_id: str) -> None:
        if not stream_id:
            return
        try:
            await self._client.delete_stream(stream_id)
        except Exception as error:
            self.logger.warning("Could not delete SSF stream", extra={"stream": stream_id, "error": error})

    def __repr__(self) -> str:
        return f"StreamRegistrar(state={self._state}, stream={self._stream.stream_id!r})"


def has_desired_events(stream: StreamConfiguration, desired: StreamConfiguration) -> bool:
    """Whether the stream requests the events the desired configuration requests, aliases resolved."""
    have = {event_types.resolve(event) for event in stream.events_requested}
    want = {event_types.resolve(event) for event in desired.events_requested}
    return have == want


def has_desired_delivery(stream: StreamConfiguration, desired: StreamConfiguration) -> bool:
    """Whether the stream is delivered as the desired configuration says: the same method and,
    for push, the same endpoint."""
    if stream.delivery_method_uri != desired.delivery_method_uri:
        return False
    if stream.delivery_method_uri == POLL_URI:
        return True
    return stream.delivery_endpoint_url == desired.delivery_endpoint_url


def changes_for(desired: StreamConfiguration) -> Claims:
    """The members of a stream to update so that it matches the desired configuration: the
    delivery, the requested events and, if any, the description."""
    changes: Claims = {
        "delivery": desired.claims.get("delivery"),
        "events_requested": list(desired.events_requested),
    }
    if desired.description:
        changes["description"] = desired.description
    return changes
