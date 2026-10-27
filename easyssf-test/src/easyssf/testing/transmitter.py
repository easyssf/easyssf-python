"""A minimal SSF transmitter / identity provider for the tests of a receiver: it publishes
transmitter metadata and a JWK Set, signs SETs and access tokens, issues access tokens for the
client credentials grant and offers stream management and a poll endpoint that behave like the
ones of Keycloak. It answers in-process: its ``client`` is an ``httpx.AsyncClient`` whose
transport routes requests for the transmitter's host to :meth:`TestTransmitter.handle` without a
socket, and :meth:`TestTransmitter.asgi` mounts the same handler on an ASGI server when a real
port is wanted. The port of ``ssftest`` of the Go port.

Example:
    >>> transmitter = TestTransmitter()
    >>> subject = complex_subject(iss_sub(transmitter.issuer, "alice"), opaque("session-1"))
    >>> claims = transmitter.set_claims("CaepSessionRevoked", subject)
    >>> claims["aud"] = "https://my-app.example"
    >>> encoded_set = transmitter.sign_set(claims)
    >>> # POST encoded_set to /ssf/push, or transmitter.queue_set(encoded_set) for a polling receiver
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Final
from urllib.parse import parse_qs, urlsplit

import httpx

from easyssf.core import (
    POLL_URI,
    PUSH_URI,
    SPEC_VERSION_1_0,
    Claims,
    StreamStatusValue,
    as_int,
    event_types,
    new_jti,
    object_member,
    parse_claims,
    string_member,
    strings,
)
from easyssf.core.signing import JWT_TYPE, SECEVENT_JWT_TYPE, Signer

from .keys import SigningKey, claims_of, shared_key, sign

__all__ = [
    "ACCESS_TOKEN",
    "AUDIENCE",
    "CLIENT_ID",
    "CLIENT_SECRET",
    "InProcessTransport",
    "MetadataLocation",
    "ReportedError",
    "TestTransmitter",
    "client_for",
]

AUDIENCE: Final = "https://receiver.example"
"""The audience of the SETs the transmitter signs by default."""
CLIENT_ID: Final = "receiver"
"""The client id the token endpoint accepts."""
CLIENT_SECRET: Final = "receiver-secret"  # noqa: S105
"""The client secret the token endpoint accepts."""
ACCESS_TOKEN: Final = "transmitter-access-token"  # noqa: S105
"""The access token the token endpoint issues until :meth:`TestTransmitter.expire_access_tokens`."""

_REALM: Final = "/realms/test"
_WELL_KNOWN_PATH: Final = "/.well-known/ssf-configuration"
_JWKS_PATH: Final = "/protocol/openid-connect/certs"
_TOKEN_PATH: Final = "/protocol/openid-connect/token"  # noqa: S105
_POLL_PATH: Final = "/ssf/poll"
_DEFAULT_MAX_EVENTS: Final = 10
_BLOCKING_POLL_INTERVAL: Final = 0.01
_JSON_HEADERS: Final = {"Content-Type": "application/json"}


class MetadataLocation(Enum):
    """Where the transmitter publishes its metadata."""

    SSF = "ssf"
    """SSF 1.0, section 7.2: ``/.well-known/ssf-configuration`` followed by the path of the issuer."""
    OIDC_STYLE = "oidc-style"
    """``/.well-known/ssf-configuration`` under the path of the issuer, as OpenID Connect Discovery
    places its document and some transmitters do."""
    NONE = "none"
    """No metadata is published."""


@dataclass(frozen=True, slots=True)
class ReportedError:
    """An error a polling receiver reported for a SET (the ``setErrs`` member of a poll request,
    RFC 8936, section 2.2)."""

    jti: str
    code: str
    description: str


@dataclass(slots=True)
class _QueuedSet:
    jti: str
    set: str


@dataclass(frozen=True, slots=True)
class _PendingPoll:
    """A poll request whose response waits for a SET: the hold and the ``maxEvents`` to answer with."""

    hold: timedelta
    max_events: int


_Scope = dict[str, Any]
_Receive = Callable[[], Awaitable[dict[str, Any]]]
_Send = Callable[[dict[str, Any]], Awaitable[None]]


class TestTransmitter:
    """A minimal SSF transmitter for tests, see the module documentation. Used from one event
    loop; the blocking ``sync_client`` may be driven from another thread.

    Args:
        location: where the metadata is published, the SSF location by default.
        host: the host of the issuer, ``transmitter.example`` by default; give every transmitter of
            a test its own, as a receiver tells transmitters apart by issuer.
    """

    __test__ = False  # not a test class, although pytest would take the name for one

    def __init__(self, location: MetadataLocation = MetadataLocation.SSF, host: str = "") -> None:
        self._issuer = "https://" + (host or "transmitter.example") + _REALM
        self._key = shared_key()
        self._available = True
        self._requests = 0
        self._tokens = 0
        self._polls = 0
        self._documents: dict[str, str] = {}
        self._streams: list[Claims] = []
        self._queued: list[_QueuedSet] = []
        self._acknowledged: list[str] = []
        self._reported_errors: list[ReportedError] = []
        self._verification_requests: list[str] = []
        self._added_subjects: list[Claims | None] = []
        self._removed_subjects: list[Claims | None] = []
        self._last_poll_request: Claims = {}
        self._long_poll_hold = timedelta(0)
        self._valid_access_token = ACCESS_TOKEN
        self._stream_issuer = ""
        self._user_agent = ""
        self._waiters: list[asyncio.Future[None]] = []  # the held poll requests, woken when a SET is queued
        self._transport: InProcessTransport | None = None
        self._client: httpx.AsyncClient | None = None
        self._sync_client: httpx.Client | None = None
        self.publish_jwks(self._key)
        self.publish_metadata(location)

    @classmethod
    def with_metadata(cls, location: MetadataLocation, host: str = "") -> TestTransmitter:
        """A transmitter that publishes its metadata at the given location, or not at all; the
        ``WithMetadata`` of the Go port."""
        return cls(location, host)

    # -- the in-process clients -------------------------------------------------------------------

    @property
    def transport(self) -> InProcessTransport:
        """The transport that answers requests for the transmitter's host in-process, for an
        ``httpx.AsyncClient`` or ``httpx.Client`` of the receiver under test."""
        if self._transport is None:
            self._transport = InProcessTransport((self,))
        return self._transport

    @property
    def client(self) -> httpx.AsyncClient:
        """The client that calls the transmitter in-process, :func:`client_for` this transmitter.
        Give it to the receiver under test."""
        if self._client is None:
            self._client = httpx.AsyncClient(transport=self.transport)
        return self._client

    @property
    def sync_client(self) -> httpx.Client:
        """The blocking client on the same transport, for sync code under test. A held long poll
        blocks the calling thread, so do not use it on the event loop that queues the SETs."""
        if self._sync_client is None:
            self._sync_client = httpx.Client(transport=self.transport)
        return self._sync_client

    # -- what the transmitter is --------------------------------------------------------------------

    @property
    def issuer(self) -> str:
        """The issuer of the transmitter: the ``iss`` of every SET and the base of its endpoints."""
        return self._issuer

    @property
    def key(self) -> SigningKey:
        """The key the transmitter signs with."""
        return self._key

    @property
    def jwks_url(self) -> str:
        """Where the JWK Set is published."""
        return self._issuer + _JWKS_PATH

    @property
    def token_url(self) -> str:
        """The token endpoint."""
        return self._issuer + _TOKEN_PATH

    @property
    def poll_url(self) -> str:
        """The poll endpoint."""
        return self._issuer + _POLL_PATH

    @property
    def host(self) -> str:
        """The host of the issuer."""
        return urlsplit(self._issuer).netloc

    @property
    def signer(self) -> Signer:
        """The transmitter's key as a :class:`~easyssf.core.signing.Signer`, RS256, for SETs built
        with :func:`easyssf.core.new_set`."""
        return self._key.signer("RS256")

    # -- what the transmitter saw -------------------------------------------------------------------

    @property
    def requests(self) -> int:
        """How many HTTP requests the transmitter received so far."""
        return self._requests

    @property
    def token_requests(self) -> int:
        """How many token requests were answered with a token."""
        return self._tokens

    @property
    def poll_requests(self) -> int:
        """How many poll requests were received."""
        return self._polls

    @property
    def last_poll_request(self) -> Claims:
        """The body of the last poll request, empty if none was received."""
        return dict(self._last_poll_request)

    @property
    def last_user_agent(self) -> str:
        """The ``User-Agent`` of the most recent request, ``""`` if none."""
        return self._user_agent

    @property
    def streams(self) -> list[Claims]:
        """The streams registered at the transmitter, a snapshot."""
        return [dict(stream) for stream in self._streams]

    @property
    def acknowledged_sets(self) -> list[str]:
        """The ``jti`` of every SET a polling receiver acknowledged, a snapshot."""
        return list(self._acknowledged)

    @property
    def reported_errors(self) -> list[ReportedError]:
        """The errors a polling receiver reported, a snapshot."""
        return list(self._reported_errors)

    @property
    def verification_requests(self) -> list[str]:
        """The states of the verification requests received, a snapshot; ``""`` for a request
        without state."""
        return list(self._verification_requests)

    @property
    def added_subjects(self) -> list[Claims | None]:
        """The subjects added to streams, a snapshot; ``None`` where a request had no subject."""
        return list(self._added_subjects)

    @property
    def removed_subjects(self) -> list[Claims | None]:
        """The subjects removed from streams, a snapshot; ``None`` where a request had no subject."""
        return list(self._removed_subjects)

    @property
    def queued_set_count(self) -> int:
        """The number of SETs queued and not yet acknowledged."""
        return len(self._queued)

    # -- knobs -----------------------------------------------------------------------------------------

    def set_available(self, available: bool) -> None:
        """Makes the token, stream management and poll endpoints answer with 503 while ``False``.
        Published documents (the JWK Set, the metadata) are served regardless."""
        self._available = available

    def set_stream_issuer(self, issuer: str) -> None:
        """Makes the transmitter create streams with the given issuer instead of its own; ``""``
        restores its own."""
        self._stream_issuer = issuer

    def set_long_poll_hold(self, hold: timedelta) -> None:
        """How long a poll request without ``returnImmediately: true`` is held while no SET is
        queued. Zero by default: the transmitter then answers at once, as if it did not support
        long polling."""
        self._long_poll_hold = hold

    def expire_access_tokens(self) -> None:
        """Makes the access tokens issued so far invalid: requests with them are answered with
        401 and the token endpoint issues another token."""
        self._valid_access_token = ACCESS_TOKEN + "-" + new_jti()

    def queue_set(self, encoded_set: str) -> None:
        """Makes the SET available at the poll endpoint, under its ``jti``."""
        self.queue_set_with_jti(string_member(claims_of(encoded_set), "jti"), encoded_set)

    def queue_set_with_jti(self, jti: str, encoded_set: str) -> None:
        """Makes the SET available at the poll endpoint under the given ``jti``."""
        for queued in self._queued:
            if queued.jti == jti:
                queued.set = encoded_set
                self._wake_polls()
                return
        self._queued.append(_QueuedSet(jti, encoded_set))
        self._wake_polls()

    def reset(self) -> None:
        """Forgets streams, queued SETs and what the receiver reported."""
        self._streams, self._queued, self._acknowledged, self._reported_errors = [], [], [], []
        self._verification_requests, self._added_subjects, self._removed_subjects = [], [], []
        self._polls = 0
        self._last_poll_request = {}
        self._long_poll_hold = timedelta(0)
        self._available = True
        self._valid_access_token = ACCESS_TOKEN
        self._stream_issuer = ""
        self._wake_polls()

    # -- documents and streams -------------------------------------------------------------------------

    def publish_document(self, path: str, body: str) -> None:
        """Serves ``body`` (JSON) at the given path of the issuer's host."""
        self._documents[path] = body

    def remove_document(self, path: str) -> None:
        """Stops serving the document at the path, so that requests for it are answered with 404."""
        self._documents.pop(path, None)

    def publish_jwks(self, *keys: SigningKey) -> None:
        """Serves the public keys as the JWK Set, replacing the one before."""
        self.publish_document(_REALM + _JWKS_PATH, _dumps({"keys": [key.public_jwk() for key in keys]}))

    def publish_metadata(self, location: MetadataLocation) -> None:
        """Serves the transmitter metadata at the given location, removing it from the other."""
        self.remove_document(_WELL_KNOWN_PATH + _REALM)
        self.remove_document(_REALM + _WELL_KNOWN_PATH)
        metadata = _dumps(
            {
                "issuer": self._issuer,
                "jwks_uri": self.jwks_url,
                "spec_version": SPEC_VERSION_1_0,
                "delivery_methods_supported": [PUSH_URI, POLL_URI],
                "configuration_endpoint": self._issuer + "/ssf/streams",
                "status_endpoint": self._issuer + "/ssf/status",
                "add_subject_endpoint": self._issuer + "/ssf/subjects:add",
                "remove_subject_endpoint": self._issuer + "/ssf/subjects:remove",
                "verification_endpoint": self._issuer + "/ssf/verify",
            }
        )
        if location is MetadataLocation.SSF:
            self.publish_document(_WELL_KNOWN_PATH + _REALM, metadata)
        elif location is MetadataLocation.OIDC_STYLE:
            self.publish_document(_REALM + _WELL_KNOWN_PATH, metadata)

    def add_stream(self, request: Claims) -> Claims:
        """Registers a stream the way the transmitter does for a create request: assigns the
        identifier, the audience and, for POLL delivery, the poll endpoint. Returns the stream as
        registered."""
        stream = dict(request)
        if not string_member(stream, "stream_id"):
            stream["stream_id"] = new_jti()
        stream_id = stream["stream_id"]
        stream["iss"] = self._stream_issuer or self._issuer
        stream["aud"] = [CLIENT_ID + "/" + stream_id]
        requested = stream.get("events_requested")
        stream["events_delivered"] = list(requested) if isinstance(requested, list) else []
        delivery = dict(object_member(stream, "delivery") or {})
        delivery.pop("authorization_header", None)
        if string_member(delivery, "method") == POLL_URI:
            delivery["endpoint_url"] = self.poll_url
        stream["delivery"] = delivery
        self._streams.append(stream)
        return dict(stream)

    # -- SETs and tokens --------------------------------------------------------------------------------

    def set_claims(self, event_type: str, subject_id: Claims | None) -> Claims:
        """The claims of a valid SET with a single event whose payload has an ``event_timestamp``.
        ``event_type`` is an alias such as ``CaepSessionRevoked`` or an event type URI,
        ``subject_id`` the ``sub_id`` claim, left out if ``None``."""
        return self.set_claims_with_payload(event_type, subject_id, {"event_timestamp": int(time.time())})

    def set_claims_with_payload(self, event_type: str, subject_id: Claims | None, payload: Claims | None) -> Claims:
        """The claims of a valid SET with a single event and the given payload."""
        claims: Claims = {
            "iss": self._issuer,
            "jti": new_jti(),
            "iat": int(time.time()),
            "aud": AUDIENCE,
            "events": {event_types.resolve(event_type): {} if payload is None else payload},
        }
        if subject_id is not None:
            claims["sub_id"] = subject_id
        return claims

    def set(self, event_type: str, subject_id: Claims | None) -> str:
        """A valid, signed SET with a single event."""
        return self.sign_set(self.set_claims(event_type, subject_id))

    def sign_set(self, claims: Claims) -> str:
        """Signs the claims as a SET: typed ``secevent+jwt``, with the transmitter's key."""
        return sign(self._key, SECEVENT_JWT_TYPE, claims)

    def access_token_for(self, subject: str, session_id: str, issued_at: datetime) -> str:
        """An access token of the identity provider, as an OAuth client would present it: ``iss``,
        ``sub``, ``sid``, ``iat`` and a five minute ``exp``."""
        claims: Claims = {
            "iss": self._issuer,
            "sub": subject,
            "sid": session_id,
            "iat": int(issued_at.timestamp()),
            "exp": int(time.time()) + 300,
        }
        return sign(self._key, JWT_TYPE, claims)

    # -- the HTTP handler --------------------------------------------------------------------------------

    async def handle(self, request: httpx.Request) -> httpx.Response:
        """Answers a request: the documents, the token endpoint, the stream management endpoints
        and the poll endpoint; the ``ServeHTTP`` of the Go port. A held long poll returns when a
        SET is queued, the hold elapses or the awaiting task is cancelled."""
        outcome = self._respond(request, await request.aread())
        if isinstance(outcome, httpx.Response):
            return outcome
        await self._wait_for_set(outcome.hold)
        return self._poll_response(outcome.max_events)

    def handle_blocking(self, request: httpx.Request) -> httpx.Response:
        """:meth:`handle` for a blocking client: a held long poll sleeps on the calling thread."""
        outcome = self._respond(request, request.read())
        if isinstance(outcome, httpx.Response):
            return outcome
        deadline = time.monotonic() + outcome.hold.total_seconds()
        while not self._queued and time.monotonic() < deadline:
            time.sleep(_BLOCKING_POLL_INTERVAL)
        return self._poll_response(outcome.max_events)

    async def asgi(self, scope: _Scope, receive: _Receive, send: _Send) -> None:
        """An ASGI 3 application serving :meth:`handle`, to mount on uvicorn when a real port is
        wanted: ``uvicorn.Server(uvicorn.Config(transmitter.asgi, port=0))``."""
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                await send({"type": message["type"] + ".complete"})
                if message["type"] == "lifespan.shutdown":
                    return
        if scope["type"] != "http":
            raise RuntimeError(f"unsupported ASGI scope {scope['type']}")
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
        headers = [(name.decode("latin-1"), value.decode("latin-1")) for name, value in scope.get("headers", [])]
        host = next((value for name, value in headers if name.lower() == "host"), None)
        if host is None:
            server = scope.get("server") or ("localhost", None)
            host = server[0] if server[1] is None else f"{server[0]}:{server[1]}"
        url = f"{scope.get('scheme', 'http')}://{host}{scope['path']}"
        if scope.get("query_string"):
            url += "?" + scope["query_string"].decode("latin-1")
        response = await self.handle(httpx.Request(scope["method"], url, headers=headers, content=body))
        await send(
            {
                "type": "http.response.start",
                "status": response.status_code,
                "headers": [(k.encode("latin-1"), v.encode("latin-1")) for k, v in response.headers.multi_items()],
            }
        )
        await send({"type": "http.response.body", "body": response.content})

    def _respond(self, request: httpx.Request, body: bytes) -> httpx.Response | _PendingPoll:
        self._requests += 1
        self._user_agent = request.headers.get("User-Agent", "")
        path = request.url.path
        document = self._documents.get(path)
        if document is not None:
            return _respond(200, document)
        if not path.startswith(_REALM + "/"):
            return _respond(404)
        endpoint = path[len(_REALM) + 1 :]
        if not self._available:
            return _respond(503)
        # the token endpoint of Keycloak, and /token as the emulated authorization server of the
        # conformance suite has it next to the transmitter
        if endpoint in (_TOKEN_PATH[1:], "token"):
            return self._handle_token(request, body)
        if request.headers.get("Authorization") != "Bearer " + self._valid_access_token:
            return _respond(401)
        claims: Claims = {}
        if body.strip():
            try:
                claims = parse_claims(body)
            except ValueError:
                claims = {}
        stream_id = request.url.params.get("stream_id", "") or string_member(claims, "stream_id")
        if endpoint == "ssf/streams":
            return self._handle_streams(request.method, stream_id, claims)
        if endpoint == "ssf/status":
            status = string_member(claims, "status") or StreamStatusValue.ENABLED
            code = 200 if stream_id and self._find_stream(stream_id) is not None else 404
            return _respond_json(code, {"stream_id": stream_id, "status": status})
        if endpoint == "ssf/verify":
            self._verification_requests.append(_string_of(claims.get("state")))
            return _respond(204)
        if endpoint == _POLL_PATH[1:]:
            return self._poll(claims)
        if endpoint == "ssf/subjects:add":
            self._added_subjects.append(object_member(claims, "subject"))
            return _respond(200)
        if endpoint == "ssf/subjects:remove":
            self._removed_subjects.append(object_member(claims, "subject"))
            return _respond(204)
        return _respond(404)

    def _handle_token(self, request: httpx.Request, body: bytes) -> httpx.Response:
        form = {
            name: values[0] for name, values in parse_qs(body.decode(errors="replace"), keep_blank_values=True).items()
        }
        basic = _basic_auth(request.headers.get("Authorization", ""))
        authenticated = basic == (CLIENT_ID, CLIENT_SECRET) or (
            form.get("client_id") == CLIENT_ID and form.get("client_secret") == CLIENT_SECRET
        )
        if not authenticated or form.get("grant_type") != "client_credentials":
            return _respond_json(401, {"error": "invalid_client"})
        self._tokens += 1
        return _respond_json(200, {"access_token": self._valid_access_token, "token_type": "Bearer", "expires_in": 300})

    def _handle_streams(self, method: str, stream_id: str, request: Claims) -> httpx.Response:
        if method == "GET":
            if not stream_id:
                return _respond(200, _dumps(self.streams))
            stream = self._find_stream(stream_id)
            return _respond(404) if stream is None else _respond_json(200, stream)
        if method == "POST":
            if self._streams:
                return _respond_json(
                    409, {"error": "stream_error", "error_description": "Only one stream per receiver is allowed"}
                )
            return _respond_json(201, self.add_stream(request))
        if method in ("PATCH", "PUT"):
            updated = self._find_stream(stream_id)
            if updated is None:
                return _respond(404)
            updated.update(request)
            self._remove_stream(stream_id)
            return _respond_json(200, self.add_stream(updated))
        if method == "DELETE":
            if self._find_stream(stream_id) is None:
                return _respond(404)
            self._remove_stream(stream_id)
            return _respond(204)
        return _respond(405)

    def _poll(self, request: Claims) -> httpx.Response | _PendingPoll:
        self._polls += 1
        max_events = as_int(request.get("maxEvents"))
        if max_events is None:
            max_events = _DEFAULT_MAX_EVENTS
        return_immediately = request.get("returnImmediately") is True
        self._last_poll_request = dict(request)
        for jti in strings(request.get("ack")):
            if self._remove_queued(jti):
                self._acknowledged.append(jti)
        for jti, reported in (object_member(request, "setErrs") or {}).items():
            self._remove_queued(jti)
            report = reported if isinstance(reported, dict) else None
            self._reported_errors.append(
                ReportedError(jti, string_member(report, "err"), string_member(report, "description"))
            )
        # a long poll (returnImmediately false or absent, RFC 8936 section 2.5) is held until a SET
        # is queued, the hold time elapses or the receiver gives up
        if not return_immediately and max_events > 0 and self._long_poll_hold > timedelta(0) and not self._queued:
            return _PendingPoll(self._long_poll_hold, max_events)
        return self._poll_response(max_events)

    def _poll_response(self, max_events: int) -> httpx.Response:
        sets = {queued.jti: queued.set for queued in self._queued[: max(max_events, 0)]}
        return _respond_json(200, {"sets": sets, "moreAvailable": len(self._queued) > len(sets)})

    async def _wait_for_set(self, hold: timedelta) -> None:
        """Waits until a SET is queued or the hold elapses; a cancellation of the awaiting task
        stops the wait, the ``ctx.Done()`` of the Go port."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + hold.total_seconds()
        while not self._queued:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return
            waiter: asyncio.Future[None] = loop.create_future()
            self._waiters.append(waiter)
            try:
                async with asyncio.timeout(remaining):
                    await waiter
            except TimeoutError:
                return
            finally:
                if waiter in self._waiters:
                    self._waiters.remove(waiter)

    def _wake_polls(self) -> None:
        """Wakes up held poll requests, from any thread."""
        waiters, self._waiters = self._waiters, []
        for waiter in waiters:
            waiter.get_loop().call_soon_threadsafe(_resolve, waiter)

    def _remove_queued(self, jti: str) -> bool:
        for index, queued in enumerate(self._queued):
            if queued.jti == jti:
                del self._queued[index]
                return True
        return False

    def _find_stream(self, stream_id: str) -> Claims | None:
        for stream in self._streams:
            if string_member(stream, "stream_id") == stream_id:
                return dict(stream)
        return None

    def _remove_stream(self, stream_id: str) -> None:
        self._streams = [stream for stream in self._streams if string_member(stream, "stream_id") != stream_id]


class InProcessTransport(httpx.MockTransport):
    """An ``httpx`` transport that answers requests for the hosts of the given transmitters
    in-process, each from its handler, and refuses every other host with an
    ``httpx.ConnectError``, so a test never reaches the network. Serves an ``httpx.AsyncClient``
    through :meth:`TestTransmitter.handle` and an ``httpx.Client`` through
    :meth:`TestTransmitter.handle_blocking`."""

    def __init__(self, transmitters: Iterable[TestTransmitter]) -> None:
        self._transmitters = tuple(transmitters)
        super().__init__(self._handle_blocking)

    @property
    def transmitters(self) -> tuple[TestTransmitter, ...]:
        """The transmitters the transport routes to."""
        return self._transmitters

    def _route(self, request: httpx.Request) -> TestTransmitter:
        origin = f"{request.url.scheme}://{request.url.netloc.decode('ascii')}"
        for transmitter in self._transmitters:
            if transmitter.issuer.startswith(origin + "/"):
                return transmitter
        issuers = [transmitter.issuer for transmitter in self._transmitters]
        raise httpx.ConnectError(f"no route to {origin}, the test transmitters are {issuers}", request=request)

    def _handle_blocking(self, request: httpx.Request) -> httpx.Response:
        return self._route(request).handle_blocking(request)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Answers the request from the transmitter of its host, without a socket."""
        await request.aread()
        return await self._route(request).handle(request)


def client_for(*transmitters: TestTransmitter) -> httpx.AsyncClient:
    """An ``httpx.AsyncClient`` that answers requests for the hosts of the given transmitters
    in-process, each from its handler, and refuses every other host, so a test never reaches the
    network. :attr:`TestTransmitter.client` is one for a single transmitter; a receiver with
    several transmitters gets one for all of them."""
    return httpx.AsyncClient(transport=InProcessTransport(transmitters))


def _resolve(waiter: asyncio.Future[None]) -> None:
    if not waiter.done():
        waiter.set_result(None)


def _basic_auth(header: str) -> tuple[str, str] | None:
    scheme, _, credentials = header.partition(" ")
    if scheme.lower() != "basic":
        return None
    try:
        decoded = base64.b64decode(credentials.strip(), validate=True).decode()
    except (binascii.Error, ValueError):
        return None
    user, separator, password = decoded.partition(":")
    return (user, password) if separator else None


def _respond(status: int, body: str = "") -> httpx.Response:
    return httpx.Response(status, headers=_JSON_HEADERS, content=body.encode())


def _respond_json(status: int, body: Any) -> httpx.Response:
    return _respond(status, _dumps(body))


def _dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"))


def _string_of(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return _dumps(value)
