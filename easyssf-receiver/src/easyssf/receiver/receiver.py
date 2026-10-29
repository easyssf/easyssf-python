"""The configured receiver: ``Receiver`` assembles the parts for every configured transmitter
from a :class:`~easyssf.receiver.config.ReceiverConfig`, as the Spring Boot auto-configuration,
the .NET ``AddSsfReceiver`` and the Rust ``SsfReceiver`` do; a port of ``receiver/receiver.go``
of the Go port.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Final

import httpx

from easyssf.core import MEMBERS, DeliveryMethod, EventToken, StreamConfiguration, event_types

from .authorizer import (
    Authorizer,
    Authorizers,
    BearerToken,
    Endpoint,
    NoAuthorization,
    RetryOptions,
    StaticHeaders,
)
from .config import (
    CONFIGURATION_SECTION,
    DEFAULT_TRANSMITTER_NAME,
    STREAM_MANAGEMENT_RECEIVER,
    ReceiverConfig,
    TransmitterConfig,
)
from .dedup import InMemoryJtiDedupStore, JtiDedupStore
from .errors import (
    Clock,
    ConfigurationError,
    EasyssfError,
    ErrorCode,
    RejectedError,
    TransmitterUnavailableError,
    system_clock,
)
from .event import EventContext, Handler, HandlerCallable
from .jwks import JWK_SET_ACCEPT, HttpJwkSetSource
from .metrics import Metrics, NoopMetrics
from .poll import InMemoryPollAckStore, PollAckStore, PollEndpoint, Poller, PollerOptions, fixed_poll_endpoint
from .processor import Processor, ProcessorOptions
from .push import PushHandler
from .revocation import (
    DEFAULT_SESSION_EVENT_TYPES,
    InMemoryTokenRevocationStore,
    TokenRevocationHandler,
    TokenRevocationStore,
)
from .session import (
    DEFAULT_SESSION_TERMINATION_USER_EVENT_TYPES,
    SessionTerminationHandler,
    SessionTerminator,
    SessionTerminatorCallable,
)
from .stream import ReceiverStream, StreamClient, StreamRegistrar, StreamVerification
from .transmitter import (
    ClientCredentialsTokenProvider,
    FixedToken,
    HealthStatus,
    MetadataResolver,
    NoToken,
    TokenProvider,
    Transmitter,
    TransmitterHealth,
    UriPolicy,
    UriPolicyError,
    default_client_credentials_options,
    get_json,
)
from .verifier import IssuerRoutingVerifier, JwtVerifier, Verifier, default_verifier_options

if TYPE_CHECKING:
    from datetime import timedelta

__all__ = [
    "Receiver",
    "ReceiverDisabledError",
    "ReceiverHealth",
    "TransmitterCustomizer",
]

_log: Final = logging.getLogger("easyssf.receiver")

TransmitterCustomizer = Callable[[Transmitter], None]
"""Replaces parts of a :class:`~easyssf.receiver.transmitter.Transmitter` before the receiver is
assembled, for example the ``keys`` of the one named ``okta``. Called for every transmitter, the
default one included; :attr:`~easyssf.receiver.transmitter.Transmitter.name` tells which."""


class ReceiverDisabledError(EasyssfError):
    """The receiver is switched off: ``easyssf.receiver.enabled`` is ``False``. The ``ErrDisabled``
    of the Go port."""

    def __init__(self) -> None:
        super().__init__(f"the SSF receiver is disabled ({CONFIGURATION_SECTION}.enabled = false)")


@dataclass(frozen=True, slots=True)
class ReceiverHealth:
    """The health of the receiver, see :meth:`Receiver.health`; :meth:`to_mapping` gives the
    JSON of a health endpoint."""

    status: HealthStatus
    """The worst status of the transmitters."""
    description: str
    """What the status means."""
    transmitters: tuple[TransmitterHealth, ...]
    """The health of every transmitter."""

    def to_mapping(self) -> dict[str, Any]:
        """The health as a JSON-ready mapping with the keys of the Go port."""
        return {
            "status": self.status.value,
            "description": self.description,
            "transmitters": [transmitter.to_mapping() for transmitter in self.transmitters],
        }


class Receiver:
    """Assembles the parts for every configured transmitter from a
    :class:`~easyssf.receiver.config.ReceiverConfig`: metadata resolution, JWK Set source,
    verifier, token provider, stream client, dedup store, processor with the handlers, the push
    handler, token revocation, session termination, and per transmitter the stream registrar and
    the poller. :meth:`start` runs the stream registration and polling in the background,
    :meth:`health` reports what the receiver knows.

    Nothing is started and the transmitter is not contacted by the constructor: call
    :meth:`start` for that, or use the receiver as an ``async with`` context. The push handler
    works at once.

    Args:
        config: the configuration, validated first; the event aliases it names are registered
            only after the whole configuration passed.
        handlers: the handlers of the application, called in order for every verified SET after
            the built-in revocation and session termination handlers; a
            :class:`~easyssf.receiver.event.Handler` or a sync or async callable each.
        http_client: the client the transmitters are called with; the ``TestTransmitter`` of
            ``easyssf.testing`` hands one out that answers in-process. A new ``httpx.AsyncClient``
            if ``None``. The timeout of ``easyssf.receiver.http`` applies per call, so that a
            long poll can wait longer than the other calls. The client is never changed: a
            configured ``user-agent`` is sent by a client of the receiver's own that sends
            through the given one.
        clock: replaces the system clock, for tests.
        metrics: records what the receiver does; nothing by default.
        dedup_store: replaces the in-memory dedup store, for example with the one of
            ``easyssf-receiver-sqlalchemy``, which is shared between instances.
        revocation_store: replaces the in-memory revocation store.
        poll_ack_store: replaces the in-memory store of the acknowledgements a poller owes.
        session_terminator: ends the server-side sessions of the application when a session event
            arrives, see :class:`~easyssf.receiver.session.SessionTerminationHandler` and
            ``easyssf.receiver.session-termination``; a
            :class:`~easyssf.receiver.session.SessionTerminator` or a sync or async callable.
        transmitter_customizers: replace parts of any transmitter before the receiver is
            assembled, see :data:`TransmitterCustomizer`.
        logger: where the receiver logs; ``easyssf.receiver`` by default.

    Raises:
        ReceiverDisabledError: if ``enabled`` is ``False``.
        ConfigurationError: if the configuration is invalid, with every failure, or if two
            transmitters have the same issuer after the customizers ran.
    """

    def __init__(
        self,
        config: ReceiverConfig,
        *,
        handlers: Sequence[Handler | HandlerCallable] = (),
        http_client: httpx.AsyncClient | None = None,
        clock: Clock | None = None,
        metrics: Metrics | None = None,
        dedup_store: JtiDedupStore | None = None,
        revocation_store: TokenRevocationStore | None = None,
        poll_ack_store: PollAckStore | None = None,
        session_terminator: SessionTerminator | SessionTerminatorCallable | None = None,
        transmitter_customizers: Sequence[TransmitterCustomizer] = (),
        logger: logging.Logger | None = None,
    ) -> None:
        if not config.enabled:
            raise ReceiverDisabledError()
        config.validate()
        # the aliases take effect only now, after the whole configuration passed: validate itself
        # changes nothing
        for alias, uri in config.event_aliases.items():
            try:
                event_types.register_alias(alias, uri)
            except ValueError as error:
                raise ConfigurationError([f"{CONFIGURATION_SECTION}.event-aliases.{alias}: {error}"]) from error
        self._config = config
        self._log = logger if logger is not None else _log
        self._clock: Clock = clock if clock is not None else system_clock
        self._metrics: Metrics = metrics if metrics is not None else NoopMetrics()
        # the clients the receiver made itself are its to close (aclose); a given one is the
        # caller's
        self._owned_clients: list[httpx.AsyncClient] = []
        if http_client is None:
            http_client = httpx.AsyncClient()
            self._owned_clients.append(http_client)
        self._client = http_client
        user_agent = config.http.user_agent.strip()
        if user_agent:
            self._client = _with_user_agent(self._client, user_agent)
            self._owned_clients.append(self._client)
        self._transmitters: list[Transmitter] = []
        self._by_issuer: dict[str, Transmitter] = {}
        self._started = False
        self._closed = False

        self._dedup: JtiDedupStore | None = None
        if config.dedup.enabled:
            self._dedup = (
                dedup_store
                if dedup_store is not None
                else InMemoryJtiDedupStore(config.dedup.capacity, config.dedup.lease, self._clock)
            )
        self._revocations: TokenRevocationStore = (
            revocation_store
            if revocation_store is not None
            else InMemoryTokenRevocationStore(config.revocation.ttl, self._clock)
        )
        self._acks: PollAckStore = poll_ack_store if poll_ack_store is not None else InMemoryPollAckStore()

        # the issuer of a SET selects the transmitter that verifies it; the transmitters are built
        # after the processor, as their pollers need it, and before anything runs, so the routing
        # verifier is bound once they are
        self._routing = _LateBoundVerifier()
        claim_renewal: timedelta | None = None
        if config.dedup.enabled:
            # a handler may run longer than the lease: the claim is renewed meanwhile
            claim_renewal = config.dedup.lease / 3
        self._processor = Processor(
            self._routing,
            self._dedup,
            ProcessorOptions(
                metrics=self._metrics,
                logger=self._log,
                stream_verifications=self._stream_verification,
                understood_subject_members=_non_empty(config.understood_subject_members, MEMBERS),
                critical_subject_members=self._critical_subject_members,
                claim_renewal=claim_renewal,
            ),
        )
        if config.revocation.enabled:
            self._processor.add_handler(
                TokenRevocationHandler(
                    self._revocations,
                    _non_empty(config.revocation.session_event_types, DEFAULT_SESSION_EVENT_TYPES),
                    config.revocation.user_event_types,
                    self._log,
                )
            )
        if config.session_termination.enabled and session_terminator is not None:
            self._processor.add_handler(
                SessionTerminationHandler(
                    session_terminator,
                    _non_empty(config.session_termination.session_event_types, DEFAULT_SESSION_EVENT_TYPES),
                    _non_empty(
                        config.session_termination.user_event_types, DEFAULT_SESSION_TERMINATION_USER_EVENT_TYPES
                    ),
                    self._log,
                )
            )
        self._processor.add_handler(*handlers)

        all_transmitters = config.all_transmitters()
        verifiers: dict[str, Verifier] = {}
        for name in config.transmitter_names():
            transmitter = self._build_transmitter(name, all_transmitters[name])
            for customize in transmitter_customizers:
                customize(transmitter)
            if transmitter.issuer in self._by_issuer:
                raise ConfigurationError(
                    [f"{CONFIGURATION_SECTION}.transmitters: two transmitters have the issuer {transmitter.issuer}"]
                )
            if transmitter.verifier is None:
                raise ConfigurationError(
                    [f"{CONFIGURATION_SECTION}.transmitters: the transmitter {transmitter.name} has no verifier"]
                )
            self._transmitters.append(transmitter)
            self._by_issuer[transmitter.issuer] = transmitter
            verifiers[transmitter.issuer] = transmitter.verifier
        self._routing.verifier = IssuerRoutingVerifier(verifiers)

        # with one transmitter the header is checked before the SET is even parsed
        if len(self._transmitters) == 1:
            self._push = PushHandler(self._processor, self._transmitters[0].push_authorization_header)
        else:
            self._push = PushHandler.by_issuer(self._processor, self._push_authorization_header)

    def _describe(self, name: str, issuer: str) -> str:
        if name == DEFAULT_TRANSMITTER_NAME:
            return issuer
        return f"'{name}' ({issuer})"

    def _build_transmitter(self, name: str, config: TransmitterConfig) -> Transmitter:
        """Builds every part of the transmitter from its configuration, as ``SsfTransmitterFactory``
        does in .NET and ``transmitter_builder`` in Rust."""
        try:
            return self._build(name, config)
        except (UriPolicyError, ValueError) as error:
            raise ConfigurationError([f"transmitter {name}: {error}"]) from error

    def _build(self, name: str, config: TransmitterConfig) -> Transmitter:
        prefix = _prefix(name)
        issuer = config.transmitter_issuer.strip()
        described = self._describe(name, issuer)
        policy = UriPolicy(allow_insecure_http=config.allow_insecure_http)
        timeout = self._config.http.timeout
        retry = RetryOptions.from_config(self._config.http.retry)
        # the configured headers go with every call, also those for metadata and keys that need no
        # token
        headers: Authorizer = StaticHeaders(config.headers) if config.headers else NoAuthorization()
        metadata = MetadataResolver(
            issuer,
            config.transmitter_metadata_url or None,
            self._client,
            policy,
            self._log,
            timeout=timeout,
            authorizer=headers,
            retry=retry,
        )
        self._log.info(
            "SSF transmitter: metadata is resolved from %s",
            metadata.metadata_urls,
            extra={"transmitter": described, "metadata_urls": metadata.metadata_urls},
        )
        if config.allow_insecure_http:
            self._log.warning(
                "%sallow-insecure-http is on, the SSF transmitter is used without TLS. For development only",
                prefix,
                extra={"transmitter": described},
            )

        tokens = self._token_provider(config, timeout, policy)
        authorizer = Authorizers(headers, BearerToken(tokens))
        stream = ReceiverStream()
        stream_client = StreamClient(metadata, self._client, authorizer, retry=retry, timeout=timeout, policy=policy)
        verification = StreamVerification(lambda: stream.stream_id, logger=self._log)
        transmitter = Transmitter(
            name=name,
            issuer=issuer,
            config=config,
            metadata=metadata,
            tokens=tokens,
            authorizer=authorizer,
            stream_client=stream_client,
            stream=stream,
            verification=verification,
            auto_start_polling=config.poll.auto_startup,
            push_authorization_header=config.push.expected_auth_header.strip(),
        )

        # the keys: fetched like the metadata, with the configured headers but no token (the keys
        # are public), retried and redirected per the same configuration
        client = self._client

        async def fetch_keys(url: str) -> bytes:
            return await get_json(
                client,
                url,
                authorizer=headers,
                policy=policy,
                retry=retry,
                timeout=timeout,
                accept=JWK_SET_ACCEPT,
                endpoint=Endpoint.JWKS,
            )

        async def resolve_jwks_url() -> str:
            resolved = await metadata.resolve()
            if not resolved.jwks_uri:
                raise TransmitterUnavailableError(
                    None,
                    f"the SSF transmitter metadata of {issuer} has no jwks_uri, configure {prefix}transmitter-jwks-url",
                )
            return resolved.jwks_uri

        if config.transmitter_jwks_url:
            policy.check_endpoint(config.transmitter_jwks_url, "the JWK Set URL")
            transmitter.keys = HttpJwkSetSource(
                client, config.transmitter_jwks_url, clock=self._clock, timeout=timeout, fetch=fetch_keys
            )
        else:
            transmitter.keys = HttpJwkSetSource(
                client, resolve_jwks_url, clock=self._clock, timeout=timeout, fetch=fetch_keys
            )

        # the verifier: the audience is the configured one; without one, the audience of the stream
        # once it is registered, and SETs are left unverified (transmitter unavailable) until it is;
        # without a registered stream, any, which the validation allows only with
        # set-validation.allow-any-audience
        subject_compatibility = config.subject_compatibility
        assert subject_compatibility is not None  # validated
        verifier_options = replace(
            default_verifier_options(),
            clock=self._clock,
            min_rsa_key_size=config.set_validation.min_rsa_key_size,
            require_type_header=config.set_validation.require_type_header,
            clock_skew=config.set_validation.clock_skew,
            subject_compatibility=subject_compatibility,
            accepted_algorithms=tuple(algorithm.strip() for algorithm in config.effective_accepted_algorithms),
        )
        audience = config.expected_audience.strip()
        if audience:
            verifier_options = replace(verifier_options, expected_audiences=(audience,))
        elif config.registers_stream:
            any_audience = config.set_validation.allow_any_audience

            def expected_audiences() -> Sequence[str]:
                if stream.configuration is None:
                    raise TransmitterUnavailableError(
                        None,
                        f"the stream at {described} is not registered yet, so the audience of SETs cannot be checked",
                    )
                stream_audience = stream.audience
                if not stream_audience and not any_audience:
                    raise RejectedError(
                        ErrorCode.INVALID_AUDIENCE,
                        f"The stream at {described} has no audience (aud), set {prefix}expected-audience or "
                        f"{prefix}set-validation.allow-any-audience",
                    )
                return stream_audience

            verifier_options = replace(verifier_options, expected_audiences_provider=expected_audiences)
        else:
            self._log.warning(
                "%sexpected-audience is not set, SETs that the transmitter issued for other receivers are accepted "
                "as well",
                prefix,
                extra={"transmitter": described},
            )
        transmitter.verifier = JwtVerifier(issuer, transmitter.keys, verifier_options)

        # the stream
        if config.registers_stream:
            if config.stream.management == STREAM_MANAGEMENT_RECEIVER:
                transmitter.registrar = StreamRegistrar.for_managed_stream(
                    stream_client,
                    stream,
                    _desired_stream(config),
                    delete_on_shutdown=config.stream.delete_on_shutdown,
                    logger=self._log,
                )
            else:
                transmitter.registrar = StreamRegistrar.for_existing_stream(
                    stream_client, stream, config.stream.id.strip(), logger=self._log
                )

        # the poller
        if config.delivery is DeliveryMethod.POLL:
            poller_options = replace(
                PollerOptions.from_config(config.poll),
                ack_store=self._acks,
                metrics=self._metrics,
                transmitter=issuer,
                timeout=timeout,
                policy=policy,
                clock=self._clock,
                logger=self._log,
            )
            endpoint: PollEndpoint
            if config.poll.endpoint_url:
                endpoint = fixed_poll_endpoint(config.poll.endpoint_url)
            else:
                endpoint = lambda: stream.poll_endpoint_url  # noqa: E731 - the Go port passes the method
            transmitter.poller = Poller(client, authorizer, endpoint, self._processor, poller_options)
        return transmitter

    def _token_provider(self, config: TransmitterConfig, timeout: timedelta, policy: UriPolicy) -> TokenProvider:
        token = config.transmitter_access_token.strip()
        if token:
            return FixedToken(token)
        if not config.oauth2.token_uri:
            return NoToken()
        with_body = config.oauth2.authenticates_with_request_body
        options = replace(
            default_client_credentials_options(),
            policy=policy,
            scopes=tuple(config.oauth2.scopes),
            authenticate_with_request_body=bool(with_body),
            expiry_safety_window=config.oauth2.expiry_safety_window,
            additional_parameters=tuple(config.oauth2.additional_parameters.items()),
            timeout=timeout,
            clock=self._clock,
        )
        return ClientCredentialsTokenProvider(
            self._client, config.oauth2.token_uri, config.oauth2.client_id, config.oauth2.client_secret, options
        )

    def _critical_subject_members(self, issuer: str) -> Sequence[str]:
        transmitter = self._by_issuer.get(issuer)
        return transmitter.critical_subject_members if transmitter is not None else []

    def _stream_verification(self, issuer: str) -> Callable[[EventContext], None] | None:
        transmitter = self._by_issuer.get(issuer)
        if transmitter is not None and transmitter.verification is not None:
            return transmitter.verification.check
        return None

    def _push_authorization_header(self, issuer: str) -> str:
        transmitter = self._by_issuer.get(issuer)
        return transmitter.push_authorization_header if transmitter is not None else ""

    # -- what the receiver holds -----------------------------------------------------------------------

    @property
    def config(self) -> ReceiverConfig:
        """The configuration the receiver was built from."""
        return self._config

    @property
    def http_client(self) -> httpx.AsyncClient:
        """The client the transmitters are called with: the given one, or the one of the receiver's
        own that sends through it with the configured ``user-agent``."""
        return self._client

    @property
    def transmitters(self) -> list[Transmitter]:
        """The configured transmitters, the default one first, then by name; a copy."""
        return list(self._transmitters)

    def transmitter(self, name: str) -> Transmitter | None:
        """The transmitter with the given name, ``None`` if there is none."""
        for transmitter in self._transmitters:
            if transmitter.name == name:
                return transmitter
        return None

    def transmitter_by_issuer(self, issuer: str) -> Transmitter | None:
        """The transmitter with the given issuer, ``None`` if there is none."""
        return self._by_issuer.get(issuer)

    def name_of(self, issuer: str) -> str:
        """The short name of a transmitter, for labels such as metric tags, where its issuer would
        be long: the name of the transmitter with the given issuer, or the issuer itself if no
        transmitter has it."""
        transmitter = self._by_issuer.get(issuer)
        return transmitter.name if transmitter is not None else issuer

    @property
    def processor(self) -> Processor:
        """The processor every SET goes through, for a framework without an adapter, or to process
        SETs received another way."""
        return self._processor

    @property
    def push_handler(self) -> PushHandler:
        """The push endpoint; mount it at :attr:`push_endpoint_path` with
        :func:`easyssf.receiver.asgi.push_app` or :func:`easyssf.receiver.wsgi.push_wsgi_app`."""
        return self._push

    @property
    def push_endpoint_path(self) -> str:
        """Where :attr:`push_handler` should be mounted, ``easyssf.receiver.push.endpoint-path``."""
        return self._config.push.endpoint_path

    @property
    def token_revocation_store(self) -> TokenRevocationStore:
        """The store the session-revoked events fill. Give it to
        :class:`~easyssf.receiver.revocation.RevocationMiddleware`."""
        return self._revocations

    @property
    def jti_dedup_store(self) -> JtiDedupStore | None:
        """The de-duplication store, ``None`` if de-duplication is off."""
        return self._dedup

    @property
    def poll_ack_store(self) -> PollAckStore:
        """The store of the acknowledgements the pollers owe."""
        return self._acks

    @property
    def metrics(self) -> Metrics:
        """What the receiver records with."""
        return self._metrics

    @property
    def logger(self) -> logging.Logger:
        """Where the receiver logs."""
        return self._log

    @property
    def started(self) -> bool:
        """Whether :meth:`start` was called and :meth:`stop` was not."""
        return self._started

    @property
    def closed(self) -> bool:
        """Whether :meth:`aclose` was called: the receiver's own HTTP clients are closed and it
        cannot start again."""
        return self._closed

    # -- lifecycle ---------------------------------------------------------------------------------------

    async def start(self) -> None:
        """Registers the streams and starts polling in the background, for every transmitter
        configured for it; it returns at once. Calling it again while started has no effect;
        after :meth:`stop`, :meth:`start` starts the work again, after :meth:`aclose` it cannot.
        When a transmitter fails to start, the ones started before it are stopped again and the
        receiver is left as before the call, so that a later :meth:`start` tries again.

        Raises:
            RuntimeError: when the receiver was closed.
        """
        if self._closed:
            raise RuntimeError("The SSF receiver was closed, a closed receiver cannot start again")
        if self._started:
            return
        self._started = True
        names: list[str] = []
        try:
            for transmitter in self._transmitters:
                await transmitter.start()
                names.append(str(transmitter))
        except BaseException:
            # the transmitters started so far would keep running, unreachable for a stop, and the
            # next start would do nothing: roll back to the state before the call, the failed one
            # included, as its registrar may run although its poller did not start
            self._started = False
            for transmitter in reversed(self._transmitters[: len(names) + 1]):
                try:
                    await transmitter.stop()
                except Exception as error:  # the failure of the start is the one to raise
                    self._log.warning(
                        "Could not stop the transmitter %s after the receiver failed to start: %s",
                        transmitter,
                        error,
                        extra={"transmitter": transmitter.issuer},
                    )
            raise
        self._log.info(
            "SSF receiver started with %d transmitter(s): %s",
            len(names),
            ", ".join(names),
            extra={"count": len(names), "transmitters": names},
        )

    async def stop(self) -> None:
        """Ends the background work: pollers send the acknowledgements they owe, registrars delete
        streams configured for it."""
        if not self._started:
            return
        self._started = False
        for transmitter in self._transmitters:
            await transmitter.stop()

    async def aclose(self) -> None:
        """Stops the receiver (:meth:`stop`) and closes the HTTP clients it made itself: the one
        of its own when no ``http_client`` was given, and the one that adds the configured
        ``user-agent``. A given client is the caller's and stays open. A closed receiver cannot
        start again; ``async with receiver:`` closes it on exit. Calling it again has no effect."""
        await self.stop()
        if self._closed:
            return
        self._closed = True
        for client in reversed(self._owned_clients):
            await client.aclose()

    async def __aenter__(self) -> Receiver:
        await self.start()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def health(self) -> ReceiverHealth:
        """The health of the receiver as of now, from what it already knows; no transmitter is
        called."""
        status = HealthStatus.HEALTHY
        transmitters: list[TransmitterHealth] = []
        for transmitter in self._transmitters:
            health = await transmitter.health()
            status = status.worse(health.status)
            transmitters.append(health)
        if status is HealthStatus.HEALTHY:
            description = "In contact with the SSF transmitter(s)"
        elif status is HealthStatus.UNHEALTHY:
            description = "An SSF transmitter cannot be polled or its stream cannot be used"
        else:
            description = "No contact with an SSF transmitter yet"
        return ReceiverHealth(status, description, tuple(transmitters))

    def __repr__(self) -> str:
        names = [str(transmitter) for transmitter in self._transmitters]
        return f"Receiver(transmitters={names!r}, started={self._started}, closed={self._closed})"


class _LateBoundVerifier:
    """A :class:`~easyssf.receiver.verifier.Verifier` that delegates to the
    :class:`~easyssf.receiver.verifier.IssuerRoutingVerifier` bound once the transmitters are
    built: the processor needs its verifier before the pollers, which need the processor, are
    built, and the routing verifier copies its mapping."""

    __slots__ = ("verifier",)

    def __init__(self) -> None:
        self.verifier: Verifier | None = None

    async def verify(self, encoded_set: str) -> EventToken:
        if self.verifier is None:
            raise TransmitterUnavailableError(None, "the SSF receiver is not assembled yet")
        return await self.verifier.verify(encoded_set)

    def __repr__(self) -> str:
        return repr(self.verifier)


def _desired_stream(config: TransmitterConfig) -> StreamConfiguration:
    """The stream the receiver wants at the transmitter, from its configuration."""
    events = config.stream.events_requested
    if config.delivery is DeliveryMethod.POLL:
        return StreamConfiguration.poll(events, config.stream.description)
    return StreamConfiguration.push(
        config.push.delivery_endpoint_url,  # validated
        config.push.expected_auth_header.strip(),
        events,
        config.stream.description,
    )


def _non_empty(values: Sequence[str], fallback: Sequence[str]) -> Sequence[str]:
    return values if values else fallback


def _prefix(name: str) -> str:
    if name == DEFAULT_TRANSMITTER_NAME:
        return CONFIGURATION_SECTION + "."
    return f"{CONFIGURATION_SECTION}.transmitters.{name}."


class _ThroughClient(httpx.AsyncBaseTransport):
    """A transport that sends every request through the client of the application, so that a
    client of the receiver's own adds to it without changing it: the copy of the client with a
    wrapping transport of the Go port. The application's mounts, hooks, authentication and
    transport apply; redirects are never followed here, the receiver follows them by hand."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._client.send(request, stream=True, follow_redirects=False)


def _with_user_agent(client: httpx.AsyncClient, user_agent: str) -> httpx.AsyncClient:
    """A client that sends through ``client`` with the ``User-Agent`` header set to
    ``user_agent`` on every request that has none of its own."""
    return httpx.AsyncClient(transport=_ThroughClient(client), headers={"User-Agent": user_agent})
