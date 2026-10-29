"""The configuration of the receiver: the keys of the Spring Boot starter and the .NET options in
kebab-case under ``easyssf.receiver``, as in the Go and Rust ports. A dataclass tree with the
defaults of the Java starter; :meth:`ReceiverConfig.from_mapping` binds it from any mapping (a
parsed YAML, TOML or JSON file) and :meth:`ReceiverConfig.validate` reports every failure at once
without changing anything. Durations are ``timedelta`` values bound from ``"30s"``, ``"24h"``,
``"1h30m"`` or a bare number of seconds.
"""

from __future__ import annotations

import difflib
import re
import typing
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import timedelta
from typing import Any, Final, TypeVar
from urllib.parse import urlsplit

from easyssf.core import DeliveryMethod, SubjectCompatibilityMode, event_types

from .errors import ConfigurationError

__all__ = [
    "CONFIGURATION_SECTION",
    "DEFAULT_SCIM_ATTRIBUTE_CLAIMS",
    "DEFAULT_TRANSMITTER_NAME",
    "SCHEMA_ALWAYS",
    "SCHEMA_EMBEDDED",
    "SCHEMA_NEVER",
    "STREAM_MANAGEMENT_NONE",
    "STREAM_MANAGEMENT_RECEIVER",
    "DataConfig",
    "DedupConfig",
    "HttpConfig",
    "OAuth2Config",
    "PollConfig",
    "PushConfig",
    "RateLimitConfig",
    "ReceiverConfig",
    "RetryConfig",
    "RevocationConfig",
    "SessionTerminationConfig",
    "SetValidationConfig",
    "StreamConfig",
    "TransmitterConfig",
    "default_receiver_config",
    "default_transmitter_config",
    "format_duration",
    "parse_duration",
    "valid_table_prefix",
]

CONFIGURATION_SECTION: Final = "easyssf.receiver"
"""The key the settings are bound from."""
DEFAULT_TRANSMITTER_NAME: Final = "default"
"""The name of the transmitter configured at ``easyssf.receiver``."""

STREAM_MANAGEMENT_NONE: Final = "none"
"""The receiver does not touch the stream; the transmitter is configured out of band."""
STREAM_MANAGEMENT_RECEIVER: Final = "receiver"
"""The receiver reuses, updates or creates the stream it wants."""

SCHEMA_EMBEDDED: Final = "embedded"
"""Creates the tables only in an embedded database (SQLite), which has no migration tool of its
own. The default."""
SCHEMA_ALWAYS: Final = "always"
"""Creates a missing table and adds the columns of this release to a table of an older one."""
SCHEMA_NEVER: Final = "never"
"""Never touches the tables: the application creates them with the SQL that ships with the
stores. A missing or outdated table fails the start with the statements to run."""

DEFAULT_SCIM_ATTRIBUTE_CLAIMS: Final[tuple[tuple[str, str], ...]] = (
    ("externalId", "sub"),
    ("id", "sub"),
    ("userName", "preferred_username"),
)
"""The attributes of a ``scim`` subject and the claims of the logged-in user they are matched by
when none are configured (``session-termination.scim-attribute-claims``)."""

_DEFAULT_HTTP_TIMEOUT: Final = timedelta(seconds=5)
_DEFAULT_DEDUP_LEASE: Final = timedelta(seconds=60)
_SUPPORTED_ALGORITHMS: Final = (
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
)
_DURATION_UNITS: Final[dict[str, float]] = {
    "ns": 1e-9,
    "us": 1e-6,
    "µs": 1e-6,
    "μs": 1e-6,
    "ms": 1e-3,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
}
_DURATION_PART: Final = re.compile(r"(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)")


def parse_duration(value: str | int | float | timedelta) -> timedelta:
    """A duration as Go's ``time.ParseDuration`` reads it (``"30s"``, ``"1h30m"``, ``"250ms"``,
    ``"-1.5h"``; the units ``ns``, ``us``, ``ms``, ``s``, ``m`` and ``h``), a bare number of
    seconds, or a ``timedelta`` as is.

    Raises:
        ValueError: for anything else, a ``bool`` included.
    """
    if isinstance(value, timedelta):
        return value
    if isinstance(value, bool):
        raise ValueError(f"not a duration: {value!r}")
    if isinstance(value, int | float):
        return timedelta(seconds=value)
    if not isinstance(value, str):
        raise ValueError(f"not a duration: {value!r}")
    text = value.strip()
    sign = 1
    if text[:1] in ("-", "+"):
        sign = -1 if text[0] == "-" else 1
        text = text[1:]
    if not text:
        raise ValueError(f"not a duration: {value!r}")
    if re.fullmatch(r"\d+(?:\.\d*)?|\.\d+", text):
        return timedelta(seconds=sign * float(text))
    seconds = 0.0
    position = 0
    while position < len(text):
        part = _DURATION_PART.match(text, position)
        if part is None:
            raise ValueError(f"not a duration: {value!r}")
        seconds += float(part.group(1)) * _DURATION_UNITS[part.group(2)]
        position = part.end()
    return timedelta(seconds=sign * seconds)


def format_duration(duration: timedelta) -> str:
    """A duration as Go's ``time.Duration`` prints it: ``"0s"``, ``"1m30s"``, ``"1h0m0s"``,
    ``"250ms"``; what :func:`parse_duration` reads back."""
    total = duration.total_seconds()
    if total == 0:
        return "0s"
    sign = "-" if total < 0 else ""
    total = abs(total)
    if total < 1:
        micros = round(total * 1_000_000)
        if micros % 1000 == 0 and micros > 0:
            return f"{sign}{micros // 1000}ms"
        return f"{sign}{micros}us" if micros > 0 else f"{sign}{round(total * 1e9)}ns"
    hours, rest = divmod(total, 3600)
    minutes, seconds = divmod(rest, 60)
    seconds_text = f"{seconds:.6f}".rstrip("0").rstrip(".") if seconds != int(seconds) else str(int(seconds))
    if hours:
        return f"{sign}{int(hours)}h{int(minutes)}m{seconds_text}s"
    if minutes:
        return f"{sign}{int(minutes)}m{seconds_text}s"
    return f"{sign}{seconds_text}s"


def valid_table_prefix(prefix: str) -> bool:
    """Whether a table prefix consists of letters, digits, ``_`` and ``.`` only."""
    return all(c.isascii() and (c.isalnum() or c in "_.") for c in prefix)


@dataclass
class OAuth2Config:
    """The client credentials grant for the transmitter's endpoints."""

    token_uri: str = ""
    """The token endpoint to obtain access tokens from with the client credentials grant."""
    client_id: str = ""
    """The client id of this receiver."""
    client_secret: str = field(default="", repr=False)
    """The client secret of this receiver."""
    scopes: list[str] = field(default_factory=list)
    """The scopes to request."""
    client_authentication_method: str = "client_secret_basic"
    """How the client authenticates at the token endpoint (RFC 6749, section 2.3.1):
    ``client_secret_basic`` (also ``basic``, the default) or ``client_secret_post`` (also ``post``)."""
    expiry_safety_window: timedelta = timedelta(seconds=30)
    """How long before its expiry an access token is renewed; never more than a quarter of the
    token's lifetime."""
    additional_parameters: dict[str, str] = field(default_factory=dict)
    """Form parameters to send with the token request in addition to the grant."""

    @property
    def authenticates_with_request_body(self) -> bool | None:
        """Whether the client credentials are sent in the request body (``client_secret_post``)
        rather than with HTTP basic authentication; ``None`` for an unknown method."""
        method = self.client_authentication_method.strip().lower()
        if method in ("", "basic", "client_secret_basic"):
            return False
        if method in ("post", "client_secret_post"):
            return True
        return None


@dataclass
class StreamConfig:
    """The stream at the transmitter."""

    management: str = STREAM_MANAGEMENT_NONE
    """``none`` (the default) or ``receiver``."""
    id: str = ""
    """The stream to look up, if the transmitter assigned one out of band."""
    events_requested: list[str] = field(default_factory=list)
    """The event types to request (alias or URI)."""
    description: str = ""
    """The description of the stream."""
    delete_on_shutdown: bool = False
    """Deletes a stream the receiver created when it shuts down."""


@dataclass
class RateLimitConfig:
    """How the poller backs off on 429 and ``Retry-After``."""

    fallback_backoff: timedelta = timedelta(0)
    """How long to pause after a 429 without a ``Retry-After`` header; zero polls again at the
    regular interval."""
    max_backoff: timedelta = timedelta(minutes=5)
    """The longest pause a ``Retry-After`` header or the fallback can cause, 5 minutes by default."""


@dataclass
class PollConfig:
    """Poll delivery (RFC 8936)."""

    endpoint_url: str = ""
    """The poll endpoint of the stream, if the stream is not looked up or registered by the receiver."""
    auto_startup: bool = True
    """Whether polling starts with the receiver; ``True`` by default."""
    interval: timedelta = timedelta(seconds=10)
    """The time between two polls, 10 seconds by default."""
    initial_delay: timedelta = timedelta(0)
    """How long the first poll waits after the start."""
    max_events: int = 100
    """The maximum number of SETs fetched with one request, 100 by default."""
    long_polling: bool = False
    """Asks the transmitter to hold a request until SETs are available (RFC 8936, section 2.5)."""
    long_polling_hold: timedelta = timedelta(seconds=30)
    """How long the transmitter holds a request, 30 seconds by default."""
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    """How the poller backs off on 429 and ``Retry-After``."""


@dataclass
class SetValidationConfig:
    """How SETs are verified."""

    accepted_algorithms: list[str] = field(default_factory=list)
    """The JWS algorithms accepted; ``RS256`` while empty."""
    min_rsa_key_size: int = 2048
    """The minimum RSA key size in bits, 0 for any."""
    require_type_header: bool = True
    """Requires the ``typ`` header of ``secevent+jwt``."""
    subject_compatibility: str = "strict"
    """``strict`` (the default) or ``legacy``."""
    clock_skew: timedelta = timedelta(minutes=1)
    """How far in the future a SET may be issued."""
    allow_any_audience: bool = False
    """Accepts SETs the transmitter issued for other receivers as well."""


@dataclass
class PushConfig:
    """Push delivery (RFC 8935)."""

    expected_auth_header: str = field(default="", repr=False)
    """The ``Authorization`` header the transmitter has to send, for example ``Bearer <secret>``.
    Recommended."""
    delivery_endpoint_url: str = ""
    """The URL under which the transmitter reaches the push endpoint of this application, for a
    stream the receiver registers."""
    endpoint_path: str = "/ssf/push"
    """Where the push endpoint is mounted, ``/ssf/push`` by default."""


@dataclass
class TransmitterConfig:
    """The settings of one transmitter."""

    transmitter_issuer: str = ""
    """The issuer of the transmitter, the ``iss`` claim of its SETs. Required."""
    transmitter_metadata_url: str = ""
    """Where the transmitter publishes its metadata, if not at the locations derived from the issuer."""
    transmitter_jwks_url: str = ""
    """Where the transmitter publishes its keys, if not in its metadata."""
    allow_insecure_http: bool = False
    """Accepts ``http`` for the issuer and the endpoints on hosts other than loopback. For
    development only."""
    expected_audience: str = ""
    """The audience the SETs must be addressed to, this receiver. Learned from the stream when the
    receiver registers or looks it up."""
    delivery_method: str = "push"
    """``push`` (the default) or ``poll``."""
    transmitter_access_token: str = field(default="", repr=False)
    """A fixed bearer token for the management and poll endpoints, instead of the client
    credentials grant of OAuth2."""
    oauth2: OAuth2Config = field(default_factory=OAuth2Config)
    """Obtains access tokens for the management and poll endpoints."""
    headers: dict[str, str] = field(default_factory=dict, repr=False)
    """Headers sent with every call to the transmitter besides the bearer token: an API key, a
    tenant, whatever the transmitter wants."""
    stream: StreamConfig = field(default_factory=StreamConfig)
    """The stream at the transmitter."""
    poll: PollConfig = field(default_factory=PollConfig)
    """Poll delivery."""
    set_validation: SetValidationConfig = field(default_factory=SetValidationConfig)
    """How SETs are verified."""
    push: PushConfig = field(default_factory=PushConfig)
    """Push delivery."""

    @property
    def delivery(self) -> DeliveryMethod | None:
        """The configured delivery method; ``None`` for an unknown name."""
        name = self.delivery_method.strip().lower()
        return DeliveryMethod.PUSH if name == "" else DeliveryMethod.from_name(name)

    @property
    def registers_stream(self) -> bool:
        """Whether the receiver looks the stream up or registers it, and learns the audience from it."""
        return self.stream.management == STREAM_MANAGEMENT_RECEIVER or bool(self.stream.id.strip())

    @property
    def subject_compatibility(self) -> SubjectCompatibilityMode | None:
        """The configured mode; ``None`` for an unknown name."""
        name = self.set_validation.subject_compatibility.strip().lower()
        if name in ("", "strict"):
            return SubjectCompatibilityMode.STRICT
        if name == "legacy":
            return SubjectCompatibilityMode.LEGACY
        return None

    @property
    def effective_accepted_algorithms(self) -> list[str]:
        """The accepted algorithms, ``RS256`` while none are configured."""
        return list(self.set_validation.accepted_algorithms) or ["RS256"]

    def validate(self, name: str = DEFAULT_TRANSMITTER_NAME) -> list[str]:
        """Checks the settings of the transmitter named ``name``. Returns what is wrong, empty if
        the settings are usable."""
        prefix = _prefix(name)
        failures: list[str] = []
        if not self.transmitter_issuer.strip():
            return [prefix + "transmitter-issuer: The issuer of the SSF transmitter must be configured"]
        issuer_failure = _check_issuer(self.transmitter_issuer, self.allow_insecure_http)
        if issuer_failure:
            failures.append(prefix + "transmitter-issuer: " + issuer_failure)
        for key, value, description in (
            ("transmitter-metadata-url", self.transmitter_metadata_url, "transmitter metadata URL"),
            ("transmitter-jwks-url", self.transmitter_jwks_url, "the JWK Set URL"),
            ("oauth2.token-uri", self.oauth2.token_uri, "the token endpoint"),
            ("poll.endpoint-url", self.poll.endpoint_url, "the poll endpoint"),
        ):
            if not value:
                continue
            endpoint_failure = _check_endpoint(value, description, self.allow_insecure_http)
            if endpoint_failure:
                failures.append(prefix + key + ": " + endpoint_failure)
        for algorithm in self.effective_accepted_algorithms:
            if algorithm.strip() not in _SUPPORTED_ALGORITHMS:
                failures.append(
                    prefix + "set-validation.accepted-algorithms: Not an asymmetric signature algorithm: " + algorithm
                )
        delivery = self.delivery
        if delivery is None:
            failures.append(prefix + "delivery-method: must be push or poll")
        if self.subject_compatibility is None:
            failures.append(prefix + "set-validation.subject-compatibility: must be strict or legacy")
        if (
            not self.expected_audience.strip()
            and not self.registers_stream
            and not self.set_validation.allow_any_audience
        ):
            failures.append(
                f"{prefix}expected-audience: The audience of the SETs must be known: set {prefix}expected-audience, "
                f'or let the receiver look the stream up ({prefix}stream.management = "receiver" or '
                f"{prefix}stream.id), "
                f"or set {prefix}set-validation.allow-any-audience = true to accept SETs the transmitter issued for "
                "other receivers as well"
            )
        if self.oauth2.authenticates_with_request_body is None:
            failures.append(
                prefix + "oauth2.client-authentication-method: must be client_secret_basic or client_secret_post"
            )
        for key, value in (
            ("oauth2.token-uri", self.oauth2.token_uri),
            ("poll.endpoint-url", self.poll.endpoint_url),
            ("push.delivery-endpoint-url", self.push.delivery_endpoint_url),
        ):
            if value and not _is_absolute(value):
                failures.append(f"{prefix}{key}: must be an absolute URI with a host: {value}")
        if (
            not self.transmitter_access_token.strip()
            and self.oauth2.token_uri
            and (not self.oauth2.client_id.strip() or not self.oauth2.client_secret.strip())
        ):
            failures.append(
                f"{prefix}oauth2.client-id: {prefix}oauth2.client-id and {prefix}oauth2.client-secret are required to "
                f"obtain access tokens from {prefix}oauth2.token-uri"
            )
        if (
            self.stream.management == STREAM_MANAGEMENT_RECEIVER
            and delivery is DeliveryMethod.PUSH
            and not self.push.delivery_endpoint_url
        ):
            failures.append(
                prefix + "push.delivery-endpoint-url: A stream managed by the receiver needs the URL under which the "
                "transmitter reaches the push endpoint of this application"
            )
        if delivery is DeliveryMethod.POLL:
            if not self.poll.endpoint_url and not self.registers_stream:
                failures.append(
                    f"{prefix}poll.endpoint-url: POLL delivery needs the poll endpoint of the stream: set "
                    f'{prefix}poll.endpoint-url, {prefix}stream.id or {prefix}stream.management = "receiver"'
                )
            if (
                self.poll.interval <= timedelta(0)
                or self.poll.max_events < 1
                or self.poll.rate_limit.max_backoff <= timedelta(0)
                or (self.poll.long_polling and self.poll.long_polling_hold <= timedelta(0))
            ):
                failures.append(
                    prefix + "poll: interval, long-polling-hold and rate-limit.max-backoff must be positive, "
                    "max-events at least 1"
                )
        return failures


@dataclass
class RetryConfig:
    """The retries of calls to the transmitter, see ``RetryOptions``."""

    max_retries: int = 2
    """How many times a failed call is tried again, 2 by default; 0 never."""
    initial_backoff: timedelta = timedelta(milliseconds=250)
    """The delay before the first retry, a quarter of a second by default; it doubles with every retry."""
    max_backoff: timedelta = timedelta(seconds=5)
    """The longest delay between two tries, also for a ``Retry-After`` header, 5 seconds by default."""


@dataclass
class HttpConfig:
    """The calls to the transmitter."""

    timeout: timedelta = _DEFAULT_HTTP_TIMEOUT
    """How long a call to the transmitter waits for its response, 5 seconds by default. A long poll
    waits for its hold time plus a margin regardless."""
    user_agent: str = ""
    """The ``User-Agent`` header to send with calls to the transmitter; the one of httpx when empty."""
    retry: RetryConfig = field(default_factory=RetryConfig)
    """How a management, metadata or JWK Set call that fails with a connection error or 408, 429,
    500, 502, 503 or 504 is tried again. Poll requests are not retried, the poller has its interval."""


@dataclass
class DedupConfig:
    """The de-duplication of SETs by ``jti``."""

    enabled: bool = True
    """Whether SETs that were already processed are skipped."""
    capacity: int = 10_000
    """The number of SET identifiers the in-memory store remembers."""
    retention: timedelta = timedelta(days=7)
    """How long a durable store remembers a processed SET, 7 days by default. Has to cover the time
    the transmitter keeps trying to deliver a SET."""
    lease: timedelta = _DEFAULT_DEDUP_LEASE
    """How long a SET counts as being handled by the instance that claimed it without renewing the
    claim, which it does every third of this time while its handlers run."""


@dataclass
class RevocationConfig:
    """The revocation of tokens and sessions by security events."""

    enabled: bool = True
    """Whether revocations are recorded."""
    session_event_types: list[str] = field(default_factory=list)
    """The event types (alias or URI) that revoke the session they name, or all tokens of the user
    issued up to the event if they name none; ``CaepSessionRevoked`` when empty."""
    user_event_types: list[str] = field(default_factory=list)
    """The event types (alias or URI) that revoke all tokens of the user they name; none by default."""
    ttl: timedelta = timedelta(hours=24)
    """How long a revocation is remembered, at least the maximum lifetime of the access tokens and
    sessions it guards; 24 hours by default."""


@dataclass
class SessionTerminationConfig:
    """The termination of server-side sessions by security events, through the
    ``SessionTerminator`` given to the receiver. Without one, nothing is terminated."""

    enabled: bool = True
    """Whether local sessions are terminated when a matching event is received and a session
    terminator is given."""
    session_event_types: list[str] = field(default_factory=list)
    """The event types (alias or URI) that terminate the sessions identified by the event's subject
    (session id and / or user); ``CaepSessionRevoked`` when empty."""
    user_event_types: list[str] = field(default_factory=list)
    """The event types (alias or URI) that terminate all sessions of the user identified by the
    event's subject; ``CaepCredentialChange`` when empty."""
    scim_attribute_claims: dict[str, str] = field(default_factory=dict)
    """The attributes of the ``scim`` subject of a SCIM Event (RFC 9967) and the claim of the
    logged-in user each is compared with, e.g. ``externalId: sub``;
    :data:`DEFAULT_SCIM_ATTRIBUTE_CLAIMS` when empty."""

    @property
    def effective_scim_attribute_claims(self) -> list[tuple[str, str]]:
        """The attribute-claim pairs a ``scim`` subject is matched by: the configured ones, sorted
        by attribute, or :data:`DEFAULT_SCIM_ATTRIBUTE_CLAIMS` if none are configured."""
        if not self.scim_attribute_claims:
            return list(DEFAULT_SCIM_ATTRIBUTE_CLAIMS)
        return sorted(self.scim_attribute_claims.items())


@dataclass
class DataConfig:
    """The database stores of ``easyssf-receiver-sqlalchemy``, which keep processed SETs,
    revocations and the acknowledgements a poller owes in the database of the application, shared
    by all its instances."""

    enabled: bool = True
    """Whether the database stores are used. ``False`` keeps the state of the receiver in memory
    although the stores were added, for example in a test environment."""
    initialize_schema: str = SCHEMA_EMBEDDED
    """When to create the tables if they do not exist: ``embedded`` (the default), ``always`` or
    ``never``."""
    table_prefix: str = "EASYSSF_"
    """The prefix of the names of the tables, ``EASYSSF_`` by default. Letters, digits, ``_`` and
    ``.`` (for a schema) only."""
    cleanup_interval: timedelta = timedelta(minutes=15)
    """How often expired rows are purged. The stores also purge when they are written to; zero
    turns the periodic cleanup off. 15 minutes by default."""
    ack_retention: timedelta = timedelta(days=7)
    """How long the store keeps an acknowledgement a polling receiver owes its transmitter if no
    poll request manages to deliver it. 7 days by default."""
    ack_delete_batch_size: int = 100
    """How many acknowledgements one ``DELETE`` of the store removes at once; databases limit the
    parameters of a statement. 100 by default."""

    @property
    def schema_initialization(self) -> str | None:
        """The configured mode; ``None`` for an unknown name."""
        mode = self.initialize_schema.strip().lower()
        if mode in ("", SCHEMA_EMBEDDED):
            return SCHEMA_EMBEDDED
        if mode in (SCHEMA_ALWAYS, SCHEMA_NEVER):
            return mode
        return None


@dataclass
class ReceiverConfig(TransmitterConfig):
    """The configuration of the receiver, bound from ``easyssf.receiver``. The settings of the
    default transmitter sit directly under it (the inherited fields), further transmitters under
    ``transmitters``."""

    enabled: bool = True
    """Whether the SSF receiver is enabled."""
    event_aliases: dict[str, str] = field(default_factory=dict)
    """Aliases for event type URIs, e.g. ``AcmeLogin = https://events.acme.example/login``, usable
    wherever an event type is named. They add to the built-in aliases and cannot redefine one."""
    understood_subject_members: list[str] = field(default_factory=list)
    """The members of a complex subject the application interprets. A SET with a member a
    transmitter declared critical (``critical_subject_members``) that is not listed here is
    rejected. Empty, the default, means the members ``Subject`` gives access to."""
    transmitters: dict[str, TransmitterConfig] = field(default_factory=dict)
    """Further transmitters by name, each with the settings of a transmitter. The settings at
    ``easyssf.receiver`` configure the transmitter named ``default``."""
    http: HttpConfig = field(default_factory=HttpConfig)
    """Outbound HTTP calls to the transmitter."""
    dedup: DedupConfig = field(default_factory=DedupConfig)
    """The de-duplication of SETs by ``jti``."""
    revocation: RevocationConfig = field(default_factory=RevocationConfig)
    """The revocation of access tokens and sessions by security events."""
    session_termination: SessionTerminationConfig = field(default_factory=SessionTerminationConfig)
    """The termination of server-side sessions by security events."""
    data: DataConfig = field(default_factory=DataConfig)
    """The database stores, when the application uses them."""
    binding_failures: list[str] = field(default_factory=list, repr=False, compare=False, metadata={"internal": True})
    """What :meth:`from_mapping` could not bind, a value of the wrong type or a key it does not
    know, reported by :meth:`validate`; empty for a configuration built in code."""

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any], *, strict: bool = True) -> ReceiverConfig:
        """Binds the configuration from the mapping under ``easyssf.receiver`` of a parsed YAML,
        TOML or JSON file: kebab-case keys (snake_case is accepted too), nested mappings for the
        sections, durations as ``"30s"``, ``"24h"`` or seconds. Nothing is raised here: a value
        of the wrong type keeps the default, and it is reported by :meth:`validate` with its key.

        Args:
            mapping: the settings under ``easyssf.receiver``.
            strict: whether a key the configuration does not know is a failure too, as a typo in
                ``push.expected-auth-header`` would otherwise leave the push endpoint without the
                header it expects; :meth:`validate` reports it with the key it resembles. ``False``
                ignores unknown keys, as the Spring Boot, .NET and Go bindings do, for a mapping
                that carries settings of other software.
        """
        failures: list[str] = []
        config = _bind(cls, mapping, CONFIGURATION_SECTION, failures, strict)
        config.binding_failures = failures
        return config

    def to_mapping(self) -> dict[str, Any]:
        """The configuration as a mapping with kebab-case keys and durations as strings, what
        :meth:`from_mapping` reads back."""
        return _unbind(self)

    def all_transmitters(self) -> dict[str, TransmitterConfig]:
        """The transmitters by name: ``default`` for the settings at ``easyssf.receiver``, if it
        names an issuer, and the ones under ``transmitters``; ``default`` first."""
        all_transmitters: dict[str, TransmitterConfig] = {}
        if self.transmitter_issuer.strip():
            all_transmitters[DEFAULT_TRANSMITTER_NAME] = self.default_transmitter()
        all_transmitters.update(self.transmitters)
        return all_transmitters

    def default_transmitter(self) -> TransmitterConfig:
        """The settings at ``easyssf.receiver`` as a :class:`TransmitterConfig`, the transmitter
        named ``default``; a shallow copy, the sections are shared."""
        return TransmitterConfig(**{f.name: getattr(self, f.name) for f in fields(TransmitterConfig)})

    def transmitter_names(self) -> list[str]:
        """The names of the configured transmitters, sorted, ``default`` first."""
        all_transmitters = self.all_transmitters()
        names = sorted(name for name in all_transmitters if name != DEFAULT_TRANSMITTER_NAME)
        if DEFAULT_TRANSMITTER_NAME in all_transmitters:
            names.insert(0, DEFAULT_TRANSMITTER_NAME)
        return names

    def validate(self, name: str = DEFAULT_TRANSMITTER_NAME) -> list[str]:
        """Checks the configuration the way the receiver does when it builds its parts and raises
        everything that is wrong at once. Pure: registers no alias, changes nothing.

        Args:
            name: unused, the signature of :meth:`TransmitterConfig.validate`; the default
                transmitter is checked under its own name.

        Raises:
            ConfigurationError: with every failure, each prefixed with the key of the setting.
        """
        failures = list(self.binding_failures)
        if not self.enabled:
            if failures:
                raise ConfigurationError(failures)
            return []
        transmitters = self.all_transmitters()
        if not transmitters:
            failures.append(
                f"{CONFIGURATION_SECTION}.transmitter-issuer: The issuer of the SSF transmitter must be configured, "
                f"or transmitters under {CONFIGURATION_SECTION}.transmitters. Set {CONFIGURATION_SECTION}.enabled = "
                "false to switch the receiver off"
            )
        if DEFAULT_TRANSMITTER_NAME in self.transmitters and self.transmitter_issuer.strip():
            failures.append(
                f"{CONFIGURATION_SECTION}.transmitters.{DEFAULT_TRANSMITTER_NAME}: The transmitter named "
                f"'{DEFAULT_TRANSMITTER_NAME}' is the one configured at {CONFIGURATION_SECTION}, it cannot be "
                f"configured under {CONFIGURATION_SECTION}.transmitters as well"
            )
        by_issuer: dict[str, str] = {}
        for transmitter_name in self.transmitter_names():
            transmitter = transmitters[transmitter_name]
            if not transmitter_name.strip():
                failures.append(
                    f"{CONFIGURATION_SECTION}.transmitters: A transmitter under {CONFIGURATION_SECTION}.transmitters "
                    "needs a name"
                )
            failures.extend(transmitter.validate(transmitter_name))
            issuer = transmitter.transmitter_issuer.strip()
            if issuer:
                if issuer in by_issuer:
                    failures.append(
                        f"{CONFIGURATION_SECTION}.transmitters: The transmitters '{transmitter_name}' and "
                        f"'{by_issuer[issuer]}' have the same issuer {issuer}"
                    )
                by_issuer[issuer] = transmitter_name
        path = self.push.endpoint_path
        if not path.strip() or not path.startswith("/"):
            failures.append(
                f"{CONFIGURATION_SECTION}.push.endpoint-path: The path of the push endpoint must start with '/' "
                f"(value: '{path}')"
            )
        for alias, uri in self.event_aliases.items():
            try:
                event_types.check_alias(alias, uri)
            except ValueError as error:
                failures.append(f"{CONFIGURATION_SECTION}.event-aliases.{alias}: {error}")
        if self.http.timeout <= timedelta(0):
            failures.append(f"{CONFIGURATION_SECTION}.http.timeout: must be positive")
        retry = self.http.retry
        if retry.max_retries < 0 or retry.initial_backoff < timedelta(0) or retry.max_backoff < timedelta(0):
            failures.append(
                f"{CONFIGURATION_SECTION}.http.retry: max-retries, initial-backoff and max-backoff must not be negative"
            )
        if self.dedup.enabled and (
            self.dedup.capacity < 1 or self.dedup.lease <= timedelta(0) or self.dedup.retention <= timedelta(0)
        ):
            failures.append(f"{CONFIGURATION_SECTION}.dedup: capacity must be at least 1, lease and retention positive")
        if self.revocation.enabled and self.revocation.ttl <= timedelta(0):
            failures.append(f"{CONFIGURATION_SECTION}.revocation.ttl: must be positive")
        if not valid_table_prefix(self.data.table_prefix):
            failures.append(
                f"{CONFIGURATION_SECTION}.data.table-prefix: may only consist of letters, digits, '_' and '.' "
                f"(value: '{self.data.table_prefix}')"
            )
        if self.data.schema_initialization is None:
            failures.append(f"{CONFIGURATION_SECTION}.data.initialize-schema: must be embedded, always or never")
        if self.data.ack_retention <= timedelta(0) or self.data.ack_delete_batch_size < 1:
            failures.append(f"{CONFIGURATION_SECTION}.data: ack-retention and ack-delete-batch-size must be positive")
        if failures:
            raise ConfigurationError(failures)
        return []


def default_transmitter_config() -> TransmitterConfig:
    """The defaults of a transmitter, the ones of the Java starter."""
    return TransmitterConfig()


def default_receiver_config() -> ReceiverConfig:
    """The defaults of the receiver."""
    return ReceiverConfig()


def _prefix(name: str) -> str:
    if name == DEFAULT_TRANSMITTER_NAME:
        return CONFIGURATION_SECTION + "."
    return f"{CONFIGURATION_SECTION}.transmitters.{name}."


def _is_absolute(value: str) -> bool:
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return bool(parts.scheme) and bool(parts.netloc)


def _check_issuer(issuer: str, allow_insecure_http: bool) -> str:
    """What is wrong with the issuer of a transmitter, ``""`` if nothing: the
    :class:`~easyssf.receiver.transmitter.UriPolicy` requires https and an issuer without query or
    fragment; loopback hosts may use http."""
    from .transmitter import UriPolicy, UriPolicyError  # the transmitter module builds on this one

    try:
        UriPolicy(allow_insecure_http=allow_insecure_http).check_issuer(issuer)
    except UriPolicyError as error:
        return str(error)
    return ""


def _check_endpoint(value: str, description: str, allow_insecure_http: bool) -> str:
    """What is wrong with an endpoint of the transmitter, ``""`` if nothing, per the
    :class:`~easyssf.receiver.transmitter.UriPolicy`."""
    from .transmitter import UriPolicy, UriPolicyError  # the transmitter module builds on this one

    try:
        UriPolicy(allow_insecure_http=allow_insecure_http).check_endpoint(value, description)
    except UriPolicyError as error:
        return str(error)
    return ""


# -- binding ------------------------------------------------------------------------------------------

_T = TypeVar("_T")


def _bind(cls: type[_T], mapping: Mapping[str, Any], prefix: str, failures: list[str], strict: bool) -> _T:
    """A dataclass bound from the mapping: every field from the kebab-case (or snake_case) key of
    its name, the defaults where the mapping has no value, a failure where it has one of the wrong
    type and, when strict, where it has a key that is no field."""
    values = {str(key).replace("_", "-"): value for key, value in mapping.items()}
    hints = typing.get_type_hints(cls)
    known = [f.name.replace("_", "-") for f in fields(cls) if not f.metadata.get("internal")]  # type: ignore[arg-type]
    if strict:
        for key in values:
            if key not in known:
                failures.append(f"{prefix}.{key}: unknown setting{_did_you_mean(key, known)}")
    arguments: dict[str, Any] = {}
    for f in fields(cls):  # type: ignore[arg-type]
        if f.metadata.get("internal"):
            continue
        key = f.name.replace("_", "-")
        if key not in values or values[key] is None:
            continue
        bound = _bind_value(hints[f.name], values[key], f"{prefix}.{key}", failures, strict)
        if bound is not _UNBOUND:
            arguments[f.name] = bound
    return cls(**arguments)


def _did_you_mean(key: str, known: list[str]) -> str:
    """``", did you mean 'expected-auth-header'?"`` for the known key the given one resembles,
    ``""`` when none does."""
    matches = difflib.get_close_matches(key, known, n=1, cutoff=0.6)
    return f", did you mean '{matches[0]}'?" if matches else ""


_UNBOUND: Final = object()


def _bind_value(hint: Any, value: Any, key: str, failures: list[str], strict: bool) -> Any:
    origin = typing.get_origin(hint)
    if hint is bool:
        if isinstance(value, bool):
            return value
        failures.append(f"{key}: must be true or false (value: {value!r})")
    elif hint is int:
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        failures.append(f"{key}: must be an integer (value: {value!r})")
    elif hint is str:
        if isinstance(value, str):
            return value
        failures.append(f"{key}: must be a string (value: {value!r})")
    elif hint is timedelta:
        try:
            return parse_duration(value)
        except (ValueError, TypeError):
            failures.append(f'{key}: must be a duration such as "30s", "24h" or a number of seconds (value: {value!r})')
    elif origin is list:
        if isinstance(value, list | tuple) and all(isinstance(element, str) for element in value):
            return list(value)
        failures.append(f"{key}: must be a list of strings (value: {value!r})")
    elif origin is dict:
        value_type = typing.get_args(hint)[1]
        if not isinstance(value, Mapping):
            failures.append(f"{key}: must be a mapping (value: {value!r})")
        elif value_type is str:
            if all(isinstance(element, str) for element in value.values()):
                return {str(name): element for name, element in value.items()}
            failures.append(f"{key}: must be a mapping of strings (value: {value!r})")
        else:
            bound: dict[str, Any] = {}
            for name, element in value.items():
                if isinstance(element, Mapping):
                    bound[str(name)] = _bind(value_type, element, f"{key}.{name}", failures, strict)
                else:
                    failures.append(f"{key}.{name}: must be a mapping (value: {element!r})")
            return bound
    elif isinstance(hint, type) and is_dataclass(hint):
        if isinstance(value, Mapping):
            return _bind(hint, value, key, failures, strict)
        failures.append(f"{key}: must be a mapping (value: {value!r})")
    else:  # pragma: no cover - every field type is handled above
        raise TypeError(f"unsupported field type {hint!r}")
    return _UNBOUND


def _unbind(config: Any) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for f in fields(config):
        if f.metadata.get("internal"):
            continue
        mapping[f.name.replace("_", "-")] = _unbind_value(getattr(config, f.name))
    return mapping


def _unbind_value(value: Any) -> Any:
    if isinstance(value, timedelta):
        return format_duration(value)
    if is_dataclass(value) and not isinstance(value, type):
        return _unbind(value)
    if isinstance(value, dict):
        return {name: _unbind_value(element) for name, element in value.items()}
    if isinstance(value, list):
        return list(value)
    return value
