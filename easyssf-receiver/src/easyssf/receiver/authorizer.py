"""What a request to the transmitter needs to be accepted, and how a failed call is tried again:
the ``Authorizer`` protocol with the built-in authorizers, the endpoint a request is for, and the
``RetryOptions`` with the retry loop; a port of ``receiver/authorizer.go`` of the Go port.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING, Final, Protocol, TypeAlias, runtime_checkable

import httpx

from .errors import TransmitterUnavailableError

if TYPE_CHECKING:
    from .config import RetryConfig
    from .transmitter import HttpResponse, TokenProvider

__all__ = [
    "DEFAULT_RETRYABLE_STATUSES",
    "ENDPOINT_EXTENSION",
    "Authorizer",
    "AuthorizerCallable",
    "AuthorizerFunc",
    "Authorizers",
    "BearerToken",
    "Endpoint",
    "EndpointHeaders",
    "NoAuthorization",
    "RetryOptions",
    "StaticHeaders",
    "TokenInvalidator",
    "default_retry_options",
    "endpoint_of",
    "invalidate_token",
    "retry_after",
    "retrying",
    "with_endpoint",
]

ENDPOINT_EXTENSION: Final = "easyssf.endpoint"
"""The key of the ``httpx.Request.extensions`` entry that names the endpoint a request is for;
the request context of the Go port."""


class Endpoint:
    """The endpoints of the transmitter a request can be for, for an :class:`Authorizer` that
    treats endpoints differently. An open set of ``str`` constants: a custom caller may name
    an endpoint of its own."""

    METADATA: Final = "metadata"
    """The transmitter configuration metadata."""
    JWKS: Final = "jwks"
    """The JWK Set."""
    TOKEN: Final = "token"  # noqa: S105 - the name of an endpoint, not a secret
    """The token endpoint of the client credentials grant."""
    CONFIGURATION: Final = "configuration"
    """The configuration endpoint of the stream management API."""
    STATUS: Final = "status"
    """The status endpoint."""
    ADD_SUBJECT: Final = "add_subject"
    """The add subject endpoint."""
    REMOVE_SUBJECT: Final = "remove_subject"
    """The remove subject endpoint."""
    VERIFICATION: Final = "verification"
    """The verification endpoint."""
    POLL: Final = "poll"
    """The poll endpoint of the stream."""


def with_endpoint(request: httpx.Request, endpoint: str) -> httpx.Request:
    """Marks the request with the endpoint it is for (see :class:`Endpoint`) and returns it."""
    request.extensions[ENDPOINT_EXTENSION] = endpoint
    return request


def endpoint_of(request: httpx.Request) -> str:
    """The endpoint the request is for, ``""`` if unknown."""
    endpoint = request.extensions.get(ENDPOINT_EXTENSION)
    return endpoint if isinstance(endpoint, str) else ""


@runtime_checkable
class Authorizer(Protocol):
    """Adds what a request to the transmitter needs to be accepted: the bearer token of a
    :class:`~easyssf.receiver.transmitter.TokenProvider` (:func:`BearerToken`), fixed headers
    such as an API key (:class:`StaticHeaders`), headers for particular endpoints
    (:class:`EndpointHeaders`), or anything else, chained with :class:`Authorizers`. Every call
    of the receiver to the transmitter goes through one: metadata, JWK Set, stream management
    and poll requests. The endpoint a request is for is in the request, see :func:`endpoint_of`.

    An authorizer that also implements :class:`TokenInvalidator` is told when the transmitter
    rejected a request with 401, and the request is sent once more.
    """

    async def authorize(self, request: httpx.Request) -> None:
        """Adds what the request needs; raises a
        :class:`~easyssf.receiver.errors.TransmitterUnavailableError` if that cannot be obtained."""
        ...


@runtime_checkable
class TokenInvalidator(Protocol):
    """Implemented by a :class:`~easyssf.receiver.transmitter.TokenProvider` or
    :class:`Authorizer` that caches tokens: :meth:`invalidate` is called when the transmitter
    rejected the access token (HTTP 401), so that the next token is a new one."""

    def invalidate(self) -> None:
        """Forgets the cached token."""
        ...


AuthorizerCallable: TypeAlias = Callable[[httpx.Request], "Awaitable[None] | None"]
"""An authorizer written as a function, sync or async."""


class AuthorizerFunc:
    """An :class:`Authorizer` written as a function, sync or async.

    Args:
        func: the callable, taking the ``httpx.Request`` to authorize.
    """

    __slots__ = ("_func",)

    def __init__(self, func: AuthorizerCallable) -> None:
        self._func = func

    async def authorize(self, request: httpx.Request) -> None:
        """Calls the function."""
        result = self._func(request)
        if inspect.isawaitable(result):
            await result


class NoAuthorization:
    """An :class:`Authorizer` that changes nothing: for transmitters whose endpoints need no
    authentication."""

    __slots__ = ()

    async def authorize(self, request: httpx.Request) -> None:
        """Changes nothing."""


class _BearerToken:
    """Sends the token of a :class:`~easyssf.receiver.transmitter.TokenProvider` as bearer
    token and passes an ``invalidate`` of the provider on."""

    __slots__ = ("_provider",)

    def __init__(self, provider: TokenProvider) -> None:
        self._provider = provider

    async def authorize(self, request: httpx.Request) -> None:
        token = await self._provider.access_token()
        if token:
            request.headers["Authorization"] = "Bearer " + token

    def invalidate(self) -> None:
        invalidate_token(self._provider)

    def __repr__(self) -> str:
        return f"BearerToken({self._provider!r})"


def BearerToken(provider: TokenProvider | Authorizer | None) -> Authorizer:  # noqa: N802 - a factory under the Go name
    """An :class:`Authorizer` that sends the access token of the provider as bearer token
    (RFC 6750); none if the provider gives ``""``. It passes an ``invalidate`` of the provider on.
    A provider that is an :class:`Authorizer` itself (:class:`~easyssf.receiver.transmitter.FixedToken`,
    :class:`~easyssf.receiver.transmitter.ClientCredentialsTokenProvider`) is returned as it is,
    ``None`` gives :class:`NoAuthorization`."""
    if provider is None:
        return NoAuthorization()
    if isinstance(provider, Authorizer):
        return provider
    return _BearerToken(provider)


class StaticHeaders:
    """An :class:`Authorizer` that sets fixed headers on every request, for example an API key
    the transmitter wants besides, or instead of, a bearer token.

    Args:
        headers: the headers by name.
    """

    __slots__ = ("_headers",)

    def __init__(self, headers: Mapping[str, str]) -> None:
        self._headers = dict(headers)

    @property
    def headers(self) -> dict[str, str]:
        """The headers, a copy."""
        return dict(self._headers)

    async def authorize(self, request: httpx.Request) -> None:
        """Sets the headers."""
        for name, value in self._headers.items():
            request.headers[name] = value

    def __repr__(self) -> str:
        return f"StaticHeaders({sorted(self._headers)})"


class EndpointHeaders:
    """An :class:`Authorizer` that sets headers on the requests to particular endpoints only, by
    :class:`Endpoint`.

    Args:
        headers: the headers by name, by endpoint.
    """

    __slots__ = ("_headers",)

    def __init__(self, headers: Mapping[str, Mapping[str, str]]) -> None:
        self._headers = {endpoint: dict(values) for endpoint, values in headers.items()}

    async def authorize(self, request: httpx.Request) -> None:
        """Sets the headers of the endpoint the request is for."""
        for name, value in self._headers.get(endpoint_of(request), {}).items():
            request.headers[name] = value

    def __repr__(self) -> str:
        return f"EndpointHeaders({sorted(self._headers)})"


class Authorizers:
    """An :class:`Authorizer` that applies several in order; an ``invalidate`` reaches every one
    that implements :class:`TokenInvalidator`.

    Args:
        authorizers: the authorizers, in the order they are applied; ``None`` entries are skipped.
    """

    __slots__ = ("_authorizers",)

    def __init__(self, *authorizers: Authorizer | None) -> None:
        self._authorizers: tuple[Authorizer, ...] = tuple(a for a in authorizers if a is not None)

    @classmethod
    def of(cls, authorizers: Iterable[Authorizer | None]) -> Authorizers:
        """The authorizers of an iterable, in order."""
        return cls(*authorizers)

    @property
    def authorizers(self) -> tuple[Authorizer, ...]:
        """The authorizers, in order."""
        return self._authorizers

    async def authorize(self, request: httpx.Request) -> None:
        """Applies every authorizer in order."""
        for authorizer in self._authorizers:
            await authorizer.authorize(request)

    def invalidate(self) -> None:
        """Invalidates every authorizer that caches a token."""
        for authorizer in self._authorizers:
            invalidate_token(authorizer)

    def __repr__(self) -> str:
        return f"Authorizers{self._authorizers!r}"


def invalidate_token(authorizer: object) -> bool:
    """Calls ``invalidate`` if the authorizer (or token provider) is a :class:`TokenInvalidator`;
    whether it was."""
    if isinstance(authorizer, TokenInvalidator):
        authorizer.invalidate()
        return True
    return False


DEFAULT_RETRYABLE_STATUSES: Final[tuple[int, ...]] = (408, 429, 500, 502, 503, 504)
"""The HTTP statuses a call is tried again on when :attr:`RetryOptions.retryable_statuses` names
none: request timeout, too many requests, and the 5xx of a transmitter in trouble."""

_FALLBACK_BACKOFF: Final = timedelta(milliseconds=250)


@dataclass(frozen=True, slots=True)
class RetryOptions:
    """How a call to the transmitter that fails for a reason that may pass is tried again: a
    connection error or timeout, or a response with one of the :attr:`retryable_statuses`. The
    delay starts at :attr:`initial_backoff`, doubles up to :attr:`max_backoff`, and follows a
    ``Retry-After`` header when the transmitter sends one. Management, metadata and JWK Set calls
    retry; poll requests do not, the poller has its interval and honours ``Retry-After`` itself.
    Start from :func:`default_retry_options`; the default values do not retry."""

    max_retries: int = 0
    """How many times a failed call is tried again; 0 never."""
    initial_backoff: timedelta = timedelta(0)
    """The delay before the first retry; a quarter of a second if zero."""
    max_backoff: timedelta = timedelta(0)
    """The longest delay between two tries, also for a ``Retry-After`` header; unbounded if zero."""
    retryable_statuses: tuple[int, ...] | None = None
    """The HTTP statuses that are tried again; :data:`DEFAULT_RETRYABLE_STATUSES` if ``None``."""

    @classmethod
    def from_config(cls, config: RetryConfig) -> RetryOptions:
        """The options of a :class:`~easyssf.receiver.config.RetryConfig`, the ``Options`` of the
        Go port."""
        return cls(
            max_retries=config.max_retries, initial_backoff=config.initial_backoff, max_backoff=config.max_backoff
        )

    def is_retryable(self, status: int) -> bool:
        """Whether a response with the status is tried again."""
        statuses = DEFAULT_RETRYABLE_STATUSES if self.retryable_statuses is None else self.retryable_statuses
        return status in statuses


def default_retry_options() -> RetryOptions:
    """The defaults: two retries, a quarter of a second doubling up to five seconds, on 408, 429,
    500, 502, 503 and 504."""
    return RetryOptions(max_retries=2, initial_backoff=timedelta(milliseconds=250), max_backoff=timedelta(seconds=5))


_RETRIED_ERRORS: Final = (httpx.TransportError, TimeoutError, TransmitterUnavailableError)


async def retrying(options: RetryOptions, call: Callable[[], Awaitable[HttpResponse]]) -> HttpResponse:
    """Runs the call and tries it again per the options: on a connection error or timeout
    (``httpx.TransportError``, ``TimeoutError``), when the transmitter could not be called
    (:class:`~easyssf.receiver.errors.TransmitterUnavailableError`, the token for it could not be
    obtained, say), or on a response with a retryable status. The last response is returned, the
    last error raised. A cancellation ends the retries at once; any other error is raised as it
    is, trying again would not help."""
    delay = options.initial_backoff if options.initial_backoff > timedelta(0) else _FALLBACK_BACKOFF
    attempt = 0
    while True:
        response: HttpResponse | None = None
        error: Exception | None = None
        try:
            response = await call()
        except _RETRIED_ERRORS as raised:
            error = raised
        if attempt >= options.max_retries:
            if error is not None:
                raise error
            assert response is not None  # either the call raised or it answered
            return response
        if response is not None and not options.is_retryable(response.status):
            return response
        wait = delay
        if response is not None:
            after = retry_after(response)
            if after is not None:
                wait = after
        if options.max_backoff > timedelta(0):
            wait = min(wait, options.max_backoff)
        await asyncio.sleep(wait.total_seconds())
        delay *= 2
        if options.max_backoff > timedelta(0):
            delay = min(delay, options.max_backoff)
        attempt += 1


def retry_after(response: HttpResponse, now: datetime | None = None) -> timedelta | None:
    """The ``Retry-After`` header of the response as a delay (RFC 9110, section 10.2.3): a number
    of seconds, or an HTTP-date measured from ``now`` (the system clock if ``None``) and zero when
    it has passed. ``None`` if the response has no header, or one that is neither."""
    value = response.headers.get("Retry-After", "").strip()
    if not value:
        return None
    if value.isdigit():
        return timedelta(seconds=int(value))
    try:
        date = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if date.tzinfo is None:
        date = date.replace(tzinfo=UTC)
    current = now if now is not None else datetime.now(tz=UTC)
    return max(date - current, timedelta(0))
