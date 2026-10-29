"""The transmitter as the receiver sees it: its metadata, how it is reached and what its URLs must
look like, the access token to call it with, and everything the receiver holds for it; a port of
``receiver/transmitter.go`` of the Go port and of ``org.easyssf.receiver.transmitter``.

Every call to a transmitter goes through :func:`send`, :func:`exchange` or :func:`get_json`: a
per-call timeout, the :class:`~easyssf.receiver.authorizer.Authorizer` of the transmitter, retries
per :class:`~easyssf.receiver.authorizer.RetryOptions`, one more try with a fresh token after a
401, and redirects followed by hand through :meth:`UriPolicy.check_redirect`.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any, Final, Protocol, runtime_checkable
from urllib.parse import SplitResult, quote_plus, urlencode, urlsplit

import httpx

from easyssf.core import TransmitterMetadata, as_int, parse_claims, string_member

from .authorizer import (
    Authorizer,
    Endpoint,
    RetryOptions,
    invalidate_token,
    retrying,
    with_endpoint,
)
from .config import DEFAULT_TRANSMITTER_NAME, TransmitterConfig
from .errors import Clock, EasyssfError, TransmitterUnavailableError, system_clock

if TYPE_CHECKING:
    # jwks.py, verifier.py and poll.py are written alongside this module; the names are only
    # needed for the annotations of the Transmitter fields
    from .jwks import JwkSetSource
    from .stream import ReceiverStream, StreamClient, StreamRegistrar, StreamVerification
    from .verifier import Verifier

__all__ = [
    "DEFAULT_HTTP_TIMEOUT",
    "LONG_POLL_MARGIN",
    "MAX_REDIRECTS",
    "MAX_RESPONSE_SIZE",
    "WELL_KNOWN_PATH",
    "ClientCredentialsOptions",
    "ClientCredentialsTokenProvider",
    "FixedToken",
    "HealthStatus",
    "HttpResponse",
    "MetadataResolver",
    "NoToken",
    "TokenProvider",
    "Transmitter",
    "TransmitterHealth",
    "UriPolicy",
    "UriPolicyError",
    "default_client_credentials_options",
    "derive_metadata_urls",
    "exchange",
    "get_json",
    "parse_absolute",
    "send",
]

WELL_KNOWN_PATH: Final = "/.well-known/ssf-configuration"
"""Where a transmitter publishes its metadata (SSF 1.0, section 7.2)."""

DEFAULT_HTTP_TIMEOUT: Final = timedelta(seconds=5)
"""How long a call to the transmitter waits for its response when nothing else is configured: 5
seconds, as in the Java library. A long poll waits for its hold time plus :data:`LONG_POLL_MARGIN`
instead."""

LONG_POLL_MARGIN: Final = timedelta(seconds=10)
"""How much longer than the hold time of the transmitter a long poll waits for the response, so
that the transmitter answers before the receiver gives up (RFC 8936, section 2.5)."""

MAX_RESPONSE_SIZE: Final = 4 << 20
"""What the receiver reads of a response at most: metadata, JWK Sets and poll responses are
small, and an endpoint must not be able to exhaust the receiver's memory."""

MAX_REDIRECTS: Final = 10
"""How many redirects of one call are followed at most."""

_log: Final = logging.getLogger("easyssf.receiver.transmitter")
_JSON: Final = "application/json"


class UriPolicyError(EasyssfError, ValueError):
    """A URL is not acceptable to the :class:`UriPolicy`: not absolute, with a fragment where none
    is allowed, not https where https is required, or a redirect that leaves the origin. A
    ``ValueError`` as well, as any other invalid value."""


@dataclass(frozen=True, slots=True)
class UriPolicy:
    """What the issuer of a transmitter and the endpoints it publishes must look like. SSF
    requires https and an issuer without query or fragment. Loopback addresses (localhost,
    127.0.0.1, ::1) may use http, so that a transmitter on the developer's machine works;
    ``allow_insecure_http`` extends that to every host, for test setups only: the metadata of the
    transmitter decides where keys come from, and without TLS anyone on the path can change it.
    """

    allow_insecure_http: bool = False
    """Accepts ``http`` on hosts other than loopback. For development only."""

    @staticmethod
    def is_insecure(url: str) -> bool:
        """Whether the URL uses plain http."""
        return urlsplit(url).scheme.lower() == "http"

    @staticmethod
    def is_loopback(url: str) -> bool:
        """Whether the host of the URL is a loopback address: ``localhost`` and its subdomains
        (RFC 6761, section 6.3), or a loopback IP address (``127.0.0.0/8``, ``::1``). A host name
        that merely starts with ``127.``, such as ``127.attacker.example``, is not one: it resolves
        wherever its owner points it, so it does not earn the exemption from https."""
        host = (urlsplit(url).hostname or "").lower()
        if host == "localhost" or host.endswith(".localhost"):
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    @staticmethod
    def same_origin(a: str, b: str) -> bool:
        """Whether the URLs have the same scheme, host and effective port, the port being 443 for
        https and 80 for http when none is given (RFC 6454, section 4)."""
        first, second = urlsplit(a), urlsplit(b)
        return (
            first.scheme.lower() == second.scheme.lower()
            and (first.hostname or "").lower() == (second.hostname or "").lower()
            and UriPolicy.effective_port(a) == UriPolicy.effective_port(b)
        )

    @staticmethod
    def effective_port(url: str) -> str:
        """The port of the URL, the default of its scheme if none is given, ``""`` if the scheme
        has none."""
        parts = urlsplit(url)
        try:
            port = parts.port
        except ValueError:
            port = None
        if port is not None:
            return str(port)
        scheme = parts.scheme.lower()
        if scheme == "https":
            return "443"
        if scheme == "http":
            return "80"
        return ""

    def check_issuer(self, issuer: str) -> SplitResult:
        """Checks the issuer of a transmitter and returns it parsed.

        Raises:
            UriPolicyError: if the issuer is not an absolute https URL (http on loopback) without
                query or fragment.
        """
        parts = parse_absolute(issuer, "transmitter issuer")
        if parts.query or parts.fragment:
            raise UriPolicyError(f"transmitter issuer must not have a query or fragment: {issuer}")
        self._check_scheme(parts, issuer, "transmitter issuer")
        return parts

    def check_endpoint(self, url: str, description: str) -> None:
        """Checks an endpoint of the transmitter: its metadata, JWK Set, stream management or
        poll endpoint. ``description`` says what the endpoint is, for the message.

        Raises:
            UriPolicyError: if the endpoint is not an absolute URL without fragment whose scheme
                passes the policy.
        """
        parts = parse_absolute(url, description)
        if parts.fragment:
            raise UriPolicyError(f"{description} must not have a fragment: {url}")
        self._check_scheme(parts, url, description)

    def check_redirect(self, target: str, original: str, followed: int = 0) -> None:
        """Decides whether a redirect of a call to the transmitter is followed: only within the
        origin of the request that was redirected, the same scheme, host and port (credentials and
        headers must not leave the transmitter, and another port is another service), only where
        the scheme passes the policy, and at most :data:`MAX_REDIRECTS` times. Every call to a
        transmitter applies it; httpx is never asked to follow redirects itself.

        Args:
            target: the ``Location`` the transmitter redirected to, resolved.
            original: the URL of the request that was redirected first.
            followed: how many redirects of this call were followed already.

        Raises:
            UriPolicyError: if the redirect is not followed.
        """
        if followed >= MAX_REDIRECTS:
            raise UriPolicyError(f"the SSF transmitter redirected more than {MAX_REDIRECTS} times")
        if not self.same_origin(target, original):
            raise UriPolicyError(
                f"the SSF transmitter redirected {original} to another origin, {target}, which is not followed"
            )
        self.check_endpoint(target, "the redirect target of " + original)

    def _check_scheme(self, parts: SplitResult, url: str, description: str) -> None:
        scheme = parts.scheme.lower()
        if scheme == "https" or (scheme == "http" and (self.allow_insecure_http or self.is_loopback(url))):
            return
        raise UriPolicyError(f"{description} must use https: {url}")


def parse_absolute(value: str, description: str) -> SplitResult:
    """Parses an absolute URL with a host.

    Raises:
        UriPolicyError: if the value is not one.
    """
    try:
        parts = urlsplit(value)
    except ValueError as error:
        raise UriPolicyError(f"{description} is not a valid URI: {value} ({error})") from error
    if not parts.scheme or not parts.netloc or not parts.hostname:
        raise UriPolicyError(f"{description} must be an absolute URI with a host: {value}")
    return parts


def derive_metadata_urls(issuer: str) -> list[str]:
    """The metadata locations of an issuer. SSF 1.0 (section 7.2) inserts
    ``/.well-known/ssf-configuration`` between the host and the path of the issuer. Transmitters
    that grew out of OpenID providers tend to append it to the issuer instead, so that location
    is used as a fallback.

    Raises:
        UriPolicyError: if the issuer is not an absolute URL.
    """
    parts = parse_absolute(issuer, "transmitter issuer")
    base = f"{parts.scheme}://{parts.netloc}"
    path = parts.path.rstrip("/")
    urls: list[str] = []
    for candidate in (base + WELL_KNOWN_PATH + path, base + path + WELL_KNOWN_PATH):
        if candidate not in urls:
            urls.append(candidate)
    return urls


class MetadataResolver:
    """Resolves the :class:`~easyssf.core.TransmitterMetadata` of the transmitter. The metadata is
    fetched on first use and cached once it was retrieved successfully, so a receiver can start
    even when the transmitter is not reachable.

    Args:
        issuer: the issuer of the transmitter.
        metadata_url: where the metadata is published, or ``None`` for the locations derived from
            the issuer (:func:`derive_metadata_urls`).
        client: the client the metadata is fetched with.
        policy: what the metadata location, the endpoints and the redirects must look like.
        logger: where the resolver logs; ``easyssf.receiver.transmitter`` by default.
        timeout: how long a fetch waits for the response; :data:`DEFAULT_HTTP_TIMEOUT` if ``None``.
        authorizer: adds what the fetch needs, for example an API key; nothing if ``None``.
        retry: how a failed fetch is tried again; not at all by default.

    Raises:
        UriPolicyError: if the issuer or the metadata URL is not acceptable to the policy.
    """

    def __init__(
        self,
        issuer: str,
        metadata_url: str | None,
        client: httpx.AsyncClient,
        policy: UriPolicy | None = None,
        logger: logging.Logger | None = None,
        *,
        timeout: timedelta | None = None,
        authorizer: Authorizer | None = None,
        retry: RetryOptions | None = None,
    ) -> None:
        self._policy = policy if policy is not None else UriPolicy()
        self._policy.check_issuer(issuer)
        if metadata_url:
            self._policy.check_endpoint(metadata_url, "transmitter metadata URL")
            urls = [metadata_url]
        else:
            urls = derive_metadata_urls(issuer)
        self._issuer = issuer
        self._urls = urls
        self._client = client
        self._log = logger if logger is not None else _log
        self.timeout = timeout
        """How long a fetch waits for the response; :data:`DEFAULT_HTTP_TIMEOUT` if ``None``."""
        self.authorizer = authorizer
        """Adds what the fetch needs, for example an API key; nothing if ``None``."""
        self.retry = retry if retry is not None else RetryOptions()
        """How a failed fetch is tried again."""
        self._lock = asyncio.Lock()
        self._metadata: TransmitterMetadata | None = None
        self._warned = False

    @property
    def issuer(self) -> str:
        """The issuer of the transmitter."""
        return self._issuer

    @property
    def policy(self) -> UriPolicy:
        """The URI policy the resolver checks the metadata locations, the endpoints and the
        redirects with."""
        return self._policy

    @property
    def client(self) -> httpx.AsyncClient:
        """The client the metadata is fetched with."""
        return self._client

    @property
    def metadata_urls(self) -> list[str]:
        """The locations the metadata is looked up at, in order."""
        return list(self._urls)

    @property
    def resolved(self) -> TransmitterMetadata | None:
        """The metadata if it was retrieved already, without retrieving it."""
        return self._metadata

    async def resolve(self) -> TransmitterMetadata:
        """The metadata, fetched on first use. Concurrent callers wait for one fetch.

        Raises:
            TransmitterUnavailableError: if the metadata could not be retrieved from any location.
        """
        async with self._lock:
            if self._metadata is not None:
                return self._metadata
            failures: list[str] = []
            for url in self._urls:
                try:
                    metadata = await self._fetch(url)
                except Exception as error:
                    self._log.debug("Could not resolve SSF transmitter metadata", extra={"url": url, "error": error})
                    failures.append(f"{url}: {error}")
                    continue
                self._log.info("Resolved SSF transmitter metadata", extra={"transmitter": self._issuer, "url": url})
                self._metadata = metadata
                return metadata
            raise TransmitterUnavailableError(
                None, "could not resolve SSF transmitter metadata from " + "; ".join(failures)
            )

    async def _fetch(self, url: str) -> TransmitterMetadata:
        body = await get_json(
            self._client,
            url,
            authorizer=self.authorizer,
            policy=self._policy,
            retry=self.retry,
            timeout=self.timeout,
            endpoint=Endpoint.METADATA,
        )
        try:
            claims = parse_claims(body)
        except ValueError as error:
            raise ValueError(f"the metadata is not JSON: {error}") from error
        issuer = string_member(claims, "issuer")
        if issuer != self._issuer:
            raise ValueError(
                f"SSF transmitter metadata issuer {issuer!r} does not match the configured transmitter issuer "
                f"{self._issuer!r}"
            )
        metadata = TransmitterMetadata(self._issuer, string_member(claims, "jwks_uri") or None, claims)
        self._check_endpoints(metadata)
        return metadata

    def _check_endpoints(self, metadata: TransmitterMetadata) -> None:
        """The metadata controls where keys and stream operations come from, so its endpoints are
        held to the same standard as the issuer."""
        endpoints = (
            (metadata.jwks_uri or "", "jwks_uri"),
            (metadata.configuration_endpoint, "configuration_endpoint"),
            (metadata.status_endpoint, "status_endpoint"),
            (metadata.add_subject_endpoint, "add_subject_endpoint"),
            (metadata.remove_subject_endpoint, "remove_subject_endpoint"),
            (metadata.verification_endpoint, "verification_endpoint"),
        )
        insecure: list[str] = []
        for url, name in endpoints:
            if not url:
                continue
            self._policy.check_endpoint(url, "SSF transmitter metadata " + name)
            if UriPolicy.is_insecure(url) and not UriPolicy.is_loopback(url):
                insecure.append(f"{name} {url}")
        if insecure and self._policy.allow_insecure_http and not self._warned:
            self._warned = True
            self._log.warning(
                "The SSF transmitter publishes endpoints without TLS, accepted because insecure http is allowed. "
                "For development only",
                extra={"transmitter": self._issuer, "endpoints": insecure},
            )

    def __repr__(self) -> str:
        return f"MetadataResolver(issuer={self._issuer!r}, urls={self._urls!r})"


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """What a call to the transmitter answered with, whatever the status."""

    status: int
    """The HTTP status."""
    headers: httpx.Headers
    """The response headers."""
    body: bytes
    """The body, at most :data:`MAX_RESPONSE_SIZE` bytes of it."""

    @property
    def successful(self) -> bool:
        """Whether the status is a 2xx."""
        return 200 <= self.status < 300

    @property
    def text(self) -> str:
        """The body as text, undecodable bytes replaced."""
        return self.body.decode("utf-8", errors="replace")


async def send(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    authorizer: Authorizer | None = None,
    policy: UriPolicy | None = None,
    timeout: timedelta | None = None,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    endpoint: str = "",
) -> HttpResponse:
    """Performs one request and returns the response whatever its status. The request is
    authorized by ``authorizer`` if given, marked as being for ``endpoint`` (see
    :class:`~easyssf.receiver.authorizer.Endpoint`), waits ``timeout``
    (:data:`DEFAULT_HTTP_TIMEOUT` if ``None``) for the response, and its body is bounded by
    :data:`MAX_RESPONSE_SIZE`. A redirect is followed by hand, only within the origin and only
    where the policy allows, see :meth:`UriPolicy.check_redirect`.

    Raises:
        httpx.TransportError: if no response was received.
        TimeoutError: if the response did not arrive in time.
        TransmitterUnavailableError: if the authorizer could not authorize the request.
        UriPolicyError: if the transmitter redirected to where the policy does not follow.
    """
    policy = policy if policy is not None else UriPolicy()
    wait = timeout if timeout is not None and timeout > timedelta(0) else DEFAULT_HTTP_TIMEOUT
    seconds = wait.total_seconds()
    target = url
    followed = 0
    async with asyncio.timeout(seconds):
        while True:
            request = client.build_request(method, target, headers=headers, content=body, timeout=seconds)
            with_endpoint(request, endpoint)
            if authorizer is not None:
                await authorizer.authorize(request)
            response = await client.send(request, follow_redirects=False, stream=True)
            try:
                next_request = response.next_request
                if next_request is None:
                    data = await _read_bounded(response)
                    return HttpResponse(response.status_code, response.headers, data)
            finally:
                await response.aclose()
            policy.check_redirect(str(next_request.url), url, followed)
            followed += 1
            target = str(next_request.url)
            if next_request.method != method:
                method, body = next_request.method, None


async def _read_bounded(response: httpx.Response) -> bytes:
    if response.is_stream_consumed:
        # a response built with its content, as an in-process transport answers
        return response.content[:MAX_RESPONSE_SIZE]
    data = bytearray()
    async for chunk in response.aiter_bytes():
        data += chunk
        if len(data) >= MAX_RESPONSE_SIZE:
            del data[MAX_RESPONSE_SIZE:]
            break
    return bytes(data)


async def get_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    authorizer: Authorizer | None = None,
    policy: UriPolicy | None = None,
    retry: RetryOptions | None = None,
    timeout: timedelta | None = None,
    accept: str = _JSON,
    endpoint: str = "",
) -> bytes:
    """Performs a GET, tried again per ``retry``, and returns the body of a 2xx response.

    Raises:
        TransmitterUnavailableError: if the transmitter answered with another status, or the
            request could not be authorized.
        httpx.TransportError, TimeoutError, UriPolicyError: as :func:`send`.
    """
    options = retry if retry is not None else RetryOptions()

    async def call() -> HttpResponse:
        return await send(
            client,
            "GET",
            url,
            authorizer=authorizer,
            policy=policy,
            timeout=timeout,
            headers={"Accept": accept},
            endpoint=endpoint,
        )

    response = await retrying(options, call)
    if not response.successful:
        raise TransmitterUnavailableError(None, f"the transmitter answered with status {response.status}")
    return response.body


async def exchange(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    authorizer: Authorizer | None = None,
    policy: UriPolicy | None = None,
    retry: RetryOptions | None = None,
    timeout: timedelta | None = None,
    json_body: bytes | None = None,
    endpoint: str = "",
) -> HttpResponse:
    """Calls an endpoint of the transmitter, authorized by ``authorizer``, with a JSON body if
    given, tried again per ``retry``, and once more with a new token when the transmitter
    answers 401 and the authorizer can invalidate its token
    (:class:`~easyssf.receiver.authorizer.TokenInvalidator`): the access token expired or was
    revoked. The response comes back whatever its status.

    Raises:
        TransmitterUnavailableError: if the request could not be authorized.
        httpx.TransportError, TimeoutError, UriPolicyError: as :func:`send`.
    """
    options = retry if retry is not None else RetryOptions()
    headers = {"Accept": _JSON}
    if json_body is not None:
        headers["Content-Type"] = _JSON

    async def call() -> HttpResponse:
        return await send(
            client,
            method,
            url,
            authorizer=authorizer,
            policy=policy,
            timeout=timeout,
            headers=headers,
            body=json_body,
            endpoint=endpoint,
        )

    response = await retrying(options, call)
    if response.status == 401 and invalidate_token(authorizer):
        return await retrying(options, call)
    return response


@runtime_checkable
class TokenProvider(Protocol):
    """Provides the access token the receiver authenticates with when it calls the stream
    management and poll endpoints of the transmitter. Implement it to obtain the token in another
    way than the built-in ones: :class:`NoToken`, :class:`FixedToken` and
    :class:`ClientCredentialsTokenProvider`. A provider that also implements
    :class:`~easyssf.receiver.authorizer.TokenInvalidator` is told when the transmitter rejected
    the token."""

    async def access_token(self) -> str:
        """The token to send as bearer token, ``""`` to call the transmitter without
        authentication.

        Raises:
            TransmitterUnavailableError: if the token could not be obtained.
        """
        ...


class FixedToken:
    """A :class:`TokenProvider` (and :class:`~easyssf.receiver.authorizer.Authorizer`) that
    always sends the same token, for transmitters that hand out long-lived tokens.

    Args:
        token: the access token.
    """

    __slots__ = ("_token",)

    def __init__(self, token: str) -> None:
        self._token = token

    async def access_token(self) -> str:
        """The fixed token."""
        return self._token

    async def authorize(self, request: httpx.Request) -> None:
        """Sets the fixed token as bearer token, nothing if it is ``""``."""
        if self._token:
            request.headers["Authorization"] = "Bearer " + self._token

    def __repr__(self) -> str:
        return "FixedToken(...)"


class NoToken:
    """A :class:`TokenProvider` (and :class:`~easyssf.receiver.authorizer.Authorizer`) for
    transmitters whose endpoints need no authentication."""

    __slots__ = ()

    async def access_token(self) -> str:
        """``""``: no token."""
        return ""

    async def authorize(self, request: httpx.Request) -> None:
        """Changes nothing."""


@dataclass(frozen=True, slots=True)
class ClientCredentialsOptions:
    """How a :class:`ClientCredentialsTokenProvider` obtains tokens. Start from
    :func:`default_client_credentials_options`."""

    scopes: tuple[str, ...] = ()
    """The scopes to request, none by default."""
    authenticate_with_request_body: bool = False
    """Sends the client credentials in the request body (``client_secret_post``) instead of with
    HTTP basic authentication (``client_secret_basic``, RFC 6749, section 2.3.1)."""
    expiry_safety_window: timedelta = timedelta(seconds=30)
    """How long before its expiry a token is renewed, 30 seconds by default; never more than a
    quarter of the token's lifetime."""
    additional_parameters: tuple[tuple[str, str], ...] = ()
    """Form parameters to send with the token request in addition to the grant, for extensions of
    the token endpoint; ``grant_type`` and ``scope`` are not replaced."""
    policy: UriPolicy = UriPolicy()
    """Decides which redirects of the token endpoint are followed; the strict one (https, or http
    on loopback) by default."""
    timeout: timedelta | None = None
    """How long the token request waits; :data:`DEFAULT_HTTP_TIMEOUT` if ``None``."""
    clock: Clock = system_clock
    """The clock the expiry is measured by."""


def default_client_credentials_options() -> ClientCredentialsOptions:
    """The defaults: basic authentication, a 30 second safety window, the strict policy."""
    return ClientCredentialsOptions()


class ClientCredentialsTokenProvider:
    """A :class:`TokenProvider` (and :class:`~easyssf.receiver.authorizer.Authorizer`) that
    obtains access tokens with the OAuth2 client credentials grant (RFC 6749, section 4.4) and
    caches them until shortly before they expire.

    Args:
        client: the client the token endpoint is called with.
        token_url: the token endpoint.
        client_id: the client id of the receiver.
        client_secret: the client secret of the receiver.
        options: how tokens are obtained; the defaults if ``None``.
    """

    def __init__(
        self,
        client: httpx.AsyncClient,
        token_url: str,
        client_id: str,
        client_secret: str,
        options: ClientCredentialsOptions | None = None,
    ) -> None:
        self._client = client
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._options = options if options is not None else default_client_credentials_options()
        self._lock = asyncio.Lock()
        self._cached = ""
        self._expires_at: datetime | None = None

    @property
    def token_url(self) -> str:
        """The token endpoint."""
        return self._token_url

    @property
    def options(self) -> ClientCredentialsOptions:
        """How tokens are obtained."""
        return self._options

    async def access_token(self) -> str:
        """The cached token while it is valid, a new one otherwise.

        Raises:
            TransmitterUnavailableError: if the token endpoint could not be called, answered with
                an error status or without an ``access_token``.
        """
        async with self._lock:
            if self._cached and self._expires_at is not None and self._options.clock() < self._expires_at:
                return self._cached
            token, expires_at = await self._request_token()
            self._cached, self._expires_at = token, expires_at
            return token

    def invalidate(self) -> None:
        """Forgets the cached token: the next :meth:`access_token` requests a new one."""
        self._cached = ""
        self._expires_at = None

    async def authorize(self, request: httpx.Request) -> None:
        """Sets the current access token as bearer token."""
        request.headers["Authorization"] = "Bearer " + await self.access_token()

    async def _request_token(self) -> tuple[str, datetime]:
        form: dict[str, str] = {"grant_type": "client_credentials"}
        if self._options.scopes:
            form["scope"] = " ".join(self._options.scopes)
        for name, value in self._options.additional_parameters:
            if name not in ("grant_type", "scope"):
                form[name] = value
        headers = {"Accept": _JSON, "Content-Type": "application/x-www-form-urlencoded"}
        if self._options.authenticate_with_request_body:
            form["client_id"] = self._client_id
            form["client_secret"] = self._client_secret
        else:
            # RFC 6749, section 2.3.1: the id and secret are form-urlencoded before basic auth
            credentials = quote_plus(self._client_id) + ":" + quote_plus(self._client_secret)
            headers["Authorization"] = "Basic " + base64.b64encode(credentials.encode()).decode("ascii")
        failure = f"could not obtain an access token for the SSF transmitter from {self._token_url}"
        try:
            response = await send(
                self._client,
                "POST",
                self._token_url,
                policy=self._options.policy,
                timeout=self._options.timeout,
                headers=headers,
                body=urlencode(form).encode(),
                endpoint=Endpoint.TOKEN,
            )
        except (httpx.TransportError, TimeoutError, UriPolicyError) as error:
            raise TransmitterUnavailableError(error, failure) from error
        if not response.successful:
            raise TransmitterUnavailableError(
                None, f"{failure}: the token endpoint answered with status {response.status}"
            )
        try:
            body = parse_claims(response.body)
        except ValueError as error:
            raise TransmitterUnavailableError(error, failure) from error
        token = body.get("access_token")
        if not isinstance(token, str) or not token.strip():
            raise TransmitterUnavailableError(None, f"the token response of {self._token_url} has no access_token")
        expires_in = as_int(body.get("expires_in"))
        if expires_in is None or expires_in <= 0:
            expires_in = 60
        # renew ahead of the expiry, but still use a short-lived token for most of its lifetime
        window = min(self._options.expiry_safety_window, timedelta(seconds=expires_in // 4))
        return token, self._options.clock() + timedelta(seconds=expires_in) - window

    def __repr__(self) -> str:
        return f"ClientCredentialsTokenProvider(token_url={self._token_url!r}, client_id={self._client_id!r})"


class HealthStatus(Enum):
    """Whether the receiver is in contact with a transmitter."""

    HEALTHY = "healthy"
    """The transmitter was reached: its metadata was retrieved (push) or the last poll succeeded
    (poll), and its stream, if it is looked up or managed, is registered."""
    DEGRADED = "degraded"
    """No contact with the transmitter yet. The application starts without it."""
    UNHEALTHY = "unhealthy"
    """The last poll failed, or the stream cannot be used."""

    def worse(self, other: HealthStatus) -> HealthStatus:
        """The worse of the two statuses."""
        if HealthStatus.UNHEALTHY in (self, other):
            return HealthStatus.UNHEALTHY
        if HealthStatus.DEGRADED in (self, other):
            return HealthStatus.DEGRADED
        return HealthStatus.HEALTHY

    def __str__(self) -> str:
        """The lowercase name."""
        return self.value


@dataclass(frozen=True, slots=True)
class TransmitterHealth:
    """The health of one transmitter, see :meth:`Transmitter.health`."""

    status: HealthStatus
    name: str
    issuer: str
    delivery: str
    """``push`` or ``poll``."""
    metadata_resolved: bool = False
    """Whether the metadata was retrieved."""
    jwks_uri: str = ""
    """The JWK Set location from the metadata, ``""`` if unknown."""
    stream_id: str = ""
    """The identifier of the stream, once known."""
    stream_registration: str = ""
    """The state of the stream registration, ``""`` if the stream is neither looked up nor managed."""
    stream_registration_error: str = ""
    """Why the stream registration failed."""
    last_poll_at: datetime | None = None
    """When the transmitter was last polled."""
    last_successful_poll_at: datetime | None = None
    """When the transmitter was last polled successfully."""
    poll_error: str = ""
    """Why the last poll failed."""
    pending_acks: int = 0
    """The number of acknowledgements and error reports waiting for the next poll request."""
    paused_until: datetime | None = None
    """Until when the transmitter asked not to be polled."""

    def to_mapping(self) -> dict[str, Any]:
        """The health as a JSON-ready mapping with the keys of the Go port, for a health endpoint."""
        health: dict[str, Any] = {
            "status": self.status.value,
            "name": self.name,
            "issuer": self.issuer,
            "delivery": self.delivery,
            "metadataResolved": self.metadata_resolved,
            "pendingAcks": self.pending_acks,
        }
        for key, value in (
            ("jwksUri", self.jwks_uri),
            ("streamId", self.stream_id),
            ("streamRegistration", self.stream_registration),
            ("streamRegistrationError", self.stream_registration_error),
            ("pollError", self.poll_error),
        ):
            if value:
                health[key] = value
        for key, when in (
            ("lastPollAt", self.last_poll_at),
            ("lastSuccessfulPollAt", self.last_successful_poll_at),
            ("pausedUntil", self.paused_until),
        ):
            if when is not None:
                health[key] = when.isoformat()
        return health


@dataclass(eq=False)
class Transmitter:
    """One transmitter as the receiver holds it: its settings, how its SETs are verified, how it is
    called, the stream of the receiver at it, and the background work for it. The receiver builds
    one per configured transmitter, ``transmitter_customizers`` replace parts before the receiver is
    assembled, and an application that assembles a receiver by hand fills one in directly. A plain
    mutable dataclass."""

    name: str = DEFAULT_TRANSMITTER_NAME
    """The name of the transmitter, ``default`` for an unnamed one."""
    issuer: str = ""
    """The issuer of the transmitter, the ``iss`` of its SETs."""
    config: TransmitterConfig = field(default_factory=TransmitterConfig)
    """The settings the transmitter was built from, the defaults if it was not."""
    metadata: MetadataResolver | None = None
    """Resolves the metadata of the transmitter."""
    keys: JwkSetSource | None = None
    """Supplies the JWK Set the SETs are verified against."""
    verifier: Verifier | None = None
    """Verifies the SETs of the transmitter."""
    tokens: TokenProvider | None = None
    """Authenticates the receiver at the transmitter; ``None`` if the transmitter is not called."""
    authorizer: Authorizer | None = None
    """What the calls to the transmitter go through: the bearer token of :attr:`tokens` and the
    configured headers."""
    stream_client: StreamClient | None = None
    """Calls the stream management API; ``None`` if the transmitter is not called."""
    stream: ReceiverStream | None = None
    """Holds the stream of the receiver at the transmitter once it is known."""
    verification: StreamVerification | None = None
    """Validates verification events of the transmitter; one that checks the identifier of
    :attr:`stream` by default."""
    registrar: StreamRegistrar | None = None
    """Looks the stream up or registers it; ``None`` if the stream is neither looked up nor managed."""
    poller: Any = None
    """The ``Poller`` of ``easyssf.receiver.poll`` that polls the transmitter; ``None`` with push
    delivery. ``Any`` because the poller is built on top of this module."""
    auto_start_polling: bool = False
    """Whether :meth:`start` starts the poller; ``poll.auto-startup``."""
    push_authorization_header: str = field(default="", repr=False)
    """The ``Authorization`` header the transmitter has to send to the push endpoint, ``""`` if
    none is expected."""

    def __str__(self) -> str:
        """The name and issuer."""
        return f"{self.name} ({self.issuer})"

    async def start(self) -> None:
        """Starts the background work: looking up or registering the stream, and polling. The
        first poll follows the registration at once: the registrar wakes the poller."""
        if self.registrar is not None:
            if self.poller is not None:
                poller = self.poller
                self.registrar.add_listener(lambda _: poller.wake_up())
            await self.registrar.start()
        if self.poller is not None and self.auto_start_polling:
            await _maybe_await(self.poller.start())

    async def stop(self) -> None:
        """Stops the background work and sends the acknowledgements the poller owes."""
        if self.poller is not None:
            await _maybe_await(self.poller.stop())
        if self.registrar is not None:
            await self.registrar.stop()

    @property
    def critical_subject_members(self) -> list[str]:
        """The ``critical_subject_members`` the transmitter declares in its metadata, empty if none
        or the metadata is not resolved yet: a SET of the transmitter was verified with its keys
        before, so the metadata is the resolved one."""
        if self.metadata is None:
            return []
        resolved = self.metadata.resolved
        return resolved.critical_subject_members if resolved is not None else []

    async def health(self) -> TransmitterHealth:
        """The health of the transmitter as of now, from what the receiver already knows; the
        transmitter is not called."""
        status = HealthStatus.DEGRADED
        metadata_resolved, jwks_uri = False, ""
        if self.metadata is not None and self.metadata.resolved is not None:
            status = HealthStatus.HEALTHY
            metadata_resolved = True
            jwks_uri = self.metadata.resolved.jwks_uri or ""
        stream_id = self.stream.stream_id if self.stream is not None else ""
        registration, registration_error = "", ""
        if self.registrar is not None:
            from .stream import StreamRegistrarState

            state = self.registrar.state
            registration, registration_error = str(state), self.registrar.last_error
            if state is StreamRegistrarState.FAILED:
                status = HealthStatus.UNHEALTHY
            elif state is not StreamRegistrarState.REGISTERED:
                status = HealthStatus.DEGRADED
        delivery = "push"
        last_poll_at: datetime | None = None
        last_successful_poll_at: datetime | None = None
        paused_until: datetime | None = None
        poll_error, pending_acks = "", 0
        if self.poller is not None:
            delivery = "poll"
            pending_acks = int(await _maybe_await(self.poller.pending_ack_count()) or 0)
            last_poll_at = self.poller.last_poll_at
            last_successful_poll_at = self.poller.last_successful_poll_at
            poll_error = self.poller.last_poll_error or ""
            paused_until = self.poller.paused_until
            if poll_error:
                status = HealthStatus.UNHEALTHY
            elif last_successful_poll_at is None and status is not HealthStatus.UNHEALTHY:
                status = HealthStatus.DEGRADED
        return TransmitterHealth(
            status=status,
            name=self.name,
            issuer=self.issuer,
            delivery=delivery,
            metadata_resolved=metadata_resolved,
            jwks_uri=jwks_uri,
            stream_id=stream_id,
            stream_registration=registration,
            stream_registration_error=registration_error,
            last_poll_at=last_poll_at,
            last_successful_poll_at=last_successful_poll_at,
            poll_error=poll_error,
            pending_acks=pending_acks,
            paused_until=paused_until,
        )


async def _maybe_await(result: Any) -> Any:
    """The result, awaited if it is awaitable: the poller is written on top of this module and may
    offer its methods sync or async."""
    if inspect.isawaitable(result):
        return await result
    return result
