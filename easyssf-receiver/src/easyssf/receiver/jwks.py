"""Where the keys that verify the SETs of a transmitter come from: the ``JwkSetSource`` protocol,
a static JWK Set, and the HTTP source that fetches the transmitter's JWK Set, caches it and fetches
it again when a SET names a key it does not know, rate limited. The port of ``receiver/jwks.go``.
"""

from __future__ import annotations

import asyncio
import warnings
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from typing import Final, Protocol, TypeAlias

import httpx
from joserfc.errors import InvalidKeyTypeError, JoseError
from joserfc.jwk import Key, KeySet

from easyssf.core import Claims, parse_claims

from .errors import Clock, TransmitterUnavailableError, system_clock
from .transmitter import send

__all__ = [
    "DEFAULT_CACHE_LIFETIME",
    "DEFAULT_FETCH_TIMEOUT",
    "DEFAULT_REFRESH_RATE_LIMIT",
    "JWK_SET_ACCEPT",
    "HttpJwkSetSource",
    "JwkSetFetch",
    "JwkSetSource",
    "JwkSetUrlResolver",
    "StaticJwkSet",
    "parse_jwk_set",
]

DEFAULT_CACHE_LIFETIME: Final = timedelta(minutes=5)
"""How long a fetched JWK Set is used before it is fetched again, by default."""
DEFAULT_REFRESH_RATE_LIMIT: Final = timedelta(seconds=30)
"""How soon after a fetch the JWK Set may be fetched again for an unknown key, by default."""
DEFAULT_FETCH_TIMEOUT: Final = timedelta(seconds=5)
"""How long the default fetch waits for the JWK Set endpoint; the ``DEFAULT_HTTP_TIMEOUT`` of the
transmitter calls."""
JWK_SET_ACCEPT: Final = "application/jwk-set+json, application/json"
"""The ``Accept`` header of a JWK Set request (RFC 7517, section 8.5.1)."""


class JwkSetSource(Protocol):
    """Supplies the JWK Set the SETs of a transmitter are verified against."""

    async def jwk_set(self, refresh: bool = False) -> KeySet:
        """The current JWK Set. ``refresh`` asks for a fetch because a SET names a key that is
        not in the cached set; a source may rate limit that.

        Raises:
            TransmitterUnavailableError: the keys could not be obtained right now.
        """
        ...


class StaticJwkSet:
    """A :class:`JwkSetSource` over keys known in advance.

    Args:
        keys: the JWK Set, or its JSON object (``{"keys": [...]}``).
    """

    __slots__ = ("_keys",)

    def __init__(self, keys: KeySet | Claims) -> None:
        self._keys = keys if isinstance(keys, KeySet) else parse_jwk_set(keys)

    @property
    def keys(self) -> KeySet:
        """The keys."""
        return self._keys

    async def jwk_set(self, refresh: bool = False) -> KeySet:
        """The keys."""
        return self._keys

    def __repr__(self) -> str:
        return f"StaticJwkSet(kids={[key.kid for key in self._keys.keys]!r})"


JwkSetUrlResolver: TypeAlias = Callable[[], Awaitable[str]]
"""Resolves the location of the JWK Set on first use, for example from the transmitter metadata.
It raises a ``TransmitterUnavailableError`` when the location cannot be resolved right now."""

JwkSetFetch: TypeAlias = Callable[[str], Awaitable[bytes]]
"""Fetches the document at the given URL and returns the body of a successful response; raises
for anything else (no response, a status that is not 2xx). The injection point through which the
receiver wires the transmitter's ``Authorizer``, ``RetryOptions`` and ``UriPolicy`` of
``easyssf.receiver.transmitter`` into :class:`HttpJwkSetSource`."""


class HttpJwkSetSource:
    """A :class:`JwkSetSource` that fetches the JWK Set over HTTP and caches it. The location is
    resolved on first use, so a transmitter that is not reachable does not prevent the receiver
    from starting. The JWK Set is fetched again after ``cache_lifetime``, and when a SET is
    signed with a key that is not in it, at most once per ``refresh_rate_limit``, so that bogus
    SETs cannot make the receiver flood the transmitter. Concurrent callers wait for one fetch.

    A failed fetch is not cached: the next SET fetches again, and is reported as
    :class:`~easyssf.receiver.errors.TransmitterUnavailableError` meanwhile.

    Args:
        client: the HTTP client of the receiver.
        url_or_resolver: the location of the JWK Set, or a :data:`JwkSetUrlResolver` that resolves
            it on first use, for example from the transmitter metadata.
        cache_lifetime: how long a fetched JWK Set is used before it is fetched again.
        refresh_rate_limit: how soon after a fetch the JWK Set may be fetched again because a SET
            names a key that is not in it.
        clock: the clock the cache ages by; the system clock by default.
        timeout: how long the default fetch waits for the response.
        max_response_size: the largest JWK Set the default fetch reads, in bytes;
            :data:`~easyssf.receiver.transmitter.MAX_RESPONSE_SIZE` if ``None``.
        fetch: how the document at the resolved URL is fetched, a :data:`JwkSetFetch`; a plain
            GET through ``send`` of ``easyssf.receiver.transmitter`` with the ``timeout`` and the
            ``max_response_size`` by default. The receiver passes a fetch that adds the
            authorizer, the retry options and the URI policy of the transmitter.
    """

    def __init__(
        self,
        client: httpx.AsyncClient,
        url_or_resolver: str | JwkSetUrlResolver,
        *,
        cache_lifetime: timedelta = DEFAULT_CACHE_LIFETIME,
        refresh_rate_limit: timedelta = DEFAULT_REFRESH_RATE_LIMIT,
        clock: Clock | None = None,
        timeout: timedelta = DEFAULT_FETCH_TIMEOUT,
        max_response_size: int | None = None,
        fetch: JwkSetFetch | None = None,
    ) -> None:
        self._client = client
        if isinstance(url_or_resolver, str):
            self._fixed: str | None = url_or_resolver
            self._resolve: JwkSetUrlResolver | None = None
        else:
            self._fixed = None
            self._resolve = url_or_resolver
        self._cache_lifetime = cache_lifetime
        self._refresh_rate_limit = refresh_rate_limit
        self._clock = clock if clock is not None else system_clock
        self._timeout = timeout
        self._max_response_size = max_response_size
        self._fetch = fetch if fetch is not None else self._get
        self._lock = asyncio.Lock()
        self._url: str | None = None
        self._keys: KeySet | None = None
        self._fetched_at: datetime | None = None

    @property
    def url(self) -> str | None:
        """The location of the JWK Set, ``None`` until it was resolved."""
        return self._url

    @property
    def cache_lifetime(self) -> timedelta:
        """How long a fetched JWK Set is used before it is fetched again."""
        return self._cache_lifetime

    @property
    def refresh_rate_limit(self) -> timedelta:
        """How soon after a fetch the JWK Set may be fetched again for an unknown key."""
        return self._refresh_rate_limit

    def _needs_fetch(self, now: datetime, refresh: bool) -> bool:
        if self._keys is None or self._fetched_at is None:
            return True
        age = now - self._fetched_at
        return age >= self._cache_lifetime or (refresh and age >= self._refresh_rate_limit)

    async def jwk_set(self, refresh: bool = False) -> KeySet:
        """The cached JWK Set, fetched when there is none, after the cache lifetime, or for
        ``refresh`` once per rate limit.

        Raises:
            TransmitterUnavailableError: the location could not be resolved, the JWK Set could
                not be fetched or the endpoint did not answer with a JWK Set.
        """
        async with self._lock:
            if not self._needs_fetch(self._clock(), refresh):
                assert self._keys is not None
                return self._keys
            if self._url is None:
                if self._fixed is not None:
                    self._url = self._fixed
                else:
                    assert self._resolve is not None
                    self._url = await self._resolve()
            url = self._url
            try:
                body = await self._fetch(url)
            except TransmitterUnavailableError:
                raise
            except Exception as error:
                raise TransmitterUnavailableError(
                    error, f"could not retrieve the keys to verify the SET from {url}"
                ) from error
            try:
                keys = parse_jwk_set(body)
            except ValueError as error:
                raise TransmitterUnavailableError(
                    error, f"the JWK Set endpoint {url} did not answer with a JWK Set"
                ) from error
            self._keys = keys
            self._fetched_at = self._clock()
            return keys

    async def _get(self, url: str) -> bytes:
        """The default fetch: a plain GET with the timeout and the bounded body, redirects only
        within the origin (see ``UriPolicy``)."""
        response = await send(
            self._client,
            "GET",
            url,
            timeout=self._timeout,
            max_response_size=self._max_response_size,
            headers={"Accept": JWK_SET_ACCEPT},
        )
        if not response.successful:
            raise TransmitterUnavailableError(
                None, f"could not retrieve the keys from {url}: the transmitter answered with status {response.status}"
            )
        return response.body

    def __repr__(self) -> str:
        return f"HttpJwkSetSource(url={self._url or self._fixed!r}, cached={self._keys is not None})"


def parse_jwk_set(document: bytes | str | Claims) -> KeySet:
    """Reads a JWK Set (RFC 7517, section 5) from its JSON or its decoded object. A key whose
    ``kty`` is not understood is skipped, as RFC 7517 allows; an empty set is a set, so that a
    transmitter that rotated all its keys away is reported as an unknown key, not as unavailable.

    Raises:
        ValueError: the document is not a JWK Set, or a key of a known type is malformed.
    """
    try:
        claims = document if isinstance(document, dict) else parse_claims(document)
    except ValueError as error:
        raise ValueError(f"not a JWK Set: {error}") from error
    entries = claims.get("keys")
    if not isinstance(entries, list):
        raise ValueError("not a JWK Set: no keys array")
    keys: list[Key] = []
    with warnings.catch_warnings():
        # a weak key is rejected by the verifier with an error code, not warned about here
        warnings.simplefilter("ignore")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("not a JWK Set: a key is not a JSON object")
            try:
                keys.append(KeySet.registry_cls.import_key(entry))
            except InvalidKeyTypeError:
                continue
            except (JoseError, ValueError, TypeError, KeyError) as error:
                raise ValueError(f"not a JWK Set: a key is malformed: {error}") from error
    return KeySet(keys)
