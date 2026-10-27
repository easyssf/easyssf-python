"""Token revocation: what session-revoked events revoke, for resource servers to check. The
``TokenRevocationStore`` protocol and its in-memory implementation, ``is_revoked``, the
``TokenRevocationHandler`` that fills the store from events, and the helpers a framework
integration rejects revoked tokens with, including a raw ASGI ``RevocationMiddleware``. The port
of ``receiver/revocation.go`` of the Go port."""

from __future__ import annotations

import inspect
import logging
from collections.abc import Awaitable, Callable, MutableMapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final, Protocol, TypeAlias

from easyssf.core import Subject, event_types

from .errors import Clock, system_clock
from .event import EventContext

__all__ = [
    "DEFAULT_REVOCATION_TTL",
    "DEFAULT_SESSION_EVENT_TYPES",
    "REVOKED_WWW_AUTHENTICATE",
    "InMemoryTokenRevocationStore",
    "RevocationMiddleware",
    "TokenClaims",
    "TokenClaimsExtractor",
    "TokenRevocationHandler",
    "TokenRevocationStore",
    "is_revoked",
    "reject_if_revoked",
    "resolve_event_types",
]

DEFAULT_REVOCATION_TTL: Final = timedelta(hours=24)
"""How long the in-memory store keeps a revocation by default: 24 hours, the maximum lifetime of
an access token."""

DEFAULT_SESSION_EVENT_TYPES: Final[tuple[str, ...]] = ("CaepSessionRevoked",)
"""The event types that revoke sessions by default."""

REVOKED_WWW_AUTHENTICATE: Final = 'Bearer error="invalid_token", error_description="The token was revoked"'
"""The ``WWW-Authenticate`` header of the 401 a revoked token is answered with (RFC 6750, 3.1)."""

_logger = logging.getLogger("easyssf.receiver.revocation")


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """The claims of an access token or session the revocation check reads."""

    issuer: str = ""
    """The ``iss`` claim; a token without one is not revoked."""
    subject: str = ""
    """The ``sub`` claim."""
    session_id: str = ""
    """The ``sid`` claim."""
    issued_at: datetime | None = None
    """The ``iat`` claim, or the time a session was established; ``None`` if unknown."""


class TokenRevocationStore(Protocol):
    """Remembers which sessions and subjects were revoked, so that their access tokens can be
    rejected. Implement it on top of a shared store to share revocations between the instances
    of a resource server, since a SET is pushed to only one of them.

    Sessions and subjects are scoped to the issuer of their tokens: a subject ``alice`` of one
    issuer is not the subject ``alice`` of another. Events name that issuer in an ``iss_sub``
    identifier; for identifiers without one, the transmitter that sent the event is taken to be
    the issuer.

    Revocations only need to be kept for as long as an access token issued before the revocation
    can still be valid, i.e. for the maximum access token lifetime. A failure of the store
    raises.
    """

    async def revoke_session(self, issuer: str, session_id: str) -> None:
        """Revokes all access tokens bound to the given session (the ``sid`` claim)."""
        ...

    async def revoke_subject(self, issuer: str, subject: str, revoked_at: datetime) -> None:
        """Revokes all access tokens of the given subject (the ``sub`` claim) that were issued at
        or before ``revoked_at``."""
        ...

    async def is_session_revoked(self, issuer: str, session_id: str) -> bool:
        """Whether the session was revoked."""
        ...

    async def subject_revoked_at(self, issuer: str, subject: str) -> datetime | None:
        """The time up to which the tokens of the given subject are revoked: the time of the most
        recent revocation, ``None`` if the subject is not revoked."""
        ...


async def is_revoked(store: TokenRevocationStore, claims: TokenClaims) -> bool:
    """Whether an access token was revoked: it is bound to a revoked session, or it belongs to a
    revoked subject and was issued at or before the revocation (a token without ``issued_at`` is
    revoked with its subject). A token without an issuer is not revoked."""
    if not claims.issuer:
        return False
    if claims.session_id and await store.is_session_revoked(claims.issuer, claims.session_id):
        return True
    if not claims.subject:
        return False
    revoked_at = await store.subject_revoked_at(claims.issuer, claims.subject)
    if revoked_at is None:
        return False
    return claims.issued_at is None or claims.issued_at <= revoked_at


@dataclass(frozen=True, slots=True)
class _SubjectRevocation:
    revoked_at: datetime
    expires_at: datetime


class InMemoryTokenRevocationStore:
    """A :class:`TokenRevocationStore` that keeps revocations in memory for a fixed time. Its
    content is lost on restart and not shared between instances. The methods do not await
    anything, so they are atomic on the event loop.

    Args:
        ttl: how long a revocation is kept, the maximum lifetime of an access token;
            :data:`DEFAULT_REVOCATION_TTL` if ``None`` or not positive.
        clock: the clock the expiry is measured by, the system clock by default.
    """

    def __init__(self, ttl: timedelta | None = None, clock: Clock | None = None) -> None:
        self._ttl = ttl if ttl is not None and ttl > timedelta(0) else DEFAULT_REVOCATION_TTL
        self._clock = clock if clock is not None else system_clock
        self._sessions: dict[tuple[str, str], datetime] = {}  # expiry
        self._subjects: dict[tuple[str, str], _SubjectRevocation] = {}

    def __len__(self) -> int:
        """The number of revocations kept, expired ones included until the next write."""
        return len(self._sessions) + len(self._subjects)

    def purge(self) -> None:
        """Drops the revocations that expired. The store purges on every write as well."""
        self._purge(self._clock())

    def _purge(self, now: datetime) -> None:
        self._sessions = {key: expiry for key, expiry in self._sessions.items() if expiry > now}
        self._subjects = {key: revocation for key, revocation in self._subjects.items() if revocation.expires_at > now}

    async def revoke_session(self, issuer: str, session_id: str) -> None:
        """Revokes the session for the ttl."""
        now = self._clock()
        self._purge(now)
        self._sessions[issuer, session_id] = now + self._ttl

    async def revoke_subject(self, issuer: str, subject: str, revoked_at: datetime) -> None:
        """Revokes the subject up to ``revoked_at`` for the ttl; a more recent revocation of the
        same subject is kept, so that an event delivered late does not shorten it."""
        now = self._clock()
        self._purge(now)
        key = (issuer, subject)
        existing = self._subjects.get(key)
        if existing is not None and existing.revoked_at > revoked_at:
            revoked_at = existing.revoked_at
        self._subjects[key] = _SubjectRevocation(revoked_at, now + self._ttl)

    async def is_session_revoked(self, issuer: str, session_id: str) -> bool:
        """Whether the session was revoked within the ttl."""
        expiry = self._sessions.get((issuer, session_id))
        return expiry is not None and expiry > self._clock()

    async def subject_revoked_at(self, issuer: str, subject: str) -> datetime | None:
        """The time of the most recent revocation of the subject within the ttl, else ``None``."""
        revocation = self._subjects.get((issuer, subject))
        if revocation is None or revocation.expires_at <= self._clock():
            return None
        return revocation.revoked_at

    def __repr__(self) -> str:
        return f"InMemoryTokenRevocationStore(ttl={self._ttl}, size={len(self)})"


def resolve_event_types(types: Sequence[str]) -> tuple[str, ...]:
    """The event type URIs of the given aliases or URIs, in order."""
    return tuple(event_types.resolve(t) for t in types)


class TokenRevocationHandler:
    """A :class:`Handler` that records the session or subject of revocation events (by default
    CAEP session-revoked) in the :class:`TokenRevocationStore`.

    A session event that names a session revokes the tokens of that session; one that only names
    a user revokes all tokens of that user issued up to the time of the event. A user event (none
    by default, ``CaepCredentialChange`` for an application whose sessions are cookies) always
    revokes all tokens of the user.

    Args:
        store: where revocations are recorded.
        session_event_types: the event types (alias or URI) that revoke the session they name, or
            all tokens of the user if they name none; :data:`DEFAULT_SESSION_EVENT_TYPES` if
            ``None``, none if empty.
        user_event_types: the event types (alias or URI) that revoke all tokens of the user they
            name, whether or not the event names a session; none if ``None`` or empty.
        logger: the logger, ``easyssf.receiver.revocation`` by default.
    """

    def __init__(
        self,
        store: TokenRevocationStore,
        session_event_types: Sequence[str] | None = None,
        user_event_types: Sequence[str] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._store = store
        self._session_event_types = resolve_event_types(
            DEFAULT_SESSION_EVENT_TYPES if session_event_types is None else session_event_types
        )
        self._user_event_types = resolve_event_types(user_event_types or ())
        self._log = logger if logger is not None else _logger

    @property
    def session_event_types(self) -> tuple[str, ...]:
        """The event type URIs that revoke the session they name."""
        return self._session_event_types

    @property
    def user_event_types(self) -> tuple[str, ...]:
        """The event type URIs that revoke all tokens of the user they name."""
        return self._user_event_types

    async def handle(self, context: EventContext) -> None:
        """Records the revocations of the session and user events of the SET."""
        for event_type in self._session_event_types:
            if context.has_event(event_type):
                await self._revoke(context, event_type, user_event=False)
        for event_type in self._user_event_types:
            if context.has_event(event_type):
                await self._revoke(context, event_type, user_event=True)

    async def _revoke(self, context: EventContext, event_type: str, *, user_event: bool) -> None:
        subject = context.subject_for(event_type)
        if user_event:
            subject = subject.without_session()
        revoked_at = context.event_timestamp(event_type)
        alias = event_types.alias_of(event_type)
        transmitter = context.event_token.issuer
        session_id = subject.session_id
        sub = subject.sub
        opaque_id = subject.opaque_id
        if session_id:
            issuer = _session_issuer(subject) or transmitter
            await self._store.revoke_session(issuer, session_id)
            self._log.info(
                "revoked access tokens of session",
                extra={"event": alias, "session": session_id, "issuer": issuer},
            )
        elif sub:
            user = subject.user_identifier
            issuer = (user.issuer if user is not None else "") or transmitter
            await self._store.revoke_subject(issuer, sub, revoked_at)
            self._log.info(
                "revoked access tokens of subject",
                extra={"event": alias, "subject": sub, "issuer": issuer},
            )
        elif opaque_id:
            # an opaque identifier does not tell whether it names a session or a user
            await self._store.revoke_session(transmitter, opaque_id)
            await self._store.revoke_subject(transmitter, opaque_id, revoked_at)
            self._log.info(
                "revoked access tokens of session or subject",
                extra={"event": alias, "id": opaque_id, "issuer": transmitter},
            )
        else:
            self._log.warning(
                "event has no subject that identifies a session or user by sid or sub, no tokens were revoked",
                extra={"event": alias, "jti": context.event_token.jti},
            )

    def __repr__(self) -> str:
        return (
            f"TokenRevocationHandler(session_event_types={self._session_event_types}, "
            f"user_event_types={self._user_event_types})"
        )


def _session_issuer(subject: Subject) -> str:
    """The issuer a session belongs to: of the session identifier, else of the user."""
    session = subject.session
    issuer = session.issuer if session is not None else ""
    user = subject.user
    if not issuer and user is not None:
        issuer = user.issuer
    return issuer


# -- rejecting revoked tokens -----------------------------------------------------------------------


async def reject_if_revoked(store: TokenRevocationStore, claims: TokenClaims | None) -> bool:
    """Whether a request must be rejected because its access token was revoked: what every
    framework integration calls after the middleware that validated the token left its claims
    on the request. ``None`` is a request without a token, which passes. A failure of the store
    raises; answer it with 503, not with 401."""
    if claims is None:
        return False
    return await is_revoked(store, claims)


_Scope: TypeAlias = MutableMapping[str, Any]
_Message: TypeAlias = MutableMapping[str, Any]
_Receive: TypeAlias = Callable[[], Awaitable[_Message]]
_Send: TypeAlias = Callable[[_Message], Awaitable[None]]
_AsgiApp: TypeAlias = Callable[[_Scope, _Receive, _Send], Awaitable[None]]

TokenClaimsExtractor: TypeAlias = Callable[
    [MutableMapping[str, Any]], "TokenClaims | Awaitable[TokenClaims | None] | None"
]
"""Reads the claims of the access token a request carries from its ASGI scope, as left there by
the middleware that validated it (``scope["state"]``, say); ``None`` for a request without a
token. Sync or async."""


class RevocationMiddleware:
    """A raw ASGI 3 middleware that rejects requests whose access token was revoked with
    401 Unauthorized and a ``WWW-Authenticate`` header (:data:`REVOKED_WWW_AUTHENTICATE`). Mount
    it after the middleware that validates the access token and leaves its claims on the scope.
    A failure of the store answers 503. Non-HTTP scopes (lifespan, websocket) pass through.

    Args:
        app: the application to guard.
        store: the revocations.
        extract: reads the :class:`TokenClaims` of the request from the scope.
    """

    def __init__(self, app: _AsgiApp, store: TokenRevocationStore, extract: TokenClaimsExtractor) -> None:
        self._app = app
        self._store = store
        self._extract = extract

    async def __call__(self, scope: _Scope, receive: _Receive, send: _Send) -> None:
        """Answers 401 for a revoked token, 503 for a failing store, else calls the application."""
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        claims = self._extract(scope)
        if inspect.isawaitable(claims):
            claims = await claims
        try:
            rejected = await reject_if_revoked(self._store, claims)
        except Exception:
            _logger.exception("revocation check failed")
            await _respond(send, 503, [(b"content-type", b"text/plain; charset=utf-8")], b"revocation check failed\n")
            return
        if rejected:
            await _respond(send, 401, [(b"www-authenticate", REVOKED_WWW_AUTHENTICATE.encode())], b"")
            return
        await self._app(scope, receive, send)


async def _respond(send: _Send, status: int, headers: list[tuple[bytes, bytes]], body: bytes) -> None:
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})
