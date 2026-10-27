"""Session termination: ending the local sessions of the subject of an event, for applications
whose sessions are not access tokens (an OIDC client with a session cookie, say), and matching
the subject of an event with the claims of a logged-in user. The ``SessionTerminator`` protocol,
the ``SessionTerminationHandler`` and ``subject_matches``; the port of ``receiver/session.go`` of
the Go port and of ``org.easyssf.receiver.session``."""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable, Iterable, Sequence
from typing import Final, Protocol, TypeAlias, runtime_checkable

from easyssf.core import Claims, Format, Subject, SubjectIdentifier, event_types, string_member
from easyssf.core.scim import ScimSubject

from .config import DEFAULT_SCIM_ATTRIBUTE_CLAIMS
from .event import EventContext
from .revocation import DEFAULT_SESSION_EVENT_TYPES, resolve_event_types

__all__ = [
    "DEFAULT_SCIM_ATTRIBUTE_CLAIMS",
    "DEFAULT_SESSION_TERMINATION_USER_EVENT_TYPES",
    "SessionTerminationHandler",
    "SessionTerminator",
    "SessionTerminatorCallable",
    "SessionTerminatorFunc",
    "as_session_terminator",
    "describe_subject",
    "subject_matches",
    "subject_matches_with",
]

DEFAULT_SESSION_TERMINATION_USER_EVENT_TYPES: Final[tuple[str, ...]] = ("CaepCredentialChange",)
"""The event types that terminate all sessions of their subject's user by default."""

_logger = logging.getLogger("easyssf.receiver.session")


@runtime_checkable
class SessionTerminator(Protocol):
    """Terminates the local sessions of a subject. Implement it over the session store of the
    application; :func:`subject_matches` tells which sessions belong to the subject. A plain
    callable, sync or async, is a terminator too: see :func:`as_session_terminator`."""

    async def terminate_sessions(self, subject: Subject) -> int:
        """Terminates the sessions that belong to the given subject: the session with the
        subject's session identifier if it has one, otherwise all sessions of its user. Returns
        the number of terminated sessions."""
        ...


SessionTerminatorCallable: TypeAlias = Callable[[Subject], "int | Awaitable[int]"]
"""A session terminator written as a function: ``async def`` is awaited, a sync ``def`` runs in
a worker thread through ``asyncio.to_thread``."""


class SessionTerminatorFunc:
    """A :class:`SessionTerminator` written as a function, sync or async; the
    ``SessionTerminatorFunc`` of the Go port.

    An ``async def`` is awaited; a sync ``def`` runs in a worker thread through
    ``asyncio.to_thread`` so that it does not block the event loop (and is awaited after all if
    it returned an awaitable).

    Args:
        func: the callable, taking the :class:`~easyssf.core.Subject` and returning the number of
            terminated sessions.
    """

    __slots__ = ("_func", "_is_async")

    def __init__(self, func: SessionTerminatorCallable) -> None:
        self._func = func
        self._is_async = inspect.iscoroutinefunction(func)

    async def terminate_sessions(self, subject: Subject) -> int:
        """Calls the function, in a worker thread if it is sync."""
        result = self._func(subject) if self._is_async else await asyncio.to_thread(self._func, subject)
        if inspect.isawaitable(result):
            result = await result
        return int(result)

    def __repr__(self) -> str:
        name = getattr(self._func, "__qualname__", None) or type(self._func).__name__
        return f"SessionTerminatorFunc({name})"


def as_session_terminator(terminator: SessionTerminator | SessionTerminatorCallable) -> SessionTerminator:
    """The given terminator as a :class:`SessionTerminator`: an object with an async
    ``terminate_sessions`` method as it is, a sync or async callable wrapped in a
    :class:`SessionTerminatorFunc`."""
    if isinstance(terminator, SessionTerminator):
        return terminator
    if not callable(terminator):
        raise TypeError(
            "a session terminator is an object with an async terminate_sessions method or a callable, "
            f"not {type(terminator).__name__}"
        )
    return SessionTerminatorFunc(terminator)


class SessionTerminationHandler:
    """A :class:`Handler` that terminates local sessions in reaction to security events.

    Session events (by default CAEP session-revoked) terminate the session named by the event, or
    all sessions of its user if it names no session. User events (by default CAEP
    credential-change) always terminate all sessions of the user.

    Args:
        terminator: the :class:`SessionTerminator` of the application, or a sync or async callable
            (see :func:`as_session_terminator`).
        session_event_types: the event types (alias or URI) that terminate the session they name;
            :data:`~easyssf.receiver.revocation.DEFAULT_SESSION_EVENT_TYPES` if ``None``, none if
            empty.
        user_event_types: the event types (alias or URI) that terminate all sessions of the user;
            :data:`DEFAULT_SESSION_TERMINATION_USER_EVENT_TYPES` if ``None``, none if empty.
        logger: the logger, ``easyssf.receiver.session`` by default.
    """

    def __init__(
        self,
        terminator: SessionTerminator | SessionTerminatorCallable,
        session_event_types: Sequence[str] | None = None,
        user_event_types: Sequence[str] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._terminator = as_session_terminator(terminator)
        self._session_event_types = resolve_event_types(
            DEFAULT_SESSION_EVENT_TYPES if session_event_types is None else session_event_types
        )
        self._user_event_types = resolve_event_types(
            DEFAULT_SESSION_TERMINATION_USER_EVENT_TYPES if user_event_types is None else user_event_types
        )
        self._log = logger if logger is not None else _logger

    @property
    def session_event_types(self) -> tuple[str, ...]:
        """The event type URIs that terminate the session they name."""
        return self._session_event_types

    @property
    def user_event_types(self) -> tuple[str, ...]:
        """The event type URIs that terminate all sessions of the user they name."""
        return self._user_event_types

    async def handle(self, context: EventContext) -> None:
        """Terminates the sessions of the subjects of the session and user events of the SET."""
        for event_type in self._session_event_types:
            if context.has_event(event_type):
                await self._terminate(context, event_type, context.subject_for(event_type))
        for event_type in self._user_event_types:
            if context.has_event(event_type):
                await self._terminate(context, event_type, context.subject_for(event_type).without_session())

    async def _terminate(self, context: EventContext, event_type: str, subject: Subject) -> None:
        alias = event_types.alias_of(event_type)
        if subject.is_empty:
            self._log.warning(
                "event has no subject that identifies a session or user, no sessions were terminated",
                extra={"event": alias, "jti": context.event_token.jti},
            )
            return
        terminated = await self._terminator.terminate_sessions(subject)
        self._log.info(
            "terminated session(s)",
            extra={"event": alias, "terminated": terminated, "subject": describe_subject(subject)},
        )

    def __repr__(self) -> str:
        return f"SessionTerminationHandler({self._terminator!r})"


def describe_subject(subject: Subject) -> str:
    """The subject for the log: ``session <id>``, ``user <value>`` or ``session or subject <id>``
    for an opaque identifier."""
    session_id = subject.session_id
    if session_id:
        return "session " + session_id
    user = subject.user_identifier
    if user is not None:
        value = user.value
        return "user " + (value if value else user.format)
    return "session or subject " + subject.opaque_id


# -- matching the subject of an event with the claims of a logged-in user ---------------------------


def subject_matches(subject: Subject, claims: Claims, name: str = "") -> bool:
    """Whether the subject of a security event refers to a user or session that is described by
    ``claims``, typically the claims of the ID token the user logged in with: ``sid`` for a
    session, ``iss`` and ``sub``, ``email`` or ``phone_number`` for a user. ``name`` is the name
    of the user, compared with the subject of the event if the claims have no ``sub``; ``""`` for
    none.

    An ``iss_sub`` identifier names the user at an issuer, so both have to match: claims without
    an ``iss`` never match such a subject. A session is matched by its ``sid`` and, if the event
    names the issuer of the session or of its user, by that issuer as well.

    A ``scim`` identifier (RFC 9967) names a resource of a SCIM service provider, whose
    identifiers an OpenID Provider may or may not share; it is matched with the
    :data:`DEFAULT_SCIM_ATTRIBUTE_CLAIMS`, see :func:`subject_matches_with`.
    """
    return subject_matches_with(subject, claims, name, DEFAULT_SCIM_ATTRIBUTE_CLAIMS)


def subject_matches_with(
    subject: Subject, claims: Claims, name: str, scim_attribute_claims: Iterable[tuple[str, str]]
) -> bool:
    """:func:`subject_matches` with the attributes of a ``scim`` subject (RFC 9967) and the claim
    each is compared with, for example ``externalId`` with ``sub``; the subject matches if any
    pair does. A SCIM attribute that is multi-valued, such as ``emails``, matches if any of its
    values (the ``value`` of each entry) does. Values compared with the ``email`` claim match
    ignoring case, all others exactly."""
    session_id = _claim_string(claims, "sid")
    user_subject = _claim_string(claims, "sub") or name
    session = subject.session
    if session is not None:
        if not session.value or session.value != session_id:
            return False
        # the session belongs to the issuer the event names, in the session identifier or the
        # user it belongs to; session identifiers are not unique across issuers
        issuer = session.issuer
        user = subject.user
        if not issuer and user is not None:
            issuer = user.issuer
        return not issuer or issuer == _claim_string(claims, "iss")
    user_identifier = subject.user_identifier
    if user_identifier is not None:
        return _matches_user(user_identifier, claims, user_subject, scim_attribute_claims)
    opaque_id = subject.opaque_id
    if opaque_id:
        # an opaque identifier does not tell whether it names a session or a user
        return opaque_id in (session_id, user_subject)
    return False


def _matches_user(
    user: SubjectIdentifier, claims: Claims, user_subject: str, scim_attribute_claims: Iterable[tuple[str, str]]
) -> bool:
    value = user.value
    fmt = user.format
    if fmt == Format.ISS_SUB:
        return (
            bool(value) and value == user_subject and bool(user.issuer) and user.issuer == _claim_string(claims, "iss")
        )
    if fmt == Format.EMAIL:
        return bool(value) and value.casefold() == _claim_string(claims, "email").casefold()
    if fmt == Format.OPAQUE:
        return bool(value) and value == user_subject
    if fmt == Format.ALIASES:
        return any(_matches_user(alias, claims, user_subject, scim_attribute_claims) for alias in user.aliases)
    if fmt == Format.SCIM:
        resource = ScimSubject.from_identifier(user)
        return resource is not None and _matches_scim_resource(resource, claims, user_subject, scim_attribute_claims)
    # phone_number, account, did, uri and unknown formats: a claim of the same name
    return bool(value) and value == _claim_string(claims, fmt)


def _matches_scim_resource(
    resource: ScimSubject, claims: Claims, user_subject: str, scim_attribute_claims: Iterable[tuple[str, str]]
) -> bool:
    for attribute, claim_name in scim_attribute_claims:
        claim_value = user_subject if claim_name == "sub" else _claim_string(claims, claim_name)
        if not claim_value:
            continue
        for value in _scim_attribute_values(resource, attribute):
            if (claim_name == "email" and value.casefold() == claim_value.casefold()) or value == claim_value:
                return True
    return False


def _scim_attribute_values(resource: ScimSubject, attribute: str) -> list[str]:
    """The values of an attribute of a SCIM resource: the string of a single-valued attribute,
    the id resolved from the uri if the resource has no id attribute, or the strings and the
    ``value`` members of a multi-valued attribute such as ``emails``."""
    if attribute == "id":
        resource_id = resource.id
        return [resource_id] if resource_id else []
    value = resource.claims.get(attribute)
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        values = []
        for element in value:
            if isinstance(element, str):
                if element.strip():
                    values.append(element)
            elif isinstance(element, dict):
                member = string_member(element, "value")
                if member:
                    values.append(member)
        return values
    return []


def _claim_string(claims: Claims, name: str) -> str:
    """A claim as text: a string as it is, ``None`` as ``""``, anything else rendered as JSON
    would, so that a numeric ``sub`` still compares."""
    value = claims.get(name)
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)
