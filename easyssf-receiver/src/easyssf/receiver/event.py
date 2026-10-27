"""The context a handler receives and the handlers themselves: the ``Handler`` protocol, plain
callables as handlers, and ``for_event`` to react to one event type only."""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any, Protocol, TypeAlias, runtime_checkable

from easyssf.core import Claims, DeliveryMethod, EventToken, Subject, event_timestamp, event_types, object_member

__all__ = [
    "EventContext",
    "Handler",
    "HandlerCallable",
    "HandlerFunc",
    "as_handler",
    "for_event",
    "handler_name",
]


class EventContext:
    """A verified :class:`~easyssf.core.EventToken` together with convenient, alias-aware access
    to its events and subjects. Passed to every :class:`Handler`. Immutable, so a handler can hand
    it to a task.

    Args:
        token: the verified SET.
        delivery: how the SET arrived.
    """

    __slots__ = ("_delivery", "_subject", "_token")

    def __init__(self, token: EventToken, delivery: DeliveryMethod) -> None:
        self._token = token
        self._subject = Subject.from_claims(token.subject_id)
        self._delivery = delivery

    @property
    def event_token(self) -> EventToken:
        """The verified SET."""
        return self._token

    @property
    def delivery_method(self) -> DeliveryMethod:
        """How the SET arrived."""
        return self._delivery

    @property
    def idempotency_key(self) -> str:
        """The key for making the side effects of a handler idempotent, the issuer and ``jti`` of
        the SET: a SET is handled at least once, not exactly once (see :class:`Handler`)."""
        return self._token.idempotency_key

    @property
    def event_types(self) -> list[str]:
        """The event type URIs contained in the SET, in the order received."""
        return list(self._token.events)

    def has_event(self, alias_or_uri: str) -> bool:
        """Whether the SET contains an event of the given type, named by alias (such as
        ``CaepSessionRevoked``) or URI."""
        return event_types.resolve(alias_or_uri) in self._token.events

    def event(self, alias_or_uri: str) -> Claims | None:
        """The payload of the event of the given type (alias or URI), ``None`` if the SET has no
        such event or its payload is not a JSON object."""
        payload = self._token.events.get(event_types.resolve(alias_or_uri))
        return payload if isinstance(payload, dict) else None

    @property
    def subject(self) -> Subject:
        """The subject of the SET, taken from its top-level ``sub_id`` claim; empty if the SET
        has none."""
        return self._subject

    def subject_for(self, alias_or_uri: str) -> Subject:
        """The subject of the event of the given type: the top-level ``sub_id`` claim of the SET
        or, for transmitters following earlier SSF drafts, the ``subject`` member of the event
        payload. SETs without the top-level claim reach a handler only in the
        :attr:`~easyssf.core.SubjectCompatibilityMode.LEGACY` subject compatibility mode of the
        verifier."""
        if not self._subject.is_empty:
            return self._subject
        legacy = object_member(self.event(alias_or_uri), "subject")
        if legacy is not None:
            return Subject.from_claims(legacy)
        return Subject.empty()

    def event_timestamp(self, alias_or_uri: str) -> datetime:
        """The time the event of the given type occurred: its ``event_timestamp`` or, if absent,
        the time the SET was issued."""
        payload = self.event(alias_or_uri)
        if payload is not None:
            timestamp = event_timestamp(payload.get("event_timestamp"))
            if timestamp is not None:
                return timestamp
        return self._token.issued_at

    def __repr__(self) -> str:
        return f"EventContext(token={self._token!r}, delivery={self._delivery})"


@runtime_checkable
class Handler(Protocol):
    """Reacts to verified security events. Every handler given to the processor is invoked for
    every SET.

    A SET is handled at least once, not exactly once, so handlers must be idempotent. A SET is
    delivered again if any handler failed, and all handlers run again, possibly on another
    instance of the application; with a shared dedup store a SET is claimed while its handlers
    run and another instance leaves it alone meanwhile, but an instance that dies after a
    handler's side effects and before the success is recorded hands the SET to the next instance
    after a lease. Side effects outside the receiver's stores should be keyed by
    :attr:`EventContext.idempotency_key`.

    An exception leaves the SET unacknowledged, the transmitter delivers it again. A plain
    callable, sync or async, is a handler too: see :func:`as_handler`.
    """

    async def handle(self, context: EventContext) -> None:
        """Handles a SET; raises to have it delivered again."""
        ...


HandlerCallable: TypeAlias = Callable[[EventContext], Awaitable[None] | None]
"""A handler written as a function: ``async def`` is awaited, a sync ``def`` runs in a worker
thread through ``asyncio.to_thread``."""


class HandlerFunc:
    """A :class:`Handler` written as a function, sync or async.

    An ``async def`` is awaited; a sync ``def`` runs in a worker thread through
    ``asyncio.to_thread`` so that it does not block the event loop (and is awaited after all if
    it returned an awaitable).

    Args:
        func: the callable, taking the :class:`EventContext`.
        name: the name for the log, that of the callable by default.
    """

    __slots__ = ("_func", "_is_async", "_name")

    def __init__(self, func: HandlerCallable, name: str | None = None) -> None:
        self._func = func
        self._is_async = _is_coroutine_function(func)
        self._name = name if name is not None else _callable_name(func)

    @property
    def name(self) -> str:
        """The name of the function, for the log."""
        return self._name

    async def handle(self, context: EventContext) -> None:
        """Calls the function, in a worker thread if it is sync."""
        if self._is_async:
            result = self._func(context)
        else:
            result = await asyncio.to_thread(self._func, context)
        if inspect.isawaitable(result):
            await result

    def __repr__(self) -> str:
        return f"HandlerFunc({self._name})"


def as_handler(handler: Handler | HandlerCallable) -> Handler:
    """The given handler as a :class:`Handler`: an object with an async ``handle`` method as it
    is, a sync or async callable wrapped in a :class:`HandlerFunc`."""
    if isinstance(handler, Handler):
        return handler
    if not callable(handler):
        raise TypeError(
            f"a handler is an object with an async handle method or a callable, not {type(handler).__name__}"
        )
    return HandlerFunc(handler)


class _ForEvent:
    """Calls a handler only for SETs with an event of the given type."""

    __slots__ = ("_event_type", "_handler")

    def __init__(self, event_type: str, handler: Handler) -> None:
        self._event_type = event_type
        self._handler = handler

    @property
    def name(self) -> str:
        """The alias of the event type and the name of the handler, for the log."""
        return f"for_event({event_types.alias_of(self._event_type)}, {handler_name(self._handler)})"

    async def handle(self, context: EventContext) -> None:
        if context.has_event(self._event_type):
            await self._handler.handle(context)

    def __repr__(self) -> str:
        return self.name


def for_event(alias_or_uri: str, handler: Handler | HandlerCallable) -> Handler:
    """A handler that calls ``handler`` only for SETs with an event of the given type (alias or
    URI); ``handler`` is a :class:`Handler` or a sync or async callable (see :func:`as_handler`)."""
    return _ForEvent(event_types.resolve(alias_or_uri), as_handler(handler))


def handler_name(handler: object) -> str:
    """The name of a handler for the log: its ``name`` if it has one (a :class:`HandlerFunc`
    names its function), the name of its type otherwise."""
    name = getattr(handler, "name", None)
    if isinstance(name, str) and name:
        return name
    return type(handler).__name__


def _is_coroutine_function(func: Callable[..., Any]) -> bool:
    """Whether calling ``func`` gives a coroutine: an ``async def``, a partial of one, or an
    object whose ``__call__`` is one."""
    while isinstance(func, functools.partial):
        func = func.func
    if inspect.iscoroutinefunction(func):
        return True
    call = getattr(type(func), "__call__", None)  # noqa: B004 - the method, to inspect it
    return not inspect.isfunction(func) and not inspect.ismethod(func) and inspect.iscoroutinefunction(call)


def _callable_name(func: Callable[..., Any]) -> str:
    while isinstance(func, functools.partial):
        func = func.func
    name = getattr(func, "__qualname__", None) or getattr(func, "__name__", None)
    return name if isinstance(name, str) and name else type(func).__name__
