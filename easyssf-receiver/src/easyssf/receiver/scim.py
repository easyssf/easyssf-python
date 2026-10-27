"""The typed handler for SCIM Events (RFC 9967): ``ScimHandler`` with one method per operation,
``scim_handler`` that adapts it to the ``Handler`` protocol, and ``dispatch_scim_event``. The port
of ``receiver/scim.go`` of the Go port."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable
from typing import Final, Protocol, runtime_checkable

from easyssf.core import scim

from .event import EventContext, Handler

__all__ = ["ScimEventHandler", "ScimHandler", "dispatch_scim_event", "scim_handler"]


class ScimHandler:
    """Reacts to SCIM Events (RFC 9967) by operation: :func:`scim_handler` turns it into a
    :class:`Handler` that dispatches every SCIM Event of a SET to the method of its operation.
    Subclass it and override the methods the receiver acts on, the others do nothing; SETs without
    SCIM Events are ignored. The ``NoopScimHandler`` of the Go port is this class itself.

    Each event comes with its :attr:`scim.Event.subject`, the SCIM resource it is about, and the
    :class:`EventContext` of the SET for its ``jti``, ``iss`` and ``txn``. Like every handler, an
    implementation has to be idempotent: a SET is delivered again if any handler failed. The
    ``txn`` claim identifies the underlying transaction across such retransmissions.

    An override may be ``async def`` or a plain ``def``; the result is awaited if it is awaitable.
    A sync override runs on the event loop, so it must not block: do I/O in an ``async def``
    override or hand it to ``asyncio.to_thread`` yourself.

    A subclass that also defines :meth:`ScimEventHandler.on_scim_event` gets every SCIM Event
    through that method instead, for example to refuse events without a SCIM subject, and
    dispatches itself with :func:`dispatch_scim_event` if it wants to.
    """

    def on_feed_add(self, event: scim.Event, context: EventContext) -> Awaitable[None] | None:
        """The resource joined the event feed (``feed:add``)."""
        return None

    def on_feed_remove(self, event: scim.Event, context: EventContext) -> Awaitable[None] | None:
        """The resource left the event feed (``feed:remove``)."""
        return None

    def on_create(self, event: scim.Event, context: EventContext) -> Awaitable[None] | None:
        """The resource was created (``prov:create:notice`` or ``prov:create:full``)."""
        return None

    def on_patch(self, event: scim.Event, context: EventContext) -> Awaitable[None] | None:
        """The resource was modified with SCIM PATCH (``prov:patch:notice`` or ``prov:patch:full``)."""
        return None

    def on_put(self, event: scim.Event, context: EventContext) -> Awaitable[None] | None:
        """The resource was replaced with SCIM PUT (``prov:put:notice`` or ``prov:put:full``)."""
        return None

    def on_delete(self, event: scim.Event, context: EventContext) -> Awaitable[None] | None:
        """The resource was deleted (``prov:delete``)."""
        return None

    def on_activate(self, event: scim.Event, context: EventContext) -> Awaitable[None] | None:
        """The resource was activated (``prov:activate``)."""
        return None

    def on_deactivate(self, event: scim.Event, context: EventContext) -> Awaitable[None] | None:
        """The resource was deactivated (``prov:deactivate``)."""
        return None

    def on_async_response(self, event: scim.Event, context: EventContext) -> Awaitable[None] | None:
        """An asynchronous SCIM request completed (``misc:asyncresp``)."""
        return None


@runtime_checkable
class ScimEventHandler(Protocol):
    """Implemented by a :class:`ScimHandler` that wants every SCIM Event of a SET through one
    method; it may call :func:`dispatch_scim_event` afterwards."""

    def on_scim_event(self, event: scim.Event, context: EventContext) -> Awaitable[None] | None:
        """Handles any SCIM Event of the SET; sync or async."""
        ...


_METHODS: Final[dict[scim.Operation, str]] = {
    scim.Operation.FEED_ADD: "on_feed_add",
    scim.Operation.FEED_REMOVE: "on_feed_remove",
    scim.Operation.CREATE: "on_create",
    scim.Operation.PATCH: "on_patch",
    scim.Operation.PUT: "on_put",
    scim.Operation.DELETE: "on_delete",
    scim.Operation.ACTIVATE: "on_activate",
    scim.Operation.DEACTIVATE: "on_deactivate",
    scim.Operation.ASYNC_RESPONSE: "on_async_response",
}


async def _await(result: Awaitable[None] | None) -> None:
    if inspect.isawaitable(result):
        await result


async def dispatch_scim_event(handler: ScimHandler, event: scim.Event, context: EventContext) -> None:
    """Calls the method of ``handler`` for the operation of the event and awaits the result if
    the method is async; an unknown operation is ignored."""
    name = _METHODS.get(event.operation)
    if name is None:
        return
    await _await(getattr(handler, name)(event, context))


class _ScimAdapter:
    """The :class:`Handler` a :func:`scim_handler` returns."""

    __slots__ = ("_handler",)

    def __init__(self, handler: ScimHandler) -> None:
        self._handler = handler

    @property
    def name(self) -> str:
        """The name of the SCIM handler, for the log."""
        return f"scim_handler({type(self._handler).__name__})"

    async def handle(self, context: EventContext) -> None:
        """Dispatches every SCIM Event of the SET, in the order of their event type URIs."""
        for event in scim.Event.in_token(context.event_token):
            if isinstance(self._handler, ScimEventHandler):
                await _await(self._handler.on_scim_event(event, context))
            else:
                await dispatch_scim_event(self._handler, event, context)

    def __repr__(self) -> str:
        return self.name


def scim_handler(handler: ScimHandler) -> Handler:
    """Turns a :class:`ScimHandler` into a :class:`Handler` that gets every SET and dispatches its
    SCIM Events; the ``Scim`` of the Go port. Give the result to the receiver."""
    return _ScimAdapter(handler)
