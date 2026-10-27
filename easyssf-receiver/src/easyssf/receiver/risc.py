"""The typed handler for RISC 1.0 events: ``RiscHandler`` with one method per kind of event,
``risc_handler`` that adapts it to the ``Handler`` protocol, and ``dispatch_risc_event``. The port
of ``receiver/risc.go`` of the Go port."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable
from typing import Final, Protocol, runtime_checkable

from easyssf.core import risc

from .event import EventContext, Handler

__all__ = ["RiscEventHandler", "RiscHandler", "dispatch_risc_event", "risc_handler"]


class RiscHandler:
    """Reacts to RISC 1.0 events by kind: :func:`risc_handler` turns it into a :class:`Handler`
    that dispatches every RISC event of a SET to the method of its kind, and
    :meth:`on_other_risc_event` for an event type in the RISC namespace this version does not
    know. Subclass it and override the methods the receiver acts on, the others do nothing; SETs
    without RISC events are ignored. The ``NoopRiscHandler`` of the Go port is this class itself.

    Each event comes with the :class:`EventContext` of the SET, whose subject is the account the
    event is about. Like every handler, an implementation has to be idempotent.

    An override may be ``async def`` or a plain ``def``; the result is awaited if it is awaitable.
    A sync override runs on the event loop, so it must not block: do I/O in an ``async def``
    override or hand it to ``asyncio.to_thread`` yourself.

    A subclass that also defines :meth:`RiscEventHandler.on_risc_event` gets every RISC event
    through that method instead, and dispatches itself with :func:`dispatch_risc_event` if it
    wants to.
    """

    def on_account_credential_change_required(self, event: risc.Event, context: EventContext) -> Awaitable[None] | None:
        """The account has to change its credential."""
        return None

    def on_account_purged(self, event: risc.Event, context: EventContext) -> Awaitable[None] | None:
        """The account was permanently deleted."""
        return None

    def on_account_disabled(self, event: risc.Event, context: EventContext) -> Awaitable[None] | None:
        """The account was disabled, see :attr:`risc.Event.reason`."""
        return None

    def on_account_enabled(self, event: risc.Event, context: EventContext) -> Awaitable[None] | None:
        """The account was enabled again."""
        return None

    def on_identifier_changed(self, event: risc.Event, context: EventContext) -> Awaitable[None] | None:
        """The identifier of the account changed, see :attr:`risc.Event.new_value`."""
        return None

    def on_identifier_recycled(self, event: risc.Event, context: EventContext) -> Awaitable[None] | None:
        """The identifier was given to someone else."""
        return None

    def on_credential_compromise(self, event: risc.Event, context: EventContext) -> Awaitable[None] | None:
        """A credential was found compromised, see :attr:`risc.Event.credential_type`."""
        return None

    def on_opt_in(self, event: risc.Event, context: EventContext) -> Awaitable[None] | None:
        """The account takes part in the RISC exchange."""
        return None

    def on_opt_out_initiated(self, event: risc.Event, context: EventContext) -> Awaitable[None] | None:
        """The user asked to leave the RISC exchange."""
        return None

    def on_opt_out_cancelled(self, event: risc.Event, context: EventContext) -> Awaitable[None] | None:
        """The user withdrew the request to leave."""
        return None

    def on_opt_out_effective(self, event: risc.Event, context: EventContext) -> Awaitable[None] | None:
        """The account left the RISC exchange."""
        return None

    def on_recovery_activated(self, event: risc.Event, context: EventContext) -> Awaitable[None] | None:
        """The account went through a recovery flow."""
        return None

    def on_recovery_information_changed(self, event: risc.Event, context: EventContext) -> Awaitable[None] | None:
        """The recovery information changed."""
        return None

    def on_sessions_revoked(self, event: risc.Event, context: EventContext) -> Awaitable[None] | None:
        """All sessions of the account were revoked (deprecated by RISC in favour of
        ``CaepSessionRevoked``)."""
        return None

    def on_other_risc_event(self, event: risc.Event, context: EventContext) -> Awaitable[None] | None:
        """An event in the RISC namespace this version of easyssf does not know
        (:attr:`risc.Kind.OTHER`); its attributes are in :attr:`risc.Event.payload`."""
        return None


@runtime_checkable
class RiscEventHandler(Protocol):
    """Implemented by a :class:`RiscHandler` that wants every RISC event of a SET through one
    method; it may call :func:`dispatch_risc_event` afterwards."""

    def on_risc_event(self, event: risc.Event, context: EventContext) -> Awaitable[None] | None:
        """Handles any RISC event of the SET; sync or async."""
        ...


_METHODS: Final[dict[risc.Kind, str]] = {
    risc.Kind.ACCOUNT_CREDENTIAL_CHANGE_REQUIRED: "on_account_credential_change_required",
    risc.Kind.ACCOUNT_PURGED: "on_account_purged",
    risc.Kind.ACCOUNT_DISABLED: "on_account_disabled",
    risc.Kind.ACCOUNT_ENABLED: "on_account_enabled",
    risc.Kind.IDENTIFIER_CHANGED: "on_identifier_changed",
    risc.Kind.IDENTIFIER_RECYCLED: "on_identifier_recycled",
    risc.Kind.CREDENTIAL_COMPROMISE: "on_credential_compromise",
    risc.Kind.OPT_IN: "on_opt_in",
    risc.Kind.OPT_OUT_INITIATED: "on_opt_out_initiated",
    risc.Kind.OPT_OUT_CANCELLED: "on_opt_out_cancelled",
    risc.Kind.OPT_OUT_EFFECTIVE: "on_opt_out_effective",
    risc.Kind.RECOVERY_ACTIVATED: "on_recovery_activated",
    risc.Kind.RECOVERY_INFORMATION_CHANGED: "on_recovery_information_changed",
    risc.Kind.SESSIONS_REVOKED: "on_sessions_revoked",
}


async def _await(result: Awaitable[None] | None) -> None:
    if inspect.isawaitable(result):
        await result


async def dispatch_risc_event(handler: RiscHandler, event: risc.Event, context: EventContext) -> None:
    """Calls the method of ``handler`` for the kind of the event, :meth:`RiscHandler.on_other_risc_event`
    for a kind without a method, and awaits the result if the method is async."""
    method = getattr(handler, _METHODS.get(event.kind, "on_other_risc_event"))
    await _await(method(event, context))


class _RiscAdapter:
    """The :class:`Handler` a :func:`risc_handler` returns."""

    __slots__ = ("_handler",)

    def __init__(self, handler: RiscHandler) -> None:
        self._handler = handler

    @property
    def name(self) -> str:
        """The name of the RISC handler, for the log."""
        return f"risc_handler({type(self._handler).__name__})"

    async def handle(self, context: EventContext) -> None:
        """Dispatches every RISC event of the SET, in the order of their event type URIs."""
        for event in risc.Event.in_token(context.event_token):
            if isinstance(self._handler, RiscEventHandler):
                await _await(self._handler.on_risc_event(event, context))
            else:
                await dispatch_risc_event(self._handler, event, context)

    def __repr__(self) -> str:
        return self.name


def risc_handler(handler: RiscHandler) -> Handler:
    """Turns a :class:`RiscHandler` into a :class:`Handler` that gets every SET and dispatches its
    RISC events; the ``Risc`` of the Go port. Give the result to the receiver."""
    return _RiscAdapter(handler)
