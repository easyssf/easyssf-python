"""The typed handler for CAEP 1.0 events: ``CaepHandler`` with one method per kind of event,
``caep_handler`` that adapts it to the ``Handler`` protocol, and ``dispatch_caep_event``. The port
of ``receiver/caep.go`` of the Go port."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable
from typing import Final, Protocol, runtime_checkable

from easyssf.core import caep

from .event import EventContext, Handler

__all__ = ["CaepEventHandler", "CaepHandler", "caep_handler", "dispatch_caep_event"]


class CaepHandler:
    """Reacts to CAEP 1.0 events by kind: :func:`caep_handler` turns it into a :class:`Handler`
    that dispatches every CAEP event of a SET to the method of its kind, and
    :meth:`on_other_caep_event` for an event type in the CAEP namespace this version does not
    know. Subclass it and override the methods the receiver acts on, the others do nothing; SETs
    without CAEP events are ignored. The ``NoopCaepHandler`` of the Go port is this class itself.

    Each event comes with typed access to its payload and with the :class:`EventContext` of the
    SET, whose subject the event is about. The built-in reactions to session-revoked and
    credential-change, ending sessions and rejecting tokens, are ``SessionTerminationHandler`` and
    ``TokenRevocationHandler``; this handler is for what the application does on top. Like every
    handler, an implementation has to be idempotent.

    An override may be ``async def`` or a plain ``def``; the result is awaited if it is awaitable.
    A sync override runs on the event loop, so it must not block: do I/O in an ``async def``
    override or hand it to ``asyncio.to_thread`` yourself.

    A subclass that also defines :meth:`CaepEventHandler.on_caep_event` gets every CAEP event
    through that method instead, and dispatches itself with :func:`dispatch_caep_event` if it
    wants to.
    """

    def on_session_revoked(self, event: caep.Event, context: EventContext) -> Awaitable[None] | None:
        """The session was revoked (``CaepSessionRevoked``)."""
        return None

    def on_token_claims_change(self, event: caep.Event, context: EventContext) -> Awaitable[None] | None:
        """Claims of the token changed (``CaepTokenClaimsChange``), see :attr:`caep.Event.claims`."""
        return None

    def on_credential_change(self, event: caep.Event, context: EventContext) -> Awaitable[None] | None:
        """A credential was created, revoked, updated or deleted (``CaepCredentialChange``), see
        :attr:`caep.Event.credential_type` and :attr:`caep.Event.change_type`."""
        return None

    def on_assurance_level_change(self, event: caep.Event, context: EventContext) -> Awaitable[None] | None:
        """The assurance level changed (``CaepAssuranceLevelChange``), see
        :attr:`caep.Event.current_level` and :attr:`caep.Event.change_direction`."""
        return None

    def on_device_compliance_change(self, event: caep.Event, context: EventContext) -> Awaitable[None] | None:
        """The compliance status of the device changed (``CaepDeviceComplianceChange``), see
        :attr:`caep.Event.current_status`."""
        return None

    def on_session_established(self, event: caep.Event, context: EventContext) -> Awaitable[None] | None:
        """A session was established (``CaepSessionEstablished``)."""
        return None

    def on_session_presented(self, event: caep.Event, context: EventContext) -> Awaitable[None] | None:
        """A session was presented (``CaepSessionPresented``)."""
        return None

    def on_risk_level_change(self, event: caep.Event, context: EventContext) -> Awaitable[None] | None:
        """The risk level changed (``CaepRiskLevelChange``), see :attr:`caep.Event.current_level`
        and :attr:`caep.Event.principal`."""
        return None

    def on_other_caep_event(self, event: caep.Event, context: EventContext) -> Awaitable[None] | None:
        """An event in the CAEP namespace this version of easyssf does not know
        (:attr:`caep.Kind.OTHER`): the common claims of CAEP section 2 are typed, the rest is in
        :attr:`caep.Event.payload`."""
        return None


@runtime_checkable
class CaepEventHandler(Protocol):
    """Implemented by a :class:`CaepHandler` that wants every CAEP event of a SET through one
    method, to treat all CAEP events alike; it may call :func:`dispatch_caep_event` afterwards."""

    def on_caep_event(self, event: caep.Event, context: EventContext) -> Awaitable[None] | None:
        """Handles any CAEP event of the SET; sync or async."""
        ...


_METHODS: Final[dict[caep.Kind, str]] = {
    caep.Kind.SESSION_REVOKED: "on_session_revoked",
    caep.Kind.TOKEN_CLAIMS_CHANGE: "on_token_claims_change",
    caep.Kind.CREDENTIAL_CHANGE: "on_credential_change",
    caep.Kind.ASSURANCE_LEVEL_CHANGE: "on_assurance_level_change",
    caep.Kind.DEVICE_COMPLIANCE_CHANGE: "on_device_compliance_change",
    caep.Kind.SESSION_ESTABLISHED: "on_session_established",
    caep.Kind.SESSION_PRESENTED: "on_session_presented",
    caep.Kind.RISK_LEVEL_CHANGE: "on_risk_level_change",
}


async def _await(result: Awaitable[None] | None) -> None:
    if inspect.isawaitable(result):
        await result


async def dispatch_caep_event(handler: CaepHandler, event: caep.Event, context: EventContext) -> None:
    """Calls the method of ``handler`` for the kind of the event, :meth:`CaepHandler.on_other_caep_event`
    for a kind without a method, and awaits the result if the method is async."""
    method = getattr(handler, _METHODS.get(event.kind, "on_other_caep_event"))
    await _await(method(event, context))


class _CaepAdapter:
    """The :class:`Handler` a :func:`caep_handler` returns."""

    __slots__ = ("_handler",)

    def __init__(self, handler: CaepHandler) -> None:
        self._handler = handler

    @property
    def name(self) -> str:
        """The name of the CAEP handler, for the log."""
        return f"caep_handler({type(self._handler).__name__})"

    async def handle(self, context: EventContext) -> None:
        """Dispatches every CAEP event of the SET, in the order of their event type URIs."""
        for event in caep.Event.in_token(context.event_token):
            if isinstance(self._handler, CaepEventHandler):
                await _await(self._handler.on_caep_event(event, context))
            else:
                await dispatch_caep_event(self._handler, event, context)

    def __repr__(self) -> str:
        return self.name


def caep_handler(handler: CaepHandler) -> Handler:
    """Turns a :class:`CaepHandler` into a :class:`Handler` that gets every SET and dispatches its
    CAEP events; the ``Caep`` of the Go port. Give the result to the receiver."""
    return _CaepAdapter(handler)
