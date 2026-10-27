"""SsfCaepEventHandlerTests, SsfRiscEventHandlerTests and SsfScimEventHandlerTests of the Java
library, receiver/typed_handlers_test.go of the Go port."""

import re
from typing import Any

import pytest

from easyssf.core import Claims, DeliveryMethod, EventToken, EventTypes, caep, risc, scim
from easyssf.core.subjects import iss_sub
from easyssf.core.subjects import scim as scim_subject
from easyssf.receiver.caep import CaepHandler, caep_handler, dispatch_caep_event
from easyssf.receiver.event import EventContext, Handler, handler_name
from easyssf.receiver.risc import RiscHandler, dispatch_risc_event, risc_handler
from easyssf.receiver.scim import ScimHandler, scim_handler
from easyssf.testing import TestTransmitter

IDP = "https://idp.example"


class Calls:
    """Records what a handler was called with, in order."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def record(self, what: str) -> None:
        self.calls.append(what)

    def take(self) -> list[str]:
        taken, self.calls = self.calls, []
        return taken

    def expect(self, *expected: str) -> None:
        assert self.take() == list(expected)


def context(claims: Claims) -> EventContext:
    token = EventToken.from_claims(claims)
    assert token is not None
    return EventContext(token, DeliveryMethod.PUSH)


def context_with(events: Claims) -> EventContext:
    return context(
        {"jti": "1", "iss": "https://t.example", "iat": 1, "sub_id": iss_sub(IDP, "alice"), "events": events}
    )


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


# CAEP: every method is async


class CaepRecorder(CaepHandler):
    def __init__(self, calls: Calls) -> None:
        self.calls = calls

    async def on_session_revoked(self, event: caep.Event, context: EventContext) -> None:
        self.calls.record(f"session_revoked:{context.subject.sub}:{event.initiating_entity}")

    async def on_token_claims_change(self, event: caep.Event, context: EventContext) -> None:
        self.calls.record("token_claims_change")

    async def on_credential_change(self, event: caep.Event, context: EventContext) -> None:
        self.calls.record("credential_change")

    async def on_assurance_level_change(self, event: caep.Event, context: EventContext) -> None:
        self.calls.record("assurance_level_change")

    async def on_device_compliance_change(self, event: caep.Event, context: EventContext) -> None:
        self.calls.record("device_compliance_change")

    async def on_session_established(self, event: caep.Event, context: EventContext) -> None:
        self.calls.record("session_established")

    async def on_session_presented(self, event: caep.Event, context: EventContext) -> None:
        self.calls.record("session_presented")

    async def on_risk_level_change(self, event: caep.Event, context: EventContext) -> None:
        self.calls.record("risk_level_change")

    async def on_other_caep_event(self, event: caep.Event, context: EventContext) -> None:
        self.calls.record("other:" + event.event_type)


async def test_caep_dispatches_every_kind_to_its_method():
    calls = Calls()
    handler = caep_handler(CaepRecorder(calls))
    for kind, event_type in caep.KNOWN:
        await handler.handle(context_with({event_type: {"initiating_entity": "admin"}}))
        expected = snake(kind.value)
        if kind is caep.Kind.SESSION_REVOKED:
            expected = "session_revoked:alice:admin"
        calls.expect(expected)
    await handler.handle(context_with({"https://schemas.openid.net/secevent/caep/event-type/future": {}}))
    calls.expect("other:https://schemas.openid.net/secevent/caep/event-type/future")


async def test_handles_all_caep_events_of_a_set_and_ignores_other_sets():
    calls = Calls()
    handler = caep_handler(CaepRecorder(calls))
    await handler.handle(
        context_with(
            {
                EventTypes.CAEP_CREDENTIAL_CHANGE: {},
                EventTypes.RISC_ACCOUNT_DISABLED: {},
                EventTypes.CAEP_RISK_LEVEL_CHANGE: {},
            }
        )
    )
    calls.expect("credential_change", "risk_level_change")
    await handler.handle(context_with({EventTypes.RISC_ACCOUNT_DISABLED: {}}))
    calls.expect()


async def test_caep_set_passes_strict_verification_and_reaches_the_handler():
    # the SET of the test transmitter, as the processor hands it to the handler after verification
    transmitter = TestTransmitter()
    calls = Calls()
    handler = caep_handler(CaepRecorder(calls))
    await handler.handle(context(transmitter.set_claims("CaepSessionRevoked", iss_sub(transmitter.issuer, "alice"))))
    calls.expect("session_revoked:alice:")


async def test_caep_handler_that_does_nothing_is_a_noop():
    handler = caep_handler(CaepHandler())
    await handler.handle(context_with({EventTypes.CAEP_SESSION_REVOKED: {}}))
    assert isinstance(handler, Handler)
    assert handler_name(handler) == "caep_handler(CaepHandler)"


async def test_error_of_a_caep_method_propagates():
    class Failing(CaepHandler):
        async def on_session_revoked(self, event: caep.Event, context: EventContext) -> None:
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        await caep_handler(Failing()).handle(context_with({EventTypes.CAEP_SESSION_REVOKED: {}}))


async def test_sync_caep_override_is_called_on_the_loop():
    calls = Calls()

    class Sync(CaepHandler):
        def on_session_revoked(self, event: caep.Event, context: EventContext) -> None:
            calls.record("sync")

    await caep_handler(Sync()).handle(context_with({EventTypes.CAEP_SESSION_REVOKED: {}}))
    calls.expect("sync")
    event = caep.Event.of("CaepSessionRevoked")
    assert event is not None
    await dispatch_caep_event(Sync(), event, context_with({EventTypes.CAEP_SESSION_REVOKED: {}}))
    calls.expect("sync")


# RISC: the methods are sync, the event handler dispatches itself


class RiscRecorder(RiscHandler):
    def __init__(self, calls: Calls) -> None:
        self.calls = calls

    async def on_risc_event(self, event: risc.Event, context: EventContext) -> None:
        self.calls.record(event.kind.value)
        await dispatch_risc_event(self, event, context)

    def on_account_disabled(self, event: risc.Event, context: EventContext) -> None:
        self.calls.record("disabled:" + event.reason)

    def on_account_purged(self, event: risc.Event, context: EventContext) -> None:
        self.calls.record("purged")


async def test_risc_dispatches_every_kind_to_its_method():
    calls = Calls()
    handler = risc_handler(RiscRecorder(calls))
    await handler.handle(context_with({EventTypes.RISC_ACCOUNT_DISABLED: {"reason": "hijacking"}}))
    calls.expect("AccountDisabled", "disabled:hijacking")
    for kind, event_type in risc.KNOWN:
        await handler.handle(context_with({event_type: {}}))
        assert calls.take()[0] == kind.value


async def test_handles_all_risc_events_of_a_set_and_ignores_other_sets():
    calls = Calls()
    handler = risc_handler(RiscRecorder(calls))
    await handler.handle(
        context_with(
            {EventTypes.CAEP_SESSION_REVOKED: {}, EventTypes.RISC_ACCOUNT_PURGED: {}, EventTypes.RISC_OPT_IN: {}}
        )
    )
    calls.expect("AccountPurged", "purged", "OptIn")


async def test_risc_set_passes_strict_verification_and_reaches_the_handler():
    transmitter = TestTransmitter()
    calls = Calls()
    handler = risc_handler(RiscRecorder(calls))
    await handler.handle(context(transmitter.set_claims("RiscAccountPurged", iss_sub(transmitter.issuer, "alice"))))
    calls.expect("AccountPurged", "purged")


async def test_unknown_risc_event_reaches_on_other_risc_event():
    calls = Calls()

    class Other(RiscHandler):
        def on_other_risc_event(self, event: risc.Event, context: EventContext) -> None:
            calls.record("other:" + event.event_type)

    future = "https://schemas.openid.net/secevent/risc/event-type/future"
    await risc_handler(Other()).handle(context_with({future: {}}))
    calls.expect("other:" + future)
    assert handler_name(risc_handler(Other())) == "risc_handler(Other)"


# SCIM


class ScimRecorder(ScimHandler):
    def __init__(self, calls: Calls) -> None:
        self.calls = calls

    async def on_scim_event(self, event: scim.Event, context: EventContext) -> None:
        resource_id = event.subject.id if event.subject is not None else ""
        self.calls.record(f"{event.operation.value}:{resource_id}")
        if event.operation is scim.Operation.CREATE:
            await self.on_create(event, context)

    async def on_create(self, event: scim.Event, context: EventContext) -> None:
        self.calls.record(f"create:full={event.is_full}")


async def test_scim_dispatches_every_operation_to_its_method():
    calls = Calls()
    handler = scim_handler(ScimRecorder(calls))
    for operation, event_type in scim.KNOWN:
        claims: dict[str, Any] = {
            "jti": "1",
            "iss": "i",
            "iat": 1,
            "sub_id": scim_subject("/Users/42"),
            "events": {event_type: {"data": {}}},
        }
        await handler.handle(context(claims))
        taken = calls.take()
        assert taken[0] == f"{operation.value}:42", event_type
        if operation is scim.Operation.CREATE:
            assert taken[1] == f"create:full={event_type.endswith(':full')}"


async def test_handles_all_scim_events_of_a_set_and_ignores_other_sets():
    calls = Calls()
    handler = scim_handler(ScimRecorder(calls))
    await handler.handle(
        context_with(
            {EventTypes.SCIM_PROV_DELETE: {}, EventTypes.CAEP_SESSION_REVOKED: {}, EventTypes.SCIM_FEED_REMOVE: {}}
        )
    )
    # the SET's subject is iss_sub, so the events have no SCIM subject; sorted by URI
    calls.expect("FeedRemove:", "Delete:")
    await handler.handle(context_with({EventTypes.CAEP_SESSION_REVOKED: {}}))
    calls.expect()


async def test_scim_set_passes_strict_verification_and_reaches_the_handler():
    transmitter = TestTransmitter()
    calls = Calls()
    handler = scim_handler(ScimRecorder(calls))
    claims = transmitter.set_claims_with_payload(
        "ScimProvCreateFull", scim_subject("/Users/42"), {"data": {"userName": "alice"}}
    )
    await handler.handle(context(claims))
    calls.expect("Create:42", "create:full=True")


async def test_scim_methods_are_dispatched_by_operation_without_an_event_handler():
    calls = Calls()

    class ByOperation(ScimHandler):
        def on_delete(self, event: scim.Event, context: EventContext) -> None:
            calls.record("delete")

        async def on_deactivate(self, event: scim.Event, context: EventContext) -> None:
            calls.record("deactivate")

    handler = scim_handler(ByOperation())
    await handler.handle(context_with({EventTypes.SCIM_PROV_DEACTIVATE: {}, EventTypes.SCIM_PROV_DELETE: {}}))
    calls.expect("deactivate", "delete")
    assert handler_name(handler) == "scim_handler(ByOperation)"
