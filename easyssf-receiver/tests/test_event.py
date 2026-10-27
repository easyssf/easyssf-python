"""The event context, the handlers and the errors: receiver/event.go and errors.go of the Go port."""

import asyncio
import threading
from datetime import UTC, datetime
from typing import Any

import pytest

from easyssf.core import Claims, DeliveryMethod, EventToken, EventTypes
from easyssf.core.subjects import complex_subject, email, iss_sub, opaque
from easyssf.receiver import (
    ConfigurationError,
    EasyssfError,
    ErrorCode,
    EventContext,
    Handler,
    HandlerFunc,
    HandlingError,
    InProgressError,
    RejectedError,
    StoreError,
    TransmitterUnavailableError,
    as_handler,
    for_event,
    handler_name,
    system_clock,
)

SESSION_REVOKED = EventTypes.CAEP_SESSION_REVOKED


def context(claims: Claims, delivery: DeliveryMethod = DeliveryMethod.PUSH) -> EventContext:
    token = EventToken.from_claims(claims)
    assert token is not None
    return EventContext(token, delivery)


def set_with(events: Claims, **claims: Any) -> Claims:
    return {"jti": "1", "iss": "https://t.example", "iat": 1700000000, "events": events, **claims}


# EventContext


def test_context_exposes_the_token_and_the_delivery():
    ctx = context(set_with({SESSION_REVOKED: {}}), DeliveryMethod.POLL)
    assert ctx.event_token.jti == "1"
    assert ctx.delivery_method is DeliveryMethod.POLL
    assert ctx.idempotency_key == "https://t.example::1"


def test_finds_events_by_alias_and_uri():
    ctx = context(
        set_with(
            {SESSION_REVOKED: {"event_timestamp": 5}, "https://events.acme.example/login": []},
            sub_id=opaque("x"),
        )
    )
    assert ctx.has_event("CaepSessionRevoked")
    assert ctx.has_event(SESSION_REVOKED)
    assert not ctx.has_event("CaepCredentialChange")
    assert ctx.event("CaepSessionRevoked") == {"event_timestamp": 5}
    assert ctx.event(SESSION_REVOKED) == {"event_timestamp": 5}
    assert ctx.event_types == [SESSION_REVOKED, "https://events.acme.example/login"]


def test_vendor_event_types_are_addressed_by_uri():
    ctx = context(set_with({"https://events.acme.example/login": {"ip": "1.2.3.4"}}, sub_id=opaque("x")))
    assert ctx.has_event("https://events.acme.example/login")
    assert ctx.event("https://events.acme.example/login") == {"ip": "1.2.3.4"}
    # a payload that is not an object has no payload
    ctx = context(set_with({"https://events.acme.example/list": [1]}))
    assert ctx.has_event("https://events.acme.example/list")
    assert ctx.event("https://events.acme.example/list") is None
    assert ctx.event("https://events.acme.example/absent") is None


def test_subject_is_taken_from_sub_id():
    ctx = context(
        set_with(
            {SESSION_REVOKED: {"subject": email("ignored@example.com")}},
            sub_id=complex_subject(user=iss_sub("https://idp.example", "alice"), session=opaque("s1")),
        )
    )
    assert ctx.subject.sub == "alice"
    assert ctx.subject.session_id == "s1"
    # the top-level claim wins over the subject of the payload, which earlier drafts used
    assert ctx.subject_for("CaepSessionRevoked") is ctx.subject
    assert ctx.subject_for("CaepSessionRevoked").email == ""


def test_subject_falls_back_to_event_subject_of_early_drafts():
    ctx = context(set_with({SESSION_REVOKED: {"subject": email("alice@example.com")}}))
    assert ctx.subject.is_empty
    assert ctx.subject_for("CaepSessionRevoked").email == "alice@example.com"
    assert ctx.subject_for(SESSION_REVOKED).email == "alice@example.com"
    assert ctx.subject_for("CaepCredentialChange").is_empty
    # a subject member that is not an object is no subject
    ctx = context(set_with({SESSION_REVOKED: {"subject": "alice"}}))
    assert ctx.subject_for("CaepSessionRevoked").is_empty


def test_event_timestamp_in_seconds_or_milliseconds_else_issued_at():
    ctx = context(
        set_with(
            {
                "https://e.example/seconds": {"event_timestamp": 1600000000},
                "https://e.example/millis": {"event_timestamp": 1600000000500},
                "https://e.example/string": {"event_timestamp": "1600000000"},
                "https://e.example/none": {},
            }
        )
    )
    assert ctx.event_timestamp("https://e.example/seconds") == datetime.fromtimestamp(1600000000, tz=UTC)
    assert ctx.event_timestamp("https://e.example/millis") == datetime.fromtimestamp(1600000000, tz=UTC)
    issued_at = datetime.fromtimestamp(1700000000, tz=UTC)
    assert ctx.event_timestamp("https://e.example/string") == issued_at
    assert ctx.event_timestamp("https://e.example/none") == issued_at
    assert ctx.event_timestamp("https://e.example/absent") == issued_at


# Handlers


class Recording:
    """A handler that records the contexts it was given."""

    def __init__(self) -> None:
        self.seen: list[EventContext] = []

    async def handle(self, context: EventContext) -> None:
        self.seen.append(context)


async def test_an_object_with_an_async_handle_method_is_a_handler_as_it_is():
    handler = Recording()
    assert as_handler(handler) is handler
    assert isinstance(handler, Handler)
    assert handler_name(handler) == "Recording"


async def test_an_async_callable_is_awaited():
    seen = []

    async def on_event(context: EventContext) -> None:
        seen.append(context.event_token.jti)

    handler = as_handler(on_event)
    assert isinstance(handler, HandlerFunc)
    await handler.handle(context(set_with({SESSION_REVOKED: {}})))
    assert seen == ["1"]
    assert handler_name(handler).endswith("on_event")


async def test_a_sync_callable_runs_in_a_worker_thread():
    threads = []

    def on_event(context: EventContext) -> None:
        threads.append(threading.current_thread())

    await as_handler(on_event).handle(context(set_with({SESSION_REVOKED: {}})))
    assert threads and threads[0] is not threading.current_thread()


async def test_an_async_callable_object_is_awaited_on_the_loop():
    class Callable:
        def __init__(self) -> None:
            self.threads: list[threading.Thread] = []

        async def __call__(self, context: EventContext) -> None:
            self.threads.append(threading.current_thread())

    callable_ = Callable()
    await as_handler(callable_).handle(context(set_with({SESSION_REVOKED: {}})))
    assert callable_.threads == [threading.current_thread()]


async def test_a_sync_callable_returning_an_awaitable_is_awaited():
    seen = []

    async def record(jti: str) -> None:
        seen.append(jti)

    await as_handler(lambda ctx: record(ctx.event_token.jti)).handle(context(set_with({SESSION_REVOKED: {}})))
    assert seen == ["1"]


async def test_an_exception_of_a_callable_propagates():
    def failing(context: EventContext) -> None:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        await as_handler(failing).handle(context(set_with({SESSION_REVOKED: {}})))


def test_something_that_is_not_a_handler_is_refused():
    with pytest.raises(TypeError):
        as_handler("not a handler")  # type: ignore[arg-type]


async def test_for_event_filters_by_event_type():
    recording = Recording()
    handler = for_event("CaepSessionRevoked", recording)
    await handler.handle(context(set_with({SESSION_REVOKED: {}})))
    await handler.handle(context(set_with({EventTypes.CAEP_CREDENTIAL_CHANGE: {}})))
    await handler.handle(context(set_with({"https://events.acme.example/login": {}})))
    assert [c.event_types for c in recording.seen] == [[SESSION_REVOKED]]
    assert handler_name(handler) == "for_event(CaepSessionRevoked, Recording)"


async def test_for_event_accepts_a_uri_and_a_callable():
    seen = []
    handler = for_event("https://events.acme.example/login", lambda ctx: seen.append(ctx.event_token.jti))
    await handler.handle(context(set_with({"https://events.acme.example/login": {}})))
    await handler.handle(context(set_with({SESSION_REVOKED: {}})))
    assert seen == ["1"]


async def test_handlers_run_concurrently_on_the_loop():
    started = asyncio.Event()

    async def waits(context: EventContext) -> None:
        started.set()
        await asyncio.sleep(0)

    task = asyncio.create_task(as_handler(waits).handle(context(set_with({SESSION_REVOKED: {}}))))
    await asyncio.wait_for(started.wait(), 1)
    await task


# Errors


def test_system_clock_is_utc():
    assert system_clock().tzinfo is UTC


def test_rejected_error_carries_the_code():
    error = RejectedError(ErrorCode.INVALID_KEY, "the key is unknown")
    assert error.code == "invalid_key"
    assert error.description == "the key is unknown"
    assert str(error) == "the key is unknown (invalid_key)"
    assert isinstance(error, EasyssfError)


def test_rejection_of_finds_the_rejection_in_the_chain():
    rejected = RejectedError(ErrorCode.INVALID_AUDIENCE, "not for us")
    assert RejectedError.of(rejected) is rejected
    assert RejectedError.of(None) is None
    assert RejectedError.of(TransmitterUnavailableError(None, "down")) is None

    try:
        try:
            raise rejected
        except RejectedError as e:
            raise RuntimeError("wrapped") from e
    except RuntimeError as wrapper:
        assert RejectedError.of(wrapper) is rejected
    assert RejectedError.of(HandlingError("h", rejected)) is rejected


def test_transmitter_unavailable_error_names_the_cause():
    cause = ConnectionError("refused")
    error = TransmitterUnavailableError(cause, "could not fetch the keys")
    assert str(error) == "could not fetch the keys: refused"
    assert error.__cause__ is cause
    assert str(TransmitterUnavailableError(None, "could not fetch the keys")) == "could not fetch the keys"
    assert TransmitterUnavailableError.of(StoreError(error)) is error
    assert TransmitterUnavailableError.of(RejectedError("invalid_request", "x")) is None


def test_in_progress_error():
    assert str(InProgressError()) == "the SET is being handled by another instance"


def test_handling_error_names_the_handler_and_the_cause():
    cause = RuntimeError("boom")
    error = HandlingError("Recording", cause, failed=2)
    assert error.handler == "Recording"
    assert error.cause is cause
    assert error.__cause__ is cause
    assert error.failed == 2
    assert str(error) == "2 handler(s) failed for the SET, the first (Recording) with: boom"
    assert HandlingError("h", cause).failed == 1


def test_store_error_wraps_the_cause():
    cause = OSError("disk full")
    error = StoreError(cause)
    assert error.cause is cause
    assert error.__cause__ is cause
    assert str(error) == "the dedup store failed: disk full"


def test_configuration_error_lists_the_failures():
    error = ConfigurationError(["transmitter-issuer: must be set", "poll.interval: must be positive"])
    assert error.failures == ["transmitter-issuer: must be set", "poll.interval: must be positive"]
    assert str(error) == (
        "the SSF receiver configuration is invalid:\n  transmitter-issuer: must be set\n  poll.interval: must be positive"
    )
