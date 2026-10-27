"""SsfStreamManagementTests and SsfStreamVerificationTests of the Java library,
receiver/stream_test.go of the Go port."""

from __future__ import annotations

from datetime import timedelta

import pytest

from easyssf.core import (
    PUSH_URI,
    Claims,
    DeliveryMethod,
    EventToken,
    EventTypes,
    StreamConfiguration,
    StreamStatusValue,
)
from easyssf.core.subjects import email, iss_sub, opaque
from easyssf.receiver.errors import ErrorCode, RejectedError, TransmitterUnavailableError
from easyssf.receiver.event import EventContext
from easyssf.receiver.stream import (
    IssuerMismatchError,
    ReceiverStream,
    StreamClient,
    StreamError,
    StreamRegistrar,
    StreamRegistrarState,
    StreamVerification,
    changes_for,
    has_desired_delivery,
    has_desired_events,
    stream_status_of,
)
from easyssf.receiver.transmitter import ClientCredentialsTokenProvider, MetadataResolver, UriPolicy
from easyssf.testing import CLIENT_ID, CLIENT_SECRET, TestTransmitter, eventually


def metadata_resolver(transmitter: TestTransmitter) -> MetadataResolver:
    return MetadataResolver(transmitter.issuer, None, transmitter.client, UriPolicy())


def token_provider(transmitter: TestTransmitter) -> ClientCredentialsTokenProvider:
    return ClientCredentialsTokenProvider(transmitter.client, transmitter.token_url, CLIENT_ID, CLIENT_SECRET)


def stream_client(transmitter: TestTransmitter) -> StreamClient:
    return StreamClient(metadata_resolver(transmitter), transmitter.client, token_provider(transmitter))


def push_stream(*events: str) -> StreamConfiguration:
    return StreamConfiguration.push("https://app.example/ssf/push", "Bearer s3cr3t", events, "test stream")


async def test_manages_stream():
    transmitter = TestTransmitter()
    client = stream_client(transmitter)
    assert await client.streams() == []
    created = await client.create_stream(push_stream("CaepSessionRevoked"))
    stream_id = created.stream_id
    assert created.issuer == transmitter.issuer
    assert created.audience[0] == CLIENT_ID + "/" + stream_id
    assert created.events_delivered == [EventTypes.CAEP_SESSION_REVOKED]
    assert "authorization_header" not in created.claims["delivery"], "the transmitter does not echo the header"
    assert len(await client.streams()) == 1
    assert (await client.stream(stream_id)).stream_id == stream_id
    updated = await client.update_stream(stream_id, {"description": "changed"})
    assert updated.description == "changed"
    replaced = await client.replace_stream(stream_id, push_stream("CaepCredentialChange"))
    assert replaced.events_requested[0] == EventTypes.CAEP_CREDENTIAL_CHANGE
    status = await client.status(stream_id)
    assert status.status == StreamStatusValue.ENABLED
    paused = await client.update_status(stream_id, StreamStatusValue.PAUSED, "maintenance")
    assert paused.status == StreamStatusValue.PAUSED
    await client.add_subject(stream_id, email("alice@example.com"), True)
    assert transmitter.added_subjects[0] == {"format": "email", "email": "alice@example.com"}
    await client.remove_subject(stream_id, email("alice@example.com"))
    assert len(transmitter.removed_subjects) == 1
    await client.request_verification(stream_id, "state-1")
    assert transmitter.verification_requests[0] == "state-1"
    await client.delete_stream(stream_id)
    assert await client.streams() == []


async def test_reports_status_of_failed_calls():
    transmitter = TestTransmitter()
    client = stream_client(transmitter)
    with pytest.raises(StreamError) as raised:
        await client.stream("missing")
    assert stream_status_of(raised.value) == 404
    assert "404" in str(raised.value)
    transmitter.set_available(False)
    with pytest.raises(StreamError) as raised:
        await client.streams()
    assert stream_status_of(raised.value) == 503, "the cached token was used, the transmitter answered"
    with pytest.raises(StreamError) as raised:
        await stream_client(transmitter).streams()
    assert stream_status_of(raised.value) == 0, "the token request failed, the transmitter was not called"
    assert TransmitterUnavailableError.of(raised.value) is not None
    assert stream_status_of(None) == 0
    assert stream_status_of(ValueError("x")) == 0


async def test_refuses_stream_created_with_another_issuer():
    transmitter = TestTransmitter()
    transmitter.set_stream_issuer("https://other.example")
    with pytest.raises(IssuerMismatchError) as raised:
        await stream_client(transmitter).create_stream(push_stream("CaepSessionRevoked"))
    assert "https://other.example" in str(raised.value)
    assert raised.value.expected_issuer == transmitter.issuer


async def test_registrar_deletes_stream_created_with_another_issuer_and_gives_up():
    transmitter = TestTransmitter()
    transmitter.set_stream_issuer("https://other.example")
    stream = ReceiverStream()
    registrar = StreamRegistrar.for_managed_stream(
        stream_client(transmitter), stream, push_stream("CaepSessionRevoked")
    )
    await registrar.start()
    await eventually(lambda: registrar.state is StreamRegistrarState.FAILED, what="the registrar gave up")
    assert "https://other.example" in registrar.last_error
    assert transmitter.streams == []
    assert stream.configuration is None
    await registrar.stop()


async def test_obtains_new_access_token_when_the_transmitter_rejects_the_current_one():
    transmitter = TestTransmitter()
    client = stream_client(transmitter)
    await client.streams()
    transmitter.expire_access_tokens()
    await client.streams()
    assert transmitter.token_requests == 2


async def test_registrar_creates_stream():
    transmitter = TestTransmitter()
    stream = ReceiverStream()
    registrar = StreamRegistrar.for_managed_stream(
        stream_client(transmitter), stream, push_stream("CaepSessionRevoked")
    )
    assert registrar.state is StreamRegistrarState.NOT_STARTED
    assert str(registrar.state) == "not_started"
    registered = await registrar.register()
    assert registrar.state is StreamRegistrarState.REGISTERED
    assert stream.stream_id == registered.stream_id
    assert len(stream.audience) == 1
    assert len(transmitter.streams) == 1
    assert registrar.current is registered
    assert registrar.stream is stream
    assert registrar.manages_stream


async def test_registrar_tells_its_listeners_once_the_stream_is_registered():
    transmitter = TestTransmitter()
    stream = ReceiverStream()
    registrar = StreamRegistrar.for_managed_stream(
        stream_client(transmitter), stream, push_stream("CaepSessionRevoked")
    )
    told: list[str] = []
    registrar.add_listener(lambda s: told.append(s.stream_id))
    await registrar.start()
    assert registrar.is_running
    await eventually(lambda: len(told) > 0, what="the listener was told")
    assert told[0] == stream.stream_id
    await registrar.stop()
    assert not registrar.is_running


async def test_registrar_reuses_existing_stream():
    transmitter = TestTransmitter()
    existing = transmitter.add_stream(push_stream("CaepSessionRevoked").claims)
    registrar = StreamRegistrar.for_managed_stream(
        stream_client(transmitter), ReceiverStream(), push_stream("CaepSessionRevoked")
    )
    registered = await registrar.register()
    assert registered.stream_id == existing["stream_id"]
    assert len(transmitter.streams) == 1


async def test_registrar_updates_requested_events_of_existing_stream():
    transmitter = TestTransmitter()
    existing = transmitter.add_stream(push_stream("CaepSessionRevoked").claims)
    registrar = StreamRegistrar.for_managed_stream(
        stream_client(transmitter), ReceiverStream(), push_stream("CaepSessionRevoked", "CaepCredentialChange")
    )
    registered = await registrar.register()
    assert registered.stream_id == existing["stream_id"]
    assert len(registered.events_requested) == 2
    assert len(transmitter.streams) == 1


async def test_registrar_changes_delivery_of_the_only_stream_the_transmitter_allows():
    transmitter = TestTransmitter()
    existing = transmitter.add_stream(StreamConfiguration.poll(["CaepSessionRevoked"]).claims)
    registrar = StreamRegistrar.for_managed_stream(
        stream_client(transmitter), ReceiverStream(), push_stream("CaepSessionRevoked")
    )
    registered = await registrar.register()
    assert registered.stream_id == existing["stream_id"]
    assert registered.delivery_method_uri == PUSH_URI
    assert registered.delivery_endpoint_url == "https://app.example/ssf/push"


async def test_registrar_looks_up_stream_created_at_the_transmitter():
    transmitter = TestTransmitter()
    existing = transmitter.add_stream(StreamConfiguration.poll(["CaepSessionRevoked"]).claims)
    stream_id = existing["stream_id"]
    stream = ReceiverStream()
    registrar = StreamRegistrar.for_existing_stream(stream_client(transmitter), stream, stream_id)
    assert not registrar.manages_stream
    await registrar.register()
    assert stream.stream_id == stream_id
    assert stream.poll_endpoint_url == transmitter.poll_url
    missing = StreamRegistrar.for_existing_stream(stream_client(transmitter), ReceiverStream(), "missing")
    with pytest.raises(StreamError) as raised:
        await missing.register()
    assert stream_status_of(raised.value) == 404


async def test_registrar_retries_in_the_background_until_the_transmitter_answers():
    transmitter = TestTransmitter()
    transmitter.set_available(False)
    stream = ReceiverStream()
    registrar = StreamRegistrar.for_managed_stream(
        stream_client(transmitter),
        stream,
        push_stream("CaepSessionRevoked"),
        initial_retry_delay=timedelta(milliseconds=20),
    )
    await registrar.start()
    await eventually(lambda: registrar.last_error != "", what="a failed attempt")
    assert registrar.state is StreamRegistrarState.REGISTERING
    transmitter.set_available(True)
    await eventually(lambda: registrar.state is StreamRegistrarState.REGISTERED, what="the registration")
    assert registrar.last_error == ""
    assert stream.stream_id != ""
    await registrar.stop()


async def test_registrar_deletes_managed_stream_on_shutdown_if_asked():
    transmitter = TestTransmitter()
    registrar = StreamRegistrar.for_managed_stream(
        stream_client(transmitter), ReceiverStream(), push_stream("CaepSessionRevoked"), delete_on_shutdown=True
    )
    await registrar.start()
    await eventually(lambda: registrar.state is StreamRegistrarState.REGISTERED, what="the registration")
    assert len(transmitter.streams) == 1, "created"
    await registrar.stop()
    assert transmitter.streams == [], "deleted"
    # not asked: the stream stays
    keep = StreamRegistrar.for_managed_stream(
        stream_client(transmitter), ReceiverStream(), push_stream("CaepSessionRevoked")
    )
    await keep.register()
    await keep.stop()
    assert len(transmitter.streams) == 1, "kept"


async def test_registrar_starts_again_after_the_context_of_start_was_cancelled():
    # there is no context to cancel in asyncio: stop ends the task of start, and start works again
    transmitter = TestTransmitter()
    transmitter.set_available(False)
    stream = ReceiverStream()
    registrar = StreamRegistrar.for_managed_stream(
        stream_client(transmitter),
        stream,
        push_stream("CaepSessionRevoked"),
        initial_retry_delay=timedelta(milliseconds=10),
    )
    await registrar.start()
    assert registrar.is_running
    await registrar.start()  # a second start while running does nothing
    await registrar.stop()
    await eventually(lambda: not registrar.is_running, what="the registrar to end")
    transmitter.set_available(True)
    await registrar.start()
    await eventually(lambda: registrar.state is StreamRegistrarState.REGISTERED, what="the stream")
    await registrar.stop()


def test_stream_comparison_helpers():
    push = push_stream("CaepSessionRevoked")
    assert has_desired_events(push, push_stream(EventTypes.CAEP_SESSION_REVOKED))
    assert not has_desired_events(push, push_stream("CaepSessionRevoked", "CaepCredentialChange"))
    assert has_desired_delivery(push, push_stream("CaepCredentialChange"))
    assert not has_desired_delivery(push, StreamConfiguration.push("https://other.example/push"))
    poll = StreamConfiguration.poll(["CaepSessionRevoked"])
    assert has_desired_delivery(
        poll, StreamConfiguration({"delivery": {"method": poll.delivery_method_uri, "endpoint_url": "x"}})
    )
    assert not has_desired_delivery(poll, push)
    changes = changes_for(push)
    assert changes == {
        "delivery": push.claims["delivery"],
        "events_requested": [EventTypes.CAEP_SESSION_REVOKED],
        "description": "test stream",
    }
    assert "description" not in changes_for(StreamConfiguration.poll(["CaepSessionRevoked"]))


def test_receiver_stream_holds_what_is_known():
    stream = ReceiverStream()
    assert stream.configuration is None
    assert stream.stream_id == ""
    assert stream.audience == []
    assert stream.poll_endpoint_url == ""
    stream.set_configuration(StreamConfiguration({"stream_id": "s-1", "aud": "a", "delivery": {"method": PUSH_URI}}))
    assert stream.stream_id == "s-1"
    assert stream.audience == ["a"]
    assert stream.poll_endpoint_url == "", "push delivery"


# -- SsfStreamVerificationTests ----------------------------------------------------------------------


def context_of(claims: Claims) -> EventContext:
    token = EventToken.from_claims(claims)
    assert token is not None
    return EventContext(token, DeliveryMethod.PUSH)


def verification_event(stream_id: str, state: str) -> EventContext:
    event: Claims = {}
    if state:
        event["state"] = state
    claims: Claims = {
        "jti": "1",
        "iss": "https://t.example",
        "iat": 1,
        "events": {EventTypes.SSF_STREAM_VERIFICATION: event},
    }
    if stream_id:
        claims["sub_id"] = opaque(stream_id)
    return context_of(claims)


def for_stream(stream_id: str) -> StreamVerification:
    return StreamVerification(lambda: stream_id)


def code(exc: BaseException) -> str:
    rejected = RejectedError.of(exc)
    assert rejected is not None, f"not rejected: {exc!r}"
    return rejected.code


def test_accepts_verification_event_that_echoes_the_requested_state():
    verification = for_stream("s-1")
    state = verification.new_state()
    assert verification.is_pending
    verification.check(verification_event("s-1", state))
    assert not verification.is_pending, "answered"


def test_rejects_verification_event_with_another_state_than_the_requested_one():
    verification = for_stream("s-1")
    verification.new_state()
    with pytest.raises(RejectedError) as raised:
        verification.check(verification_event("s-1", "other"))
    assert code(raised.value) == ErrorCode.INVALID_STATE
    assert verification.is_pending, "the request stays pending"


def test_accepts_verification_event_initiated_by_the_transmitter():
    verification = for_stream("s-1")
    verification.check(verification_event("s-1", ""))
    verification.new_state()
    verification.check(verification_event("s-1", ""))


def test_accepts_state_when_no_verification_was_requested_unless_strict():
    for_stream("s-1").check(verification_event("s-1", "transmitter-state"))
    strict = StreamVerification(lambda: "s-1", reject_unrequested_state=True)
    with pytest.raises(RejectedError) as raised:
        strict.check(verification_event("s-1", "transmitter-state"))
    assert code(raised.value) == ErrorCode.INVALID_STATE


def test_rejects_verification_event_about_another_stream():
    verification = for_stream("s-1")
    with pytest.raises(RejectedError) as raised:
        verification.check(verification_event("s-2", ""))
    assert code(raised.value) == ErrorCode.INVALID_REQUEST
    # an iss_sub subject is not a stream either
    claims: Claims = {
        "jti": "1",
        "iss": "i",
        "iat": 1,
        "sub_id": iss_sub("i", "s-1"),
        "events": {EventTypes.SSF_STREAM_VERIFICATION: {}},
    }
    with pytest.raises(RejectedError) as raised:
        verification.check(context_of(claims))
    assert code(raised.value) == ErrorCode.INVALID_REQUEST


def test_rejects_verification_event_without_subject_id():
    with pytest.raises(RejectedError) as raised:
        for_stream("s-1").check(verification_event("", ""))
    assert code(raised.value) == ErrorCode.INVALID_REQUEST


def test_does_not_check_the_stream_while_it_is_unknown():
    verification = StreamVerification(None)
    verification.check(verification_event("whatever", ""))
    verification.check(verification_event("", ""))


def test_ignores_other_events():
    verification = for_stream("s-1")
    verification.new_state()
    claims: Claims = {
        "jti": "1",
        "iss": "i",
        "iat": 1,
        "sub_id": iss_sub("i", "alice"),
        "events": {EventTypes.CAEP_SESSION_REVOKED: {"state": "x"}},
    }
    verification.check(context_of(claims))
    assert verification.is_pending


async def test_request_verification_remembers_the_state_until_answered():
    transmitter = TestTransmitter()
    client = stream_client(transmitter)
    created = await client.create_stream(push_stream("CaepSessionRevoked"))
    verification = for_stream(created.stream_id)
    state = await verification.request_verification(client, created.stream_id)
    assert transmitter.verification_requests == [state]
    assert verification.is_pending
    verification.check(verification_event(created.stream_id, state))
    assert not verification.is_pending
    # a failed request forgets the state
    transmitter.set_available(False)
    with pytest.raises(StreamError):
        await verification.request_verification(client, created.stream_id)
    assert not verification.is_pending


async def test_processor_rejects_invalid_verification_event_without_handling_or_remembering_it():
    from dataclasses import replace

    from easyssf.receiver.dedup import InMemoryJtiDedupStore
    from easyssf.receiver.jwks import HttpJwkSetSource
    from easyssf.receiver.processor import Processor, ProcessorOptions
    from easyssf.receiver.verifier import JwtVerifier, default_verifier_options
    from easyssf.testing import AUDIENCE

    transmitter = TestTransmitter()
    verification = for_stream("s-1")
    handled: list[EventContext] = []
    verifier = JwtVerifier(
        transmitter.issuer,
        HttpJwkSetSource(transmitter.client, transmitter.jwks_url),
        replace(default_verifier_options(), expected_audiences=[AUDIENCE]),
    )
    options = ProcessorOptions(stream_verifications=lambda issuer: verification.check)
    processor = Processor(verifier, InMemoryJtiDedupStore(10), options).add_handler(handled.append)
    verification.new_state()
    encoded = transmitter.sign_set(
        transmitter.set_claims_with_payload("SsfStreamVerification", opaque("s-1"), {"state": "unexpected"})
    )
    with pytest.raises(RejectedError) as raised:
        await processor.process(encoded, DeliveryMethod.PUSH)
    assert code(raised.value) == ErrorCode.INVALID_STATE
    assert handled == []
    # a valid one is handled, and the SET was not remembered as processed by the rejection
    encoded = transmitter.sign_set(transmitter.set_claims_with_payload("SsfStreamVerification", opaque("s-1"), None))
    await processor.process(encoded, DeliveryMethod.PUSH)
    assert len(handled) == 1
