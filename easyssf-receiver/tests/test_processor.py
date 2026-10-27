"""SsfSetProcessorTests of the Java library, receiver/processor_test.go of the Go port (the
revocation handler and the configured receiver have modules and tests of their own)."""

import asyncio
from dataclasses import replace
from datetime import timedelta

import pytest

from easyssf.core import Claims, DeliveryMethod, EventToken, EventTypes
from easyssf.core.subjects import complex_members, complex_subject, iss_sub, opaque
from easyssf.receiver.dedup import InMemoryJtiDedupStore, JtiClaim, JtiClaimState
from easyssf.receiver.errors import ErrorCode, HandlingError, InProgressError, RejectedError, StoreError
from easyssf.receiver.event import EventContext, Handler
from easyssf.receiver.jwks import HttpJwkSetSource
from easyssf.receiver.metrics import NoopMetrics, SetOutcome
from easyssf.receiver.processor import ProcessingOutcome, Processor, ProcessorOptions
from easyssf.receiver.verifier import JwtVerifier, default_verifier_options, unverified_payload
from easyssf.testing import AUDIENCE, ManualClock, TestTransmitter, eventually


class Recorder:
    """Counts the SETs it handled."""

    def __init__(self) -> None:
        self.count = 0
        self.contexts: list[EventContext] = []

    async def handle(self, context: EventContext) -> None:
        self.count += 1
        self.contexts.append(context)


class RecordingMetrics(NoopMetrics):
    def __init__(self) -> None:
        self.sets: list[tuple[str, DeliveryMethod, str]] = []
        self.events: list[tuple[str, str, DeliveryMethod]] = []

    def set_received(self, transmitter: str, delivery: DeliveryMethod, outcome: str) -> None:
        self.sets.append((transmitter, delivery, outcome))

    def event_handled(self, transmitter: str, event_type: str, delivery: DeliveryMethod) -> None:
        self.events.append((transmitter, event_type, delivery))


def verifier(transmitter: TestTransmitter) -> JwtVerifier:
    keys = HttpJwkSetSource(transmitter.client, transmitter.jwks_url)
    return JwtVerifier(transmitter.issuer, keys, replace(default_verifier_options(), expected_audiences=[AUDIENCE]))


def processor(transmitter: TestTransmitter, *handlers: Handler, options: ProcessorOptions | None = None) -> Processor:
    return Processor(verifier(transmitter), InMemoryJtiDedupStore(10), options).add_handler(*handlers)


def alice(transmitter: TestTransmitter) -> Claims:
    return iss_sub(transmitter.issuer, "alice")


PUSH = DeliveryMethod.PUSH
POLL = DeliveryMethod.POLL


async def test_rejected_set_reaches_no_handler_and_is_counted_as_invalid():
    transmitter = TestTransmitter()
    recorder = Recorder()
    metrics = RecordingMetrics()
    p = processor(transmitter, recorder, options=ProcessorOptions(metrics=metrics))
    claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    claims["aud"] = "https://other.example"
    with pytest.raises(RejectedError) as rejected:
        await p.process(transmitter.sign_set(claims), PUSH)
    assert rejected.value.code == ErrorCode.INVALID_AUDIENCE
    assert recorder.count == 0
    assert metrics.sets == [(transmitter.issuer, PUSH, SetOutcome.INVALID)]


async def test_failing_handler_does_not_keep_others_from_handling_and_allows_redelivery():
    transmitter = TestTransmitter()
    after = Recorder()

    async def boom(context: EventContext) -> None:
        raise RuntimeError("boom")

    p = processor(transmitter, boom, after)
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter))
    with pytest.raises(HandlingError) as handling:
        await p.process(encoded_set, PUSH)
    assert handling.value.failed == 1
    assert "boom" in str(handling.value)
    assert handling.value.handler.endswith("boom")
    assert after.count == 1, "the handler after the failing one ran"
    # the redelivery runs the handlers again
    with pytest.raises(HandlingError):
        await p.process(encoded_set, PUSH)
    assert after.count == 2, "redelivered"


async def test_panicking_handler_counts_as_failed():
    transmitter = TestTransmitter()

    def kaboom(context: EventContext) -> None:
        raise AssertionError("kaboom")

    with pytest.raises(HandlingError) as handling:
        await processor(transmitter, kaboom).process(transmitter.set("CaepSessionRevoked", alice(transmitter)), PUSH)
    assert "kaboom" in str(handling.value)
    assert isinstance(handling.value.cause, AssertionError)


class InProgressStore(InMemoryJtiDedupStore):
    """Says every SET is in progress elsewhere."""

    async def claim(self, token: EventToken) -> JtiClaim:
        return JtiClaim(JtiClaimState.IN_PROGRESS)


async def test_set_being_handled_elsewhere_is_left_for_a_redelivery():
    transmitter = TestTransmitter()
    recorder = Recorder()
    p = Processor(verifier(transmitter), InProgressStore(10)).add_handler(recorder)
    with pytest.raises(InProgressError):
        await p.process(transmitter.set("CaepSessionRevoked", alice(transmitter)), PUSH)
    assert recorder.count == 0


class BrokenStore(InMemoryJtiDedupStore):
    async def claim(self, token: EventToken) -> JtiClaim:
        raise OSError("database down")


async def test_failing_dedup_store_is_reported_as_store_error():
    transmitter = TestTransmitter()
    recorder = Recorder()
    p = Processor(verifier(transmitter), BrokenStore(10)).add_handler(recorder)
    with pytest.raises(StoreError) as error:
        await p.process(transmitter.set("CaepSessionRevoked", alice(transmitter)), PUSH)
    assert isinstance(error.value.cause, OSError)
    assert recorder.count == 0


async def test_rejects_set_with_critical_subject_member_the_receiver_does_not_understand():
    transmitter = TestTransmitter()
    recorder = Recorder()
    p = Processor(
        verifier(transmitter),
        InMemoryJtiDedupStore(10),
        ProcessorOptions(
            understood_subject_members=["user", "session"],
            critical_subject_members=lambda issuer: ["tenant", "device"],
        ),
    ).add_handler(recorder)
    with_tenant = complex_members({"user": alice(transmitter), "tenant": opaque("t-1")})
    with pytest.raises(RejectedError) as rejected:
        await p.process(transmitter.set("CaepSessionRevoked", with_tenant), PUSH)
    assert rejected.value.code == ErrorCode.INVALID_REQUEST
    assert "tenant" in str(rejected.value)
    assert recorder.count == 0
    # a critical member that is absent, or one that is understood, is fine
    with_session = transmitter.set("CaepSessionRevoked", complex_subject(alice(transmitter), opaque("s1")))
    result = await p.process(with_session, PUSH)
    assert result.outcome is ProcessingOutcome.HANDLED
    assert recorder.count == 1


async def test_stream_verification_check_runs_before_the_handlers():
    transmitter = TestTransmitter()
    recorder = Recorder()
    checked: list[str] = []

    def check(event: EventContext) -> None:
        state = event.event("SsfStreamVerification")
        checked.append(str(state["state"]) if state else "")
        if state and state.get("state") != "expected":
            raise RejectedError(ErrorCode.INVALID_STATE, "not the state this receiver sent")

    def lookup(issuer: str):
        return check if issuer == transmitter.issuer else None

    p = processor(transmitter, recorder, options=ProcessorOptions(stream_verifications=lookup))
    claims = transmitter.set_claims_with_payload("SsfStreamVerification", opaque("stream-1"), {"state": "other"})
    with pytest.raises(RejectedError) as rejected:
        await p.process(transmitter.sign_set(claims), PUSH)
    assert rejected.value.code == ErrorCode.INVALID_STATE
    assert recorder.count == 0
    claims = transmitter.set_claims_with_payload("SsfStreamVerification", opaque("stream-1"), {"state": "expected"})
    assert (await p.process(transmitter.sign_set(claims), PUSH)).is_handled
    assert checked == ["other", "expected"]
    assert recorder.count == 1


# what works


async def test_hands_verified_set_to_all_handlers():
    transmitter = TestTransmitter()
    first, second = Recorder(), Recorder()
    p = processor(transmitter, first, second)
    result = await p.process(transmitter.set("CaepSessionRevoked", alice(transmitter)), PUSH)
    assert result.outcome is ProcessingOutcome.HANDLED and result.is_handled
    assert result.token.issuer == transmitter.issuer
    assert first.count == 1 and second.count == 1
    assert first.contexts[0].delivery_method is PUSH
    assert p.handler_count == 2


async def test_skips_set_that_was_processed_before():
    transmitter = TestTransmitter()
    recorder = Recorder()
    metrics = RecordingMetrics()
    p = processor(transmitter, recorder, options=ProcessorOptions(metrics=metrics))
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter))
    await p.process(encoded_set, PUSH)
    result = await p.process(encoded_set, POLL)
    assert result.outcome is ProcessingOutcome.DUPLICATE and result.is_duplicate
    assert recorder.count == 1
    assert metrics.sets == [
        (transmitter.issuer, PUSH, SetOutcome.HANDLED),
        (transmitter.issuer, POLL, SetOutcome.DUPLICATE),
    ]
    assert metrics.events == [(transmitter.issuer, EventTypes.CAEP_SESSION_REVOKED, PUSH)]


async def test_processes_duplicates_without_dedup_store():
    transmitter = TestTransmitter()
    recorder = Recorder()
    p = Processor(verifier(transmitter), None).add_handler(recorder)
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter))
    await p.process(encoded_set, PUSH)
    await p.process(encoded_set, PUSH)
    assert recorder.count == 2, "both handled"


async def test_sync_handler_runs_in_a_worker_thread():
    transmitter = TestTransmitter()
    seen: list[str] = []

    def handler(context: EventContext) -> None:
        import threading

        seen.append(threading.current_thread().name)

    await processor(transmitter, handler).process(transmitter.set("CaepSessionRevoked", alice(transmitter)), PUSH)
    assert seen and seen[0] != "MainThread"


async def test_claim_is_renewed_while_a_long_handler_runs():
    transmitter = TestTransmitter()
    clock = ManualClock()
    store = InMemoryJtiDedupStore(10, timedelta(seconds=60), clock)
    release = asyncio.Event()
    renewals = 0
    original_renew = store.renew

    async def counting_renew(token: EventToken, claim: JtiClaim) -> JtiClaim | None:
        nonlocal renewals
        renewals += 1
        return await original_renew(token, claim)

    store.renew = counting_renew  # type: ignore[method-assign]

    async def slow(context: EventContext) -> None:
        await release.wait()

    p = Processor(verifier(transmitter), store, ProcessorOptions(claim_renewal=timedelta(milliseconds=10)))
    p.add_handler(slow)
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter))
    processing = asyncio.create_task(p.process(encoded_set, PUSH))
    await eventually(lambda: renewals >= 2, what="the claim is renewed while the handler runs")
    # the renewal keeps the claim although the lease would have passed
    clock.advance(timedelta(seconds=61))
    await eventually(lambda: renewals >= 4)
    assert (await store.claim(token_of(encoded_set))).state is JtiClaimState.IN_PROGRESS, "still held"
    release.set()
    assert (await processing).is_handled
    assert (await p.process(encoded_set, PUSH)).is_duplicate, "the success was recorded"
    assert renewals >= 4


async def test_result_of_handlers_is_not_recorded_when_the_claim_was_taken_over():
    transmitter = TestTransmitter()
    clock = ManualClock()
    store = InMemoryJtiDedupStore(10, timedelta(seconds=60), clock)
    release = asyncio.Event()
    started = asyncio.Event()

    async def slow(context: EventContext) -> None:
        started.set()
        await release.wait()

    p = Processor(verifier(transmitter), store, ProcessorOptions(claim_renewal=timedelta(milliseconds=10)))
    p.add_handler(slow)
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter))
    processing = asyncio.create_task(p.process(encoded_set, PUSH))
    await started.wait()
    # another instance takes the SET over after the lease
    clock.advance(timedelta(seconds=61))
    taken_over = await store.claim(token_of(encoded_set))
    assert taken_over.is_granted
    await asyncio.sleep(0.03)
    release.set()
    assert (await processing).is_handled, "the handlers still ran to completion"
    # the first instance did not record the success: the claim of the second still holds
    assert (await store.claim(token_of(encoded_set))).state is JtiClaimState.IN_PROGRESS


def token_of(encoded_set: str) -> EventToken:
    """The token of a SET as the store keys it."""
    token = EventToken.from_claims(unverified_payload(encoded_set))
    assert token is not None
    return token
