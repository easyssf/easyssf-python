"""SsfPollerTests and SsfPollerRateLimitTests of the Java library, receiver/poll_test.go of the
Go port."""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from datetime import timedelta

import httpx
import pytest

from easyssf.core import Claims, strings
from easyssf.core.subjects import iss_sub
from easyssf.receiver.dedup import InMemoryJtiDedupStore
from easyssf.receiver.errors import ErrorCode
from easyssf.receiver.event import EventContext, Handler
from easyssf.receiver.jwks import HttpJwkSetSource
from easyssf.receiver.metrics import NoopMetrics
from easyssf.receiver.poll import (
    InMemoryPollAckStore,
    PendingAck,
    PollAckStore,
    Poller,
    PollerOptions,
    PollError,
    default_poller_options,
    fixed_poll_endpoint,
)
from easyssf.receiver.processor import Processor
from easyssf.receiver.transmitter import ClientCredentialsTokenProvider, FixedToken, UriPolicyError
from easyssf.receiver.verifier import JwtVerifier, default_verifier_options
from easyssf.testing import (
    ACCESS_TOKEN,
    AUDIENCE,
    CLIENT_ID,
    CLIENT_SECRET,
    ManualClock,
    TestTransmitter,
    claims_of,
    during,
    eventually,
)


class Recorder:
    """Counts the SETs it handled."""

    def __init__(self) -> None:
        self.count = 0

    async def handle(self, context: EventContext) -> None:
        self.count += 1


def alice(transmitter: TestTransmitter) -> Claims:
    return iss_sub(transmitter.issuer, "alice")


def verifier(transmitter: TestTransmitter) -> JwtVerifier:
    keys = HttpJwkSetSource(transmitter.client, transmitter.jwks_url)
    return JwtVerifier(transmitter.issuer, keys, replace(default_verifier_options(), expected_audiences=[AUDIENCE]))


def processor(transmitter: TestTransmitter, *handlers: Handler) -> Processor:
    return Processor(verifier(transmitter), InMemoryJtiDedupStore(10)).add_handler(*handlers)


def token_provider(transmitter: TestTransmitter) -> ClientCredentialsTokenProvider:
    return ClientCredentialsTokenProvider(transmitter.client, transmitter.token_url, CLIENT_ID, CLIENT_SECRET)


def poller_options() -> PollerOptions:
    return replace(
        default_poller_options(), interval=timedelta(milliseconds=100), endpoint_retry=timedelta(milliseconds=20)
    )


def poller_with(transmitter: TestTransmitter, p: Processor, options: PollerOptions) -> Poller:
    return Poller(transmitter.client, FixedToken(ACCESS_TOKEN), fixed_poll_endpoint(transmitter.poll_url), p, options)


def poller(transmitter: TestTransmitter, recorder: Recorder | None = None) -> Poller:
    handlers = (recorder,) if recorder is not None else ()
    return poller_with(transmitter, processor(transmitter, *handlers), poller_options())


def queue(transmitter: TestTransmitter) -> str:
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter))
    transmitter.queue_set(encoded_set)
    return str(claims_of(encoded_set)["jti"])


async def test_start_is_idempotent_and_stop_ends_the_polling_task():
    transmitter = TestTransmitter()
    p = poller(transmitter, Recorder())
    assert not p.is_running
    await p.start()
    await p.start()
    assert p.is_running
    await eventually(lambda: transmitter.poll_requests > 0, what="a poll")
    await p.stop()
    assert not p.is_running
    polls = transmitter.poll_requests
    await during(lambda: transmitter.poll_requests == polls, 0.25, what="no more polls")
    await p.stop()


async def test_handles_and_acknowledges_available_sets():
    transmitter = TestTransmitter()
    recorder = Recorder()
    p = poller(transmitter, recorder)
    jti = queue(transmitter)
    assert await p.poll_now() == 1
    assert recorder.count == 1
    assert transmitter.acknowledged_sets == [jti], "acknowledged with a second, immediate request"
    assert transmitter.queued_set_count == 0
    assert await p.pending_ack_count() == 0
    assert p.last_successful_poll_at is not None
    assert p.last_poll_error == ""
    assert await p.poll_now() == 0, "nothing more"


async def test_fetches_all_sets_when_more_are_available_than_fit_in_one_request():
    transmitter = TestTransmitter()
    recorder = Recorder()
    options = replace(poller_options(), max_events=2)
    p = poller_with(transmitter, processor(transmitter, recorder), options)
    for _ in range(5):
        queue(transmitter)
    assert await p.poll_now() == 5
    assert recorder.count == 5
    assert len(transmitter.acknowledged_sets) == 5


async def test_reports_invalid_set_to_the_transmitter():
    transmitter = TestTransmitter()
    recorder = Recorder()
    p = poller(transmitter, recorder)
    claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    claims["aud"] = "https://other.example"
    claims["jti"] = "bad"
    transmitter.queue_set_with_jti("bad", transmitter.sign_set(claims))
    transmitter.queue_set_with_jti("garbage", "not a set")
    assert await p.poll_now() == 2
    assert recorder.count == 0, "fetched, not handled"
    codes = {reported.jti: reported.code for reported in transmitter.reported_errors}
    assert codes == {"bad": ErrorCode.INVALID_AUDIENCE, "garbage": ErrorCode.INVALID_REQUEST}
    assert transmitter.acknowledged_sets == []


async def test_reports_set_whose_jti_differs_from_the_key_it_is_listed_under_without_handling_it():
    transmitter = TestTransmitter()
    recorder = Recorder()
    p = poller(transmitter, recorder)
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter))
    jti = str(claims_of(encoded_set)["jti"])
    transmitter.queue_set_with_jti("another-key", encoded_set)
    valid = queue(transmitter)
    assert await p.poll_now() == 2
    # the SET is not handled, and the error names the key so that the transmitter drops it
    assert recorder.count == 1
    assert transmitter.acknowledged_sets == [valid]
    assert [(reported.jti, reported.code) for reported in transmitter.reported_errors] == [
        ("another-key", ErrorCode.INVALID_REQUEST)
    ]
    assert jti in transmitter.reported_errors[0].description
    assert "another-key" in transmitter.reported_errors[0].description


async def test_does_not_acknowledge_set_that_could_not_be_handled_so_that_it_is_delivered_again():
    transmitter = TestTransmitter()
    attempts = 0

    async def failing(context: EventContext) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("first attempt fails")

    p = poller_with(transmitter, processor(transmitter).add_handler(failing), poller_options())
    jti = queue(transmitter)
    assert await p.poll_now() == 1
    assert transmitter.acknowledged_sets == []
    assert transmitter.queued_set_count == 1, "not acknowledged"
    # delivered again with the next poll
    assert await p.poll_now() == 1
    assert transmitter.acknowledged_sets == [jti]
    assert attempts == 2, "redelivered"


async def test_poller_obtains_new_access_token_when_the_transmitter_rejects_the_current_one():
    transmitter = TestTransmitter()
    p = Poller(
        transmitter.client,
        token_provider(transmitter),
        fixed_poll_endpoint(transmitter.poll_url),
        processor(transmitter, Recorder()),
        poller_options(),
    )
    await p.poll_now()
    transmitter.expire_access_tokens()
    queue(transmitter)
    assert await p.poll_now() == 1
    assert transmitter.token_requests == 2, "new token"


class KnownEndpoint:
    """A poll endpoint that becomes known later, as the one of a stream being registered."""

    def __init__(self) -> None:
        self.url = ""

    def get(self) -> str:
        return self.url


async def test_does_not_poll_while_the_poll_endpoint_is_unknown():
    transmitter = TestTransmitter()
    known = KnownEndpoint()
    p = Poller(transmitter.client, FixedToken(ACCESS_TOKEN), known.get, processor(transmitter), poller_options())
    assert await p.poll_now() == 0
    assert transmitter.poll_requests == 0
    assert p.last_poll_at is None
    assert await p.pending_ack_count() == 0, "not polled"
    known.url = transmitter.poll_url
    await p.poll_now()
    assert transmitter.poll_requests == 1, "polled"


async def test_polls_soon_after_the_endpoint_becomes_known_instead_of_waiting_the_interval():
    transmitter = TestTransmitter()
    known = KnownEndpoint()
    options = replace(
        default_poller_options(), interval=timedelta(minutes=1), endpoint_retry=timedelta(milliseconds=20)
    )
    p = Poller(transmitter.client, FixedToken(ACCESS_TOKEN), known.get, processor(transmitter), options)
    await p.start()
    try:
        await during(lambda: transmitter.poll_requests == 0, 0.1, what="no poll without an endpoint")
        known.url = transmitter.poll_url
        await eventually(lambda: transmitter.poll_requests > 0, 2, what="a poll within the endpoint retry")
    finally:
        await p.stop()


async def test_wake_up_ends_the_pause_and_polls_at_once():
    transmitter = TestTransmitter()
    options = replace(default_poller_options(), interval=timedelta(minutes=1))
    p = poller_with(transmitter, processor(transmitter), options)
    await p.start()
    try:
        await eventually(lambda: transmitter.poll_requests == 1, 2, what="the first poll")
        await during(lambda: transmitter.poll_requests == 1, 0.1, what="the pause")
        p.wake_up()
        await eventually(lambda: transmitter.poll_requests == 2, 2, what="the second poll")
    finally:
        await p.stop()


async def test_wake_up_does_nothing_while_the_poller_is_not_running():
    transmitter = TestTransmitter()
    poller(transmitter, Recorder()).wake_up()
    await during(lambda: transmitter.poll_requests == 0, 0.1, what="no poll")


async def test_reports_failed_poll_request():
    transmitter = TestTransmitter()
    p = poller(transmitter, Recorder())
    transmitter.set_available(False)
    with pytest.raises(PollError, match="503"):
        await p.poll_now()
    assert p.last_poll_at is not None
    assert p.last_successful_poll_at is None
    assert "503" in p.last_poll_error
    transmitter.set_available(True)
    await p.poll_now()
    assert p.last_poll_error == "", "recovered"


async def test_acknowledgements_wait_in_the_store_until_a_request_carried_them():
    transmitter = TestTransmitter()
    store = InMemoryPollAckStore()
    options = replace(poller_options(), ack_store=store, transmitter=transmitter.issuer)
    p = poller_with(transmitter, processor(transmitter), options)
    jti = queue(transmitter)
    await p.poll_now()
    assert transmitter.acknowledged_sets == [jti]
    assert await store.size(transmitter.issuer) == 0, "empty"
    # an acknowledgement recorded by hand rides on the next request
    await store.record(transmitter.issuer, PendingAck.ack("manual"))
    assert await p.pending_ack_count() == 1, "pending"
    transmitter.set_available(False)
    with pytest.raises(PollError):
        await p.poll_now()
    assert await p.pending_ack_count() == 1, "kept after a failed request"
    transmitter.set_available(True)
    await p.poll_now()
    assert await p.pending_ack_count() == 0, "delivered"
    assert strings(transmitter.last_poll_request.get("ack")) == ["manual"], "delivered with the fetch"


async def test_acknowledgements_are_sent_in_batches():
    transmitter = TestTransmitter()
    store = InMemoryPollAckStore()
    options = replace(poller_options(), ack_store=store, max_ack_batch=2, transmitter=transmitter.issuer)
    p = poller_with(transmitter, processor(transmitter), options)
    for jti in ("a", "b", "c"):
        await store.record(transmitter.issuer, PendingAck.ack(jti))
    await p.poll_now()
    assert len(strings(transmitter.last_poll_request.get("ack"))) == 1, (
        "two with the fetch, the third with the acknowledging request"
    )
    assert await p.pending_ack_count() == 0, "all delivered"


class Gauge(NoopMetrics):
    def __init__(self) -> None:
        self.values: list[int] = []
        self.polls: list[bool] = []

    def pending_acks_changed(self, transmitter: str, pending_acks: int) -> None:
        self.values.append(pending_acks)

    def poll_completed(self, transmitter: str, duration: timedelta, success: bool) -> None:
        self.polls.append(success)


async def test_pending_acknowledgements_are_a_gauge():
    transmitter = TestTransmitter()
    gauge = Gauge()
    options = replace(poller_options(), metrics=gauge)
    p = poller_with(transmitter, processor(transmitter), options)
    queue(transmitter)
    await p.poll_now()
    assert gauge.values == [1, 0]
    assert gauge.polls == [True, True], "the fetch and the acknowledging request"


async def test_stop_flushes_the_pending_acknowledgements():
    transmitter = TestTransmitter()
    store = InMemoryPollAckStore()
    options = replace(
        default_poller_options(), ack_store=store, transmitter=transmitter.issuer, interval=timedelta(minutes=1)
    )
    p = poller_with(transmitter, processor(transmitter), options)
    await p.start()
    await eventually(lambda: transmitter.poll_requests == 1, 2, what="the first poll")
    await store.record(transmitter.issuer, PendingAck.ack("owed"))
    await p.stop()
    assert strings(transmitter.last_poll_request.get("ack")) == ["owed"]
    assert transmitter.last_poll_request.get("maxEvents") == 0
    assert await store.size(transmitter.issuer) == 0, "flushed"


async def test_long_poll_is_held_until_a_set_arrives():
    transmitter = TestTransmitter()
    transmitter.set_long_poll_hold(timedelta(seconds=10))
    recorder = Recorder()
    options = replace(default_poller_options(), long_polling_hold=timedelta(seconds=10), interval=timedelta(minutes=1))
    p = poller_with(transmitter, processor(transmitter, recorder), options)
    assert p.is_long_polling
    await p.start()
    try:
        await eventually(lambda: transmitter.poll_requests == 1, 2, what="the held request")
        assert transmitter.last_poll_request["returnImmediately"] is False, "held"
        await during(lambda: recorder.count == 0, 0.15, what="held")
        queue(transmitter)
        await eventually(lambda: recorder.count == 1, 2, what="the SET")
        await eventually(
            lambda: len(transmitter.acknowledged_sets) == 1, 2, what="the acknowledgement with the next held request"
        )
    finally:
        await p.stop()


async def test_long_poll_against_a_transmitter_that_answers_at_once_waits_the_interval():
    transmitter = TestTransmitter()
    options = replace(default_poller_options(), long_polling_hold=timedelta(seconds=10), interval=timedelta(minutes=1))
    p = poller_with(transmitter, processor(transmitter), options)
    await p.start()
    try:
        await eventually(lambda: transmitter.poll_requests == 1, 2, what="the first poll")
        await during(lambda: transmitter.poll_requests == 1, 0.3, what="no tight loop")
    finally:
        await p.stop()


async def test_stop_cancels_a_held_long_poll():
    transmitter = TestTransmitter()
    transmitter.set_long_poll_hold(timedelta(seconds=30))
    options = replace(default_poller_options(), long_polling_hold=timedelta(seconds=30))
    p = poller_with(transmitter, processor(transmitter), options)
    await p.start()
    await eventually(lambda: transmitter.poll_requests == 1, 2, what="the held request")
    started = time.monotonic()
    await p.stop()
    assert time.monotonic() - started < 2, "stop returned before the hold elapsed"
    assert not p.is_running


async def test_poll_now_asks_for_an_immediate_answer_even_when_long_polling():
    transmitter = TestTransmitter()
    transmitter.set_long_poll_hold(timedelta(seconds=30))
    options = replace(default_poller_options(), long_polling_hold=timedelta(seconds=30))
    p = poller_with(transmitter, processor(transmitter), options)
    async with asyncio.timeout(2):
        await p.poll_now()
    assert transmitter.last_poll_request["returnImmediately"] is True, "immediate"


# SsfPollerRateLimitTests


class RateLimiting(httpx.AsyncBaseTransport):
    """Answers the poll endpoint with a canned response, everything else goes to the transmitter."""

    def __init__(self, next_transport: httpx.AsyncBaseTransport, status: int, retry_after: str) -> None:
        self.next = next_transport
        self.status = status
        self.retry_after = retry_after

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/poll"):
            headers = {"Retry-After": self.retry_after} if self.retry_after else {}
            return httpx.Response(self.status, headers=headers, request=request)
        return await self.next.handle_async_request(request)


def rate_limited(transmitter: TestTransmitter, status: int, retry_after: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=RateLimiting(transmitter.transport, status, retry_after))


async def paused_after(status: int, retry_after: str, options: PollerOptions) -> timedelta:
    transmitter = TestTransmitter()
    clock = ManualClock()
    p = Poller(
        rate_limited(transmitter, status, retry_after),
        FixedToken(ACCESS_TOKEN),
        fixed_poll_endpoint(transmitter.poll_url),
        processor(transmitter),
        replace(options, clock=clock),
    )
    with pytest.raises(PollError):
        await p.poll_now()
    until = p.paused_until
    return until - clock.now if until is not None else timedelta(0)


async def test_pauses_for_retry_after():
    assert await paused_after(429, "120", poller_options()) == timedelta(seconds=120)
    assert await paused_after(503, "60", poller_options()) == timedelta(seconds=60)
    # a date instead of seconds is treated like no header
    assert await paused_after(429, "Wed, 21 Oct 2026 07:28:00 GMT", poller_options()) == timedelta(0)


async def test_polls_again_at_the_regular_interval_after_429_without_retry_after_by_default():
    assert await paused_after(429, "", poller_options()) == timedelta(0)


async def test_pauses_for_the_fallback_after_429_without_retry_after():
    options = replace(poller_options(), rate_limit_fallback=timedelta(seconds=90))
    assert await paused_after(429, "", options) == timedelta(seconds=90)


async def test_fallback_does_not_apply_to_503_without_retry_after():
    options = replace(poller_options(), rate_limit_fallback=timedelta(seconds=90))
    assert await paused_after(503, "", options) == timedelta(0)


async def test_pause_is_capped_at_the_maximum():
    options = replace(poller_options(), max_pause=timedelta(seconds=300))
    assert await paused_after(429, "3600", options) == timedelta(seconds=300)


async def test_paused_poller_skips_polls_until_the_pause_is_over():
    transmitter = TestTransmitter()
    clock = ManualClock()
    p = Poller(
        rate_limited(transmitter, 429, "60"),
        FixedToken(ACCESS_TOKEN),
        fixed_poll_endpoint(transmitter.poll_url),
        processor(transmitter),
        replace(poller_options(), clock=clock),
    )
    with pytest.raises(PollError):
        await p.poll_now()
    assert await p.poll_now() == 0, "skipped while paused"
    assert p.paused_until is not None
    clock.advance(timedelta(seconds=61))
    assert p.paused_until is None
    with pytest.raises(PollError):
        await p.poll_now()


async def test_in_memory_poll_ack_store_keeps_acknowledgements_and_errors_in_order_per_issuer():
    store: PollAckStore = InMemoryPollAckStore()
    await store.record("a", PendingAck.ack("1"))
    await store.record("a", PendingAck.ack_error("2", ErrorCode.INVALID_REQUEST, "bad"))
    await store.record("b", PendingAck.ack("3"))
    pending = await store.pending("a", 10)
    assert [ack.jti for ack in pending] == ["1", "2"]
    assert not pending[0].is_error and pending[1].is_error
    assert pending[1].error == ErrorCode.INVALID_REQUEST and pending[1].description == "bad"
    assert len(await store.pending("a", 1)) == 1, "limit"
    assert len(await store.pending("a", -1)) == 2, "no limit"
    assert await store.size("b") == 1
    assert await store.size("c") == 0
    # recording the same SET again changes nothing
    await store.record("a", PendingAck.ack_error("1", ErrorCode.INVALID_REQUEST, ""))
    pending = await store.pending("a", 10)
    assert len(pending) == 2 and not pending[0].is_error, "unchanged"
    # removes what the transmitter received
    await store.remove("a", ["1", "x"])
    pending = await store.pending("a", 10)
    assert [ack.jti for ack in pending] == ["2"], "removed"
    await store.remove("unknown", ["1"])


async def test_poller_starts_again_after_the_context_of_start_was_cancelled():
    # there is no context to cancel in asyncio: stop ends the task of start, and start works again
    transmitter = TestTransmitter()
    p = poller(transmitter, Recorder())
    await p.start()
    assert p.is_running
    await p.stop()
    await eventually(lambda: not p.is_running, what="the poller to end")
    await p.start()
    assert p.is_running, "not started again"
    await p.stop()
    assert not p.is_running, "not stopped"


async def test_poller_refuses_poll_endpoint_the_policy_forbids():
    transmitter = TestTransmitter()
    insecure = "http://transmitter.example/realms/test/ssf/poll"
    p = Poller(
        transmitter.client,
        FixedToken(ACCESS_TOKEN),
        fixed_poll_endpoint(insecure),
        processor(transmitter, Recorder()),
        poller_options(),
    )
    with pytest.raises(UriPolicyError, match="https"):
        await p.poll_now()
    assert transmitter.poll_requests == 0


async def test_does_not_flush_acknowledgements_on_stop_to_a_poll_endpoint_without_tls():
    # the stream moved to plain http after the acknowledgements were recorded
    transmitter = TestTransmitter()
    store = InMemoryPollAckStore()
    options = replace(poller_options(), ack_store=store, transmitter=transmitter.issuer)
    insecure = transmitter.poll_url.replace("https://", "http://")
    p = Poller(transmitter.client, FixedToken(ACCESS_TOKEN), lambda: insecure, processor(transmitter), options)
    await store.record(transmitter.issuer, PendingAck.ack("owed"))
    await p.stop()
    assert transmitter.poll_requests == 0, "the access token stayed home"
    assert await store.size(transmitter.issuer) == 1, "still owed"


def test_poller_refuses_options_out_of_range():
    transmitter = TestTransmitter()
    for bad in (
        replace(default_poller_options(), interval=timedelta(0)),
        replace(default_poller_options(), max_events=0),
        replace(default_poller_options(), max_ack_batch=0),
        replace(default_poller_options(), max_pause=timedelta(0)),
        replace(default_poller_options(), endpoint_retry=timedelta(0)),
        replace(default_poller_options(), long_polling_hold=timedelta(seconds=-1)),
    ):
        with pytest.raises(ValueError):
            poller_with(transmitter, processor(transmitter), bad)
    p = poller_with(transmitter, processor(transmitter), default_poller_options())
    assert p.options.ack_store is not None and p.options.metrics is not None
    assert not p.is_long_polling
