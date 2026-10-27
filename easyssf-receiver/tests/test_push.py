"""SsfPushHandlerTests of the Java library, receiver/push_test.go of the Go port, plus the ASGI
and WSGI applications."""

import asyncio
import json
from dataclasses import replace

import httpx
import pytest

from easyssf.core import Claims, DeliveryMethod
from easyssf.core.subjects import iss_sub
from easyssf.receiver.asgi import push_app
from easyssf.receiver.dedup import InMemoryJtiDedupStore
from easyssf.receiver.event import EventContext, Handler
from easyssf.receiver.jwks import HttpJwkSetSource
from easyssf.receiver.metrics import NoopMetrics, SetOutcome
from easyssf.receiver.processor import Processor, ProcessorOptions
from easyssf.receiver.push import (
    MAX_SET_SIZE,
    PUSH_CONTENT_LANGUAGE,
    PUSH_CONTENT_TYPE,
    PushHandler,
    PushResponse,
)
from easyssf.receiver.verifier import JwtVerifier, default_verifier_options
from easyssf.receiver.wsgi import push_wsgi_app
from easyssf.testing import AUDIENCE, TestTransmitter, eventually

JWKS_PATH = "/realms/test/protocol/openid-connect/certs"
SECRET = "Bearer s3cr3t"


class Recorder:
    """Counts the SETs it handled."""

    def __init__(self) -> None:
        self.count = 0

    async def handle(self, context: EventContext) -> None:
        self.count += 1


class RecordingMetrics(NoopMetrics):
    def __init__(self) -> None:
        self.sets: list[tuple[str, DeliveryMethod, str]] = []

    def set_received(self, transmitter: str, delivery: DeliveryMethod, outcome: str) -> None:
        self.sets.append((transmitter, delivery, outcome))


def verifier(transmitter: TestTransmitter) -> JwtVerifier:
    keys = HttpJwkSetSource(transmitter.client, transmitter.jwks_url)
    return JwtVerifier(transmitter.issuer, keys, replace(default_verifier_options(), expected_audiences=[AUDIENCE]))


def processor(transmitter: TestTransmitter, *handlers: Handler, options: ProcessorOptions | None = None) -> Processor:
    return Processor(verifier(transmitter), InMemoryJtiDedupStore(10), options).add_handler(*handlers)


def push_handler(transmitter: TestTransmitter, recorder: Recorder) -> PushHandler:
    return PushHandler(processor(transmitter, recorder), SECRET)


def alice(transmitter: TestTransmitter) -> Claims:
    return iss_sub(transmitter.issuer, "alice")


def error_code(response: PushResponse) -> str:
    assert response.body is not None, "no error document"
    assert response.body_bytes is not None and json.loads(response.body_bytes) == response.body
    return str(response.body["err"])


# what is refused


async def test_rejects_transmitter_that_does_not_authenticate():
    transmitter = TestTransmitter()
    recorder = Recorder()
    metrics = RecordingMetrics()
    handler = PushHandler(processor(transmitter, recorder, options=ProcessorOptions(metrics=metrics)), SECRET)
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter)).encode()
    for authorization in [None, "", "Bearer wrong", "bearer s3cr3t", "Bearer s3cr3t "]:
        response = await handler.handle(authorization, encoded_set)
        assert response.status == 401 and not response.is_accepted, authorization
        assert error_code(response) == "authentication_failed"
    assert recorder.count == 0, "nothing handled"
    assert metrics.sets == [("", DeliveryMethod.PUSH, SetOutcome.UNAUTHENTICATED)] * 5
    # without an expected header anything goes
    open_handler = PushHandler(processor(transmitter, recorder), "")
    assert (await open_handler.handle("", encoded_set)).status == 202


async def test_rejects_invalid_set_with_error_document():
    transmitter = TestTransmitter()
    recorder = Recorder()
    handler = push_handler(transmitter, recorder)
    claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    claims["aud"] = "https://other.example"
    response = await handler.handle(SECRET, transmitter.sign_set(claims).encode())
    assert response.status == 400
    assert error_code(response) == "invalid_audience"
    assert "not addressed" in str(response.body["description"])
    assert error_code(await handler.handle(SECRET, b"garbage")) == "invalid_request"
    response = await handler.handle(SECRET, b"\xff\xfe")
    assert response.status == 400 and error_code(response) == "invalid_request"
    assert recorder.count == 0, "nothing handled"


async def test_rejects_oversized_set():
    transmitter = TestTransmitter()
    response = await push_handler(transmitter, Recorder()).handle(SECRET, b"a" * (MAX_SET_SIZE + 1))
    assert response.status == 413
    assert error_code(response) == "invalid_request"


async def test_asks_for_redelivery_when_handler_fails():
    transmitter = TestTransmitter()

    async def failing(context: EventContext) -> None:
        raise RuntimeError("nope")

    handler = PushHandler(processor(transmitter, failing), SECRET)
    response = await handler.handle(SECRET, transmitter.set("CaepSessionRevoked", alice(transmitter)))
    assert response.status == 500 and response.body is None and response.body_bytes is None


async def test_asks_for_redelivery_while_transmitter_keys_are_unavailable():
    transmitter = TestTransmitter()
    transmitter.remove_document(JWKS_PATH)
    handler = push_handler(transmitter, Recorder())
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter))
    assert (await handler.handle(SECRET, encoded_set)).status == 503, "503 while unavailable"
    transmitter.publish_jwks(transmitter.key)
    assert (await handler.handle(SECRET, encoded_set)).status == 202, "202 once available"


async def test_asks_for_redelivery_while_another_instance_handles_the_set():
    transmitter = TestTransmitter()
    recorder = Recorder()
    release = asyncio.Event()

    async def slow(context: EventContext) -> None:
        await release.wait()

    handler = PushHandler(processor(transmitter, slow, recorder), SECRET)
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter))
    first = asyncio.create_task(handler.handle(SECRET, encoded_set))
    await asyncio.sleep(0.01)
    assert (await handler.handle(SECRET, encoded_set)).status == 503, "in progress"
    release.set()
    assert (await first).status == 202
    assert recorder.count == 1


# what is accepted


async def test_accepts_and_handles_set():
    transmitter = TestTransmitter()
    recorder = Recorder()
    response = await push_handler(transmitter, recorder).handle(
        SECRET, transmitter.set("CaepSessionRevoked", alice(transmitter)).encode()
    )
    assert response.status == 202 and response.is_accepted and response.body is None
    assert recorder.count == 1


async def test_accepts_duplicate_without_handling_it_again():
    transmitter = TestTransmitter()
    recorder = Recorder()
    handler = push_handler(transmitter, recorder)
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter)).encode()
    await handler.handle(SECRET, encoded_set)
    assert (await handler.handle(SECRET, encoded_set)).status == 202
    assert recorder.count == 1, "duplicate accepted and skipped"


async def test_authenticates_every_transmitter_with_its_own_header():
    transmitter = TestTransmitter()
    recorder = Recorder()
    metrics = RecordingMetrics()
    handler = PushHandler.by_issuer(
        processor(transmitter, recorder, options=ProcessorOptions(metrics=metrics)),
        lambda issuer: "Bearer mine" if issuer == transmitter.issuer else "",
    )
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter))
    assert (await handler.handle(SECRET, encoded_set)).status == 401
    assert metrics.sets[-1] == (transmitter.issuer, DeliveryMethod.PUSH, SetOutcome.UNAUTHENTICATED)
    assert (await handler.handle("Bearer mine", encoded_set)).status == 202
    # a SET of an unknown issuer needs no header to be rejected as invalid_issuer
    claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    claims["iss"] = "https://unknown.example"
    response = await handler.handle("", transmitter.sign_set(claims))
    assert response.status == 400 and error_code(response) == "invalid_issuer"
    assert handler.processor.handler_count == 1


async def test_dropped_request_does_not_cancel_the_handlers():
    transmitter = TestTransmitter()
    started = asyncio.Event()
    release = asyncio.Event()
    handled: list[str] = []

    async def slow(context: EventContext) -> None:
        started.set()
        await release.wait()
        handled.append(context.event_token.jti)

    handler = PushHandler(processor(transmitter, slow), SECRET)
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter))
    request = asyncio.create_task(handler.handle(SECRET, encoded_set))
    await started.wait()
    request.cancel()
    with pytest.raises(asyncio.CancelledError):
        await request
    assert not handled, "the handler is still waiting"
    release.set()
    await eventually(lambda: len(handled) == 1, what="the handler finishes after the request was dropped")
    assert (await handler.handle(SECRET, encoded_set)).status == 202, "the SET was recorded as processed"
    assert handled == [handled[0]], "and not handled again"


# the ASGI and WSGI applications


async def test_serves_push_endpoint_over_asgi():
    transmitter = TestTransmitter()
    recorder = Recorder()
    app = push_app(push_handler(transmitter, recorder))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://receiver.example") as client:

        async def post(authorization: str, body: str) -> httpx.Response:
            headers = {"Authorization": authorization, "Content-Type": "application/secevent+jwt"}
            return await client.post("/ssf/push", content=body, headers=headers)

        response = await post(SECRET, transmitter.set("CaepSessionRevoked", alice(transmitter)))
        assert response.status_code == 202 and response.content == b""
        assert recorder.count == 1
        response = await post(SECRET, "garbage")
        assert response.status_code == 400
        assert response.headers["Content-Type"] == PUSH_CONTENT_TYPE
        assert response.headers["Content-Language"] == PUSH_CONTENT_LANGUAGE
        assert response.json()["err"] == "invalid_request"
        response = await post("Bearer wrong", "garbage")
        assert response.status_code == 401 and response.json()["err"] == "authentication_failed"
        response = await client.get("/ssf/push")
        assert response.status_code == 405 and response.headers["Allow"] == "POST", "POST only"
        response = await post(SECRET, "a" * (MAX_SET_SIZE + 1))
        assert response.status_code == 413


async def test_asgi_app_acknowledges_lifespan_events():
    transmitter = TestTransmitter()
    app = push_app(push_handler(transmitter, Recorder()))
    messages = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])
    sent: list[dict] = []

    async def receive() -> dict:
        return next(messages)

    async def send(message: dict) -> None:
        sent.append(dict(message))

    await app({"type": "lifespan"}, receive, send)
    assert [m["type"] for m in sent] == ["lifespan.startup.complete", "lifespan.shutdown.complete"]
    with pytest.raises(RuntimeError):
        await app({"type": "websocket"}, receive, send)


def test_serves_push_endpoint_over_wsgi():
    transmitter = TestTransmitter()
    recorder = Recorder()
    app = push_wsgi_app(push_handler(transmitter, recorder), asyncio.run)
    with httpx.Client(transport=httpx.WSGITransport(app=app), base_url="http://receiver.example") as client:

        def post(authorization: str, body: str) -> httpx.Response:
            headers = {"Authorization": authorization, "Content-Type": "application/secevent+jwt"}
            return client.post("/ssf/push", content=body, headers=headers)

        response = post(SECRET, transmitter.set("CaepSessionRevoked", alice(transmitter)))
        assert response.status_code == 202 and response.content == b""
        assert recorder.count == 1
        response = post(SECRET, "garbage")
        assert response.status_code == 400
        assert response.headers["Content-Type"] == PUSH_CONTENT_TYPE
        assert response.headers["Content-Language"] == PUSH_CONTENT_LANGUAGE
        assert response.json()["err"] == "invalid_request"
        response = post("Bearer wrong", "garbage")
        assert response.status_code == 401 and response.json()["err"] == "authentication_failed"
        response = client.get("/ssf/push")
        assert response.status_code == 405 and response.headers["Allow"] == "POST", "POST only"
        response = post(SECRET, "a" * (MAX_SET_SIZE + 1))
        assert response.status_code == 413
