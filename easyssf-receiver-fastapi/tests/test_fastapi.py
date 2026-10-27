"""The FastAPI integration: the push router end to end against the test transmitter, the
revocation dependency and middleware, the lifespan and the health route. The counterpart of the
tests of the Rust easyssf-receiver-axum crate."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import Depends, FastAPI, Request

from easyssf.core.subjects import complex_subject, iss_sub, opaque
from easyssf.fastapi import (
    REVOKED_WWW_AUTHENTICATE,
    RevocationMiddleware,
    health_router,
    into_response,
    push_router,
    push_router_for,
    receiver_lifespan,
    revocation_dependency,
)
from easyssf.receiver.config import ReceiverConfig, default_receiver_config
from easyssf.receiver.errors import StoreError
from easyssf.receiver.event import EventContext, for_event
from easyssf.receiver.push import MAX_SET_SIZE, PushResponse
from easyssf.receiver.receiver import Receiver
from easyssf.receiver.revocation import InMemoryTokenRevocationStore, TokenClaims
from easyssf.testing import AUDIENCE, SECEVENT_JWT_TYPE, TestTransmitter, eventually, shared_key, sign

SECRET = "Bearer s3cr3t"
PUSH_HEADERS = {"Authorization": SECRET, "Content-Type": "application/secevent+jwt"}


class Recorder:
    """Counts the SETs it handled."""

    def __init__(self) -> None:
        self.count = 0

    async def handle(self, context: EventContext) -> None:
        self.count += 1


class FailingStore:
    """A revocation store that fails every call."""

    async def revoke_session(self, issuer: str, session_id: str) -> None:
        raise StoreError(RuntimeError("down"))

    async def revoke_subject(self, issuer: str, subject: str, revoked_at: datetime) -> None:
        raise StoreError(RuntimeError("down"))

    async def is_session_revoked(self, issuer: str, session_id: str) -> bool:
        raise StoreError(RuntimeError("down"))

    async def subject_revoked_at(self, issuer: str, subject: str) -> datetime | None:
        raise StoreError(RuntimeError("down"))


def push_config(transmitter: TestTransmitter) -> ReceiverConfig:
    config = default_receiver_config()
    config.transmitter_issuer = transmitter.issuer
    config.expected_audience = AUDIENCE
    config.push.expected_auth_header = SECRET
    return config


def client_of(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://app.example")


def claims_of_request(request: Request) -> TokenClaims | None:
    token = request.headers.get("x-token")
    if token is None:
        return None
    issuer, subject, session_id = token.split("|")
    return TokenClaims(issuer=issuer, subject=subject, session_id=session_id, issued_at=datetime.now(tz=UTC))


def claims_of_scope(scope: dict[str, object]) -> TokenClaims | None:
    headers = dict(scope.get("headers") or ())  # type: ignore[call-overload]
    token = headers.get(b"x-token")
    if token is None:
        return None
    issuer, subject, session_id = token.decode().split("|")
    return TokenClaims(issuer=issuer, subject=subject, session_id=session_id, issued_at=datetime.now(tz=UTC))


# -- the push router --------------------------------------------------------------------------------


async def test_push_route_rejects_a_request_without_the_authorization_header():
    transmitter = TestTransmitter()
    receiver = Receiver(push_config(transmitter), http_client=transmitter.client)
    app = FastAPI()
    app.include_router(push_router(receiver.push_handler))
    encoded_set = transmitter.set("CaepSessionRevoked", iss_sub(transmitter.issuer, "alice"))
    async with client_of(app) as client:
        response = await client.post(
            "/ssf/push", content=encoded_set, headers={"Content-Type": "application/secevent+jwt"}
        )
    assert response.status_code == 401
    assert response.headers["content-type"] == "application/json"
    assert response.headers["content-language"] == "en"
    assert response.json()["err"] == "authentication_failed"


async def test_push_route_accepts_a_set_and_invokes_the_handlers():
    transmitter = TestTransmitter()
    recorder = Recorder()
    receiver = Receiver(
        push_config(transmitter), http_client=transmitter.client, handlers=[for_event("CaepSessionRevoked", recorder)]
    )
    app = FastAPI()
    app.include_router(push_router(receiver.push_handler))
    subject = complex_subject(iss_sub(transmitter.issuer, "alice"), opaque("s1"))
    encoded_set = transmitter.set("CaepSessionRevoked", subject)
    async with client_of(app) as client:
        response = await client.post("/ssf/push", content=encoded_set, headers=PUSH_HEADERS)
    assert response.status_code == 202
    assert response.content == b""
    assert "content-type" not in response.headers
    assert "content-language" not in response.headers
    assert recorder.count == 1
    token = TokenClaims(issuer=transmitter.issuer, subject="alice", session_id="s1", issued_at=datetime.now(tz=UTC))
    assert await receiver.token_revocation_store.is_session_revoked(token.issuer, token.session_id)


async def test_push_route_rejects_an_invalid_set_with_an_error_document():
    transmitter = TestTransmitter()
    receiver = Receiver(push_config(transmitter), http_client=transmitter.client)
    app = FastAPI()
    app.include_router(push_router(receiver.push_handler))
    claims = transmitter.set_claims("CaepSessionRevoked", iss_sub(transmitter.issuer, "alice"))
    unknown_key = sign(shared_key().with_key_id("unknown"), SECEVENT_JWT_TYPE, claims)
    async with client_of(app) as client:
        garbage = await client.post("/ssf/push", content="not-a-security-event-token", headers=PUSH_HEADERS)
        response = await client.post("/ssf/push", content=unknown_key, headers=PUSH_HEADERS)
    # not a JWS at all: no issuer to route it by
    assert garbage.status_code == 400
    assert garbage.json()["err"] == "invalid_issuer"
    assert response.status_code == 400
    assert response.headers["content-type"] == "application/json"
    assert response.headers["content-language"] == "en"
    assert response.json() == {"err": "invalid_key", "description": "The SET is signed with an unknown key"}


async def test_push_route_rejects_an_oversized_body_by_its_content_length():
    transmitter = TestTransmitter()
    receiver = Receiver(push_config(transmitter), http_client=transmitter.client)
    app = FastAPI()
    app.include_router(push_router(receiver.push_handler))
    async with client_of(app) as client:
        response = await client.post("/ssf/push", content=b"a" * (MAX_SET_SIZE + 1), headers=PUSH_HEADERS)
    assert response.status_code == 413
    assert response.json() == {"err": "invalid_request", "description": "The SET is too large"}
    assert response.headers["content-language"] == "en"


async def test_push_route_rejects_an_oversized_body_sent_in_chunks():
    transmitter = TestTransmitter()
    receiver = Receiver(push_config(transmitter), http_client=transmitter.client)
    app = FastAPI()
    app.include_router(push_router(receiver.push_handler))

    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(MAX_SET_SIZE // 1024 + 1):
            yield b"a" * 1024

    async with client_of(app) as client:
        response = await client.post("/ssf/push", content=chunks(), headers=PUSH_HEADERS)
    assert response.status_code == 413
    assert response.json()["err"] == "invalid_request"


async def test_push_route_answers_other_methods_with_405():
    transmitter = TestTransmitter()
    receiver = Receiver(push_config(transmitter), http_client=transmitter.client)
    app = FastAPI()
    app.include_router(push_router(receiver.push_handler))
    async with client_of(app) as client:
        response = await client.get("/ssf/push")
    assert response.status_code == 405


async def test_push_router_for_mounts_at_the_configured_path():
    transmitter = TestTransmitter()
    config = push_config(transmitter)
    config.push.endpoint_path = "/events/ssf"
    receiver = Receiver(config, http_client=transmitter.client)
    app = FastAPI()
    app.include_router(push_router_for(receiver))
    encoded_set = transmitter.set("CaepSessionRevoked", iss_sub(transmitter.issuer, "alice"))
    async with client_of(app) as client:
        assert (await client.post("/events/ssf", content=encoded_set, headers=PUSH_HEADERS)).status_code == 202
        assert (await client.post("/ssf/push", content=encoded_set, headers=PUSH_HEADERS)).status_code == 404


def test_into_response_sets_the_headers_only_with_a_body():
    accepted = into_response(PushResponse(202))
    assert accepted.status_code == 202
    assert accepted.body == b""
    assert "content-type" not in accepted.headers
    rejected = into_response(PushResponse.error(400, "invalid_key", "The signature of the SET is invalid"))
    assert rejected.status_code == 400
    assert rejected.headers["content-type"] == "application/json"
    assert rejected.headers["content-language"] == "en"
    assert rejected.body == b'{"err":"invalid_key","description":"The signature of the SET is invalid"}'


# -- the revocation dependency and middleware -----------------------------------------------------


def guarded_app(store: object, extract: object = claims_of_request) -> FastAPI:
    app = FastAPI()
    reject_revoked = revocation_dependency(store, extract)  # type: ignore[arg-type]

    @app.get("/api/me", dependencies=[Depends(reject_revoked)])
    async def me() -> dict[str, str]:
        return {"user": "alice"}

    return app


async def test_revocation_dependency_lets_a_request_without_or_with_a_valid_token_through():
    store = InMemoryTokenRevocationStore()
    app = guarded_app(store)
    async with client_of(app) as client:
        assert (await client.get("/api/me")).status_code == 200, "no token"
        response = await client.get("/api/me", headers={"X-Token": "https://idp.example|alice|s1"})
    assert response.status_code == 200
    assert response.json() == {"user": "alice"}


async def test_revocation_dependency_rejects_a_revoked_token_with_401_and_the_challenge():
    store = InMemoryTokenRevocationStore()
    await store.revoke_session("https://idp.example", "s1")
    app = guarded_app(store)
    async with client_of(app) as client:
        response = await client.get("/api/me", headers={"X-Token": "https://idp.example|alice|s1"})
        other = await client.get("/api/me", headers={"X-Token": "https://idp.example|alice|s2"})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == REVOKED_WWW_AUTHENTICATE
    assert other.status_code == 200, "another session of the same user"


async def test_revocation_dependency_accepts_an_async_extractor():
    store = InMemoryTokenRevocationStore()
    await store.revoke_subject("https://idp.example", "alice", datetime.now(tz=UTC) + timedelta(minutes=1))

    async def extract(request: Request) -> TokenClaims | None:
        return claims_of_request(request)

    app = guarded_app(store, extract)
    async with client_of(app) as client:
        response = await client.get("/api/me", headers={"X-Token": "https://idp.example|alice|s1"})
    assert response.status_code == 401


async def test_revocation_dependency_answers_503_when_the_store_fails():
    app = guarded_app(FailingStore())
    async with client_of(app) as client:
        response = await client.get("/api/me", headers={"X-Token": "https://idp.example|alice|s1"})
        anonymous = await client.get("/api/me")
    assert response.status_code == 503
    assert anonymous.status_code == 200, "no token, no lookup"


async def test_revocation_middleware_guards_the_application():
    store = InMemoryTokenRevocationStore()
    await store.revoke_session("https://idp.example", "s1")
    app = FastAPI()
    app.add_middleware(RevocationMiddleware, store=store, extract=claims_of_scope)

    @app.get("/api/me")
    async def me() -> dict[str, str]:
        return {"user": "alice"}

    async with client_of(app) as client:
        allowed = await client.get("/api/me", headers={"X-Token": "https://idp.example|alice|s2"})
        revoked = await client.get("/api/me", headers={"X-Token": "https://idp.example|alice|s1"})
    assert allowed.status_code == 200
    assert revoked.status_code == 401
    assert revoked.headers["www-authenticate"] == REVOKED_WWW_AUTHENTICATE


async def test_revocation_middleware_answers_503_when_the_store_fails():
    app = FastAPI()
    app.add_middleware(RevocationMiddleware, store=FailingStore(), extract=claims_of_scope)

    @app.get("/api/me")
    async def me() -> dict[str, str]:
        return {"user": "alice"}

    async with client_of(app) as client:
        response = await client.get("/api/me", headers={"X-Token": "https://idp.example|alice|s1"})
    assert response.status_code == 503


# -- the lifespan -------------------------------------------------------------------------------------


async def test_lifespan_starts_and_stops_the_receiver():
    transmitter = TestTransmitter()
    receiver = Receiver(push_config(transmitter), http_client=transmitter.client)
    app = FastAPI(lifespan=receiver_lifespan(receiver))
    assert not receiver.started
    async with app.router.lifespan_context(app):
        assert receiver.started
    assert not receiver.started


async def test_lifespan_wraps_the_lifespan_of_the_application():
    transmitter = TestTransmitter()
    receiver = Receiver(push_config(transmitter), http_client=transmitter.client)
    events: list[str] = []

    @asynccontextmanager
    async def inner(app: FastAPI) -> AsyncIterator[dict[str, str]]:
        events.append(f"inner enter, receiver started: {receiver.started}")
        yield {"database": "ready"}
        events.append(f"inner exit, receiver started: {receiver.started}")

    app = FastAPI(lifespan=receiver_lifespan(receiver, inner))
    async with app.router.lifespan_context(app) as state:
        assert receiver.started
        assert state == {"database": "ready"}
    assert events == ["inner enter, receiver started: False", "inner exit, receiver started: False"]
    assert not receiver.started


# -- the health route -----------------------------------------------------------------------------


async def test_health_route_answers_200_while_healthy_or_degraded():
    transmitter = TestTransmitter()
    receiver = Receiver(push_config(transmitter), http_client=transmitter.client)
    app = FastAPI()
    app.include_router(health_router(receiver))
    async with client_of(app) as client:
        degraded = await client.get("/health")
        assert degraded.status_code == 200
        assert degraded.json()["status"] == "degraded"
        assert degraded.json()["transmitters"][0]["name"] == "default"
        # a verified SET means the metadata and the keys were fetched: healthy
        encoded_set = transmitter.set("CaepSessionRevoked", iss_sub(transmitter.issuer, "alice"))
        assert (await receiver.push_handler.handle(SECRET, encoded_set)).status == 202
        healthy = await client.get("/health")
    assert healthy.status_code == 200
    assert healthy.json()["status"] == "healthy"
    assert healthy.json()["description"] == "In contact with the SSF transmitter(s)"


async def test_health_route_answers_503_when_unhealthy():
    transmitter = TestTransmitter()
    config = default_receiver_config()
    config.transmitter_issuer = transmitter.issuer
    config.expected_audience = AUDIENCE
    config.delivery_method = "poll"
    config.poll.endpoint_url = transmitter.poll_url
    config.poll.interval = timedelta(milliseconds=50)
    config.transmitter_access_token = "token"
    receiver = Receiver(config, http_client=transmitter.client)
    transmitter.set_available(False)
    app = FastAPI(lifespan=receiver_lifespan(receiver))
    app.include_router(health_router(receiver, path="/ready"))
    async with app.router.lifespan_context(app), client_of(app) as client:
        poller = receiver.transmitters[0].poller
        await eventually(lambda: bool(poller.last_poll_error), what="a failed poll")
        response = await client.get("/ready")
    assert response.status_code == 503
    assert response.json()["status"] == "unhealthy"
    assert response.json()["transmitters"][0]["pollError"]


@pytest.mark.parametrize("path", ["/health", "/ready"])
async def test_health_route_is_mounted_at_the_given_path(path: str):
    transmitter = TestTransmitter()
    receiver = Receiver(push_config(transmitter), http_client=transmitter.client)
    app = FastAPI()
    app.include_router(health_router(receiver, path=path))
    async with client_of(app) as client:
        assert (await client.get(path)).status_code == 200
