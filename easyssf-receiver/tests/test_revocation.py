"""SsfTokenRevocationTests of the Java library: the revocation tests of receiver/processor_test.go
of the Go port and tests/token_revocation.rs of the Rust port."""

import logging
from collections.abc import Awaitable, Callable, MutableMapping
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from easyssf.core import Claims, DeliveryMethod, EventToken
from easyssf.core.subjects import complex_subject, email, iss_sub, opaque
from easyssf.receiver.event import EventContext, Handler
from easyssf.receiver.revocation import (
    DEFAULT_REVOCATION_TTL,
    DEFAULT_SESSION_EVENT_TYPES,
    REVOKED_WWW_AUTHENTICATE,
    InMemoryTokenRevocationStore,
    RevocationMiddleware,
    TokenClaims,
    TokenRevocationHandler,
    TokenRevocationStore,
    is_revoked,
    reject_if_revoked,
)
from easyssf.testing import ManualClock, TestTransmitter

IDP = "https://idp.example"


def claims(issuer: str, subject: str = "", session: str = "", issued_at: datetime | None = None) -> TokenClaims:
    return TokenClaims(issuer=issuer, subject=subject, session_id=session, issued_at=issued_at)


def context(set_claims: Claims) -> EventContext:
    token = EventToken.from_claims(set_claims)
    assert token is not None
    return EventContext(token, DeliveryMethod.PUSH)


async def revoke(
    transmitter: TestTransmitter,
    store: TokenRevocationStore,
    event_type: str,
    subject: Claims | None,
    handler: Handler | None = None,
) -> None:
    handler = handler if handler is not None else TokenRevocationHandler(store)
    await handler.handle(context(transmitter.set_claims(event_type, subject)))


def now() -> datetime:
    return datetime.now(tz=UTC)


# the handler


async def test_session_event_revokes_tokens_of_that_session_only():
    transmitter = TestTransmitter()
    store = InMemoryTokenRevocationStore()
    await revoke(transmitter, store, "CaepSessionRevoked", complex_subject(iss_sub(IDP, "alice"), opaque("s1")))
    assert await is_revoked(store, claims(IDP, "alice", "s1"))
    assert not await is_revoked(store, claims(IDP, "alice", "s2"))
    assert not await is_revoked(store, claims(IDP, "alice"))
    assert await store.is_session_revoked(IDP, "s1")


async def test_user_event_revokes_tokens_issued_up_to_the_event():
    transmitter = TestTransmitter()
    store = InMemoryTokenRevocationStore()
    before = now()
    await revoke(transmitter, store, "CaepSessionRevoked", iss_sub(IDP, "alice"))
    assert await is_revoked(store, claims(IDP, "alice", issued_at=before - timedelta(seconds=5)))
    assert await is_revoked(store, claims(IDP, "alice", "any")), "without iat: revoked"
    assert not await is_revoked(store, claims(IDP, "alice", issued_at=before + timedelta(seconds=60)))
    assert not await is_revoked(store, claims(IDP, "bob", issued_at=before - timedelta(seconds=5)))
    assert await store.subject_revoked_at(IDP, "alice") is not None
    assert not await is_revoked(store, claims("https://other.example", "alice")), "scoped to the issuer"


async def test_opaque_subject_revokes_matching_session_and_subject():
    transmitter = TestTransmitter()
    store = InMemoryTokenRevocationStore()
    await revoke(transmitter, store, "CaepSessionRevoked", opaque("xyz"))
    issuer = transmitter.issuer
    assert await is_revoked(store, claims(issuer, session="xyz"))
    assert await is_revoked(store, claims(issuer, "xyz", issued_at=now() - timedelta(seconds=1)))
    assert not await is_revoked(store, claims(issuer, "other", "other"))


async def test_revocations_are_scoped_to_the_issuer():
    transmitter = TestTransmitter()
    store = InMemoryTokenRevocationStore()
    await revoke(transmitter, store, "CaepSessionRevoked", complex_subject(iss_sub(IDP, "alice"), opaque("s1")))
    assert not await is_revoked(store, claims("https://other-idp.example", "alice", "s1"))
    assert not await is_revoked(store, TokenClaims(issuer="", subject="alice", session_id="s1"))


async def test_session_is_revoked_at_the_issuer_of_its_user():
    transmitter = TestTransmitter()
    store = InMemoryTokenRevocationStore()
    await revoke(transmitter, store, "CaepSessionRevoked", complex_subject(iss_sub(IDP, "alice"), opaque("s1")))
    assert await store.is_session_revoked(IDP, "s1")
    assert not await store.is_session_revoked(transmitter.issuer, "s1")
    # a session without a user is revoked at the transmitter
    await revoke(transmitter, store, "CaepSessionRevoked", complex_subject(None, opaque("s2")))
    assert await store.is_session_revoked(transmitter.issuer, "s2")
    # a session identifier that names its issuer is revoked there
    await revoke(transmitter, store, "CaepSessionRevoked", complex_subject(None, iss_sub(IDP, "s3")))
    assert await store.is_session_revoked(IDP, "s3")


async def test_identifier_of_another_issuer_is_revoked_at_that_issuer():
    transmitter = TestTransmitter()
    store = InMemoryTokenRevocationStore()
    await revoke(transmitter, store, "CaepSessionRevoked", iss_sub("https://third.example", "carol"))
    assert await store.subject_revoked_at("https://third.example", "carol") is not None
    assert await store.subject_revoked_at(transmitter.issuer, "carol") is None


async def test_ignores_other_events_and_subjects_without_session_or_subject():
    transmitter = TestTransmitter()
    store = InMemoryTokenRevocationStore()
    await revoke(transmitter, store, "CaepCredentialChange", complex_subject(iss_sub(IDP, "alice"), opaque("s1")))
    assert not await store.is_session_revoked(IDP, "s1")
    await revoke(transmitter, store, "CaepSessionRevoked", email("alice@example.com"))
    assert not await is_revoked(store, claims(IDP, "alice@example.com"))
    await revoke(transmitter, store, "CaepSessionRevoked", None)
    assert len(store) == 0
    # user event types revoke the user even if the event names a session
    handler = TokenRevocationHandler(store, [], ["CaepCredentialChange"])
    subject = complex_subject(iss_sub(IDP, "alice"), opaque("s1"))
    await revoke(transmitter, store, "CaepCredentialChange", subject, handler)
    assert not await store.is_session_revoked(IDP, "s1")
    assert await store.subject_revoked_at(IDP, "alice") is not None


async def test_user_event_without_a_session_member_revokes_the_user_at_the_event_time():
    transmitter = TestTransmitter()
    store = InMemoryTokenRevocationStore()
    handler = TokenRevocationHandler(store, None, ["CaepCredentialChange"])
    assert handler.session_event_types == ("https://schemas.openid.net/secevent/caep/event-type/session-revoked",)
    assert handler.user_event_types == ("https://schemas.openid.net/secevent/caep/event-type/credential-change",)
    set_claims = transmitter.set_claims_with_payload(
        "CaepCredentialChange", iss_sub(IDP, "alice"), {"event_timestamp": 1_700_000_000}
    )
    await handler.handle(context(set_claims))
    assert await store.subject_revoked_at(IDP, "alice") == datetime.fromtimestamp(1_700_000_000, tz=UTC)


async def test_event_without_sid_or_sub_is_logged_and_revokes_nothing(caplog: pytest.LogCaptureFixture):
    transmitter = TestTransmitter()
    store = InMemoryTokenRevocationStore()
    with caplog.at_level(logging.WARNING, logger="easyssf.receiver.revocation"):
        await revoke(transmitter, store, "CaepSessionRevoked", email("alice@example.com"))
    assert any("no tokens were revoked" in record.message for record in caplog.records)
    assert len(store) == 0


# the store


async def test_revocations_expire():
    clock = ManualClock()
    store = InMemoryTokenRevocationStore(timedelta(seconds=60), clock)
    await store.revoke_session(IDP, "s1")
    await store.revoke_subject(IDP, "alice", clock.now)
    clock.advance(timedelta(seconds=59))
    assert await store.is_session_revoked(IDP, "s1")
    assert await store.subject_revoked_at(IDP, "alice") is not None
    clock.advance(timedelta(seconds=2))
    assert not await store.is_session_revoked(IDP, "s1")
    assert await store.subject_revoked_at(IDP, "alice") is None
    # expired revocations are purged on the next write, or on demand
    assert len(store) == 2
    store.purge()
    assert len(store) == 0
    await store.revoke_session(IDP, "s2")
    clock.advance(timedelta(seconds=61))
    await store.revoke_session(IDP, "s3")
    assert len(store) == 1


async def test_event_delivered_late_does_not_shorten_more_recent_revocation():
    clock = ManualClock()
    store = InMemoryTokenRevocationStore(timedelta(hours=1), clock)
    at = clock.now
    await store.revoke_subject(IDP, "alice", at)
    await store.revoke_subject(IDP, "alice", at - timedelta(minutes=10))
    assert await store.subject_revoked_at(IDP, "alice") == at
    assert await is_revoked(store, claims(IDP, "alice", issued_at=at - timedelta(minutes=5)))
    # a more recent revocation moves the time forward
    await store.revoke_subject(IDP, "alice", at + timedelta(minutes=10))
    assert await store.subject_revoked_at(IDP, "alice") == at + timedelta(minutes=10)


async def test_store_defaults():
    store = InMemoryTokenRevocationStore(timedelta(0))
    assert repr(store) == f"InMemoryTokenRevocationStore(ttl={DEFAULT_REVOCATION_TTL}, size=0)"
    assert DEFAULT_SESSION_EVENT_TYPES == ("CaepSessionRevoked",)
    assert isinstance(TokenRevocationHandler(store), Handler)


async def test_is_revoked_asks_the_store_only_for_what_the_token_carries():
    class Recording:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, str]] = []

        async def revoke_session(self, issuer: str, session_id: str) -> None:
            pass

        async def revoke_subject(self, issuer: str, subject: str, revoked_at: datetime) -> None:
            pass

        async def is_session_revoked(self, issuer: str, session_id: str) -> bool:
            self.calls.append(("session", issuer, session_id))
            return False

        async def subject_revoked_at(self, issuer: str, subject: str) -> datetime | None:
            self.calls.append(("subject", issuer, subject))
            return None

    store = Recording()
    assert not await is_revoked(store, TokenClaims())
    assert not await is_revoked(store, claims("", "alice", "s1"))
    assert store.calls == [], "a token without an issuer is not revoked, without asking"
    assert not await is_revoked(store, claims(IDP, session="s1"))
    assert store.calls == [("session", IDP, "s1")]
    store.calls = []
    assert not await is_revoked(store, claims(IDP, "alice", "s1"))
    assert store.calls == [("session", IDP, "s1"), ("subject", IDP, "alice")]
    assert not await reject_if_revoked(store, None)


# the ASGI middleware

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]


async def ok(scope: Scope, receive: Receive, send: Send) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": b"orders"})


def session_of(scope: Scope) -> TokenClaims | None:
    for name, value in scope["headers"]:
        if name == b"x-session":
            return claims(IDP, "alice", value.decode())
    return None


def client(app: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://app.example")


async def test_revocation_middleware_rejects_revoked_tokens():
    store = InMemoryTokenRevocationStore()
    await store.revoke_session(IDP, "s1")
    app = RevocationMiddleware(ok, store, session_of)
    async with client(app) as c:
        rejected = await c.get("/api/orders", headers={"X-Session": "s1"})
        assert rejected.status_code == 401
        assert rejected.headers["www-authenticate"] == REVOKED_WWW_AUTHENTICATE
        assert rejected.content == b""
        passed = await c.get("/api/orders", headers={"X-Session": "s2"})
        assert passed.status_code == 200
        assert passed.text == "orders"
        # a request without a token passes
        assert (await c.get("/api/orders")).status_code == 200


async def test_revocation_middleware_awaits_an_async_extractor():
    store = InMemoryTokenRevocationStore()
    await store.revoke_subject(IDP, "alice", now())

    async def extract(scope: Scope) -> TokenClaims | None:
        return claims(IDP, "alice", issued_at=now() - timedelta(minutes=1))

    async with client(RevocationMiddleware(ok, store, extract)) as c:
        assert (await c.get("/api/orders")).status_code == 401


async def test_revocation_middleware_answers_503_when_the_store_fails():
    class Failing(InMemoryTokenRevocationStore):
        async def is_session_revoked(self, issuer: str, session_id: str) -> bool:
            raise ConnectionError("down")

    async with client(RevocationMiddleware(ok, Failing(), session_of)) as c:
        response = await c.get("/api/orders", headers={"X-Session": "s1"})
        assert response.status_code == 503
        assert response.text == "revocation check failed\n"


async def test_revocation_middleware_passes_other_scopes_through():
    seen: list[str] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(scope["type"])

    middleware = RevocationMiddleware(app, InMemoryTokenRevocationStore(), session_of)

    async def receive() -> MutableMapping[str, Any]:
        return {"type": "lifespan.startup"}

    async def send(message: MutableMapping[str, Any]) -> None:
        pass

    await middleware({"type": "lifespan"}, receive, send)
    assert seen == ["lifespan"]
