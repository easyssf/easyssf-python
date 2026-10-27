"""The example resource server against the in-process test transmitter: it registers its
stream, a pushed (or polled) session-revoked event revokes the session, and the API rejects the
access token of that session from then on."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import FastAPI

from easyssf.core import POLL_URI, PUSH_URI, Claims, audiences, object_member, string_member
from easyssf.core.subjects import complex_subject, iss_sub, opaque
from easyssf.receiver.config import ReceiverConfig
from easyssf.receiver.revocation import REVOKED_WWW_AUTHENTICATE
from easyssf.testing import CLIENT_ID, CLIENT_SECRET, TestTransmitter, eventually
from resource_server import create_app, receiver_config
from resource_server.config import DEFAULT_ISSUER, DEFAULT_PUSH_URL, PUSH_AUTHORIZATION_HEADER

PUSH_HEADERS = {"Authorization": PUSH_AUTHORIZATION_HEADER, "Content-Type": "application/secevent+jwt"}


def config_for(transmitter: TestTransmitter, poll: bool = False) -> ReceiverConfig:
    """The configuration of the example, pointed at the test transmitter."""
    config = receiver_config(poll)
    config.transmitter_issuer = transmitter.issuer
    config.allow_insecure_http = False
    config.oauth2.token_uri = transmitter.token_url
    config.oauth2.client_id = CLIENT_ID
    config.oauth2.client_secret = CLIENT_SECRET
    config.poll.interval = timedelta(milliseconds=50)
    return config


def client_of(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost:8081")


def session_revoked(transmitter: TestTransmitter, subject: str, session_id: str) -> str:
    """A session-revoked SET addressed to the stream the application registered."""
    claims: Claims = transmitter.set_claims(
        "CaepSessionRevoked", complex_subject(iss_sub(transmitter.issuer, subject), opaque(session_id))
    )
    claims["aud"] = audiences(transmitter.streams[0]["aud"])[0]
    return transmitter.sign_set(claims)


def test_receiver_config_has_the_defaults_of_the_go_example(monkeypatch: pytest.MonkeyPatch):
    for name in ("SSF_TRANSMITTER_ISSUER", "SSF_TOKEN_URI", "SSF_CLIENT_ID", "SSF_CLIENT_SECRET", "SSF_PUSH_URL"):
        monkeypatch.delenv(name, raising=False)
    config = receiver_config(poll=False)
    assert config.transmitter_issuer == DEFAULT_ISSUER
    assert config.allow_insecure_http, "the compose setup is plain http"
    assert config.stream.management == "receiver"
    assert config.stream.events_requested == ["CaepSessionRevoked"]
    assert config.push.delivery_endpoint_url == DEFAULT_PUSH_URL
    assert config.push.expected_auth_header == PUSH_AUTHORIZATION_HEADER
    assert config.oauth2.token_uri == DEFAULT_ISSUER + "/protocol/openid-connect/token"
    assert config.oauth2.client_id == "example-resource-server"
    assert config.oauth2.scopes == ["ssf.read", "ssf.manage"]
    assert config.revocation.ttl == timedelta(minutes=10)
    assert config.delivery_method == "push"
    assert config.validate() == []
    poll = receiver_config(poll=True)
    assert poll.delivery_method == "poll"
    assert poll.oauth2.client_id == "example-poll-receiver"
    assert poll.poll.interval == timedelta(seconds=2)
    assert poll.stream.description == "example-resource-server (poll)"
    assert poll.validate() == []


def test_receiver_config_reads_the_environment(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SSF_TRANSMITTER_ISSUER", "https://idp.example/realms/demo")
    monkeypatch.setenv("SSF_TOKEN_URI", "https://idp.example/token")
    monkeypatch.setenv("SSF_CLIENT_ID", "my-app")
    monkeypatch.setenv("SSF_CLIENT_SECRET", "my-secret")
    monkeypatch.setenv("SSF_PUSH_URL", "https://my-app.example/ssf/push")
    config = receiver_config(poll=False)
    assert config.transmitter_issuer == "https://idp.example/realms/demo"
    assert not config.allow_insecure_http
    assert config.oauth2.token_uri == "https://idp.example/token"
    assert config.oauth2.client_id == "my-app"
    assert config.oauth2.client_secret == "my-secret"
    assert config.push.delivery_endpoint_url == "https://my-app.example/ssf/push"
    assert config.validate() == []


async def test_registers_its_stream_and_rejects_the_access_token_of_a_revoked_session():
    transmitter = TestTransmitter()
    app = create_app(config=config_for(transmitter), http_client=transmitter.client)
    async with app.router.lifespan_context(app), client_of(app) as client:
        await eventually(lambda: len(transmitter.streams) == 1, what="the stream registration")
        stream = transmitter.streams[0]
        delivery = object_member(stream, "delivery")
        assert string_member(delivery, "method") == PUSH_URI
        assert string_member(delivery, "endpoint_url") == DEFAULT_PUSH_URL
        assert stream["events_requested"] == [transmitter.set_claims("CaepSessionRevoked", None)["events"].popitem()[0]]

        now = datetime.now(tz=UTC)
        access_token = transmitter.access_token_for("alice", "session-1", now)
        before = await client.get("/api/me", headers={"Authorization": f"Bearer {access_token}"})
        assert before.status_code == 200, before.text
        assert before.json()["subject"] == "alice"
        assert before.json()["sessionId"] == "session-1"
        assert before.json()["tokenIssuedAt"] == now.replace(microsecond=0).isoformat().replace("+00:00", "Z")

        pushed = await client.post(
            "/ssf/push", content=session_revoked(transmitter, "alice", "session-1"), headers=PUSH_HEADERS
        )
        assert pushed.status_code == 202, pushed.text

        after = await client.get("/api/me", headers={"Authorization": f"Bearer {access_token}"})
        assert after.status_code == 401
        assert after.headers["www-authenticate"] == REVOKED_WWW_AUTHENTICATE

        other = transmitter.access_token_for("alice", "session-2", now)
        assert (await client.get("/api/me", headers={"Authorization": f"Bearer {other}"})).status_code == 200

        health = await client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "healthy"
        assert health.json()["transmitters"][0]["streamId"] == stream["stream_id"]
    assert not app.state.receiver.started


async def test_answers_401_with_the_bearer_challenges_of_rfc_6750():
    transmitter = TestTransmitter()
    app = create_app(config=config_for(transmitter), http_client=transmitter.client)
    async with app.router.lifespan_context(app), client_of(app) as client:
        without = await client.get("/api/me")
        assert without.status_code == 401
        assert without.headers["www-authenticate"] == "Bearer"
        basic = await client.get("/api/me", headers={"Authorization": "Basic dXNlcjpwYXNz"})
        assert basic.status_code == 401
        assert basic.headers["www-authenticate"] == "Bearer"
        garbage = await client.get("/api/me", headers={"Authorization": "Bearer not-a-token"})
        assert garbage.status_code == 401
        assert garbage.headers["www-authenticate"].startswith('Bearer error="invalid_token", error_description="')
        other_issuer = TestTransmitter(host="other.example")
        foreign = other_issuer.access_token_for("alice", "s1", datetime.now(tz=UTC))
        rejected = await client.get("/api/me", headers={"Authorization": f"Bearer {foreign}"})
        assert rejected.status_code == 401
        assert rejected.headers["www-authenticate"] == (
            'Bearer error="invalid_token", error_description="the token was not issued by the expected issuer"'
        )


async def test_push_endpoint_accepts_only_the_transmitter():
    transmitter = TestTransmitter()
    app = create_app(config=config_for(transmitter), http_client=transmitter.client)
    async with app.router.lifespan_context(app), client_of(app) as client:
        await eventually(lambda: len(transmitter.streams) == 1, what="the stream registration")
        encoded_set = session_revoked(transmitter, "alice", "session-1")
        unauthenticated = await client.post(
            "/ssf/push", content=encoded_set, headers={"Content-Type": "application/secevent+jwt"}
        )
        assert unauthenticated.status_code == 401
        assert unauthenticated.json()["err"] == "authentication_failed"
        invalid = await client.post("/ssf/push", content="not-a-security-event-token", headers=PUSH_HEADERS)
        assert invalid.status_code == 400
        assert invalid.headers["content-language"] == "en"


async def test_poll_profile_polls_the_stream_it_registered():
    transmitter = TestTransmitter()
    app = create_app(poll=True, config=config_for(transmitter, poll=True), http_client=transmitter.client)
    async with app.router.lifespan_context(app), client_of(app) as client:
        await eventually(lambda: len(transmitter.streams) == 1, what="the stream registration")
        assert string_member(object_member(transmitter.streams[0], "delivery"), "method") == POLL_URI
        now = datetime.now(tz=UTC)
        access_token = transmitter.access_token_for("alice", "session-1", now)
        assert (await client.get("/api/me", headers={"Authorization": f"Bearer {access_token}"})).status_code == 200
        transmitter.queue_set(session_revoked(transmitter, "alice", "session-1"))
        await eventually(lambda: len(transmitter.acknowledged_sets) == 1, what="the acknowledgement")
        after = await client.get("/api/me", headers={"Authorization": f"Bearer {access_token}"})
        assert after.status_code == 401
        assert after.headers["www-authenticate"] == REVOKED_WWW_AUTHENTICATE
        health = await client.get("/health")
        assert health.json()["transmitters"][0]["delivery"] == "poll"
