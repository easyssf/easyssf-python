import asyncio
import json
import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from joserfc import jws
from joserfc.jwk import RSAKey

from easyssf.core import POLL_URI, PUSH_URI, EventTypes, StreamConfiguration, new_set
from easyssf.core.subjects import complex_subject, email, iss_sub, opaque
from easyssf.testing import (
    ACCESS_TOKEN,
    AUDIENCE,
    CLIENT_ID,
    CLIENT_SECRET,
    JWT_TYPE,
    SECEVENT_JWT_TYPE,
    MetadataLocation,
    ReportedError,
    TestTransmitter,
    claims_of,
    client_for,
    generate_key,
    shared_key,
)

AUTH = {"Authorization": "Bearer " + ACCESS_TOKEN}


@pytest.fixture
def transmitter() -> TestTransmitter:
    return TestTransmitter()


# -- documents --------------------------------------------------------------------------------------


async def test_publishes_metadata_at_the_ssf_location_by_default(transmitter: TestTransmitter):
    assert transmitter.issuer == "https://transmitter.example/realms/test"
    assert transmitter.host == "transmitter.example"
    response = await transmitter.client.get("https://transmitter.example/.well-known/ssf-configuration/realms/test")
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/json"
    metadata = response.json()
    assert metadata["issuer"] == transmitter.issuer
    assert metadata["jwks_uri"] == transmitter.jwks_url == transmitter.issuer + "/protocol/openid-connect/certs"
    assert metadata["spec_version"] == "1_0"
    assert metadata["delivery_methods_supported"] == [PUSH_URI, POLL_URI]
    assert metadata["configuration_endpoint"] == transmitter.issuer + "/ssf/streams"
    assert metadata["status_endpoint"] == transmitter.issuer + "/ssf/status"
    assert metadata["verification_endpoint"] == transmitter.issuer + "/ssf/verify"
    assert metadata["add_subject_endpoint"] == transmitter.issuer + "/ssf/subjects:add"
    assert metadata["remove_subject_endpoint"] == transmitter.issuer + "/ssf/subjects:remove"
    # under the realm, an unauthenticated request is answered with 401 before anything else, as in Go
    oidc = await transmitter.client.get(transmitter.issuer + "/.well-known/ssf-configuration")
    assert oidc.status_code == 401
    assert transmitter.requests == 2


async def test_publishes_metadata_at_the_oidc_location_or_nowhere():
    oidc = TestTransmitter.with_metadata(MetadataLocation.OIDC_STYLE, "oidc.example")
    assert oidc.issuer == "https://oidc.example/realms/test"
    assert (await oidc.client.get(oidc.issuer + "/.well-known/ssf-configuration")).status_code == 200
    assert (await oidc.client.get("https://oidc.example/.well-known/ssf-configuration/realms/test")).status_code == 404
    none = TestTransmitter(MetadataLocation.NONE, "none.example")
    assert (await none.client.get(none.issuer + "/.well-known/ssf-configuration")).status_code == 401
    assert (await none.client.get("https://none.example/.well-known/ssf-configuration/realms/test")).status_code == 404
    # the JWK Set is published regardless
    assert (await none.client.get(none.jwks_url)).status_code == 200
    none.publish_metadata(MetadataLocation.SSF)
    assert (await none.client.get("https://none.example/.well-known/ssf-configuration/realms/test")).status_code == 200
    assert (await none.client.get(none.issuer + "/.well-known/ssf-configuration")).status_code == 401


async def test_serves_the_jwk_set_and_replaces_it(transmitter: TestTransmitter):
    response = await transmitter.client.get(transmitter.jwks_url)
    assert response.status_code == 200
    keys = response.json()["keys"]
    assert len(keys) == 1
    assert keys[0]["kid"] == "test-key"
    assert keys[0]["use"] == "sig"
    assert "d" not in keys[0]
    other = generate_key(2048, "other")
    transmitter.publish_jwks(transmitter.key, other)
    assert [key["kid"] for key in (await transmitter.client.get(transmitter.jwks_url)).json()["keys"]] == [
        "test-key",
        "other",
    ]
    transmitter.publish_jwks()
    assert (await transmitter.client.get(transmitter.jwks_url)).json() == {"keys": []}


async def test_publishes_and_removes_documents_and_serves_them_while_unavailable(transmitter: TestTransmitter):
    transmitter.publish_document("/custom.json", '{"custom": true}')
    assert (await transmitter.client.get(transmitter.issuer + "/../custom.json")).status_code in (200, 404)
    assert (await transmitter.client.get("https://transmitter.example/custom.json")).json() == {"custom": True}
    transmitter.set_available(False)
    assert (await transmitter.client.get("https://transmitter.example/custom.json")).status_code == 200
    assert (await transmitter.client.get(transmitter.jwks_url)).status_code == 200
    transmitter.remove_document("/custom.json")
    assert (await transmitter.client.get("https://transmitter.example/custom.json")).status_code == 404
    transmitter.remove_document("/never-published")


# -- the token endpoint ---------------------------------------------------------------------------------


async def test_token_endpoint_accepts_basic_and_post_credentials(transmitter: TestTransmitter):
    assert transmitter.token_url == transmitter.issuer + "/protocol/openid-connect/token"
    basic = await transmitter.client.post(
        transmitter.token_url, data={"grant_type": "client_credentials"}, auth=(CLIENT_ID, CLIENT_SECRET)
    )
    assert basic.status_code == 200
    assert basic.json() == {"access_token": ACCESS_TOKEN, "token_type": "Bearer", "expires_in": 300}
    post = await transmitter.client.post(
        transmitter.token_url,
        data={"grant_type": "client_credentials", "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET},
    )
    assert post.status_code == 200
    assert post.json()["access_token"] == ACCESS_TOKEN
    # /token next to the transmitter, as the conformance suite has it
    short = await transmitter.client.post(
        transmitter.issuer + "/token", data={"grant_type": "client_credentials"}, auth=(CLIENT_ID, CLIENT_SECRET)
    )
    assert short.status_code == 200
    assert transmitter.token_requests == 3


async def test_token_endpoint_refuses_wrong_credentials_and_grants(transmitter: TestTransmitter):
    wrong_secret = await transmitter.client.post(
        transmitter.token_url, data={"grant_type": "client_credentials"}, auth=(CLIENT_ID, "nope")
    )
    assert wrong_secret.status_code == 401
    assert wrong_secret.json() == {"error": "invalid_client"}
    wrong_grant = await transmitter.client.post(
        transmitter.token_url, data={"grant_type": "password"}, auth=(CLIENT_ID, CLIENT_SECRET)
    )
    assert wrong_grant.status_code == 401
    no_credentials = await transmitter.client.post(transmitter.token_url, data={"grant_type": "client_credentials"})
    assert no_credentials.status_code == 401
    garbage = await transmitter.client.post(
        transmitter.token_url, data={"grant_type": "client_credentials"}, headers={"Authorization": "Basic %%%"}
    )
    assert garbage.status_code == 401
    assert transmitter.token_requests == 0


async def test_expired_access_tokens_are_refused_and_a_new_one_is_issued(transmitter: TestTransmitter):
    assert (await transmitter.client.get(transmitter.issuer + "/ssf/streams", headers=AUTH)).status_code == 200
    transmitter.expire_access_tokens()
    assert (await transmitter.client.get(transmitter.issuer + "/ssf/streams", headers=AUTH)).status_code == 401
    assert (await transmitter.client.get(transmitter.issuer + "/ssf/streams")).status_code == 401
    token = (
        await transmitter.client.post(
            transmitter.token_url, data={"grant_type": "client_credentials"}, auth=(CLIENT_ID, CLIENT_SECRET)
        )
    ).json()["access_token"]
    assert token != ACCESS_TOKEN
    assert token.startswith(ACCESS_TOKEN + "-")
    response = await transmitter.client.get(
        transmitter.issuer + "/ssf/streams", headers={"Authorization": "Bearer " + token}
    )
    assert response.status_code == 200


async def test_unavailable_transmitter_answers_503_for_every_endpoint(transmitter: TestTransmitter):
    transmitter.set_available(False)
    assert (await transmitter.client.post(transmitter.token_url, data={})).status_code == 503
    assert (await transmitter.client.get(transmitter.issuer + "/ssf/streams", headers=AUTH)).status_code == 503
    assert (await transmitter.client.post(transmitter.poll_url, json={}, headers=AUTH)).status_code == 503
    assert transmitter.poll_requests == 0
    transmitter.set_available(True)
    assert (await transmitter.client.get(transmitter.issuer + "/ssf/streams", headers=AUTH)).status_code == 200


async def test_unknown_endpoints_are_not_found(transmitter: TestTransmitter):
    assert (await transmitter.client.get("https://transmitter.example/realms/other/ssf/streams")).status_code == 404
    assert (await transmitter.client.get(transmitter.issuer + "/ssf/nothing", headers=AUTH)).status_code == 404
    assert (await transmitter.client.head(transmitter.issuer + "/ssf/streams", headers=AUTH)).status_code == 405


# -- stream management ------------------------------------------------------------------------------------


async def test_creates_gets_lists_updates_and_deletes_the_stream(transmitter: TestTransmitter):
    streams = transmitter.issuer + "/ssf/streams"
    request = StreamConfiguration.push(
        "https://app.example/ssf/push", "Bearer secret", ["CaepSessionRevoked"], "the app"
    ).claims
    created = await transmitter.client.post(streams, json=request, headers=AUTH)
    assert created.status_code == 201
    stream = created.json()
    stream_id = stream["stream_id"]
    assert stream_id
    assert stream["iss"] == transmitter.issuer
    assert stream["aud"] == [CLIENT_ID + "/" + stream_id]
    assert stream["events_requested"] == [EventTypes.CAEP_SESSION_REVOKED]
    assert stream["events_delivered"] == [EventTypes.CAEP_SESSION_REVOKED]
    assert stream["delivery"] == {"method": PUSH_URI, "endpoint_url": "https://app.example/ssf/push"}
    assert stream["description"] == "the app"
    assert transmitter.streams == [stream]

    listed = await transmitter.client.get(streams, headers=AUTH)
    assert listed.status_code == 200
    assert listed.json() == [stream]
    got = await transmitter.client.get(streams, params={"stream_id": stream_id}, headers=AUTH)
    assert got.status_code == 200
    assert got.json() == stream
    assert (await transmitter.client.get(streams, params={"stream_id": "other"}, headers=AUTH)).status_code == 404

    updated = await transmitter.client.patch(
        streams, json={"stream_id": stream_id, "events_requested": [EventTypes.CAEP_CREDENTIAL_CHANGE]}, headers=AUTH
    )
    assert updated.status_code == 200
    assert updated.json()["stream_id"] == stream_id
    assert updated.json()["events_delivered"] == [EventTypes.CAEP_CREDENTIAL_CHANGE]
    assert updated.json()["description"] == "the app"
    assert len(transmitter.streams) == 1
    put = await transmitter.client.put(streams, json={"stream_id": stream_id, "description": "renamed"}, headers=AUTH)
    assert put.status_code == 200
    assert put.json()["description"] == "renamed"
    assert (await transmitter.client.patch(streams, json={"stream_id": "other"}, headers=AUTH)).status_code == 404

    assert (await transmitter.client.delete(streams, params={"stream_id": "other"}, headers=AUTH)).status_code == 404
    deleted = await transmitter.client.delete(streams, params={"stream_id": stream_id}, headers=AUTH)
    assert deleted.status_code == 204
    assert transmitter.streams == []


async def test_allows_one_stream_per_receiver_like_keycloak(transmitter: TestTransmitter):
    streams = transmitter.issuer + "/ssf/streams"
    assert (
        await transmitter.client.post(streams, json=StreamConfiguration.poll().claims, headers=AUTH)
    ).status_code == 201
    second = await transmitter.client.post(streams, json=StreamConfiguration.poll().claims, headers=AUTH)
    assert second.status_code == 409
    assert second.json() == {"error": "stream_error", "error_description": "Only one stream per receiver is allowed"}
    assert len(transmitter.streams) == 1


async def test_poll_stream_gets_the_poll_endpoint_and_the_configured_issuer(transmitter: TestTransmitter):
    transmitter.set_stream_issuer("https://other.example")
    stream = transmitter.add_stream({"stream_id": "given", "delivery": {"method": POLL_URI}})
    assert stream["stream_id"] == "given"
    assert stream["iss"] == "https://other.example"
    assert stream["delivery"] == {"method": POLL_URI, "endpoint_url": transmitter.poll_url}
    assert stream["events_delivered"] == []
    transmitter.set_stream_issuer("")
    transmitter.reset()
    assert transmitter.add_stream({})["iss"] == transmitter.issuer


async def test_status_verify_and_subject_endpoints(transmitter: TestTransmitter):
    stream_id = transmitter.add_stream(StreamConfiguration.poll().claims)["stream_id"]
    status = await transmitter.client.post(
        transmitter.issuer + "/ssf/status", json={"stream_id": stream_id}, headers=AUTH
    )
    assert status.status_code == 200
    assert status.json() == {"stream_id": stream_id, "status": "enabled"}
    paused = await transmitter.client.post(
        transmitter.issuer + "/ssf/status", json={"stream_id": stream_id, "status": "paused"}, headers=AUTH
    )
    assert paused.json()["status"] == "paused"
    unknown = await transmitter.client.get(transmitter.issuer + "/ssf/status", params={"stream_id": "x"}, headers=AUTH)
    assert unknown.status_code == 404
    assert unknown.json() == {"stream_id": "x", "status": "enabled"}
    assert (await transmitter.client.get(transmitter.issuer + "/ssf/status", headers=AUTH)).status_code == 404

    verify = transmitter.issuer + "/ssf/verify"
    assert (
        await transmitter.client.post(verify, json={"stream_id": stream_id, "state": "s1"}, headers=AUTH)
    ).status_code == 204
    assert (await transmitter.client.post(verify, json={"stream_id": stream_id}, headers=AUTH)).status_code == 204
    assert (await transmitter.client.post(verify, json={"state": {"n": 1}}, headers=AUTH)).status_code == 204
    assert transmitter.verification_requests == ["s1", "", '{"n":1}']

    subject = email("alice@example.com")
    add = await transmitter.client.post(
        transmitter.issuer + "/ssf/subjects:add", json={"stream_id": stream_id, "subject": subject}, headers=AUTH
    )
    assert add.status_code == 200
    remove = await transmitter.client.post(
        transmitter.issuer + "/ssf/subjects:remove", json={"stream_id": stream_id, "subject": subject}, headers=AUTH
    )
    assert remove.status_code == 204
    assert (
        await transmitter.client.post(transmitter.issuer + "/ssf/subjects:add", content=b"", headers=AUTH)
    ).status_code == 200
    assert transmitter.added_subjects == [subject, None]
    assert transmitter.removed_subjects == [subject]
    assert (await transmitter.client.post(verify, content=b"not json", headers=AUTH)).status_code == 204
    assert transmitter.verification_requests[-1] == ""


# -- the poll endpoint --------------------------------------------------------------------------------------


async def test_poll_returns_queued_sets_acks_and_errors_and_pages_by_max_events(transmitter: TestTransmitter):
    first = transmitter.set("CaepSessionRevoked", email("alice@example.com"))
    second = transmitter.set("CaepCredentialChange", email("bob@example.com"))
    third = transmitter.set("RiscAccountDisabled", email("carol@example.com"))
    transmitter.queue_set(first)
    transmitter.queue_set(second)
    transmitter.queue_set_with_jti("custom", third)
    assert transmitter.queued_set_count == 3
    jti = claims_of(first)["jti"]

    page = await transmitter.client.post(
        transmitter.poll_url, json={"maxEvents": 2, "returnImmediately": True}, headers=AUTH
    )
    assert page.status_code == 200
    assert page.json() == {"sets": {jti: first, claims_of(second)["jti"]: second}, "moreAvailable": True}
    assert transmitter.poll_requests == 1
    assert transmitter.last_poll_request == {"maxEvents": 2, "returnImmediately": True}

    acked = await transmitter.client.post(
        transmitter.poll_url,
        json={"ack": [jti, "unknown"], "setErrs": {"custom": {"err": "invalid_request", "description": "bad"}}},
        headers=AUTH,
    )
    assert acked.json() == {"sets": {claims_of(second)["jti"]: second}, "moreAvailable": False}
    assert transmitter.acknowledged_sets == [jti]
    assert transmitter.reported_errors == [ReportedError("custom", "invalid_request", "bad")]
    assert transmitter.queued_set_count == 1

    # queueing again under the same jti replaces the SET
    replaced = transmitter.sign_set(claims_of(second))
    transmitter.queue_set(replaced)
    assert transmitter.queued_set_count == 1
    empty = await transmitter.client.post(transmitter.poll_url, json={"maxEvents": 0}, headers=AUTH)
    assert empty.json() == {"sets": {}, "moreAvailable": True}
    assert transmitter.poll_requests == 3
    # ten by default, more than that stays available
    for _ in range(12):
        transmitter.queue_set(transmitter.set("CaepSessionRevoked", None))
    page = await transmitter.client.post(transmitter.poll_url, content=b"", headers=AUTH)
    assert len(page.json()["sets"]) == 10
    assert page.json()["moreAvailable"] is True
    assert transmitter.last_poll_request == {}


async def test_poll_answers_at_once_without_a_hold_and_is_woken_by_a_queued_set(transmitter: TestTransmitter):
    started = time.monotonic()
    assert (await transmitter.client.post(transmitter.poll_url, json={}, headers=AUTH)).json()["sets"] == {}
    assert time.monotonic() - started < 0.5

    transmitter.set_long_poll_hold(timedelta(seconds=5))
    held = asyncio.ensure_future(transmitter.client.post(transmitter.poll_url, json={}, headers=AUTH))
    await asyncio.sleep(0.02)
    assert not held.done()
    encoded_set = transmitter.set("CaepSessionRevoked", email("alice@example.com"))
    transmitter.queue_set(encoded_set)
    response = await asyncio.wait_for(held, 1)
    assert response.json()["sets"] == {claims_of(encoded_set)["jti"]: encoded_set}
    assert time.monotonic() - started < 2

    # a queued SET is answered at once, returnImmediately as well, and the hold elapses otherwise
    assert (
        await asyncio.wait_for(transmitter.client.post(transmitter.poll_url, json={}, headers=AUTH), 1)
    ).status_code == 200
    transmitter.reset()
    transmitter.set_long_poll_hold(timedelta(milliseconds=50))
    started = time.monotonic()
    assert (
        await transmitter.client.post(transmitter.poll_url, json={"returnImmediately": True}, headers=AUTH)
    ).json() == {
        "sets": {},
        "moreAvailable": False,
    }
    assert time.monotonic() - started < 0.04
    assert (await transmitter.client.post(transmitter.poll_url, json={}, headers=AUTH)).json()["sets"] == {}
    assert time.monotonic() - started >= 0.05


async def test_long_poll_stops_when_the_receiver_gives_up(transmitter: TestTransmitter):
    transmitter.set_long_poll_hold(timedelta(seconds=10))
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.05):
            await transmitter.client.post(transmitter.poll_url, json={}, headers=AUTH)
    assert time.monotonic() - started < 1
    assert transmitter.poll_requests == 1
    # the waiter is gone, a later queue_set wakes nothing stale and the next poll works
    transmitter.queue_set(transmitter.set("CaepSessionRevoked", None))
    assert len((await transmitter.client.post(transmitter.poll_url, json={}, headers=AUTH)).json()["sets"]) == 1


# -- SETs and tokens ----------------------------------------------------------------------------------------


async def test_set_is_a_signed_set_verifiable_with_the_public_jwk(transmitter: TestTransmitter):
    subject = complex_subject(iss_sub(transmitter.issuer, "alice"), opaque("session-1"))
    encoded = transmitter.set("CaepSessionRevoked", subject)
    public = RSAKey.import_key((await transmitter.client.get(transmitter.jwks_url)).json()["keys"][0])
    verified = jws.deserialize_compact(encoded, public, algorithms=["RS256"])
    assert verified.protected == {"alg": "RS256", "kid": "test-key", "typ": SECEVENT_JWT_TYPE}
    claims = json.loads(verified.payload)
    assert claims["iss"] == transmitter.issuer
    assert claims["aud"] == AUDIENCE
    assert claims["sub_id"] == subject
    assert len(claims["jti"]) == 32
    assert abs(claims["iat"] - time.time()) < 5
    payload = claims["events"][EventTypes.CAEP_SESSION_REVOKED]
    assert abs(payload["event_timestamp"] - time.time()) < 5
    assert claims_of(encoded) == claims

    assert transmitter.set_claims("CaepSessionRevoked", None).get("sub_id") is None
    custom = transmitter.set_claims_with_payload(
        EventTypes.RISC_ACCOUNT_DISABLED, email("a@b"), {"reason": "hijacking"}
    )
    assert custom["events"] == {EventTypes.RISC_ACCOUNT_DISABLED: {"reason": "hijacking"}}
    assert transmitter.set_claims_with_payload("CaepSessionRevoked", None, None)["events"] == {
        EventTypes.CAEP_SESSION_REVOKED: {}
    }
    assert transmitter.key is shared_key()
    assert transmitter.signer.key_id == "test-key"
    built = transmitter.signer.sign(new_set(transmitter.issuer).event("CaepSessionRevoked").claims())
    assert jws.deserialize_compact(built, public, algorithms=["RS256"]).protected["typ"] == SECEVENT_JWT_TYPE


def test_access_token_for_is_a_jwt_of_the_identity_provider(transmitter: TestTransmitter):
    issued_at = datetime(2026, 1, 1, tzinfo=UTC)
    token = transmitter.access_token_for("alice", "session-1", issued_at)
    header = jws.extract_compact(token.encode()).protected
    assert header == {"alg": "RS256", "kid": "test-key", "typ": JWT_TYPE}
    claims = claims_of(token)
    assert claims["iss"] == transmitter.issuer
    assert claims["sub"] == "alice"
    assert claims["sid"] == "session-1"
    assert claims["iat"] == int(issued_at.timestamp())
    assert claims["exp"] - time.time() == pytest.approx(300, abs=5)


# -- routing, the sync client, the ASGI application, reset --------------------------------------------------


async def test_client_routes_to_the_transmitter_of_the_host_and_refuses_others(transmitter: TestTransmitter):
    other = TestTransmitter(MetadataLocation.SSF, "other.example")
    both = client_for(transmitter, other)
    assert (await both.get(transmitter.jwks_url)).status_code == 200
    assert (await both.get(other.jwks_url)).status_code == 200
    assert transmitter.requests == 1
    assert other.requests == 1
    with pytest.raises(httpx.ConnectError, match=r"no route to https://unknown\.example") as refused:
        await both.get("https://unknown.example/realms/test/ssf/streams")
    assert transmitter.issuer in str(refused.value)
    assert other.issuer in str(refused.value)
    with pytest.raises(httpx.ConnectError):
        await transmitter.client.get(other.jwks_url)
    with pytest.raises(httpx.ConnectError):
        await transmitter.client.get("http://transmitter.example/realms/test/ssf/streams")
    assert transmitter.client is transmitter.client
    assert transmitter.transport.transmitters == (transmitter,)
    async with httpx.AsyncClient(transport=transmitter.transport) as own:
        assert (await own.get(transmitter.jwks_url)).status_code == 200


async def test_records_the_user_agent_of_the_most_recent_request(transmitter: TestTransmitter):
    await transmitter.client.get(transmitter.jwks_url, headers={"User-Agent": "easyssf-test/1"})
    assert transmitter.last_user_agent == "easyssf-test/1"


def test_sync_client_serves_the_same_endpoints_including_a_held_poll(transmitter: TestTransmitter):
    assert transmitter.sync_client.get(transmitter.jwks_url).status_code == 200
    token = transmitter.sync_client.post(
        transmitter.token_url, data={"grant_type": "client_credentials"}, auth=(CLIENT_ID, CLIENT_SECRET)
    )
    assert token.json()["access_token"] == ACCESS_TOKEN
    transmitter.set_long_poll_hold(timedelta(milliseconds=30))
    started = time.monotonic()
    assert transmitter.sync_client.post(transmitter.poll_url, json={}, headers=AUTH).json()["sets"] == {}
    assert time.monotonic() - started >= 0.03
    transmitter.queue_set(transmitter.set("CaepSessionRevoked", None))
    assert len(transmitter.sync_client.post(transmitter.poll_url, json={}, headers=AUTH).json()["sets"]) == 1
    with pytest.raises(httpx.ConnectError):
        transmitter.sync_client.get("https://unknown.example/")
    assert transmitter.sync_client is transmitter.sync_client


async def test_asgi_application_serves_the_handler(transmitter: TestTransmitter):
    stream_id = transmitter.add_stream(StreamConfiguration.poll().claims)["stream_id"]
    body = json.dumps({"stream_id": stream_id}).encode()
    scope = {
        "type": "http",
        "method": "POST",
        "scheme": "https",
        "path": "/realms/test/ssf/status",
        "query_string": b"",
        "headers": [(b"host", b"transmitter.example"), (b"authorization", b"Bearer " + ACCESS_TOKEN.encode())],
    }
    chunks = [{"type": "http.request", "body": body[:5], "more_body": True}, {"type": "http.request", "body": body[5:]}]
    sent: list[dict] = []

    async def receive() -> dict:
        return chunks.pop(0)

    async def send(message: dict) -> None:
        sent.append(message)

    await transmitter.asgi(scope, receive, send)
    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 200
    assert (b"content-type", b"application/json") in sent[0]["headers"]
    assert json.loads(sent[1]["body"]) == {"stream_id": stream_id, "status": "enabled"}

    # a document by path with the query string and a server tuple instead of a host header
    sent.clear()
    chunks.append({"type": "http.request", "body": b""})
    await transmitter.asgi(
        {
            "type": "http",
            "method": "GET",
            "path": "/realms/test/protocol/openid-connect/certs",
            "query_string": b"a=1",
            "headers": [],
            "server": ("127.0.0.1", 8080),
        },
        receive,
        send,
    )
    assert sent[0]["status"] == 200
    assert json.loads(sent[1]["body"])["keys"][0]["kid"] == "test-key"

    sent.clear()
    chunks.extend([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])
    await transmitter.asgi({"type": "lifespan"}, receive, send)
    assert [message["type"] for message in sent] == ["lifespan.startup.complete", "lifespan.shutdown.complete"]
    with pytest.raises(RuntimeError):
        await transmitter.asgi({"type": "websocket"}, receive, send)


async def test_reset_forgets_streams_sets_and_reports_but_not_documents(transmitter: TestTransmitter):
    transmitter.add_stream(StreamConfiguration.poll().claims)
    transmitter.queue_set(transmitter.set("CaepSessionRevoked", None))
    transmitter.set_long_poll_hold(timedelta(seconds=10))
    transmitter.set_available(False)
    transmitter.set_stream_issuer("https://other.example")
    transmitter.expire_access_tokens()
    await transmitter.client.post(transmitter.issuer + "/ssf/verify", json={"state": "s"}, headers=AUTH)
    requests = transmitter.requests
    transmitter.reset()
    assert transmitter.streams == []
    assert transmitter.queued_set_count == 0
    assert transmitter.verification_requests == []
    assert transmitter.poll_requests == 0
    assert transmitter.requests == requests
    assert transmitter.last_poll_request == {}
    assert (await transmitter.client.post(transmitter.poll_url, json={}, headers=AUTH)).status_code == 200
    assert transmitter.add_stream({})["iss"] == transmitter.issuer
    assert (await transmitter.client.get(transmitter.jwks_url)).status_code == 200
