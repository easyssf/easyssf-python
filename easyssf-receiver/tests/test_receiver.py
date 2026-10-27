"""The configured receiver: SsfReceiverOptionsValidator, SsfTransmitterFactory and the hosting
integration tests of the .NET port, receiver/receiver_test.go of the Go port. The two tests of
the configuration alone are in test_config.py."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from easyssf.core import POLL_URI, Claims, Subject, audiences, event_types, object_member, string_member
from easyssf.core.subjects import complex_subject, iss_sub, opaque
from easyssf.receiver.config import STREAM_MANAGEMENT_RECEIVER, OAuth2Config, ReceiverConfig, default_receiver_config
from easyssf.receiver.errors import ConfigurationError
from easyssf.receiver.event import EventContext, for_event
from easyssf.receiver.poll import InMemoryPollAckStore
from easyssf.receiver.receiver import Receiver, ReceiverDisabledError, ReceiverHealth
from easyssf.receiver.revocation import TokenClaims, is_revoked
from easyssf.receiver.stream import StreamRegistrarState
from easyssf.receiver.transmitter import HealthStatus, Transmitter
from easyssf.testing import (
    ACCESS_TOKEN,
    AUDIENCE,
    CLIENT_ID,
    CLIENT_SECRET,
    MetadataLocation,
    TestTransmitter,
    eventually,
)

SECRET = "Bearer s3cr3t"


class Recorder:
    """Counts the SETs it handled."""

    def __init__(self) -> None:
        self.count = 0

    async def handle(self, context: EventContext) -> None:
        self.count += 1


def alice(transmitter: TestTransmitter) -> Claims:
    return iss_sub(transmitter.issuer, "alice")


def push_config(transmitter: TestTransmitter) -> ReceiverConfig:
    config = default_receiver_config()
    config.transmitter_issuer = transmitter.issuer
    config.expected_audience = AUDIENCE
    config.push.expected_auth_header = SECRET
    return config


async def test_builds_a_push_receiver_and_handles_sets_end_to_end():
    transmitter = TestTransmitter()
    recorder = Recorder()
    receiver = Receiver(
        push_config(transmitter), http_client=transmitter.client, handlers=[for_event("CaepSessionRevoked", recorder)]
    )
    async with receiver:
        assert receiver.started
        assert receiver.push_endpoint_path == "/ssf/push"
        assert len(receiver.transmitters) == 1
        push = receiver.push_handler
        encoded_set = transmitter.set("CaepSessionRevoked", complex_subject(alice(transmitter), opaque("s1")))
        assert (await push.handle("", encoded_set)).status == 401
        assert (await push.handle(SECRET, encoded_set)).status == 202
        assert recorder.count == 1, "handled"
        # the built-in revocation handler filled the store
        token = TokenClaims(issuer=transmitter.issuer, subject="alice", session_id="s1", issued_at=datetime.now(tz=UTC))
        assert await is_revoked(receiver.token_revocation_store, token), "revoked"
        # a duplicate is accepted but not handled again
        assert (await push.handle(SECRET, encoded_set)).status == 202
        assert recorder.count == 1, "duplicate"
        health = await receiver.health()
        assert health.status is HealthStatus.HEALTHY
        assert health.transmitters[0].delivery == "push"
        assert health.transmitters[0].metadata_resolved
        assert health.to_mapping()["transmitters"][0]["name"] == "default"
        assert health.to_mapping()["status"] == "healthy"
    assert not receiver.started
    assert receiver.jti_dedup_store is not None
    assert isinstance(receiver.poll_ack_store, InMemoryPollAckStore)
    assert receiver.config is not None and receiver.processor is not None
    assert receiver.http_client is transmitter.client, "the application's client is used as it is"


async def test_health_is_degraded_until_the_transmitter_was_reached():
    transmitter = TestTransmitter.with_metadata(MetadataLocation.NONE)
    receiver = Receiver(push_config(transmitter), http_client=transmitter.client)
    health = await receiver.health()
    assert isinstance(health, ReceiverHealth)
    assert health.status is HealthStatus.DEGRADED
    assert health.description == "No contact with an SSF transmitter yet"
    assert not health.transmitters[0].metadata_resolved
    assert health.transmitters[0].name == "default"
    # a SET cannot be verified without the keys: 503, the transmitter delivers it again
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter))
    assert (await receiver.push_handler.handle(SECRET, encoded_set)).status == 503


async def test_polling_receiver_registers_its_stream_and_polls():
    transmitter = TestTransmitter()
    config = default_receiver_config()
    config.transmitter_issuer = transmitter.issuer
    config.delivery_method = "poll"
    config.oauth2 = OAuth2Config(token_uri=transmitter.token_url, client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
    config.stream.management = STREAM_MANAGEMENT_RECEIVER
    config.poll.interval = timedelta(milliseconds=100)
    recorder = Recorder()
    receiver = Receiver(config, http_client=transmitter.client, handlers=[recorder])
    await receiver.start()
    await eventually(lambda: len(transmitter.streams) > 0, what="the stream")
    stream = transmitter.streams[0]
    assert string_member(object_member(stream, "delivery"), "method") == POLL_URI, "poll stream"
    # the audience of the stream is the audience the verifier expects
    audience = audiences(stream["aud"])[0]
    claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    claims["aud"] = audience
    transmitter.queue_set(transmitter.sign_set(claims))
    await eventually(lambda: recorder.count == 1, what="the SET")
    await eventually(lambda: len(transmitter.acknowledged_sets) == 1, what="the acknowledgement")
    # a SET for another audience is reported
    transmitter.queue_set(transmitter.set("CaepSessionRevoked", iss_sub(transmitter.issuer, "bob")))
    await eventually(lambda: len(transmitter.reported_errors) == 1, what="the error report")
    assert transmitter.reported_errors[0].code == "invalid_audience"
    health = await receiver.health()
    assert health.status is HealthStatus.HEALTHY, health
    assert health.description == "In contact with the SSF transmitter(s)"
    assert health.transmitters[0].delivery == "poll"
    assert health.transmitters[0].stream_id != ""
    assert health.transmitters[0].last_successful_poll_at is not None
    assert "lastSuccessfulPollAt" in health.to_mapping()["transmitters"][0]
    await receiver.stop()
    poller = receiver.transmitters[0].poller
    assert poller is not None and not poller.is_running, "stopped"


async def test_sets_are_left_for_redelivery_until_the_stream_tells_the_audience():
    transmitter = TestTransmitter()
    transmitter.set_available(False)
    config = default_receiver_config()
    config.transmitter_issuer = transmitter.issuer
    config.transmitter_access_token = ACCESS_TOKEN
    config.stream.management = STREAM_MANAGEMENT_RECEIVER
    config.push.delivery_endpoint_url = "https://app.example/ssf/push"
    receiver = Receiver(config, http_client=transmitter.client)
    push = receiver.push_handler
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter))
    assert (await push.handle("", encoded_set)).status == 503, "the stream is not registered yet"
    transmitter.set_available(True)
    async with receiver:
        await eventually(lambda: len(transmitter.streams) > 0, what="the stream")
        assert (await push.handle("", encoded_set)).status == 400, "wrong audience now that the stream tells it"
        claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
        claims["aud"] = audiences(transmitter.streams[0]["aud"])[0]
        assert (await push.handle("", transmitter.sign_set(claims))).status == 202, "accepted"


async def test_customizer_replaces_parts_before_the_transmitter_is_built():
    transmitter = TestTransmitter()
    seen: list[str] = []

    def customize(built: Transmitter) -> None:
        seen.append(built.name)
        built.push_authorization_header = "Bearer custom"

    receiver = Receiver(push_config(transmitter), http_client=transmitter.client, transmitter_customizers=[customize])
    assert seen == ["default"]
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter))
    assert (await receiver.push_handler.handle("Bearer custom", encoded_set)).status == 202, "custom header"


async def test_session_terminator_is_called_for_session_events():
    transmitter = TestTransmitter()
    terminated: list[Subject] = []

    async def terminate(subject: Subject) -> int:
        terminated.append(subject)
        return 1

    receiver = Receiver(push_config(transmitter), http_client=transmitter.client, session_terminator=terminate)
    encoded_set = transmitter.set("CaepSessionRevoked", complex_subject(alice(transmitter), opaque("s1")))
    assert (await receiver.push_handler.handle(SECRET, encoded_set)).status == 202
    assert len(terminated) == 1 and terminated[0].session_id == "s1", "terminated"


async def test_user_agent_is_sent_when_configured():
    transmitter = TestTransmitter()
    config = push_config(transmitter)
    config.http.user_agent = "my-app/1.0"
    client = transmitter.client
    receiver = Receiver(config, http_client=client)
    await receiver.push_handler.handle(SECRET, transmitter.set("CaepSessionRevoked", alice(transmitter)))
    assert transmitter.last_user_agent == "my-app/1.0"
    assert transmitter.requests == 2, "metadata and JWK Set, through the application's client"
    # the application's client is not changed
    assert client.headers.get("User-Agent", "").startswith("python-httpx")
    assert receiver.http_client is not client


async def test_receiver_registers_the_aliases_only_after_the_whole_configuration_passed():
    transmitter = TestTransmitter()
    config = push_config(transmitter)
    config.event_aliases = {"AcmeLoginRcv": "https://events.acme.example/login"}
    config.push.endpoint_path = "no-slash"
    with pytest.raises(ConfigurationError, match=r"push\.endpoint-path"):
        Receiver(config, http_client=transmitter.client)
    assert not event_types.is_alias("AcmeLoginRcv"), "a failed validation registered the alias"
    config.push.endpoint_path = "/ssf/push"
    Receiver(config, http_client=transmitter.client)
    assert event_types.resolve("AcmeLoginRcv") == "https://events.acme.example/login", (
        "the receiver registers the aliases"
    )


def test_disabled_receiver_is_refused():
    config = default_receiver_config()
    config.enabled = False
    with pytest.raises(ReceiverDisabledError):
        Receiver(config)
    with pytest.raises(ConfigurationError):
        Receiver(default_receiver_config())


async def test_receiver_starts_again_after_the_context_of_start_was_cancelled():
    # there is no context to cancel in asyncio: stop ends the work of start, and start works again
    transmitter = TestTransmitter()
    config = default_receiver_config()
    config.transmitter_issuer = transmitter.issuer
    config.transmitter_access_token = ACCESS_TOKEN
    config.stream.management = STREAM_MANAGEMENT_RECEIVER
    config.stream.events_requested = ["CaepSessionRevoked"]
    config.push.delivery_endpoint_url = "https://app.example/ssf/push"
    config.push.expected_auth_header = SECRET
    receiver = Receiver(config, http_client=transmitter.client)
    registrar = receiver.transmitters[0].registrar
    assert registrar is not None
    await receiver.start()
    await receiver.start()  # a second start while started does nothing
    await eventually(lambda: registrar.state is StreamRegistrarState.REGISTERED, what="the stream")
    await receiver.stop()
    await eventually(lambda: not registrar.is_running, what="the registrar to end")
    transmitter.set_available(False)
    await receiver.start()
    assert registrar.is_running, "not started again"
    await receiver.stop()
    assert not registrar.is_running, "not stopped"


async def test_receiver_without_a_given_client_makes_its_own():
    transmitter = TestTransmitter()
    receiver = Receiver(push_config(transmitter))
    assert isinstance(receiver.http_client, httpx.AsyncClient)
    assert receiver.transmitter("default") is receiver.transmitters[0]
    assert receiver.transmitter("other") is None
    assert receiver.transmitter_by_issuer(transmitter.issuer) is receiver.transmitters[0]
    assert receiver.name_of(transmitter.issuer) == "default"
    assert receiver.name_of("https://unknown.example") == "https://unknown.example"
    assert "default" in repr(receiver)
    await receiver.http_client.aclose()
