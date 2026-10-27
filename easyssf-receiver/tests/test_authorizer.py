"""receiver/authorizer_test.go of the Go port: the authorizers and the retries of the calls to the
transmitter."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from easyssf.core import StreamConfiguration
from easyssf.receiver.authorizer import (
    Authorizer,
    AuthorizerFunc,
    Authorizers,
    BearerToken,
    Endpoint,
    EndpointHeaders,
    RetryOptions,
    StaticHeaders,
    default_retry_options,
    endpoint_of,
    retry_after,
)
from easyssf.receiver.config import RetryConfig, default_receiver_config
from easyssf.receiver.errors import TransmitterUnavailableError
from easyssf.receiver.receiver import Receiver
from easyssf.receiver.stream import StreamClient, StreamError, stream_status_of
from easyssf.receiver.transmitter import (
    ClientCredentialsTokenProvider,
    FixedToken,
    HttpResponse,
    MetadataResolver,
    UriPolicy,
    get_json,
)
from easyssf.testing import ACCESS_TOKEN, AUDIENCE, CLIENT_ID, CLIENT_SECRET, TestTransmitter


class FlakyTransport(httpx.AsyncBaseTransport):
    """Fails the first ``failures`` requests with the status, or a connection error if the status
    is 0, and records every request that reaches it."""

    def __init__(self, next_transport: httpx.AsyncBaseTransport, status: int, failures: int) -> None:
        self.next = next_transport
        self.status = status
        self.failures = failures
        self.headers: dict[str, str] = {}
        self.attempts = 0
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.attempts += 1
        self.requests.append(request)
        if self.attempts <= self.failures:
            if self.status == 0:
                raise httpx.ConnectError("connection refused", request=request)
            return httpx.Response(self.status, headers=self.headers, request=request)
        return await self.next.handle_async_request(request)


def flaky(transmitter: TestTransmitter, status: int, failures: int) -> tuple[FlakyTransport, httpx.AsyncClient]:
    transport = FlakyTransport(transmitter.transport, status, failures)
    return transport, httpx.AsyncClient(transport=transport)


def quick_retry() -> RetryOptions:
    return RetryOptions(max_retries=2, initial_backoff=timedelta(milliseconds=1), max_backoff=timedelta(milliseconds=5))


def metadata_resolver(transmitter: TestTransmitter, client: httpx.AsyncClient | None = None) -> MetadataResolver:
    return MetadataResolver(transmitter.issuer, None, client or transmitter.client, UriPolicy())


def token_provider(transmitter: TestTransmitter) -> ClientCredentialsTokenProvider:
    return ClientCredentialsTokenProvider(transmitter.client, transmitter.token_url, CLIENT_ID, CLIENT_SECRET)


def push_stream(*events: str) -> StreamConfiguration:
    return StreamConfiguration.push("https://app.example/ssf/push", "Bearer s3cr3t", events, "test stream")


async def test_retries_management_call_that_fails_with_503():
    transmitter = TestTransmitter()
    transport, client = flaky(transmitter, 503, 2)
    streams = StreamClient(metadata_resolver(transmitter), client, FixedToken(ACCESS_TOKEN), retry=quick_retry())
    await streams.streams()
    assert transport.attempts == 3


async def test_retries_management_call_that_fails_with_connection_error():
    transmitter = TestTransmitter()
    transport, client = flaky(transmitter, 0, 1)
    streams = StreamClient(metadata_resolver(transmitter), client, FixedToken(ACCESS_TOKEN), retry=quick_retry())
    await streams.streams()
    assert transport.attempts == 2


async def test_gives_up_after_max_retries():
    transmitter = TestTransmitter()
    transport, client = flaky(transmitter, 502, 10)
    streams = StreamClient(metadata_resolver(transmitter), client, FixedToken(ACCESS_TOKEN), retry=quick_retry())
    with pytest.raises(StreamError) as raised:
        await streams.streams()
    assert raised.value.status == 502
    assert stream_status_of(raised.value) == 502
    assert transport.attempts == 3


async def test_does_not_retry_client_errors():
    transmitter = TestTransmitter()
    transport, client = flaky(transmitter, 400, 10)
    streams = StreamClient(metadata_resolver(transmitter), client, FixedToken(ACCESS_TOKEN), retry=quick_retry())
    with pytest.raises(StreamError):
        await streams.streams()
    assert transport.attempts == 1


async def test_does_not_retry_without_retry_options():
    transmitter = TestTransmitter()
    transport, client = flaky(transmitter, 503, 1)
    streams = StreamClient(metadata_resolver(transmitter), client, FixedToken(ACCESS_TOKEN))
    with pytest.raises(StreamError) as raised:
        await streams.streams()
    assert stream_status_of(raised.value) == 503
    assert transport.attempts == 1


async def test_retry_waits_for_retry_after_capped_at_max_backoff():
    transmitter = TestTransmitter()
    transport, client = flaky(transmitter, 429, 1)
    transport.headers["Retry-After"] = "3600"
    retry = RetryOptions(
        max_retries=1, initial_backoff=timedelta(milliseconds=1), max_backoff=timedelta(milliseconds=20)
    )
    streams = StreamClient(metadata_resolver(transmitter), client, FixedToken(ACCESS_TOKEN), retry=retry)
    started = time.monotonic()
    await streams.streams()
    elapsed = time.monotonic() - started
    assert 0.02 <= elapsed <= 2, f"waited {elapsed}"


async def test_retry_stops_when_the_context_is_cancelled():
    transmitter = TestTransmitter()
    transport, client = flaky(transmitter, 503, 10)
    retry = RetryOptions(max_retries=10, initial_backoff=timedelta(hours=1), max_backoff=timedelta(hours=1))
    streams = StreamClient(metadata_resolver(transmitter), client, FixedToken(ACCESS_TOKEN), retry=retry)
    # the cancellation of the calling task plays the cancelled context of the Go port
    with pytest.raises(asyncio.TimeoutError):
        async with asyncio.timeout(0.02):
            await streams.streams()
    assert transport.attempts == 1


async def test_metadata_and_keys_are_fetched_again_after_transient_failure():
    from easyssf.receiver.jwks import HttpJwkSetSource

    transmitter = TestTransmitter()
    transport, client = flaky(transmitter, 504, 1)
    metadata = MetadataResolver(transmitter.issuer, None, client, UriPolicy(), retry=quick_retry())
    resolved = await metadata.resolve()
    assert transport.attempts == 2
    assert resolved.jwks_uri is not None
    # the JWK Set source fetches through get_json, the receiver wires it so
    keys = HttpJwkSetSource(
        client, resolved.jwks_uri, fetch=lambda url: get_json(client, url, retry=quick_retry(), endpoint=Endpoint.JWKS)
    )
    transport.attempts, transport.failures = 0, 1
    await keys.jwk_set(False)
    assert transport.attempts == 2
    assert transport.requests[-1].headers["Accept"] == "application/json"
    assert endpoint_of(transport.requests[-1]) == Endpoint.JWKS


async def test_static_headers_are_sent_with_every_call():
    transmitter = TestTransmitter()
    transport, client = flaky(transmitter, 0, 0)
    metadata = MetadataResolver(
        transmitter.issuer, None, client, UriPolicy(), authorizer=StaticHeaders({"X-Api-Key": "k3y"})
    )
    streams = StreamClient(metadata, client, Authorizers(StaticHeaders({"X-Api-Key": "k3y"}), FixedToken(ACCESS_TOKEN)))
    await streams.streams()
    assert len(transport.requests) == 2
    for request in transport.requests:
        assert request.headers.get("X-Api-Key") == "k3y", f"{request.method} {request.url} lacks the header"
    assert transport.requests[1].headers.get("Authorization", "").startswith("Bearer ")


async def test_endpoint_headers_reach_only_their_endpoint():
    transmitter = TestTransmitter()
    transport, client = flaky(transmitter, 0, 0)
    streams = StreamClient(
        metadata_resolver(transmitter, client),
        client,
        Authorizers(EndpointHeaders({Endpoint.STATUS: {"X-Status": "yes"}}), FixedToken(ACCESS_TOKEN)),
    )
    created = await streams.create_stream(push_stream("CaepSessionRevoked"))
    await streams.status(created.stream_id)
    with_header = [request.url.path for request in transport.requests if request.headers.get("X-Status")]
    assert len(with_header) == 1
    assert with_header[0].endswith("/ssf/status")


async def test_authorizer_chain_invalidates_the_token_on_401():
    transmitter = TestTransmitter()
    streams = StreamClient(
        metadata_resolver(transmitter),
        transmitter.client,
        Authorizers(StaticHeaders({"X-Tenant": "acme"}), BearerToken(token_provider(transmitter))),
    )
    await streams.streams()
    transmitter.expire_access_tokens()
    await streams.streams()
    assert transmitter.token_requests == 2


async def test_authorizer_func_sees_the_endpoint():
    transmitter = TestTransmitter()
    seen: list[str] = []
    record = AuthorizerFunc(lambda request: seen.append(endpoint_of(request)))
    metadata = MetadataResolver(transmitter.issuer, None, transmitter.client, UriPolicy(), authorizer=record)
    streams = StreamClient(metadata, transmitter.client, Authorizers(record, FixedToken(ACCESS_TOKEN)))
    await streams.streams()
    assert seen == [Endpoint.METADATA, Endpoint.CONFIGURATION]


async def test_async_authorizer_func_is_awaited():
    transmitter = TestTransmitter()

    async def authorize(request: httpx.Request) -> None:
        await asyncio.sleep(0)
        request.headers["Authorization"] = "Bearer " + ACCESS_TOKEN

    streams = StreamClient(metadata_resolver(transmitter), transmitter.client, AuthorizerFunc(authorize))
    assert await streams.streams() == []
    assert isinstance(AuthorizerFunc(authorize), Authorizer)


async def test_bearer_token_of_a_provider_without_token_sends_nothing():
    transmitter = TestTransmitter()

    class Empty:
        async def access_token(self) -> str:
            return ""

    transport, client = flaky(transmitter, 0, 0)
    metadata = MetadataResolver(transmitter.issuer, None, client, UriPolicy(), authorizer=BearerToken(Empty()))
    await metadata.resolve()
    assert "Authorization" not in transport.requests[0].headers


async def test_token_provider_failure_is_reported_as_unavailable():
    transmitter = TestTransmitter()
    transmitter.set_available(False)
    streams = StreamClient(metadata_resolver(transmitter), transmitter.client, token_provider(transmitter))
    with pytest.raises(StreamError) as raised:
        await streams.streams()
    assert stream_status_of(raised.value) == 0
    assert TransmitterUnavailableError.of(raised.value) is not None


async def test_configured_headers_are_sent_to_the_transmitter():
    transmitter = TestTransmitter()
    transport, client = flaky(transmitter, 0, 0)
    config = default_receiver_config()
    config.transmitter_issuer = transmitter.issuer
    config.transmitter_access_token = ACCESS_TOKEN
    config.headers = {"X-Api-Key": "k3y"}
    config.expected_audience = AUDIENCE
    config.push.expected_auth_header = "Bearer s3cr3t"
    receiver = Receiver(config, http_client=client)
    stream_client = receiver.transmitters[0].stream_client
    assert stream_client is not None
    await stream_client.streams()
    assert len(transport.requests) == 2, "metadata and the configuration endpoint"
    for request in transport.requests:
        assert request.headers.get("X-Api-Key") == "k3y", f"{request.url} lacks the header"
    assert transport.requests[1].headers.get("Authorization") == "Bearer " + ACCESS_TOKEN


def test_retry_options_from_config_and_defaults():
    options = RetryOptions.from_config(RetryConfig())
    assert options == default_retry_options()
    assert options.max_retries == 2
    assert options.initial_backoff == timedelta(milliseconds=250)
    assert options.max_backoff == timedelta(seconds=5)
    for status in (408, 429, 500, 502, 503, 504):
        assert options.is_retryable(status)
    assert not options.is_retryable(400)
    assert not options.is_retryable(401)
    custom = RetryOptions(max_retries=1, retryable_statuses=(418,))
    assert custom.is_retryable(418)
    assert not custom.is_retryable(503)
    assert RetryOptions().max_retries == 0


def test_retry_after_reads_seconds_and_http_dates():
    def response(value: str | None) -> HttpResponse:
        headers = httpx.Headers({"Retry-After": value} if value is not None else {})
        return HttpResponse(429, headers, b"")

    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    assert retry_after(response(None)) is None
    assert retry_after(response("")) is None
    assert retry_after(response("120")) == timedelta(seconds=120)
    assert retry_after(response(" 5 ")) == timedelta(seconds=5)
    assert retry_after(response("-1")) is None
    assert retry_after(response("soon")) is None
    assert retry_after(response("Thu, 01 Jan 2026 12:01:30 GMT"), now) == timedelta(seconds=90)
    assert retry_after(response("Thu, 01 Jan 2026 11:00:00 GMT"), now) == timedelta(0)
