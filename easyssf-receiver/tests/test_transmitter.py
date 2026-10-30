"""SsfTransmittersTests and SsfTransmitterTests of the Java library, receiver/transmitter_test.go
of the Go port: the URI policy, the metadata locations, redirects, the client credentials token
provider, and the transmitters of a configured receiver."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from urllib.parse import quote

import httpx
import pytest

from easyssf.core import PUSH_URI, SPEC_VERSION_1_0, StreamConfiguration
from easyssf.core.subjects import iss_sub
from easyssf.receiver.authorizer import default_retry_options
from easyssf.receiver.config import default_receiver_config, default_transmitter_config
from easyssf.receiver.dedup import InMemoryJtiDedupStore
from easyssf.receiver.errors import ConfigurationError, ErrorCode, TransmitterUnavailableError
from easyssf.receiver.jwks import HttpJwkSetSource
from easyssf.receiver.poll import Poller, default_poller_options
from easyssf.receiver.processor import Processor
from easyssf.receiver.receiver import Receiver
from easyssf.receiver.stream import ReceiverStream, StreamClient, StreamError, StreamRegistrar, StreamRegistrarState
from easyssf.receiver.transmitter import (
    MAX_RESPONSE_SIZE,
    ClientCredentialsTokenProvider,
    FixedToken,
    HealthStatus,
    MetadataResolver,
    ResponseTooLargeError,
    Transmitter,
    UriPolicy,
    UriPolicyError,
    default_client_credentials_options,
    derive_metadata_urls,
)
from easyssf.receiver.verifier import JwtVerifier, default_verifier_options
from easyssf.testing import (
    ACCESS_TOKEN,
    AUDIENCE,
    CLIENT_ID,
    CLIENT_SECRET,
    ManualClock,
    MetadataLocation,
    TestTransmitter,
    client_for,
    eventually,
)


def test_inserts_well_known_path_between_host_and_issuer_path():
    assert derive_metadata_urls("https://idp.example/realms/demo/") == [
        "https://idp.example/.well-known/ssf-configuration/realms/demo",
        "https://idp.example/realms/demo/.well-known/ssf-configuration",
    ]
    assert derive_metadata_urls("https://idp.example") == ["https://idp.example/.well-known/ssf-configuration"]
    for relative in ("/realms/demo", "idp.example"):
        with pytest.raises(UriPolicyError):
            derive_metadata_urls(relative)


def test_uri_policy_requires_https_except_on_loopback():
    policy = UriPolicy()
    assert policy.check_issuer("https://idp.example/realms/demo").path == "/realms/demo"
    with pytest.raises(UriPolicyError, match="must use https"):
        policy.check_issuer("http://idp.example/realms/demo")
    for issuer in (
        "http://localhost:8080/realms/demo",
        "http://127.0.0.1:8080/x",
        "http://[::1]:8080/x",
        "http://app.localhost/x",
    ):
        policy.check_issuer(issuer)
    insecure = UriPolicy(allow_insecure_http=True)
    insecure.check_issuer("http://idp.example/realms/demo")
    with pytest.raises(UriPolicyError):
        insecure.check_issuer("ftp://idp.example/realms/demo")
    for bad in (
        "https://idp.example/x?y=1",
        "https://idp.example/x#frag",
        "https://",
        "mailto:alice@example.com",
        "not a uri",
    ):
        with pytest.raises(UriPolicyError):
            policy.check_issuer(bad)
    # endpoints follow the same rules but may have a query
    policy.check_endpoint("https://idp.example/jwks?x=1", "The JWK Set URL")
    with pytest.raises(UriPolicyError, match="fragment"):
        policy.check_endpoint("https://idp.example/jwks#f", "The JWK Set URL")
    with pytest.raises(UriPolicyError):
        policy.check_endpoint("http://idp.example/jwks", "The JWK Set URL")
    policy.check_endpoint("http://localhost/jwks", "The JWK Set URL")
    # a policy error is a ValueError as well
    with pytest.raises(ValueError, match="https"):
        policy.check_endpoint("http://idp.example/jwks", "The JWK Set URL")


def test_metadata_resolver_checks_issuer_and_metadata_url():
    transmitter = TestTransmitter()
    with pytest.raises(UriPolicyError):
        MetadataResolver("http://idp.example", None, transmitter.client, UriPolicy())
    with pytest.raises(UriPolicyError):
        MetadataResolver(transmitter.issuer, "http://idp.example/meta", transmitter.client, UriPolicy())
    resolver = MetadataResolver(transmitter.issuer, None, transmitter.client)
    assert resolver.metadata_urls == derive_metadata_urls(transmitter.issuer)
    assert resolver.resolved is None
    explicit = MetadataResolver(transmitter.issuer, "https://transmitter.example/meta", transmitter.client)
    assert explicit.metadata_urls == ["https://transmitter.example/meta"]


async def test_metadata_is_resolved_once_and_cached():
    transmitter = TestTransmitter()
    resolver = MetadataResolver(transmitter.issuer, None, transmitter.client)
    metadata = await resolver.resolve()
    assert metadata.issuer == transmitter.issuer
    assert metadata.jwks_uri == transmitter.jwks_url
    assert resolver.resolved is metadata
    assert await resolver.resolve() is metadata
    assert transmitter.requests == 1


async def test_metadata_resolution_fails_as_unavailable_and_is_tried_again_later():
    transmitter = TestTransmitter()
    transmitter.remove_document("/.well-known/ssf-configuration/realms/test")
    resolver = MetadataResolver(transmitter.issuer, None, transmitter.client)
    with pytest.raises(TransmitterUnavailableError, match="could not resolve SSF transmitter metadata"):
        await resolver.resolve()
    assert resolver.resolved is None
    from easyssf.testing import MetadataLocation

    transmitter.publish_metadata(MetadataLocation.SSF)
    assert (await resolver.resolve()).issuer == transmitter.issuer


async def test_metadata_with_another_issuer_is_refused():
    transmitter = TestTransmitter()
    transmitter.publish_document(
        "/.well-known/ssf-configuration/realms/test",
        '{"issuer": "https://other.example", "jwks_uri": "' + transmitter.jwks_url + '"}',
    )
    resolver = MetadataResolver(transmitter.issuer, None, transmitter.client)
    with pytest.raises(TransmitterUnavailableError, match="does not match"):
        await resolver.resolve()


async def test_metadata_with_insecure_endpoint_is_refused_unless_allowed():
    transmitter = TestTransmitter()
    transmitter.publish_document(
        "/.well-known/ssf-configuration/realms/test",
        '{"issuer": "' + transmitter.issuer + '", "jwks_uri": "http://transmitter.example/jwks"}',
    )
    strict = MetadataResolver(transmitter.issuer, None, transmitter.client)
    with pytest.raises(TransmitterUnavailableError, match="jwks_uri must use https"):
        await strict.resolve()
    lenient = MetadataResolver(transmitter.issuer, None, transmitter.client, UriPolicy(allow_insecure_http=True))
    assert (await lenient.resolve()).jwks_uri == "http://transmitter.example/jwks"


async def test_client_credentials_token_is_cached_until_shortly_before_it_expires():
    test = TestTransmitter()
    clock = ManualClock()
    options = replace(default_client_credentials_options(), clock=clock, scopes=("ssf.read",))
    provider = ClientCredentialsTokenProvider(test.client, test.token_url, CLIENT_ID, CLIENT_SECRET, options)
    assert await provider.access_token() == ACCESS_TOKEN
    # the transmitter issues tokens for 300 seconds, renewed 30 seconds ahead
    clock.advance(timedelta(seconds=260))
    await provider.access_token()
    assert test.token_requests == 1, "cached"
    clock.advance(timedelta(seconds=20))
    await provider.access_token()
    assert test.token_requests == 2, "renewed ahead of the expiry"
    provider.invalidate()
    await provider.access_token()
    assert test.token_requests == 3, "invalidated"
    # client_secret_post and wrong credentials
    options = replace(options, authenticate_with_request_body=True)
    post = ClientCredentialsTokenProvider(test.client, test.token_url, CLIENT_ID, CLIENT_SECRET, options)
    assert await post.access_token() == ACCESS_TOKEN
    wrong = ClientCredentialsTokenProvider(test.client, test.token_url, CLIENT_ID, "nope", options)
    with pytest.raises(TransmitterUnavailableError):
        await wrong.access_token()
    assert "nope" not in repr(wrong)
    assert "nope" not in repr(provider)


async def test_token_provider_reports_unreachable_token_endpoint_as_unavailable():
    test = TestTransmitter()
    provider = ClientCredentialsTokenProvider(test.client, "https://nowhere.example/token", CLIENT_ID, CLIENT_SECRET)
    with pytest.raises(TransmitterUnavailableError):
        await provider.access_token()
    test.set_available(False)
    unavailable = ClientCredentialsTokenProvider(test.client, test.token_url, CLIENT_ID, CLIENT_SECRET)
    with pytest.raises(TransmitterUnavailableError, match="503"):
        await unavailable.access_token()


# -- redirects ----------------------------------------------------------------------------------------


class Redirecting(httpx.AsyncBaseTransport):
    """Answers requests under /redirect/ with a 302 to the location the query names; everything
    else goes to the transmitter."""

    def __init__(self, next_transport: httpx.AsyncBaseTransport) -> None:
        self.next = next_transport

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if not request.url.path.startswith("/redirect/"):
            return await self.next.handle_async_request(request)
        return httpx.Response(302, headers={"Location": request.url.params.get("to", "")}, request=request)


METADATA_PATH = "/.well-known/ssf-configuration/realms/test"


def redirecting_resolver(transmitter: TestTransmitter, to: str, policy: UriPolicy) -> MetadataResolver:
    client = httpx.AsyncClient(transport=Redirecting(transmitter.transport))
    metadata_url = "https://transmitter.example/redirect/metadata?to=" + quote(to, safe="")
    return MetadataResolver(transmitter.issuer, metadata_url, client, policy)


async def test_follows_redirect_to_the_same_host_over_https():
    transmitter = TestTransmitter()
    resolver = redirecting_resolver(transmitter, "https://transmitter.example" + METADATA_PATH, UriPolicy())
    metadata = await resolver.resolve()
    assert metadata.issuer == transmitter.issuer


async def test_refuses_redirect_from_https_to_http():
    transmitter = TestTransmitter()
    resolver = redirecting_resolver(transmitter, "http://transmitter.example" + METADATA_PATH, UriPolicy())
    with pytest.raises(TransmitterUnavailableError, match="another origin"):
        await resolver.resolve()


def test_redirect_stays_within_the_origin():
    policy = UriPolicy(allow_insecure_http=True)
    for from_, to, followed in (
        ("https://transmitter.example/a", "https://transmitter.example/b", True),
        ("https://transmitter.example:443/a", "https://transmitter.example/b", True),
        ("https://transmitter.example/a", "https://transmitter.example:443/b", True),
        ("https://transmitter.example/a", "https://TRANSMITTER.example/b", True),
        ("http://transmitter.example:8080/a", "http://transmitter.example:8080/b", True),
        ("https://transmitter.example/a", "https://transmitter.example:8443/b", False),
        ("https://transmitter.example:8443/a", "https://transmitter.example/b", False),
        ("https://transmitter.example/a", "http://transmitter.example/b", False),
        ("http://transmitter.example/a", "https://transmitter.example/b", False),
        ("https://transmitter.example/a", "https://other.example/b", False),
        ("https://transmitter.example/a", "https://sub.transmitter.example/b", False),
    ):
        try:
            policy.check_redirect(to, from_)
            was_followed = True
        except UriPolicyError:
            was_followed = False
        assert was_followed == followed, f"{from_} -> {to}: followed {was_followed}, want {followed}"
    with pytest.raises(UriPolicyError, match="more than"):
        policy.check_redirect("https://transmitter.example/b", "https://transmitter.example/a", followed=10)
    assert UriPolicy.same_origin("https://a.example", "https://a.example:443/x")
    assert UriPolicy.effective_port("https://a.example") == "443"
    assert UriPolicy.effective_port("http://a.example") == "80"
    assert UriPolicy.effective_port("http://a.example:8080") == "8080"
    assert UriPolicy.effective_port("ftp://a.example") == ""
    assert UriPolicy.is_insecure("http://a.example") and not UriPolicy.is_insecure("https://a.example")
    assert UriPolicy.is_loopback("http://[::1]:8080/x") and not UriPolicy.is_loopback("http://a.example")


@pytest.mark.parametrize(
    "url",
    [
        "http://127.attacker.example/x",
        "http://127.0.0.1.attacker.example/x",
        "http://localhost.attacker.example/x",
        "http://xlocalhost/x",
        "http://127/x",
        "http://[::2]/x",
        "http://10.0.0.1/x",
    ],
)
def test_host_that_merely_looks_like_loopback_must_use_https(url: str):
    # 127.attacker.example resolves wherever its owner points it: no exemption from https
    assert not UriPolicy.is_loopback(url)
    with pytest.raises(UriPolicyError, match="must use https"):
        UriPolicy().check_issuer(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/x",
        "http://127.255.255.254:8080/x",
        "http://[::1]/x",
        "http://[0:0:0:0:0:0:0:1]/x",
        "http://LOCALHOST/x",
        "http://app.localhost/x",
    ],
)
def test_loopback_addresses_are_exempt_from_https(url: str):
    assert UriPolicy.is_loopback(url)
    UriPolicy().check_issuer(url)


async def test_refuses_redirect_to_another_port_of_the_same_host():
    transmitter = TestTransmitter()
    resolver = redirecting_resolver(transmitter, "https://transmitter.example:8443" + METADATA_PATH, UriPolicy())
    with pytest.raises(TransmitterUnavailableError, match="another origin"):
        await resolver.resolve()


async def test_follows_redirect_from_the_explicit_default_port():
    transmitter = TestTransmitter()
    client = httpx.AsyncClient(transport=Redirecting(transmitter.transport))
    metadata_url = "https://transmitter.example:443/redirect/metadata?to=" + quote(
        "https://transmitter.example" + METADATA_PATH, safe=""
    )
    resolver = MetadataResolver(transmitter.issuer, metadata_url, client, UriPolicy())
    assert (await resolver.resolve()).issuer == transmitter.issuer


async def test_refuses_redirect_to_another_host():
    transmitter = TestTransmitter()
    resolver = redirecting_resolver(
        transmitter, "https://other.example" + METADATA_PATH, UriPolicy(allow_insecure_http=True)
    )
    with pytest.raises(TransmitterUnavailableError, match="another origin"):
        await resolver.resolve()


async def test_redirect_check_ignores_the_clients_own_policy():
    transmitter = TestTransmitter()
    # a client that would follow every redirect itself: the receiver never lets it
    client = httpx.AsyncClient(transport=Redirecting(transmitter.transport), follow_redirects=True)
    metadata_url = "https://transmitter.example/redirect/metadata?to=" + quote(
        "http://transmitter.example" + METADATA_PATH, safe=""
    )
    resolver = MetadataResolver(transmitter.issuer, metadata_url, client, UriPolicy())
    with pytest.raises(TransmitterUnavailableError, match="another origin"):
        await resolver.resolve()
    assert client.follow_redirects is True, "the caller's client was changed"


async def test_stream_management_calls_refuse_redirect_to_http():
    transmitter = TestTransmitter()
    client = httpx.AsyncClient(transport=Redirecting(transmitter.transport))
    # the configuration endpoint of the metadata redirects to http
    configuration_endpoint = "https://transmitter.example/redirect/streams?to=" + quote(
        "http://transmitter.example/realms/test/ssf/streams", safe=""
    )
    import json

    transmitter.publish_document(
        METADATA_PATH,
        json.dumps(
            {
                "issuer": transmitter.issuer,
                "jwks_uri": transmitter.jwks_url,
                "spec_version": SPEC_VERSION_1_0,
                "delivery_methods_supported": [PUSH_URI],
                "configuration_endpoint": configuration_endpoint,
            }
        ),
    )
    resolver = MetadataResolver(transmitter.issuer, None, client, UriPolicy())
    streams = StreamClient(resolver, client, FixedToken(ACCESS_TOKEN))
    with pytest.raises(StreamError, match="another origin"):
        await streams.streams()


# -- the Transmitter ----------------------------------------------------------------------------------


async def test_transmitter_reports_its_health_from_what_it_knows():
    test = TestTransmitter()
    resolver = MetadataResolver(test.issuer, None, test.client)
    transmitter = Transmitter(
        name="default", issuer=test.issuer, metadata=resolver, push_authorization_header="Bearer x"
    )
    assert str(transmitter) == f"default ({test.issuer})"
    assert "Bearer x" not in repr(transmitter)
    assert transmitter.critical_subject_members == []
    health = await transmitter.health()
    assert health.status is HealthStatus.DEGRADED
    assert health.delivery == "push"
    assert not health.metadata_resolved
    await resolver.resolve()
    health = await transmitter.health()
    assert health.status is HealthStatus.HEALTHY
    assert health.metadata_resolved
    assert health.jwks_uri == test.jwks_url
    assert health.to_mapping()["status"] == "healthy"
    assert HealthStatus.HEALTHY.worse(HealthStatus.DEGRADED) is HealthStatus.DEGRADED
    assert HealthStatus.DEGRADED.worse(HealthStatus.UNHEALTHY) is HealthStatus.UNHEALTHY
    # without any part, start and stop do nothing
    await Transmitter().start()
    await Transmitter().stop()


async def test_transmitter_starts_and_stops_its_registrar():
    from easyssf.core import StreamConfiguration
    from easyssf.receiver.stream import ReceiverStream, StreamRegistrar

    test = TestTransmitter()
    resolver = MetadataResolver(test.issuer, None, test.client)
    stream = ReceiverStream()
    client = StreamClient(resolver, test.client, FixedToken(ACCESS_TOKEN))
    registrar = StreamRegistrar.for_managed_stream(client, stream, StreamConfiguration.poll(["CaepSessionRevoked"]))
    transmitter = Transmitter(name="default", issuer=test.issuer, metadata=resolver, stream=stream, registrar=registrar)
    await transmitter.start()
    from easyssf.testing import eventually

    await eventually(lambda: registrar.state is StreamRegistrarState.REGISTERED)
    health = await transmitter.health()
    assert health.status is HealthStatus.HEALTHY
    assert health.stream_id == stream.stream_id
    assert health.stream_registration == "registered"
    await transmitter.stop()
    assert not registrar.is_running


# -- the transmitters of a configured receiver ------------------------------------------------------------


class Recorder:
    """Counts the SETs it handled."""

    def __init__(self) -> None:
        self.count = 0

    async def handle(self, context: object) -> None:
        self.count += 1


def two() -> tuple[TestTransmitter, TestTransmitter, Receiver]:
    first = TestTransmitter.with_metadata(MetadataLocation.SSF, "first.example")
    second = TestTransmitter.with_metadata(MetadataLocation.SSF, "second.example")
    config = default_receiver_config()
    config.transmitter_issuer = first.issuer
    config.expected_audience = AUDIENCE
    config.push.expected_auth_header = "Bearer first"
    other = default_transmitter_config()
    other.transmitter_issuer = second.issuer
    other.expected_audience = AUDIENCE
    config.transmitters = {"second": other}
    return first, second, Receiver(config, http_client=client_for(first, second))


async def test_verifies_sets_of_every_transmitter_by_issuer():
    first, second, receiver = two()
    recorder = Recorder()
    receiver.processor.add_handler(recorder)
    push = receiver.push_handler
    encoded_set = first.set("CaepSessionRevoked", iss_sub(first.issuer, "alice"))
    assert (await push.handle("", encoded_set)).status == 401
    assert (await push.handle("Bearer first", encoded_set)).status == 202, "first"
    encoded_set = second.set("CaepSessionRevoked", iss_sub(second.issuer, "bob"))
    assert (await push.handle("", encoded_set)).status == 202, "the second expects no header"
    assert recorder.count == 2, "both handled"
    claims = first.set_claims("CaepSessionRevoked", iss_sub(first.issuer, "alice"))
    claims["iss"] = "https://unknown.example"
    response = await push.handle("", first.sign_set(claims))
    assert response.status == 400
    assert response.body is not None and response.body["err"] == ErrorCode.INVALID_ISSUER


async def test_looks_up_transmitters_by_name_and_issuer():
    first, second, receiver = two()
    by_name = receiver.transmitter("second")
    assert by_name is not None and by_name.issuer == second.issuer
    by_issuer = receiver.transmitter_by_issuer(first.issuer)
    assert by_issuer is not None and by_issuer.name == "default"
    assert receiver.transmitter("third") is None
    assert receiver.name_of(second.issuer) == "second"
    assert receiver.name_of("https://unknown.example") == "https://unknown.example"
    assert by_issuer.push_authorization_header == "Bearer first"
    second_transmitter = receiver.transmitter_by_issuer(second.issuer)
    assert second_transmitter is not None and second_transmitter.push_authorization_header == ""
    assert by_issuer.critical_subject_members == [], "metadata not resolved yet"
    transmitters = receiver.transmitters
    assert len(transmitters) == 2 and transmitters[0].name == "default", "default first"
    assert str(transmitters[0]) == "default (" + first.issuer + ")"


def test_rejects_duplicate_issuers():
    test = TestTransmitter()
    config = default_receiver_config()
    config.transmitter_issuer = test.issuer
    config.expected_audience = AUDIENCE
    same = default_transmitter_config()
    same.transmitter_issuer = test.issuer
    same.expected_audience = AUDIENCE
    config.transmitters = {"y": same}
    with pytest.raises(ConfigurationError, match="same issuer"):
        config.validate()
    config.transmitters = {"default": same}
    with pytest.raises(ConfigurationError, match=r"transmitters\.default"):
        config.validate()
    # the default transmitter is not needed when others are configured
    config.transmitter_issuer = ""
    config.transmitters = {"okta": same}
    config.validate()
    receiver = Receiver(config, http_client=test.client)
    assert len(receiver.transmitters) == 1 and receiver.transmitters[0].name == "okta"
    # a customizer that gives two transmitters the same issuer is refused as well
    config.transmitter_issuer = test.issuer
    other = default_transmitter_config()
    other.transmitter_issuer = "https://other.example"
    other.expected_audience = AUDIENCE
    config.transmitters = {"other": other}

    def same_issuer(transmitter: Transmitter) -> None:
        transmitter.issuer = test.issuer

    with pytest.raises(ConfigurationError, match="two transmitters have the issuer"):
        Receiver(config, http_client=test.client, transmitter_customizers=[same_issuer])


async def test_poller_fetches_as_soon_as_the_stream_is_registered():
    test = TestTransmitter()
    resolver = MetadataResolver(test.issuer, None, test.client)
    tokens = FixedToken(ACCESS_TOKEN)
    client = StreamClient(resolver, test.client, tokens)
    stream = ReceiverStream()
    registrar = StreamRegistrar.for_managed_stream(client, stream, StreamConfiguration.poll(["CaepSessionRevoked"]))
    options = replace(default_poller_options(), interval=timedelta(minutes=1), endpoint_retry=timedelta(minutes=1))
    keys = HttpJwkSetSource(test.client, test.jwks_url)
    verifier = JwtVerifier(test.issuer, keys, replace(default_verifier_options(), expected_audiences=[AUDIENCE]))
    processor = Processor(verifier, InMemoryJtiDedupStore(10))
    poller = Poller(test.client, tokens, lambda: stream.poll_endpoint_url, processor, options)
    built = Transmitter(
        name="default",
        issuer=test.issuer,
        metadata=resolver,
        verifier=verifier,
        stream=stream,
        registrar=registrar,
        poller=poller,
        auto_start_polling=True,
    )
    await built.start()
    # the poller looked once without an endpoint and would wait a minute; the registration wakes it
    await eventually(lambda: test.poll_requests >= 1, what="a poll right after the registration")
    await built.stop()
    assert not poller.is_running and not registrar.is_running, "stopped"


class Sized:
    """Answers every request with metadata padded to ``size`` bytes, with a Content-Length or
    chunked."""

    def __init__(self, size: int, content_length: bool) -> None:
        self.size = size
        self.content_length = content_length
        self.requests = 0

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        prefix = '{"issuer":"https://transmitter.example","pad":"'
        body = (prefix + "x" * max(self.size - len(prefix) - 2, 0) + '"}').encode()
        assert len(body) == self.size
        if self.content_length:
            return httpx.Response(200, headers={"Content-Type": "application/json"}, content=body)

        async def chunks():
            for start in range(0, len(body), 64 << 10):
                yield body[start : start + (64 << 10)]

        return httpx.Response(200, headers={"Content-Type": "application/json"}, content=chunks())


def sized_resolver(transport: Sized, max_response_size: int | None) -> MetadataResolver:
    return MetadataResolver(
        "https://transmitter.example",
        "https://transmitter.example/metadata",
        httpx.AsyncClient(transport=httpx.MockTransport(transport)),
        retry=replace(default_retry_options(), initial_backoff=timedelta(milliseconds=1)),
        max_response_size=max_response_size,
    )


@pytest.mark.parametrize("content_length", [True, False])
async def test_rejects_response_larger_than_the_maximum(content_length):
    transport = Sized(101, content_length)
    with pytest.raises(TransmitterUnavailableError) as raised:
        await sized_resolver(transport, 100).resolve()
    assert "larger than the 100 bytes accepted" in str(raised.value)
    assert transport.requests == 1, "not tried again, a larger response comes again"


@pytest.mark.parametrize("content_length", [True, False])
async def test_accepts_response_of_the_maximum_size(content_length):
    metadata = await sized_resolver(Sized(100, content_length), 100).resolve()
    assert metadata.issuer == "https://transmitter.example"


async def test_bounds_responses_to_four_mib_by_default():
    transport = Sized(MAX_RESPONSE_SIZE + 1, False)
    with pytest.raises(TransmitterUnavailableError, match="larger than the 4194304 bytes"):
        await sized_resolver(transport, None).resolve()


async def test_response_too_large_error_names_the_url_and_the_maximum():
    error = ResponseTooLargeError("https://transmitter.example/metadata", 100)
    assert str(error) == "The response of https://transmitter.example/metadata is larger than the 100 bytes accepted"
