"""The JWK Set sources: the JWKS parts of receiver/set_test.go and authorizer_test.go of the Go
port that need no transmitter client beyond httpx."""

import asyncio
import json
from datetime import timedelta

import httpx
import pytest

from easyssf.receiver.errors import TransmitterUnavailableError
from easyssf.receiver.jwks import (
    DEFAULT_CACHE_LIFETIME,
    DEFAULT_REFRESH_RATE_LIMIT,
    HttpJwkSetSource,
    StaticJwkSet,
    parse_jwk_set,
)
from easyssf.testing import ManualClock, TestTransmitter, generate_key

JWKS_PATH = "/realms/test/protocol/openid-connect/certs"


def kids(keys) -> list[str | None]:
    return [key.kid for key in keys.keys]


# what must fail


async def test_unreachable_jwk_set_is_reported_as_unavailable_and_not_cached():
    transmitter = TestTransmitter()
    transmitter.remove_document(JWKS_PATH)
    source = HttpJwkSetSource(transmitter.client, transmitter.jwks_url)
    with pytest.raises(TransmitterUnavailableError):
        await source.jwk_set()
    transmitter.publish_jwks(transmitter.key)
    assert kids(await source.jwk_set()) == ["test-key"]


async def test_unroutable_host_is_reported_as_unavailable():
    transmitter = TestTransmitter()
    source = HttpJwkSetSource(transmitter.client, "https://elsewhere.example/certs")
    with pytest.raises(TransmitterUnavailableError) as unavailable:
        await source.jwk_set()
    assert isinstance(unavailable.value.cause, httpx.ConnectError)


async def test_document_that_is_not_a_jwk_set_is_reported_as_unavailable():
    transmitter = TestTransmitter()
    source = HttpJwkSetSource(transmitter.client, transmitter.jwks_url)
    for body in [
        "not json",
        "[]",
        '{"nokeys": 1}',
        '{"keys": "x"}',
        '{"keys": [1]}',
        '{"keys": [{"kty": "RSA", "n": "x"}]}',
    ]:
        transmitter.publish_document(JWKS_PATH, body)
        with pytest.raises(TransmitterUnavailableError):
            await source.jwk_set()


async def test_resolver_failure_is_raised_and_tried_again_on_the_next_use():
    transmitter = TestTransmitter()
    attempts = 0

    async def resolve() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise TransmitterUnavailableError(None, "no metadata yet")
        return transmitter.jwks_url

    source = HttpJwkSetSource(transmitter.client, resolve)
    with pytest.raises(TransmitterUnavailableError):
        await source.jwk_set()
    assert source.url is None
    assert kids(await source.jwk_set()) == ["test-key"]
    assert source.url == transmitter.jwks_url
    assert attempts == 2


async def test_failing_fetch_is_reported_as_unavailable():
    transmitter = TestTransmitter()

    async def fetch(url: str) -> bytes:
        raise RuntimeError("boom")

    source = HttpJwkSetSource(transmitter.client, transmitter.jwks_url, fetch=fetch)
    with pytest.raises(TransmitterUnavailableError) as unavailable:
        await source.jwk_set()
    assert isinstance(unavailable.value.cause, RuntimeError)


# what works


def test_parses_jwk_set_skipping_unknown_key_types_and_accepting_an_empty_set():
    rsa = generate_key(2048, "rsa").public_jwk()
    keys = parse_jwk_set(json.dumps({"keys": [rsa, {"kty": "PQ", "kid": "future"}]}))
    assert kids(keys) == ["rsa"]
    assert kids(parse_jwk_set({"keys": []})) == []
    assert kids(parse_jwk_set(json.dumps({"keys": [rsa]}).encode())) == ["rsa"]


async def test_static_jwk_set_serves_the_keys_given():
    key = generate_key(2048, "static")
    source = StaticJwkSet({"keys": [key.public_jwk()]})
    assert kids(await source.jwk_set()) == ["static"]
    assert kids(await source.jwk_set(refresh=True)) == ["static"]
    assert kids(StaticJwkSet(source.keys).keys) == ["static"]


async def test_fetches_jwk_set_once_and_serves_it_from_the_cache():
    transmitter = TestTransmitter()
    source = HttpJwkSetSource(transmitter.client, transmitter.jwks_url)
    assert transmitter.requests == 0, "nothing is fetched before the first use"
    assert kids(await source.jwk_set()) == ["test-key"]
    assert kids(await source.jwk_set()) == ["test-key"]
    assert transmitter.requests == 1
    assert source.cache_lifetime == DEFAULT_CACHE_LIFETIME
    assert source.refresh_rate_limit == DEFAULT_REFRESH_RATE_LIMIT


async def test_fetches_jwk_set_again_after_the_cache_lifetime():
    transmitter = TestTransmitter()
    clock = ManualClock()
    source = HttpJwkSetSource(
        transmitter.client, transmitter.jwks_url, cache_lifetime=timedelta(minutes=5), clock=clock
    )
    await source.jwk_set()
    rotated = generate_key(2048, "rotated")
    transmitter.publish_jwks(rotated)
    clock.advance(timedelta(minutes=4, seconds=59))
    assert kids(await source.jwk_set()) == ["test-key"], "still cached"
    clock.advance(timedelta(seconds=2))
    assert kids(await source.jwk_set()) == ["rotated"]
    assert transmitter.requests == 2


async def test_refresh_for_an_unknown_key_is_rate_limited():
    transmitter = TestTransmitter()
    clock = ManualClock()
    source = HttpJwkSetSource(
        transmitter.client, transmitter.jwks_url, refresh_rate_limit=timedelta(seconds=30), clock=clock
    )
    await source.jwk_set()
    transmitter.publish_jwks(generate_key(2048, "rotated"))
    assert kids(await source.jwk_set(refresh=True)) == ["test-key"], "within the rate limit no fetch happens"
    assert transmitter.requests == 1
    clock.advance(timedelta(seconds=31))
    assert kids(await source.jwk_set(refresh=True)) == ["rotated"]
    assert transmitter.requests == 2
    assert kids(await source.jwk_set(refresh=True)) == ["rotated"], "rate limited again"
    assert transmitter.requests == 2


async def test_concurrent_callers_wait_for_one_fetch():
    transmitter = TestTransmitter()
    started = asyncio.Event()
    release = asyncio.Event()

    async def fetch(url: str) -> bytes:
        started.set()
        await release.wait()
        response = await transmitter.client.get(url)
        return response.content

    source = HttpJwkSetSource(transmitter.client, transmitter.jwks_url, fetch=fetch)
    first = asyncio.create_task(source.jwk_set())
    await started.wait()
    second = asyncio.create_task(source.jwk_set(refresh=True))
    await asyncio.sleep(0.01)
    assert not second.done(), "the second caller waits for the fetch of the first"
    release.set()
    assert kids(await first) == ["test-key"]
    assert kids(await second) == ["test-key"]
    assert transmitter.requests == 1


async def test_fetch_hook_receives_the_resolved_url_and_supplies_the_document():
    transmitter = TestTransmitter()
    fetched: list[str] = []

    async def fetch(url: str) -> bytes:
        # the receiver wires the authorizer, retry and URI policy of the transmitter in here
        fetched.append(url)
        return json.dumps({"keys": [generate_key(2048, "from-hook").public_jwk()]}).encode()

    async def resolve() -> str:
        return transmitter.jwks_url

    source = HttpJwkSetSource(transmitter.client, resolve, fetch=fetch)
    assert kids(await source.jwk_set()) == ["from-hook"]
    assert fetched == [transmitter.jwks_url]
    assert transmitter.requests == 0, "the hook replaces the plain GET"


async def test_default_fetch_asks_for_a_jwk_set_and_rejects_non_2xx_answers():
    transmitter = TestTransmitter()
    seen: list[httpx.Request] = []

    async def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("/missing"):
            return httpx.Response(404)
        return httpx.Response(200, json={"keys": [transmitter.key.public_jwk()]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
    source = HttpJwkSetSource(client, "https://keys.example/certs")
    assert kids(await source.jwk_set()) == ["test-key"]
    assert seen[0].headers["Accept"] == "application/jwk-set+json, application/json"
    missing = HttpJwkSetSource(client, "https://keys.example/missing")
    with pytest.raises(TransmitterUnavailableError) as unavailable:
        await missing.jwk_set()
    assert "status 404" in str(unavailable.value)
