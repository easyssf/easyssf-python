import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from joserfc import jws
from joserfc.jwk import ECKey, RSAKey

from easyssf.core import new_set
from easyssf.core.signing import SECEVENT_JWT_TYPE
from easyssf.testing import (
    ManualClock,
    claims_of,
    during,
    eventually,
    generate_key,
    shared_key,
    sign,
    sign_with,
    unsigned,
)


def test_shared_key_is_one_key_per_process():
    assert shared_key() is shared_key()
    assert shared_key().key_id == "test-key"
    assert shared_key().key.raw_value.key_size == 2048
    assert shared_key().with_key_id("other").key is shared_key().key
    assert shared_key().public_jwk()["kid"] == "test-key"
    assert "d" not in shared_key().public_jwk()


def test_signs_with_any_key_size_and_algorithm():
    claims = new_set("https://idp.example").event("CaepSessionRevoked").claims()
    weak = generate_key(1024, "weak")
    compact = sign(weak, SECEVENT_JWT_TYPE, claims)
    public = RSAKey.import_key(weak.public_jwk())
    assert jws.deserialize_compact(compact, public, algorithms=["RS256"]).protected == {
        "alg": "RS256",
        "kid": "weak",
        "typ": SECEVENT_JWT_TYPE,
    }
    assert claims_of(compact) == claims
    assert "typ" not in jws.extract_compact(sign(weak, None, claims).encode()).protected
    ps = sign_with(shared_key(), "PS256", "JWT", {"sub": "a"})
    assert jws.extract_compact(ps.encode()).protected["alg"] == "PS256"
    ec = sign_with(ECKey.generate_key("P-256", parameters={"kid": "ec"}), "ES256", "JWT", {"sub": "a"})
    assert jws.extract_compact(ec.encode()).protected == {"alg": "ES256", "kid": "ec", "typ": "JWT"}
    with pytest.raises(ValueError):
        shared_key().signer("ES256")
    assert shared_key().signer().key_id == "test-key"


def test_unsigned_token_has_no_signature():
    token = unsigned({"iss": "i"})
    signature = token.split(".")[2]
    assert signature == ""
    assert claims_of(token) == {"iss": "i"}
    assert jws.extract_compact(token.encode()).protected == {"alg": "none", "typ": SECEVENT_JWT_TYPE}
    with pytest.raises(ValueError):
        claims_of("not.a")


def test_manual_clock_moves_by_hand():
    clock = ManualClock(datetime(2026, 1, 1, tzinfo=UTC))
    assert clock() == clock.now == datetime(2026, 1, 1, tzinfo=UTC)
    assert clock.advance(timedelta(minutes=5)) == datetime(2026, 1, 1, 0, 5, tzinfo=UTC)
    clock.set(datetime(2027, 1, 1, tzinfo=UTC))
    assert clock().year == 2027


async def test_eventually_and_during():
    counter = {"n": 0}

    async def tick():
        counter["n"] += 1
        return counter["n"] >= 3

    await eventually(tick, timeout=1, what="three ticks")
    assert counter["n"] == 3
    await during(lambda: counter["n"] == 3, duration=0.05)
    with pytest.raises(AssertionError, match="Timed out waiting for: never"):
        await eventually(lambda: False, timeout=0.05, what="never")
    task = asyncio.get_running_loop().call_later(0.03, lambda: counter.update(n=0))
    with pytest.raises(AssertionError, match="Stopped holding"):
        await during(lambda: counter["n"] == 3, duration=timedelta(seconds=0.5))
    task.cancel()
