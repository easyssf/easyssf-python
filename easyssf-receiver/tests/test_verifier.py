"""NimbusSsfSetVerifierTests of the Java library, receiver/set_test.go of the Go port."""

import json
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from joserfc import jws
from joserfc.jwk import ECKey, OKPKey

from easyssf.core import Claims, EventTypes, SubjectCompatibilityMode, caep, new_set
from easyssf.core.subjects import complex_subject, email, iss_sub, opaque
from easyssf.receiver.errors import ErrorCode, RejectedError, TransmitterUnavailableError
from easyssf.receiver.jwks import HttpJwkSetSource, StaticJwkSet
from easyssf.receiver.verifier import (
    SUPPORTED_ALGORITHMS,
    IssuerRoutingVerifier,
    JwtVerifier,
    VerifierOptions,
    default_verifier_options,
    rsa_key_bits,
    supported_algorithm,
    unverified_issuer,
    unverified_payload,
)
from easyssf.testing import (
    AUDIENCE,
    SECEVENT_JWT_TYPE,
    ManualClock,
    TestTransmitter,
    generate_key,
    sign,
    sign_with,
    unsigned,
)

JWKS_PATH = "/realms/test/protocol/openid-connect/certs"


def options() -> VerifierOptions:
    return replace(default_verifier_options(), expected_audiences=[AUDIENCE])


def verifier_with(transmitter: TestTransmitter, o: VerifierOptions) -> JwtVerifier:
    keys = HttpJwkSetSource(transmitter.client, transmitter.jwks_url)
    return JwtVerifier(transmitter.issuer, keys, o)


def verifier(transmitter: TestTransmitter) -> JwtVerifier:
    return verifier_with(transmitter, options())


def alice(transmitter: TestTransmitter) -> Claims:
    return iss_sub(transmitter.issuer, "alice")


async def code(verifier: JwtVerifier, encoded_set: str) -> str:
    """The error code the verifier rejects the SET with."""
    with pytest.raises(RejectedError) as rejected:
        await verifier.verify(encoded_set)
    return rejected.value.code


# the SETs that must be rejected


async def test_rejects_malformed_set():
    v = verifier(TestTransmitter())
    for malformed in ["", "   ", "not.a.jwt", "a.b", "a.b.c.d", "eyJ.eyJ.sig"]:
        assert await code(v, malformed) == ErrorCode.INVALID_REQUEST, malformed


async def test_rejects_set_signed_with_unknown_key():
    transmitter = TestTransmitter()
    other = generate_key(2048, "other-key")
    claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    assert await code(verifier(transmitter), sign(other, SECEVENT_JWT_TYPE, claims)) == ErrorCode.INVALID_KEY
    # the same kid as the transmitter's key, another key: the signature does not verify
    forged = generate_key(2048, "test-key")
    assert await code(verifier(transmitter), sign(forged, SECEVENT_JWT_TYPE, claims)) == ErrorCode.INVALID_KEY


async def test_rejects_unsigned_set():
    transmitter = TestTransmitter()
    unsecured = unsigned(transmitter.set_claims("CaepSessionRevoked", alice(transmitter)))
    assert await code(verifier(transmitter), unsecured) == ErrorCode.INVALID_REQUEST


async def test_rejects_algorithm_that_is_not_accepted():
    transmitter = TestTransmitter()
    claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    encoded_set = sign_with(transmitter.key, "RS512", SECEVENT_JWT_TYPE, claims)
    assert await code(verifier(transmitter), encoded_set) == ErrorCode.INVALID_KEY
    accepting = replace(options(), accepted_algorithms=["RS256", "RS512"])
    await verifier_with(transmitter, accepting).verify(encoded_set)
    ps = sign_with(transmitter.key, "PS256", SECEVENT_JWT_TYPE, claims)
    ps_only = replace(options(), accepted_algorithms=["PS256"])
    await verifier_with(transmitter, ps_only).verify(ps)


def test_refuses_algorithms_that_are_not_asymmetric():
    keys = StaticJwkSet({"keys": []})
    for algorithms in [["HS256"], ["none"], [""], ["RS256", "HS512"], []]:
        with pytest.raises(ValueError):
            JwtVerifier("https://idp.example", keys, replace(options(), accepted_algorithms=algorithms))
    JwtVerifier("https://idp.example", keys, replace(options(), accepted_algorithms=["RS256 "]))
    assert supported_algorithm(" ES256 ") == "ES256"
    assert supported_algorithm("HS256") is None
    assert "EdDSA" in SUPPORTED_ALGORITHMS and "Ed25519" in SUPPORTED_ALGORITHMS


async def test_rejects_signing_key_below_minimum_size():
    transmitter = TestTransmitter()
    weak = generate_key(1024, "weak")
    transmitter.publish_jwks(transmitter.key, weak)
    encoded_set = sign(weak, SECEVENT_JWT_TYPE, transmitter.set_claims("CaepSessionRevoked", alice(transmitter)))
    assert await code(verifier(transmitter), encoded_set) == ErrorCode.INVALID_KEY
    any_size = replace(options(), min_rsa_key_size=0)
    await verifier_with(transmitter, any_size).verify(encoded_set)
    assert rsa_key_bits(weak.key) == 1024
    assert rsa_key_bits(ECKey.generate_key("P-256")) == 0


async def test_rejects_set_that_is_not_typed_as_security_event():
    transmitter = TestTransmitter()
    claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    untyped = sign(transmitter.key, "", claims)
    assert await code(verifier(transmitter), untyped) == ErrorCode.INVALID_REQUEST
    lenient = replace(options(), require_type_header=False)
    await verifier_with(transmitter, lenient).verify(untyped)
    # the type is compared ignoring case
    await verifier(transmitter).verify(sign(transmitter.key, "SECEVENT+JWT", claims))


async def test_rejects_access_token_presented_as_set():
    transmitter = TestTransmitter()
    token = transmitter.access_token_for("alice", "session-1", datetime.now(tz=UTC))
    assert await code(verifier(transmitter), token) == ErrorCode.INVALID_REQUEST


async def test_rejects_set_of_another_issuer():
    transmitter = TestTransmitter()
    claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    claims["iss"] = "https://evil.example"
    assert await code(verifier(transmitter), transmitter.sign_set(claims)) == ErrorCode.INVALID_ISSUER


async def test_rejects_set_for_another_audience():
    transmitter = TestTransmitter()
    claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    claims["aud"] = ["https://other.example"]
    assert await code(verifier(transmitter), transmitter.sign_set(claims)) == ErrorCode.INVALID_AUDIENCE
    # one of several audiences is enough
    claims["aud"] = ["https://other.example", AUDIENCE]
    await verifier(transmitter).verify(transmitter.sign_set(claims))
    # a provider decides per SET
    provided = replace(options(), expected_audiences=[], expected_audiences_provider=lambda: ["https://other.example"])
    claims["aud"] = AUDIENCE
    assert await code(verifier_with(transmitter, provided), transmitter.sign_set(claims)) == ErrorCode.INVALID_AUDIENCE


async def test_audience_provider_may_be_async_and_may_not_know_the_audience_yet():
    transmitter = TestTransmitter()
    claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    known = False

    async def provider() -> list[str]:
        if not known:
            raise TransmitterUnavailableError(None, "the stream is not registered yet")
        return [AUDIENCE]

    v = verifier_with(transmitter, replace(options(), expected_audiences=[], expected_audiences_provider=provider))
    with pytest.raises(TransmitterUnavailableError):
        await v.verify(transmitter.sign_set(claims))
    known = True
    await v.verify(transmitter.sign_set(claims))


async def test_accepts_any_audience_when_none_is_expected():
    transmitter = TestTransmitter()
    claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    claims["aud"] = "https://other.example"
    any_audience = replace(options(), expected_audiences=[])
    await verifier_with(transmitter, any_audience).verify(transmitter.sign_set(claims))
    del claims["aud"]
    await verifier_with(transmitter, any_audience).verify(transmitter.sign_set(claims))


async def test_rejects_set_without_required_claims():
    transmitter = TestTransmitter()
    v = verifier(transmitter)
    for claim in ["jti", "iat", "events"]:
        claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
        del claims[claim]
        assert await code(v, transmitter.sign_set(claims)) == ErrorCode.INVALID_REQUEST, claim
    claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    claims["events"] = {}
    assert await code(v, transmitter.sign_set(claims)) == ErrorCode.INVALID_REQUEST
    claims["events"] = {"e": {}}
    claims["aud"] = 42
    assert await code(v, transmitter.sign_set(claims)) == ErrorCode.INVALID_REQUEST


async def test_rejects_set_without_top_level_subject_unless_allowed():
    transmitter = TestTransmitter()
    payload = {"subject": email("alice@example.com")}
    encoded_set = transmitter.sign_set(transmitter.set_claims_with_payload("CaepSessionRevoked", None, payload))
    assert await code(verifier(transmitter), encoded_set) == ErrorCode.INVALID_REQUEST
    legacy = replace(options(), subject_compatibility=SubjectCompatibilityMode.LEGACY)
    token = await verifier_with(transmitter, legacy).verify(encoded_set)
    assert token.subject_id is None


async def test_rejects_set_issued_in_the_future():
    transmitter = TestTransmitter()
    claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    claims["iat"] = int(time.time()) + 120
    assert await code(verifier(transmitter), transmitter.sign_set(claims)) == ErrorCode.INVALID_REQUEST
    # within the clock skew
    claims["iat"] = int(time.time()) + 30
    await verifier(transmitter).verify(transmitter.sign_set(claims))
    # against the verifier's clock
    clock = ManualClock(datetime.fromtimestamp(claims["iat"] - 120, tz=UTC))
    assert await code(verifier_with(transmitter, replace(options(), clock=clock)), transmitter.sign_set(claims)) == (
        ErrorCode.INVALID_REQUEST
    )


async def test_rejects_set_whose_payload_is_not_an_object():
    transmitter = TestTransmitter()
    encoded = jws.serialize_compact(
        {"alg": "RS256", "kid": transmitter.key.key_id, "typ": SECEVENT_JWT_TYPE}, b"[1,2]", transmitter.key.key
    )
    assert await code(verifier(transmitter), encoded) == ErrorCode.INVALID_REQUEST


async def test_rejects_set_signed_with_key_of_another_type_than_the_algorithm():
    # an EC key published under the kid of the SET does not verify an RS256 signature
    transmitter = TestTransmitter()
    ec = ECKey.generate_key("P-256", parameters={"kid": "ec-key", "use": "sig"})
    transmitter.publish_document(JWKS_PATH, json.dumps({"keys": [ec.as_dict(private=False)]}))
    claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    forged = sign(transmitter.key.with_key_id("ec-key"), SECEVENT_JWT_TYPE, claims)
    assert await code(verifier(transmitter), forged) == ErrorCode.INVALID_KEY


async def test_selects_the_key_by_kid_and_needs_an_unambiguous_set_without_one():
    transmitter = TestTransmitter()
    other = generate_key(2048, "other")
    transmitter.publish_jwks(other, transmitter.key)
    claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    await verifier(transmitter).verify(transmitter.sign_set(claims))
    # without a kid, two usable keys are ambiguous
    without_kid = sign_with(transmitter.key.key, "RS256", SECEVENT_JWT_TYPE, claims)
    assert await code(verifier(transmitter), without_kid) == ErrorCode.INVALID_KEY
    transmitter.publish_jwks(transmitter.key)
    await verifier(transmitter).verify(without_kid)
    # a key marked for encryption, or for another algorithm, is not a signing key
    enc = transmitter.key.public_jwk() | {"use": "enc"}
    rs512 = transmitter.key.public_jwk() | {"alg": "RS512"}
    transmitter.publish_document(JWKS_PATH, json.dumps({"keys": [enc, rs512]}))
    assert await code(verifier(transmitter), transmitter.sign_set(claims)) == ErrorCode.INVALID_KEY


# the SETs that are accepted


async def test_verifies_set():
    transmitter = TestTransmitter()
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter))
    token = await verifier(transmitter).verify(encoded_set)
    assert token.issuer == transmitter.issuer
    assert token.audience[0] == AUDIENCE
    assert EventTypes.CAEP_SESSION_REVOKED in token.events
    assert token.subject_id is not None and token.subject_id["sub"] == "alice"


async def test_verifies_set_signed_with_ec_and_ed25519_keys_under_both_eddsa_names(recwarn):
    transmitter = TestTransmitter()
    ec = ECKey.generate_key("P-256", parameters={"kid": "ec", "use": "sig"})
    ed = OKPKey.generate_key("Ed25519", parameters={"kid": "ed", "use": "sig"})
    transmitter.publish_document(JWKS_PATH, json.dumps({"keys": [ec.as_dict(), ed.as_dict()]}))
    claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    es = verifier_with(transmitter, replace(options(), accepted_algorithms=["ES256"]))
    await es.verify(sign_with(ec, "ES256", SECEVENT_JWT_TYPE, claims))
    assert await code(es, transmitter.sign_set(claims)) == ErrorCode.INVALID_KEY
    for accepted in ["EdDSA", "Ed25519"]:
        v = verifier_with(transmitter, replace(options(), accepted_algorithms=[accepted]))
        for named in ["EdDSA", "Ed25519"]:
            await v.verify(sign_with(ed, named, SECEVENT_JWT_TYPE, claims))
    assert not [w for w in recwarn if "EdDSA" in str(w.message)], "the verifier does not warn about EdDSA"


async def test_unreachable_jwk_set_is_reported_as_unavailable():
    transmitter = TestTransmitter()
    transmitter.remove_document(JWKS_PATH)
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter))
    v = verifier(transmitter)
    with pytest.raises(TransmitterUnavailableError):
        await v.verify(encoded_set)
    # not cached: the next SET fetches again
    transmitter.publish_jwks(transmitter.key)
    await v.verify(encoded_set)


async def test_fetches_the_jwk_set_again_for_an_unknown_key_but_rate_limited():
    transmitter = TestTransmitter()
    clock = ManualClock()
    keys = HttpJwkSetSource(
        transmitter.client, transmitter.jwks_url, refresh_rate_limit=timedelta(seconds=30), clock=clock
    )
    v = JwtVerifier(transmitter.issuer, keys, options())
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter))
    await v.verify(encoded_set)
    fetches = transmitter.requests

    # the transmitter rotates its key: the first SET with the new kid triggers a fetch
    rotated = generate_key(2048, "rotated")
    transmitter.publish_jwks(rotated)
    signed_with_rotated = sign(
        rotated, SECEVENT_JWT_TYPE, transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    )
    assert await code(v, signed_with_rotated) == ErrorCode.INVALID_KEY
    assert transmitter.requests == fetches, "within the rate limit no fetch happens"
    clock.advance(timedelta(seconds=31))
    await v.verify(signed_with_rotated)
    assert transmitter.requests == fetches + 1
    # and the old key is gone
    assert await code(v, encoded_set) == ErrorCode.INVALID_KEY


async def test_jwk_set_location_is_resolved_from_the_metadata_on_first_use():
    transmitter = TestTransmitter()

    async def resolve() -> str:
        response = await transmitter.client.get("https://transmitter.example/.well-known/ssf-configuration/realms/test")
        return str(response.json()["jwks_uri"])

    keys = HttpJwkSetSource(transmitter.client, resolve)
    v = JwtVerifier(transmitter.issuer, keys, options())
    assert transmitter.requests == 0, "nothing is fetched before the first SET"
    encoded_set = transmitter.set("CaepSessionRevoked", alice(transmitter))
    await v.verify(encoded_set)
    assert transmitter.requests == 2, "metadata and JWK Set"
    await v.verify(encoded_set)
    assert transmitter.requests == 2, "both are cached"


async def test_verifies_with_static_keys():
    transmitter = TestTransmitter()
    v = JwtVerifier(transmitter.issuer, StaticJwkSet({"keys": [transmitter.key.public_jwk()]}), options())
    token = await v.verify(transmitter.set("CaepSessionRevoked", alice(transmitter)))
    assert token.issuer == transmitter.issuer
    assert v.issuer == transmitter.issuer and v.options.expected_audiences == [AUDIENCE]


async def test_accepts_set_built_with_the_builder_and_signed_with_the_signer():
    transmitter = TestTransmitter()
    payload = (
        caep.new_payload()
        .event_timestamp(datetime.now(tz=UTC))
        .initiating_entity("admin")
        .reason_admin("en", "Policy")
        .build()
    )
    claims = (
        new_set(transmitter.issuer)
        .audience(AUDIENCE)
        .subject(complex_subject(iss_sub(transmitter.issuer, "alice"), opaque("session-1")))
        .event("CaepSessionRevoked", payload)
        .claims()
    )
    encoded = transmitter.signer.sign(claims)
    token = await verifier(transmitter).verify(encoded)
    events = caep.Event.in_token(token)
    assert len(events) == 1
    assert events[0].kind is caep.Kind.SESSION_REVOKED
    assert events[0].initiating_entity == "admin"
    assert events[0].reason_admin["en"] == "Policy"


# reading before verifying, and routing by issuer


def test_reads_the_unverified_payload_and_issuer():
    transmitter = TestTransmitter()
    claims = transmitter.set_claims("CaepSessionRevoked", alice(transmitter))
    encoded_set = transmitter.sign_set(claims)
    assert unverified_issuer(encoded_set) == transmitter.issuer
    payload = unverified_payload(encoded_set)
    assert payload is not None and payload["jti"] == claims["jti"]
    for garbage in ["", "garbage", "a.!!!.c", "a." + "WyJub3QiLCJhbiIsIm9iamVjdCJd" + ".c"]:
        assert unverified_payload(garbage) is None, garbage
        assert unverified_issuer(garbage) == ""


async def test_routes_sets_to_the_verifier_of_their_issuer():
    one = TestTransmitter(host="one.example")
    two = TestTransmitter(host="two.example")
    routing = IssuerRoutingVerifier({one.issuer: verifier(one), two.issuer: verifier(two)})
    assert (await routing.verify(one.set("CaepSessionRevoked", alice(one)))).issuer == one.issuer
    assert (await routing.verify(two.set("CaepSessionRevoked", alice(two)))).issuer == two.issuer
    claims = one.set_claims("CaepSessionRevoked", alice(one))
    claims["iss"] = "https://unknown.example"
    with pytest.raises(RejectedError) as rejected:
        await routing.verify(one.sign_set(claims))
    assert rejected.value.code == ErrorCode.INVALID_ISSUER
    # the verifier of the issuer checks the issuer again: a SET that claims another known issuer
    claims["iss"] = two.issuer
    claims["aud"] = "https://other.example"
    with pytest.raises(RejectedError) as rejected:
        await routing.verify(one.sign_set(claims))
    assert rejected.value.code == ErrorCode.INVALID_AUDIENCE, "verified by the verifier of two"
    assert sorted(routing.issuers) == sorted([one.issuer, two.issuer])
