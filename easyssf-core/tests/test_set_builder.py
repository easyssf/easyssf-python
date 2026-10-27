from datetime import UTC, datetime

import pytest

from easyssf.core import EventToken, EventTypes, Subject, new_set
from easyssf.core.subjects import email


def test_builds_set_with_the_required_claims_and_one_event():
    issued_at = datetime.fromtimestamp(1700000000, tz=UTC)
    claims = (
        new_set("https://idp.example")
        .jti("set-1")
        .issued_at(issued_at)
        .audience("https://app.example")
        .subject(email("alice@example.com"))
        .txn("txn-1")
        .event("CaepSessionRevoked", {"event_timestamp": 1700000000})
        .claims()
    )
    token = EventToken.from_claims(claims)
    assert token is not None
    assert token.jti == "set-1"
    assert token.issuer == "https://idp.example"
    assert token.issued_at_seconds == 1700000000
    assert token.txn == "txn-1"
    assert token.audience == ["https://app.example"]
    assert isinstance(claims["aud"], str), "one audience is a string"
    assert EventTypes.CAEP_SESSION_REVOKED in token.events, "alias resolved"
    assert Subject.from_claims(token.subject_id).email == "alice@example.com"


def test_several_audiences_are_an_array_and_the_jti_is_random():
    first = new_set("https://idp.example").audience("a", "b").event(EventTypes.RISC_ACCOUNT_DISABLED).claims()
    second = new_set("https://idp.example").event(EventTypes.RISC_ACCOUNT_DISABLED, None).claims()
    assert first["aud"] == ["a", "b"]
    assert first["jti"] != second["jti"]
    assert len(first["jti"]) == 32
    assert first["events"][EventTypes.RISC_ACCOUNT_DISABLED] == {}, "a None payload becomes an empty object"


def test_refuses_set_without_event_or_issuer():
    with pytest.raises(ValueError, match="no event"):
        new_set("https://idp.example").claims()
    with pytest.raises(ValueError, match="lacks"):
        new_set("").event("CaepSessionRevoked").claims()
    with pytest.raises(ValueError, match="empty"):
        new_set("https://idp.example").event("").claims()


def test_claims_of_the_builder_are_a_copy():
    builder = new_set("https://idp.example").event("CaepSessionRevoked")
    claims = builder.claims()
    claims["iss"] = "changed"
    claims["events"]["x"] = {}
    assert builder.claims()["iss"] == "https://idp.example"
    assert "x" not in builder.claims()["events"]


def test_removes_claims_set_to_nothing():
    builder = new_set("i").event("CaepSessionRevoked").audience("a").subject(email("a@b")).txn("t").claim("x", 1)
    claims = builder.audience().subject(None).txn("").claim("x", None).claims()
    assert "aud" not in claims and "sub_id" not in claims and "txn" not in claims and "x" not in claims
