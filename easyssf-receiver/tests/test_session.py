"""SsfSessionTerminationEventHandlerTests and SsfSubjectClaimsMatcherTests of the Java library,
receiver/session_test.go of the Go port."""

import asyncio
import threading

import pytest

from easyssf.core import Claims, DeliveryMethod, EventToken, Subject
from easyssf.core.subjects import aliases, complex_members, complex_subject, did, email, iss_sub, opaque, phone_number
from easyssf.core.subjects import scim as scim_subject
from easyssf.receiver.event import EventContext, Handler
from easyssf.receiver.session import (
    DEFAULT_SCIM_ATTRIBUTE_CLAIMS,
    SessionTerminationHandler,
    SessionTerminator,
    SessionTerminatorFunc,
    as_session_terminator,
    describe_subject,
    subject_matches,
    subject_matches_with,
)
from easyssf.testing import TestTransmitter

IDP = "https://idp.example"


class Sessions:
    """The claims of logged-in users that a terminator ends when the subject matches."""

    def __init__(self, logged_in: list[Claims] | None = None) -> None:
        self.logged_in: list[Claims] = logged_in if logged_in is not None else []
        self.terminated: list[Subject] = []

    async def terminate_sessions(self, subject: Subject) -> int:
        self.terminated.append(subject)
        before = len(self.logged_in)
        self.logged_in = [claims for claims in self.logged_in if not subject_matches(subject, claims, "")]
        return before - len(self.logged_in)


def claims(iss: str, sub: str, sid: str) -> Claims:
    c: Claims = {}
    if iss:
        c["iss"] = iss
    if sub:
        c["sub"] = sub
    if sid:
        c["sid"] = sid
    return c


def subject(identifier: Claims) -> Subject:
    return Subject.from_claims(identifier)


def context(set_claims: Claims) -> EventContext:
    token = EventToken.from_claims(set_claims)
    assert token is not None
    return EventContext(token, DeliveryMethod.PUSH)


async def login_and_handle(transmitter: TestTransmitter, sessions: Sessions, event_type: str, sub_id: Claims) -> int:
    sessions.terminated = []
    sessions.logged_in = [claims(IDP, "alice", "s1"), claims(IDP, "alice", "s2"), claims(IDP, "bob", "s3")]
    handler = SessionTerminationHandler(sessions)
    await handler.handle(context(transmitter.set_claims(event_type, sub_id)))
    return 3 - len(sessions.logged_in)


async def test_session_event_terminates_the_session_named():
    transmitter = TestTransmitter()
    sessions = Sessions()
    terminated = await login_and_handle(
        transmitter, sessions, "CaepSessionRevoked", complex_subject(iss_sub(IDP, "alice"), opaque("s1"))
    )
    assert terminated == 1
    assert sessions.terminated[0].session_id == "s1"
    # naming only the user ends all sessions of the user
    assert await login_and_handle(transmitter, sessions, "CaepSessionRevoked", iss_sub(IDP, "alice")) == 2


async def test_user_event_terminates_all_sessions_of_the_user():
    transmitter = TestTransmitter()
    sessions = Sessions()
    terminated = await login_and_handle(
        transmitter, sessions, "CaepCredentialChange", complex_subject(iss_sub(IDP, "alice"), opaque("s1"))
    )
    assert terminated == 2, "the session of the event is ignored, the user is widened"
    assert sessions.terminated[0].session_id == ""


async def test_scim_deactivate_and_delete_terminate_the_sessions_of_the_resource():
    transmitter = TestTransmitter()
    sessions = Sessions([claims(IDP, "ext-alice", "s1")])
    handler = SessionTerminationHandler(sessions, ["CaepSessionRevoked"], ["ScimProvDeactivate", "ScimProvDelete"])
    await handler.handle(context(transmitter.set_claims("ScimProvDeactivate", scim_subject("/Users/42", "ext-alice"))))
    assert sessions.logged_in == []


async def test_event_without_subject_terminates_nothing():
    transmitter = TestTransmitter()
    sessions = Sessions([claims(IDP, "alice", "s1")])
    handler = SessionTerminationHandler(sessions)
    # a subject without a format resolves to nothing
    await handler.handle(context(transmitter.set_claims("CaepSessionRevoked", {"sub": "alice"})))
    assert sessions.terminated == []
    assert len(sessions.logged_in) == 1


async def test_handler_is_a_handler_with_resolved_event_types():
    handler = SessionTerminationHandler(Sessions())
    assert isinstance(handler, Handler)
    assert handler.session_event_types == ("https://schemas.openid.net/secevent/caep/event-type/session-revoked",)
    assert handler.user_event_types == ("https://schemas.openid.net/secevent/caep/event-type/credential-change",)
    none = SessionTerminationHandler(Sessions(), [], [])
    assert none.session_event_types == ()
    assert none.user_event_types == ()


async def test_error_of_the_terminator_propagates():
    class Failing:
        async def terminate_sessions(self, subject: Subject) -> int:
            raise RuntimeError("store down")

    handler = SessionTerminationHandler(Failing())
    transmitter = TestTransmitter()
    with pytest.raises(RuntimeError, match="store down"):
        await handler.handle(context(transmitter.set_claims("CaepSessionRevoked", iss_sub(IDP, "alice"))))


# SessionTerminatorFunc


async def test_sync_terminator_runs_in_a_worker_thread():
    seen: list[tuple[str, Subject]] = []

    def terminate(subject: Subject) -> int:
        seen.append((threading.current_thread().name, subject))
        return 7

    terminator = as_session_terminator(terminate)
    assert isinstance(terminator, SessionTerminatorFunc)
    assert isinstance(terminator, SessionTerminator)
    assert await terminator.terminate_sessions(subject(opaque("s1"))) == 7
    assert seen[0][0] != threading.current_thread().name
    assert seen[0][1].opaque_id == "s1"


async def test_async_terminator_is_awaited_on_the_loop():
    loop = asyncio.get_running_loop()

    async def terminate(subject: Subject) -> int:
        assert asyncio.get_running_loop() is loop
        return 1

    terminator = as_session_terminator(terminate)
    assert await terminator.terminate_sessions(subject(opaque("s1"))) == 1
    sessions = Sessions()
    assert as_session_terminator(sessions) is sessions
    with pytest.raises(TypeError):
        as_session_terminator(42)  # type: ignore[arg-type]


def test_describe_subject():
    assert describe_subject(subject(complex_subject(iss_sub(IDP, "alice"), opaque("s1")))) == "session s1"
    assert describe_subject(subject(iss_sub(IDP, "alice"))) == "user alice"
    assert describe_subject(subject(email("alice@example.com"))) == "user alice@example.com"
    assert describe_subject(subject({"format": "employee_id", "employee_id": "E-1"})) == "user employee_id"
    assert describe_subject(subject(opaque("xyz"))) == "session or subject xyz"


# SsfSubjectClaimsMatcherTests


def matches(s: Subject, c: Claims) -> bool:
    return subject_matches(s, c, "")


def test_session_subject_matches_that_session_only():
    s = subject(complex_subject(iss_sub(IDP, "alice"), opaque("s1")))
    assert matches(s, claims(IDP, "alice", "s1"))
    assert not matches(s, claims(IDP, "alice", "s2"))
    assert not matches(s, claims(IDP, "alice", ""))
    # the user is not compared when a session is named
    assert matches(s, claims(IDP, "bob", "s1"))


def test_session_subject_matches_only_at_the_issuer_of_its_user():
    s = subject(complex_subject(iss_sub(IDP, "alice"), opaque("s1")))
    assert not matches(s, claims("https://other.example", "", "s1"))
    assert not matches(s, claims("", "", "s1"))
    # a session without an issuer matches any
    assert matches(subject(complex_subject(None, opaque("s1"))), claims("", "", "s1"))
    # or the issuer of an iss_sub session identifier
    with_issuer = subject(complex_subject(None, iss_sub(IDP, "s1")))
    assert matches(with_issuer, claims(IDP, "", "s1"))
    assert not matches(with_issuer, claims("https://other.example", "", "s1"))


def test_user_subject_matches_subject_of_that_issuer():
    s = subject(iss_sub(IDP, "alice"))
    assert matches(s, claims(IDP, "alice", "s1"))
    assert matches(s, claims(IDP, "alice", "s2"))
    assert not matches(s, claims(IDP, "bob", ""))
    # iss_sub requires the issuer of the claims
    assert not matches(s, claims("", "alice", ""))
    assert not matches(s, claims("https://other.example", "alice", ""))


def test_email_subject_matches_ignoring_case():
    s = subject(email("Alice@Example.com"))
    assert matches(s, {"email": "alice@example.com"})
    assert not matches(s, {"email": "bob@example.com"})
    assert not matches(s, {"sub": "Alice@Example.com"})


def test_opaque_subject_matches_session_or_user():
    s = subject(opaque("xyz"))
    assert matches(s, {"sid": "xyz"})
    assert matches(s, {"sub": "xyz"})
    assert not matches(s, claims("", "abc", "def"))


def test_name_is_used_when_claims_have_no_subject():
    s = subject(iss_sub(IDP, "alice"))
    assert subject_matches(s, claims(IDP, "", ""), "alice")
    assert not subject_matches(s, claims(IDP, "", ""), "bob")
    assert not subject_matches(s, claims(IDP, "bob", ""), "alice"), "a sub claim wins over the name"


def test_phone_number_and_other_formats_match_the_claim_of_the_same_name():
    assert matches(subject(phone_number("+15555550123")), {"phone_number": "+15555550123"})
    assert not matches(subject(phone_number("+15555550123")), {"phone_number": "+15555550124"})
    assert not matches(subject({"format": "employee_id", "employee_id": "E-1"}), {"employee_id": "E-1"}), (
        "an unknown format has no value"
    )
    assert matches(subject(did("did:example:1")), {"did": "did:example:1"})


def test_aliases_match_if_any_identifier_does():
    s = subject(aliases(iss_sub(IDP, "alice"), email("alice@example.com")))
    assert matches(s, {"email": "ALICE@example.com"})
    assert matches(s, claims(IDP, "alice", ""))
    assert not matches(s, claims(IDP, "bob", ""))


def test_scim_resource_matches_by_external_id_or_id_against_the_subject():
    s = subject(scim_subject("/Users/42", "ext-alice"))
    assert matches(s, {"sub": "ext-alice"})
    assert matches(s, {"sub": "42"})
    assert not matches(s, {"sub": "bob"})
    assert subject_matches(s, {}, "42")


def test_scim_resource_matches_by_user_name_against_the_preferred_username():
    s = subject({"format": "scim", "uri": "/Users/42", "userName": "alice"})
    assert matches(s, {"preferred_username": "alice"})
    assert not matches(s, {"preferred_username": "bob"})


def test_scim_attribute_claims_are_configurable():
    s = subject({"format": "scim", "uri": "/Users/42", "userName": "alice", "externalId": "ext"})
    pairs = [("userName", "sub")]
    assert subject_matches_with(s, {"sub": "alice"}, "", pairs)
    assert not subject_matches_with(s, {"sub": "ext"}, "", pairs)
    assert len(DEFAULT_SCIM_ATTRIBUTE_CLAIMS) == 3


def test_multi_valued_scim_attributes_match_by_any_value():
    s = subject(
        {
            "format": "scim",
            "uri": "/Users/42",
            "emails": [{"value": "Alice@Example.com", "primary": True}, "alias@example.com", 3],
        }
    )
    pairs = [("emails", "email")]
    assert subject_matches_with(s, {"email": "alice@example.com"}, "", pairs)
    assert subject_matches_with(s, {"email": "alias@example.com"}, "", pairs)
    assert not subject_matches_with(s, {"email": "bob@example.com"}, "", pairs)


def test_complex_subject_with_other_members_only_does_not_match():
    s = subject(complex_members({"device": opaque("d1"), "tenant": opaque("t1")}))
    assert not matches(s, claims(IDP, "alice", "d1"))
    assert not matches(Subject.empty(), {"sub": "alice"})
    assert not matches(subject(scim_subject("/Users/42")), {"sub": "43"})


def test_numeric_claims_compare_as_text():
    assert matches(subject(opaque("42")), {"sub": 42})
    assert matches(subject(iss_sub(IDP, "42")), {"iss": IDP, "sub": 42.0})
