from datetime import UTC, datetime

from easyssf.core import (
    ALL_SESSIONS,
    MEMBERS,
    EventToken,
    Format,
    Subject,
    SubjectIdentifier,
    event_timestamp,
    parse_claims,
)
from easyssf.core.subjects import (
    account,
    aliases,
    complex_members,
    complex_subject,
    did,
    email,
    iss_sub,
    opaque,
    phone_number,
    scim,
    uri,
)


def test_absent_subject_is_empty():
    assert Subject.from_claims(None).is_empty
    assert Subject.from_claims({}).is_empty
    assert not Subject.from_claims(None).has_user
    assert Subject.from_claims(None).session_id == ""


def test_resolves_iss_sub():
    subject = Subject.from_claims(iss_sub("https://idp.example", "alice"))
    assert subject.issuer == "https://idp.example"
    assert subject.sub == "alice"
    assert subject.has_user
    assert not subject.is_complex
    assert subject.session_id == ""
    assert subject.identifier is not None
    assert subject.identifier.format == Format.ISS_SUB
    assert subject.member_names == []


def test_resolves_email():
    subject = Subject.from_claims(email("alice@example.com"))
    assert subject.email == "alice@example.com"
    assert subject.sub == ""
    assert subject.has_user


def test_simple_opaque_subject_is_neither_user_nor_session():
    subject = Subject.from_claims(opaque("abc"))
    assert subject.opaque_id == "abc"
    assert not subject.has_user
    assert subject.sub == ""
    assert subject.session_id == ""
    assert not subject.is_empty


def test_resolves_complex_subject_with_user_and_session():
    subject = Subject.from_claims(complex_subject(iss_sub("https://idp.example", "alice"), opaque("session-1")))
    assert subject.is_complex
    assert subject.issuer == "https://idp.example"
    assert subject.sub == "alice"
    assert subject.session_id == "session-1"
    assert subject.session is not None
    assert subject.session.format == Format.OPAQUE
    assert subject.member_names == ["session", "user"]


def test_keycloak_all_sessions_marker_names_only_the_user():
    subject = Subject.from_claims(complex_subject(iss_sub("https://idp.example", "alice"), opaque(ALL_SESSIONS)))
    assert subject.sub == "alice"
    assert subject.session_id == ""
    assert subject.session is None
    # the raw claim keeps the member
    assert subject.member_names == ["session", "user"]
    # without a user the marker is an ordinary session identifier
    assert Subject.from_claims(complex_subject(None, opaque(ALL_SESSIONS))).session_id == ALL_SESSIONS


def test_resolves_complex_subject_with_opaque_user():
    subject = Subject.from_claims(complex_subject(opaque("user-1"), opaque("session-1")))
    assert subject.sub == "user-1"
    assert subject.issuer == ""
    assert subject.opaque_id == ""
    assert subject.has_user


def test_resolves_complex_subject_without_format_of_early_drafts():
    subject = Subject.from_claims(
        {
            "user": {"format": "iss_sub", "iss": "https://idp.example", "sub": "alice"},
            "session": {"format": "opaque", "id": "s1"},
        }
    )
    assert subject.is_complex
    assert subject.sub == "alice"
    assert subject.session_id == "s1"


def test_other_formats_of_rfc_9493_name_the_user():
    for identifier, value in [
        (account("acct:alice@example.com"), "acct:alice@example.com"),
        (phone_number("+12025550123"), "+12025550123"),
        (did("did:example:123"), "did:example:123"),
        (uri("https://example.com/alice"), "https://example.com/alice"),
    ]:
        subject = Subject.from_claims(identifier)
        assert subject.has_user, identifier
        assert subject.user_identifier is not None
        assert subject.user_identifier.value == value
        assert subject.sub == ""


def test_scim_resource_of_rfc_9967_names_the_user_by_its_uri():
    user = Subject.from_claims(scim("/Users/2b2f880a", "ext-1")).user_identifier
    assert user is not None
    assert user.is_scim
    assert user.value == "/Users/2b2f880a"
    assert user.claim("externalId") == "ext-1"
    assert "externalId" not in scim("/Users/1")


def test_aliases_carry_every_identifier():
    user = Subject.from_claims(
        aliases(iss_sub("https://idp.example", "alice"), email("alice@example.com"))
    ).user_identifier
    assert user is not None
    assert user.value == "", "an aliases identifier has no value of its own"
    found = user.aliases
    assert len(found) == 2
    assert found[0].value == "alice"
    assert found[1].value == "alice@example.com"
    other = SubjectIdentifier.from_claims(iss_sub("i", "s"))
    assert other is not None
    assert other.aliases == []


def test_unknown_format_is_kept_without_value():
    user = Subject.from_claims({"format": "custom", "thing": "x"}).user_identifier
    assert user is not None
    assert user.format == "custom"
    assert user.value == ""
    assert user.claim("thing") == "x"


def test_identifier_without_format_is_empty():
    assert Subject.from_claims({"sub": "alice"}).is_empty
    assert SubjectIdentifier.from_claims({}) is None
    assert SubjectIdentifier.from_claims({"format": " "}) is None
    assert SubjectIdentifier.from_claims(None) is None


def test_complex_subject_exposes_all_members():
    subject = Subject.from_claims(
        complex_members(
            {
                "user": iss_sub("https://idp.example", "alice"),
                "device": opaque("dev-1"),
                "tenant": opaque("t-1"),
                "application": opaque("app-1"),
                "org_unit": opaque("ou-1"),
                "group": opaque("g-1"),
            }
        )
    )
    assert subject.device is not None and subject.device.value == "dev-1"
    assert subject.tenant is not None and subject.tenant.value == "t-1"
    assert subject.application is not None and subject.application.value == "app-1"
    assert subject.org_unit is not None and subject.org_unit.value == "ou-1"
    assert subject.group is not None and subject.group.value == "g-1"
    assert subject.member("device") == subject.device
    assert len(list(subject.members)) == 6
    assert len(MEMBERS) == 7


def test_without_session_widens_to_user():
    subject = Subject.from_claims(complex_subject(iss_sub("https://idp.example", "alice"), opaque("session-1")))
    widened = subject.without_session()
    assert widened.sub == "alice"
    assert widened.session_id == ""
    assert widened.raw == subject.raw
    simple = Subject.from_claims(email("a@b"))
    assert simple.without_session() is simple


def test_subjects_compare_by_their_claims():
    a = Subject.from_claims(complex_subject(iss_sub("i", "alice"), opaque("s")))
    b = Subject.from_claims(complex_subject(iss_sub("i", "alice"), opaque("s")))
    assert a == b
    assert hash(a) == hash(b)
    assert a != a.without_session()


def test_event_token_reads_the_profile_claims():
    claims = parse_claims(
        """{
        "jti": "1", "iss": "https://t.example", "iat": 1700000000, "aud": ["a", "b"],
        "txn": "tx-1", "sub_id": { "format": "opaque", "id": "x" },
        "events": { "https://e.example/one": {} }
    }"""
    )
    token = EventToken.from_claims(claims)
    assert token is not None
    assert token.jti == "1"
    assert token.issuer == "https://t.example"
    assert token.issued_at == datetime.fromtimestamp(1700000000, tz=UTC)
    assert token.audience == ["a", "b"]
    assert token.txn == "tx-1"
    assert token.subject_id is not None and token.subject_id["id"] == "x"
    assert token.idempotency_key == "https://t.example::1"
    assert len(token.claims) == 7

    single = EventToken.from_claims({"jti": "1", "iss": "i", "iat": 1.0, "aud": "one", "events": {"e": {}}})
    assert single is not None
    assert single.audience == ["one"]
    assert single.txn == ""
    assert single.subject_id is None

    for broken in [
        '{ "iss": "i", "iat": 1, "events": { "e": {} } }',
        '{ "jti": "", "iss": "i", "iat": 1, "events": { "e": {} } }',
        '{ "jti": "1", "iat": 1, "events": { "e": {} } }',
        '{ "jti": "1", "iss": "i", "events": { "e": {} } }',
        '{ "jti": "1", "iss": "i", "iat": "now", "events": { "e": {} } }',
        '{ "jti": "1", "iss": "i", "iat": true, "events": { "e": {} } }',
        '{ "jti": "1", "iss": "i", "iat": 1, "events": {} }',
        '{ "jti": "1", "iss": "i", "iat": 1 }',
    ]:
        assert EventToken.from_claims(parse_claims(broken)) is None, broken


def test_event_timestamp_in_seconds_or_milliseconds():
    assert event_timestamp(1700000000.0) == datetime.fromtimestamp(1700000000, tz=UTC)
    assert event_timestamp(1700000000123) == datetime.fromtimestamp(1700000000, tz=UTC)
    assert event_timestamp("2024-01-01") is None
    assert event_timestamp(None) is None
    assert event_timestamp(True) is None
    assert event_timestamp(float("nan")) is None
