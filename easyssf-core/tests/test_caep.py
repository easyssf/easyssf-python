from datetime import UTC, datetime

from easyssf.core import Claims, EventToken, EventTypes, caep
from easyssf.core.caep import KNOWN, Event, Kind, localized, new_payload
from easyssf.core.event_types import alias_of


def token(events: Claims) -> EventToken:
    event_token = EventToken.from_claims({"jti": "1", "iss": "https://t.example", "iat": 1700000000, "events": events})
    assert event_token is not None
    return event_token


def test_every_caep_event_type_has_a_kind_and_an_alias():
    for kind, event_type in KNOWN:
        assert Kind.of(event_type) is kind
        assert kind.event_type == event_type
        alias = alias_of(event_type)
        assert alias != event_type, f"{event_type} has no alias"
        assert Kind.of(alias) is kind
        assert str(kind) == alias.removeprefix("Caep")
    assert Kind.OTHER.event_type == ""
    assert str(Kind.OTHER) == "Other"
    assert len(KNOWN) == len(Kind) - 1


def test_unknown_event_type_in_the_caep_namespace_is_other_and_anything_else_is_not_caep():
    assert Kind.of("https://schemas.openid.net/secevent/caep/event-type/future") is Kind.OTHER
    for not_caep in ("RiscAccountDisabled", "https://events.acme.example/login"):
        assert Kind.of(not_caep) is None


def test_common_claims_of_section_2_are_typed_for_every_kind():
    payload = {
        "event_timestamp": 1700000000,
        "initiating_entity": "admin",
        "reason_admin": {"en": "Landspeed violation", "de": "Zu schnell"},
        "reason_user": {"en": "You moved too fast"},
    }
    for kind, event_type in KNOWN:
        event = Event.of(event_type, payload)
        assert event is not None
        assert event.kind is kind
        assert event.event_timestamp == datetime.fromtimestamp(1700000000, tz=UTC)
        assert event.initiating_entity == "admin"
        assert event.reason_admin["de"] == "Zu schnell"
        assert event.reason_user["en"] == "You moved too fast"


def test_absent_common_claims_are_empty_and_milliseconds_are_tolerated():
    event = Event.of("CaepSessionRevoked", None)
    assert event is not None
    assert event.event_timestamp is None
    assert event.initiating_entity == ""
    assert event.reason_admin == {}
    assert event.amr == []
    assert event.claims is None
    millis = Event.of("CaepSessionRevoked", {"event_timestamp": 1700000000123})
    assert millis is not None
    assert millis.event_timestamp == datetime.fromtimestamp(1700000000, tz=UTC)


def test_plain_string_reason_is_kept_under_the_empty_language_tag():
    event = Event.of("CaepSessionRevoked", {"reason_admin": "Policy", "reason_user": 42})
    assert event is not None
    assert event.reason_admin[""] == "Policy"
    assert event.reason_user[""] == "42"
    assert localized(None) == {}
    assert localized({"en": "ok", "de": None, "fr": {"b": 1, "a": [1, 2]}}) == {"en": "ok", "fr": '{"a":[1,2],"b":1}'}


def test_event_specific_claims():
    claims = Event.of("CaepTokenClaimsChange", {"claims": {"role": "ro", "level": 2}})
    assert claims is not None and claims.claims == {"role": "ro", "level": 2}
    credential = Event.of(
        "CaepCredentialChange",
        {
            "credential_type": "fido2-roaming",
            "change_type": "create",
            "friendly_name": "Yubikey",
            "x509_issuer": "CN=CA",
            "x509_serial": "1234",
            "fido2_aaguid": "aaguid",
        },
    )
    assert credential is not None
    assert credential.credential_type == "fido2-roaming"
    assert credential.change_type == "create"
    assert credential.friendly_name == "Yubikey"
    assert credential.x509_issuer == "CN=CA"
    assert credential.x509_serial == "1234"
    assert credential.fido2_aaguid == "aaguid"
    assurance = Event.of(
        "CaepAssuranceLevelChange",
        {
            "namespace": "NIST-AAL",
            "current_level": "nist-aal1",
            "previous_level": "nist-aal2",
            "change_direction": "decrease",
        },
    )
    assert assurance is not None
    assert assurance.namespace == "NIST-AAL"
    assert assurance.current_level == "nist-aal1"
    assert assurance.previous_level == "nist-aal2"
    assert assurance.change_direction == "decrease"
    device = Event.of("CaepDeviceComplianceChange", {"current_status": "not-compliant", "previous_status": "compliant"})
    assert device is not None
    assert device.current_status == "not-compliant"
    assert device.previous_status == "compliant"
    session = Event.of(
        "CaepSessionEstablished", {"fp_ua": "abc", "acr": "urn:acr", "amr": ["pwd", "otp", 3], "ext_id": "saml-1"}
    )
    assert session is not None
    assert session.fp_ua == "abc"
    assert session.acr == "urn:acr"
    assert session.amr == ["pwd", "otp"]
    assert session.ext_id == "saml-1"
    presented = Event.of("CaepSessionPresented", None)
    assert presented is not None and presented.kind is Kind.SESSION_PRESENTED
    risk = Event.of(
        "CaepRiskLevelChange",
        {"principal": "USER", "current_level": "HIGH", "previous_level": "LOW", "risk_reason": "Credential stuffing"},
    )
    assert risk is not None
    assert risk.principal == "USER"
    assert risk.current_level == "HIGH"
    assert risk.previous_level == "LOW"
    assert risk.risk_reason == "Credential stuffing"


def test_finds_all_caep_events_of_a_set_in_order_and_ignores_others():
    set_ = token(
        {
            EventTypes.CAEP_SESSION_REVOKED: {"event_timestamp": 1},
            EventTypes.RISC_ACCOUNT_DISABLED: {},
            "https://schemas.openid.net/secevent/caep/event-type/future": "not an object",
            EventTypes.CAEP_CREDENTIAL_CHANGE: {"change_type": "revoke"},
        }
    )
    events = Event.in_token(set_)
    assert [event.kind for event in events] == [Kind.CREDENTIAL_CHANGE, Kind.OTHER, Kind.SESSION_REVOKED]
    assert events[0].change_type == "revoke"
    assert events[1].payload == {}
    assert events[1].event_type == "https://schemas.openid.net/secevent/caep/event-type/future"
    assert caep.Event.in_token(token({EventTypes.RISC_ACCOUNT_DISABLED: {}})) == []


def test_of_resolves_aliases_and_rejects_other_event_types():
    event = Event.of("CaepSessionRevoked", None)
    assert event is not None and event.event_type == EventTypes.CAEP_SESSION_REVOKED
    assert Event.of("RiscAccountDisabled", None) is None
    assert Event.of("https://events.acme.example/login", None) is None


def test_payload_builder_makes_the_common_claims():
    at = datetime.fromtimestamp(1700000000, tz=UTC)
    builder = (
        new_payload()
        .event_timestamp(at)
        .initiating_entity("admin")
        .reason_admin("en", "Policy")
        .reason_admin("de", "Richtlinie")
        .reason_user("en", "Please sign in again")
        .claim("current_level", "high")
    )
    payload = builder.build()
    assert payload == {
        "event_timestamp": 1700000000,
        "initiating_entity": "admin",
        "reason_admin": {"en": "Policy", "de": "Richtlinie"},
        "reason_user": {"en": "Please sign in again"},
        "current_level": "high",
    }
    event = Event.of(EventTypes.CAEP_ASSURANCE_LEVEL_CHANGE, payload)
    assert event is not None
    assert event.event_timestamp == at
    assert event.initiating_entity == "admin"
    assert event.reason_admin["de"] == "Richtlinie"
    assert event.reason_user["en"] == "Please sign in again"
    assert event.current_level == "high"
    # build() gives a copy: the builder may go on without touching the payload handed out
    builder.claim("current_level", None).reason_admin("fr", "Politique")
    assert payload["current_level"] == "high"
    assert "fr" not in payload["reason_admin"]
    assert "current_level" not in builder.build()
