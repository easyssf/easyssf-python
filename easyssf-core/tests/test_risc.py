from datetime import UTC, datetime

from easyssf.core import Claims, EventToken, EventTypes
from easyssf.core.event_types import alias_of
from easyssf.core.risc import KNOWN, Event, Kind


def token(events: Claims) -> EventToken:
    event_token = EventToken.from_claims({"jti": "1", "iss": "https://t.example", "iat": 1700000000, "events": events})
    assert event_token is not None
    return event_token


def test_every_risc_event_type_has_a_kind_and_an_alias():
    for kind, event_type in KNOWN:
        assert Kind.of(event_type) is kind
        assert kind.event_type == event_type
        alias = alias_of(event_type)
        assert alias != event_type, f"{event_type} has no alias"
        assert Kind.of(alias) is kind
        assert str(kind) == alias.removeprefix("Risc")
    assert Kind.OTHER.event_type == ""
    assert str(Kind.OTHER) == "Other"
    assert len(KNOWN) == len(Kind) - 1


def test_unknown_event_type_in_the_risc_namespace_is_other_and_anything_else_is_not_risc():
    assert Kind.of("https://schemas.openid.net/secevent/risc/event-type/future") is Kind.OTHER
    assert Kind.of("CaepSessionRevoked") is None


def test_opt_in_and_opt_out_events_report_the_participation():
    for kind in (Kind.OPT_IN, Kind.OPT_OUT_INITIATED, Kind.OPT_OUT_CANCELLED, Kind.OPT_OUT_EFFECTIVE):
        assert kind.is_opt_out_state
    assert not Kind.ACCOUNT_DISABLED.is_opt_out_state
    assert not Kind.OTHER.is_opt_out_state


def test_attributes():
    disabled = Event.of("RiscAccountDisabled", {"reason": "hijacking"})
    assert disabled is not None and disabled.reason == "hijacking"
    no_reason = Event.of("RiscAccountDisabled", None)
    assert no_reason is not None and no_reason.reason == ""
    changed = Event.of("RiscIdentifierChanged", {"new-value": "new@example.com"})
    assert changed is not None and changed.new_value == "new@example.com"
    compromise = Event.of(
        "RiscCredentialCompromise",
        {
            "credential_type": "password",
            "event_timestamp": 1700000000,
            "reason_admin": {"en": "leak"},
            "reason_user": "Change it",
        },
    )
    assert compromise is not None
    assert compromise.credential_type == "password"
    assert compromise.event_timestamp == datetime.fromtimestamp(1700000000, tz=UTC)
    assert compromise.reason_admin == '{"en":"leak"}'
    assert compromise.reason_user == "Change it"
    purged = Event.of("RiscAccountPurged", None)
    assert purged is not None
    assert purged.payload == {}
    assert purged.reason == ""
    assert purged.event_timestamp is None
    assert purged.reason_admin == ""


def test_finds_all_risc_events_of_a_set_in_order_and_ignores_others():
    events = Event.in_token(
        token(
            {
                EventTypes.CAEP_SESSION_REVOKED: {},
                EventTypes.RISC_ACCOUNT_DISABLED: {"reason": "hijacking"},
                EventTypes.RISC_SESSIONS_REVOKED: {},
            }
        )
    )
    assert [event.kind for event in events] == [Kind.ACCOUNT_DISABLED, Kind.SESSIONS_REVOKED]
    assert events[0].reason == "hijacking"
    enabled = Event.of("RiscAccountEnabled", None)
    assert enabled is not None and enabled.event_type == EventTypes.RISC_ACCOUNT_ENABLED
    assert Event.of("CaepSessionRevoked", None) is None
