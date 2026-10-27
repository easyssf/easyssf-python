import pytest

from easyssf.core import EventTypes, event_types
from easyssf.core.event_types import (
    alias_of,
    aliases,
    check_alias,
    is_alias,
    is_caep_event,
    is_risc_event,
    is_scim_event,
    is_ssf_event,
    register_alias,
    resolve,
)


def test_resolves_built_in_aliases_and_passes_uris_through():
    assert resolve("CaepSessionRevoked") == EventTypes.CAEP_SESSION_REVOKED
    assert resolve(EventTypes.CAEP_SESSION_REVOKED) == EventTypes.CAEP_SESSION_REVOKED
    assert resolve("https://events.acme.example/login") == "https://events.acme.example/login"
    assert alias_of(EventTypes.RISC_ACCOUNT_DISABLED) == "RiscAccountDisabled"
    assert alias_of("https://events.acme.example/unaliased") == "https://events.acme.example/unaliased"
    assert is_alias("CaepCredentialChange")
    assert not is_alias("Nope")
    assert is_caep_event("CaepSessionRevoked")
    assert is_caep_event("https://schemas.openid.net/secevent/caep/event-type/future")
    assert not is_caep_event("RiscAccountDisabled")
    assert is_risc_event(EventTypes.RISC_SESSIONS_REVOKED)
    assert is_ssf_event("SsfStreamVerification")


def test_scim_event_types_are_urns_with_aliases():
    assert resolve("ScimProvCreateFull") == "urn:ietf:params:scim:event:prov:create:full"
    assert alias_of(EventTypes.SCIM_PROV_DEACTIVATE) == "ScimProvDeactivate"
    assert is_scim_event("ScimFeedAdd")
    assert sum(1 for alias, _ in aliases() if alias.startswith("Scim")) == 12


def test_registered_alias_resolves_like_a_built_in_one():
    register_alias("AcmeLoginTest", "https://events.acme.example/login")
    assert resolve("AcmeLoginTest") == "https://events.acme.example/login"
    assert alias_of("https://events.acme.example/login") == "AcmeLoginTest"
    # registering the same mapping again does nothing
    register_alias("AcmeLoginTest", "https://events.acme.example/login")
    check_alias("AcmeLoginTest", "https://events.acme.example/login")


def test_alias_cannot_be_mapped_to_another_uri():
    with pytest.raises(ValueError, match="already mapped"):
        register_alias("CaepSessionRevoked", "https://events.acme.example/other")
    register_alias("AcmeOnce", "https://events.acme.example/once")
    with pytest.raises(ValueError, match="already mapped"):
        register_alias("AcmeOnce", "https://events.acme.example/twice")
    with pytest.raises(ValueError, match="already mapped"):
        check_alias("AcmeOnce", "https://events.acme.example/twice")
    assert resolve("AcmeOnce") == "https://events.acme.example/once"


def test_uri_may_have_several_aliases_and_keeps_the_first_for_display():
    register_alias("AcmeFirst", "https://events.acme.example/several")
    register_alias("AcmeSecond", "https://events.acme.example/several")
    assert resolve("AcmeSecond") == "https://events.acme.example/several"
    assert alias_of("https://events.acme.example/several") == "AcmeFirst"


@pytest.mark.parametrize(
    ("alias", "uri"),
    [
        ("", "https://x.example/e"),
        ("has:colon", "https://x.example/e"),
        ("has/slash", "https://x.example/e"),
        (" padded", "https://x.example/e"),
        ("Ok", "not-a-uri"),
        ("Ok", ""),
    ],
)
def test_rejects_malformed_aliases_and_uris(alias, uri):
    with pytest.raises(ValueError):
        register_alias(alias, uri)
    assert not is_alias("Ok")


def test_the_module_is_reachable_from_the_package():
    assert event_types.resolve("SsfStreamUpdated") == EventTypes.SSF_STREAM_UPDATED
