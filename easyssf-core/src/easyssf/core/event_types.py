"""The event type URIs defined by OpenID SSF, CAEP and RISC, and by SCIM Events (RFC 9967),
together with short aliases (for example ``CaepSessionRevoked``) that can be used wherever an
event type is expected.

Event types are identified by their URIs; the aliases are a convenience of easyssf, the family and
the event name in PascalCase. Both forms are accepted wherever an event type is named;
:func:`resolve` goes from one to the other. Vendor specific event types get aliases of their own
with :func:`register_alias`.
"""

from __future__ import annotations

import threading
from typing import Final

__all__ = [
    "CAEP_NAMESPACE",
    "RISC_NAMESPACE",
    "SCIM_NAMESPACE",
    "SSF_NAMESPACE",
    "EventTypes",
    "alias_of",
    "aliases",
    "check_alias",
    "is_alias",
    "is_caep_event",
    "is_risc_event",
    "is_scim_event",
    "is_ssf_event",
    "register_alias",
    "resolve",
]

SSF_NAMESPACE: Final = "https://schemas.openid.net/secevent/ssf/event-type/"
CAEP_NAMESPACE: Final = "https://schemas.openid.net/secevent/caep/event-type/"
RISC_NAMESPACE: Final = "https://schemas.openid.net/secevent/risc/event-type/"
SCIM_NAMESPACE: Final = "urn:ietf:params:scim:event:"


class EventTypes:
    """The event types of SSF 1.0 (section 8.1.4), CAEP 1.0 (section 3), RISC 1.0 (section 2) and
    SCIM Events (RFC 9967), by URI."""

    SSF_STREAM_VERIFICATION: Final = SSF_NAMESPACE + "verification"
    """SSF 1.0, section 8.1.4.1, the stream verification event."""
    SSF_STREAM_UPDATED: Final = SSF_NAMESPACE + "stream-updated"
    """SSF 1.0, section 8.1.4.2, the stream was updated."""

    CAEP_SESSION_REVOKED: Final = CAEP_NAMESPACE + "session-revoked"  # CAEP 1.0, 3.1
    CAEP_TOKEN_CLAIMS_CHANGE: Final = CAEP_NAMESPACE + "token-claims-change"  # CAEP 1.0, 3.2
    CAEP_CREDENTIAL_CHANGE: Final = CAEP_NAMESPACE + "credential-change"  # CAEP 1.0, 3.3
    CAEP_ASSURANCE_LEVEL_CHANGE: Final = CAEP_NAMESPACE + "assurance-level-change"  # CAEP 1.0, 3.4
    CAEP_DEVICE_COMPLIANCE_CHANGE: Final = CAEP_NAMESPACE + "device-compliance-change"  # CAEP 1.0, 3.5
    CAEP_SESSION_ESTABLISHED: Final = CAEP_NAMESPACE + "session-established"  # CAEP 1.0, 3.6
    CAEP_SESSION_PRESENTED: Final = CAEP_NAMESPACE + "session-presented"  # CAEP 1.0, 3.7
    CAEP_RISK_LEVEL_CHANGE: Final = CAEP_NAMESPACE + "risk-level-change"  # CAEP 1.0, 3.8

    RISC_ACCOUNT_CREDENTIAL_CHANGE_REQUIRED: Final = (
        RISC_NAMESPACE + "account-credential-change-required"
    )  # RISC 1.0, 2.1
    RISC_ACCOUNT_PURGED: Final = RISC_NAMESPACE + "account-purged"  # RISC 1.0, 2.2
    RISC_ACCOUNT_DISABLED: Final = RISC_NAMESPACE + "account-disabled"  # RISC 1.0, 2.3
    RISC_ACCOUNT_ENABLED: Final = RISC_NAMESPACE + "account-enabled"  # RISC 1.0, 2.4
    RISC_IDENTIFIER_CHANGED: Final = RISC_NAMESPACE + "identifier-changed"  # RISC 1.0, 2.5
    RISC_IDENTIFIER_RECYCLED: Final = RISC_NAMESPACE + "identifier-recycled"  # RISC 1.0, 2.6
    RISC_CREDENTIAL_COMPROMISE: Final = RISC_NAMESPACE + "credential-compromise"  # RISC 1.0, 2.7
    RISC_OPT_IN: Final = RISC_NAMESPACE + "opt-in"  # RISC 1.0, 2.8.1
    RISC_OPT_OUT_INITIATED: Final = RISC_NAMESPACE + "opt-out-initiated"  # RISC 1.0, 2.8.2
    RISC_OPT_OUT_CANCELLED: Final = RISC_NAMESPACE + "opt-out-cancelled"  # RISC 1.0, 2.8.3
    RISC_OPT_OUT_EFFECTIVE: Final = RISC_NAMESPACE + "opt-out-effective"  # RISC 1.0, 2.8.4
    RISC_RECOVERY_ACTIVATED: Final = RISC_NAMESPACE + "recovery-activated"  # RISC 1.0, 2.9
    RISC_RECOVERY_INFORMATION_CHANGED: Final = RISC_NAMESPACE + "recovery-information-changed"  # RISC 1.0, 2.10
    RISC_SESSIONS_REVOKED: Final = RISC_NAMESPACE + "sessions-revoked"
    """All sessions of the account were revoked (RISC 1.0, section 2.11). Deprecated by RISC in
    favour of :attr:`CAEP_SESSION_REVOKED`, but still emitted by some transmitters."""

    SCIM_FEED_ADD: Final = SCIM_NAMESPACE + "feed:add"  # RFC 9967, 2.3.1
    SCIM_FEED_REMOVE: Final = SCIM_NAMESPACE + "feed:remove"  # RFC 9967, 2.3.2
    SCIM_PROV_CREATE_NOTICE: Final = SCIM_NAMESPACE + "prov:create:notice"  # RFC 9967, 2.4.1
    SCIM_PROV_CREATE_FULL: Final = SCIM_NAMESPACE + "prov:create:full"  # RFC 9967, 2.4.1
    SCIM_PROV_PATCH_NOTICE: Final = SCIM_NAMESPACE + "prov:patch:notice"  # RFC 9967, 2.4.2
    SCIM_PROV_PATCH_FULL: Final = SCIM_NAMESPACE + "prov:patch:full"  # RFC 9967, 2.4.2
    SCIM_PROV_PUT_NOTICE: Final = SCIM_NAMESPACE + "prov:put:notice"  # RFC 9967, 2.4.3
    SCIM_PROV_PUT_FULL: Final = SCIM_NAMESPACE + "prov:put:full"  # RFC 9967, 2.4.3
    SCIM_PROV_DELETE: Final = SCIM_NAMESPACE + "prov:delete"  # RFC 9967, 2.4.4
    SCIM_PROV_ACTIVATE: Final = SCIM_NAMESPACE + "prov:activate"  # RFC 9967, 2.4.5
    SCIM_PROV_DEACTIVATE: Final = SCIM_NAMESPACE + "prov:deactivate"  # RFC 9967, 2.4.6
    SCIM_MISC_ASYNC_RESPONSE: Final = SCIM_NAMESPACE + "misc:asyncresp"  # RFC 9967, 2.5.1.3


_BUILT_IN: Final[tuple[tuple[str, str], ...]] = (
    ("SsfStreamVerification", EventTypes.SSF_STREAM_VERIFICATION),
    ("SsfStreamUpdated", EventTypes.SSF_STREAM_UPDATED),
    ("CaepSessionRevoked", EventTypes.CAEP_SESSION_REVOKED),
    ("CaepTokenClaimsChange", EventTypes.CAEP_TOKEN_CLAIMS_CHANGE),
    ("CaepCredentialChange", EventTypes.CAEP_CREDENTIAL_CHANGE),
    ("CaepAssuranceLevelChange", EventTypes.CAEP_ASSURANCE_LEVEL_CHANGE),
    ("CaepDeviceComplianceChange", EventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE),
    ("CaepSessionEstablished", EventTypes.CAEP_SESSION_ESTABLISHED),
    ("CaepSessionPresented", EventTypes.CAEP_SESSION_PRESENTED),
    ("CaepRiskLevelChange", EventTypes.CAEP_RISK_LEVEL_CHANGE),
    ("RiscAccountCredentialChangeRequired", EventTypes.RISC_ACCOUNT_CREDENTIAL_CHANGE_REQUIRED),
    ("RiscAccountPurged", EventTypes.RISC_ACCOUNT_PURGED),
    ("RiscAccountDisabled", EventTypes.RISC_ACCOUNT_DISABLED),
    ("RiscAccountEnabled", EventTypes.RISC_ACCOUNT_ENABLED),
    ("RiscIdentifierChanged", EventTypes.RISC_IDENTIFIER_CHANGED),
    ("RiscIdentifierRecycled", EventTypes.RISC_IDENTIFIER_RECYCLED),
    ("RiscCredentialCompromise", EventTypes.RISC_CREDENTIAL_COMPROMISE),
    ("RiscOptIn", EventTypes.RISC_OPT_IN),
    ("RiscOptOutInitiated", EventTypes.RISC_OPT_OUT_INITIATED),
    ("RiscOptOutCancelled", EventTypes.RISC_OPT_OUT_CANCELLED),
    ("RiscOptOutEffective", EventTypes.RISC_OPT_OUT_EFFECTIVE),
    ("RiscRecoveryActivated", EventTypes.RISC_RECOVERY_ACTIVATED),
    ("RiscRecoveryInformationChanged", EventTypes.RISC_RECOVERY_INFORMATION_CHANGED),
    ("RiscSessionsRevoked", EventTypes.RISC_SESSIONS_REVOKED),
    ("ScimFeedAdd", EventTypes.SCIM_FEED_ADD),
    ("ScimFeedRemove", EventTypes.SCIM_FEED_REMOVE),
    ("ScimProvCreateNotice", EventTypes.SCIM_PROV_CREATE_NOTICE),
    ("ScimProvCreateFull", EventTypes.SCIM_PROV_CREATE_FULL),
    ("ScimProvPatchNotice", EventTypes.SCIM_PROV_PATCH_NOTICE),
    ("ScimProvPatchFull", EventTypes.SCIM_PROV_PATCH_FULL),
    ("ScimProvPutNotice", EventTypes.SCIM_PROV_PUT_NOTICE),
    ("ScimProvPutFull", EventTypes.SCIM_PROV_PUT_FULL),
    ("ScimProvDelete", EventTypes.SCIM_PROV_DELETE),
    ("ScimProvActivate", EventTypes.SCIM_PROV_ACTIVATE),
    ("ScimProvDeactivate", EventTypes.SCIM_PROV_DEACTIVATE),
    ("ScimMiscAsyncResponse", EventTypes.SCIM_MISC_ASYNC_RESPONSE),
)

_lock = threading.Lock()
_uri_by_alias: dict[str, str] = {alias: uri for alias, uri in _BUILT_IN}
_alias_by_uri: dict[str, str] = {uri: alias for alias, uri in _BUILT_IN}


def register_alias(alias: str, uri: str) -> None:
    """Registers an alias for an event type URI, for example of a vendor specific event type, so
    that it can be used wherever an event type is named: in handlers, in the events requested of a
    stream, in configuration. Aliases are a convenience of easyssf, the URIs stay the canonical names.

    Aliases do not conflict: an alias cannot be redefined to another URI, neither a built-in one
    nor one registered before. A URI may have several aliases; the first one registered is the one
    :func:`alias_of` returns. Registering a mapping that exists already does nothing.

    Raises:
        ValueError: if the alias is not a name without ``:`` or ``/``, the URI is not an absolute
            URI, or the alias is already mapped to another URI.
    """
    with _lock:
        _check_alias(alias, uri)
        _uri_by_alias[alias] = uri
        _alias_by_uri.setdefault(uri, alias)


def check_alias(alias: str, uri: str) -> None:
    """Checks whether :func:`register_alias` would accept the alias, without registering it, for
    validating a configuration before anything of it takes effect. Raises ``ValueError`` if not."""
    with _lock:
        _check_alias(alias, uri)


def _check_alias(alias: str, uri: str) -> None:
    if not alias.strip() or ":" in alias or "/" in alias or alias != alias.strip():
        raise ValueError(f"an event type alias must be a name without ':' or '/' and surrounding whitespace: {alias!r}")
    if not uri.strip() or ":" not in uri or uri != uri.strip():
        raise ValueError(f"an event type must be an absolute URI: {uri!r}")
    existing = _uri_by_alias.get(alias)
    if existing is not None and existing != uri:
        raise ValueError(f"the event type alias {alias!r} is already mapped to {existing}, not to {uri}")


def aliases() -> list[tuple[str, str]]:
    """The known aliases and their event type URIs, built-in and registered, sorted by alias."""
    with _lock:
        return sorted(_uri_by_alias.items())


def is_alias(name: str) -> bool:
    """Whether the name is a known alias."""
    with _lock:
        return name in _uri_by_alias


def resolve(alias_or_uri: str) -> str:
    """Resolves an alias to its event type URI. Anything that is not a known alias is returned
    unchanged, so full URIs (including vendor specific ones) pass through."""
    with _lock:
        return _uri_by_alias.get(alias_or_uri, alias_or_uri)


def alias_of(event_type_uri: str) -> str:
    """The alias of the given event type URI, or the URI itself if it has none."""
    with _lock:
        return _alias_by_uri.get(event_type_uri, event_type_uri)


def is_caep_event(alias_or_uri: str) -> bool:
    """Whether the event type is in the CAEP namespace, one of the events of CAEP 1.0 or a later one."""
    return resolve(alias_or_uri).startswith(CAEP_NAMESPACE)


def is_risc_event(alias_or_uri: str) -> bool:
    """Whether the event type is in the RISC namespace, one of the events of RISC 1.0 or a later one."""
    return resolve(alias_or_uri).startswith(RISC_NAMESPACE)


def is_ssf_event(alias_or_uri: str) -> bool:
    """Whether the event type is in the SSF namespace, a stream management event."""
    return resolve(alias_or_uri).startswith(SSF_NAMESPACE)


def is_scim_event(alias_or_uri: str) -> bool:
    """Whether the event type is one of SCIM Events (RFC 9967)."""
    return resolve(alias_or_uri).startswith(SCIM_NAMESPACE)
