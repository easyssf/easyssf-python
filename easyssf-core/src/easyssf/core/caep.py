"""The CAEP 1.0 events: the kinds of section 3 and typed access to their claims, the common ones
of section 2 (``event_timestamp``, ``initiating_entity``, ``reason_admin``, ``reason_user``) and
the event-specific ones (``credential_type``, ``change_type``, ``current_level``, ...). The port
of ``ssf/caep`` of the Go port and of ``org.easyssf.core.caep``."""

from __future__ import annotations

import copy
import json
from datetime import datetime
from enum import Enum
from typing import Any, Final

from . import event_types
from .claims import Claims, event_timestamp, object_member, string_member, strings
from .event_types import EventTypes
from .token import EventToken

__all__ = ["KNOWN", "Event", "Kind", "PayloadBuilder", "localized", "new_payload"]


class Kind(Enum):
    """One of the events of CAEP 1.0, section 3, or :attr:`OTHER` for an event type in the CAEP
    namespace this version does not know. New kinds are added as CAEP defines events, so do not
    match over them exhaustively; implement the receiver's CAEP handler instead."""

    OTHER = "Other"
    """An event type in the CAEP namespace this version does not know, for example one of a later
    CAEP version. The common claims of CAEP section 2 are still available."""
    SESSION_REVOKED = "SessionRevoked"
    """The session was revoked (section 3.1)."""
    TOKEN_CLAIMS_CHANGE = "TokenClaimsChange"  # noqa: S105  # an event type name, not a credential
    """Claims of the token the subject identifies changed (section 3.2)."""
    CREDENTIAL_CHANGE = "CredentialChange"
    """A credential was created, revoked, updated or deleted (section 3.3)."""
    ASSURANCE_LEVEL_CHANGE = "AssuranceLevelChange"
    """The assurance level of the subject changed (section 3.4)."""
    DEVICE_COMPLIANCE_CHANGE = "DeviceComplianceChange"
    """The compliance status of the device changed (section 3.5)."""
    SESSION_ESTABLISHED = "SessionEstablished"
    """A session was established (section 3.6)."""
    SESSION_PRESENTED = "SessionPresented"
    """A session was presented to the transmitter (section 3.7)."""
    RISK_LEVEL_CHANGE = "RiskLevelChange"
    """The risk level of the subject changed (section 3.8)."""

    @property
    def event_type(self) -> str:
        """The event type URI of the kind, ``""`` for :attr:`OTHER`."""
        for kind, uri in KNOWN:
            if kind is self:
                return uri
        return ""

    @classmethod
    def of(cls, event_type: str) -> Kind | None:
        """The kind of CAEP event of an event type URI or alias: :attr:`OTHER` for an unknown
        event type in the CAEP namespace, ``None`` if the event type is not a CAEP event."""
        if not event_types.is_caep_event(event_type):
            return None
        uri = event_types.resolve(event_type)
        for kind, known in KNOWN:
            if known == uri:
                return kind
        return cls.OTHER

    def __str__(self) -> str:
        """The name of the kind: ``SessionRevoked``, ..., ``Other``."""
        return self.value


KNOWN: Final[tuple[tuple[Kind, str], ...]] = (
    (Kind.SESSION_REVOKED, EventTypes.CAEP_SESSION_REVOKED),
    (Kind.TOKEN_CLAIMS_CHANGE, EventTypes.CAEP_TOKEN_CLAIMS_CHANGE),
    (Kind.CREDENTIAL_CHANGE, EventTypes.CAEP_CREDENTIAL_CHANGE),
    (Kind.ASSURANCE_LEVEL_CHANGE, EventTypes.CAEP_ASSURANCE_LEVEL_CHANGE),
    (Kind.DEVICE_COMPLIANCE_CHANGE, EventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE),
    (Kind.SESSION_ESTABLISHED, EventTypes.CAEP_SESSION_ESTABLISHED),
    (Kind.SESSION_PRESENTED, EventTypes.CAEP_SESSION_PRESENTED),
    (Kind.RISK_LEVEL_CHANGE, EventTypes.CAEP_RISK_LEVEL_CHANGE),
)
"""The known kinds and their event type URIs, in the order of the specification."""


class Event:
    """A CAEP 1.0 event of a SET, with typed access to the claims every CAEP event may carry
    (section 2) and to the event-specific claims of section 3. An accessor returns ``""`` (or an
    empty collection, or ``None``) when the claim is absent, whether because the transmitter left
    it out or because the :attr:`kind` does not define it. :attr:`payload` is the event as
    received, for anything else.

    The subject of the event is the ``sub_id`` of the SET, the subject of the event context in a
    handler: CAEP does not prescribe a subject format.
    """

    __slots__ = ("_event_type", "_kind", "_payload")

    def __init__(self, event_type: str, kind: Kind, payload: Claims) -> None:
        self._event_type = event_type
        self._kind = kind
        self._payload = payload

    @classmethod
    def of(cls, event_type: str, payload: Claims | None = None) -> Event | None:
        """The CAEP event with the given type (URI or alias) and payload; ``None`` if the type is
        not a CAEP event. Lenient: no payload is an empty one."""
        kind = Kind.of(event_type)
        if kind is None:
            return None
        return cls(event_types.resolve(event_type), kind, {} if payload is None else payload)

    @classmethod
    def in_token(cls, token: EventToken) -> list[Event]:
        """The CAEP events of a SET, in the order of their event type URIs (sorted, as the Go port
        does, so that the order is the same whatever the transmitter sent). CAEP allows one event
        per SET; a SET with several is read like one of each. A payload that is not a JSON object
        is read as an empty one."""
        events = []
        for event_type in sorted(token.events):
            event = cls.of(event_type, object_member(token.events, event_type))
            if event is not None:
                events.append(event)
        return events

    @property
    def event_type(self) -> str:
        """The event type URI."""
        return self._event_type

    @property
    def kind(self) -> Kind:
        """The kind of event."""
        return self._kind

    @property
    def payload(self) -> Claims:
        """The event payload as received."""
        return self._payload

    # CAEP section 2: claims every event may carry

    @property
    def event_timestamp(self) -> datetime | None:
        """The ``event_timestamp``, the time the event occurred. CAEP defines seconds since the
        epoch; a value that is clearly milliseconds is accepted too. ``None`` if absent."""
        return event_timestamp(self._payload.get("event_timestamp"))

    @property
    def initiating_entity(self) -> str:
        """The ``initiating_entity``, who invoked the event: ``admin``, ``user``, ``policy`` or
        ``system``."""
        return self._string("initiating_entity")

    @property
    def reason_admin(self) -> dict[str, str]:
        """The ``reason_admin``, the reason for administrators, by BCP 47 language tag (``en``,
        ``de-CH``, ...); empty if absent. A transmitter that sends a plain string instead of the
        localizable object of CAEP gets the key ``""``."""
        return localized(self._payload.get("reason_admin"))

    @property
    def reason_user(self) -> dict[str, str]:
        """The ``reason_user``, the reason for display to the end user, by BCP 47 language tag;
        empty if absent, a plain string under the key ``""``."""
        return localized(self._payload.get("reason_user"))

    # CAEP section 3: event-specific claims

    @property
    def claims(self) -> Claims | None:
        """The ``claims`` of a :attr:`Kind.TOKEN_CLAIMS_CHANGE`, each with its new value; ``None``
        if absent."""
        return object_member(self._payload, "claims")

    @property
    def credential_type(self) -> str:
        """The ``credential_type`` of a :attr:`Kind.CREDENTIAL_CHANGE`: ``password``, ``pin``,
        ``x509``, ``fido2-platform``, ``fido2-roaming``, ``fido-u2f``, ``verifiable-credential``,
        ``phone-voice``, ``phone-sms``, ``app`` or a value agreed with the transmitter."""
        return self._string("credential_type")

    @property
    def change_type(self) -> str:
        """The ``change_type`` of a :attr:`Kind.CREDENTIAL_CHANGE`: ``create``, ``revoke``,
        ``update`` or ``delete``."""
        return self._string("change_type")

    @property
    def friendly_name(self) -> str:
        """The ``friendly_name`` of the credential of a :attr:`Kind.CREDENTIAL_CHANGE`."""
        return self._string("friendly_name")

    @property
    def x509_issuer(self) -> str:
        """The ``x509_issuer`` of an X.509 credential."""
        return self._string("x509_issuer")

    @property
    def x509_serial(self) -> str:
        """The ``x509_serial`` of an X.509 credential."""
        return self._string("x509_serial")

    @property
    def fido2_aaguid(self) -> str:
        """The ``fido2_aaguid``, the FIDO2 Authenticator Attestation GUID of the credential."""
        return self._string("fido2_aaguid")

    @property
    def namespace(self) -> str:
        """The ``namespace`` of the levels of an :attr:`Kind.ASSURANCE_LEVEL_CHANGE`: ``RFC8176``,
        ``RFC6711``, ``ISO-IEC-29115``, ``NIST-IAL``, ``NIST-AAL``, ``NIST-FAL`` or a value agreed
        with the transmitter."""
        return self._string("namespace")

    @property
    def current_level(self) -> str:
        """The ``current_level``: the assurance level of an :attr:`Kind.ASSURANCE_LEVEL_CHANGE` in
        its :attr:`namespace`, or the risk level of a :attr:`Kind.RISK_LEVEL_CHANGE` (``LOW``,
        ``MEDIUM``, ``HIGH``)."""
        return self._string("current_level")

    @property
    def previous_level(self) -> str:
        """The ``previous_level`` of an assurance or risk level change, ``""`` if the transmitter
        does not know the previous level."""
        return self._string("previous_level")

    @property
    def change_direction(self) -> str:
        """The ``change_direction`` of an :attr:`Kind.ASSURANCE_LEVEL_CHANGE`: ``increase`` or
        ``decrease``."""
        return self._string("change_direction")

    @property
    def current_status(self) -> str:
        """The ``current_status`` of a :attr:`Kind.DEVICE_COMPLIANCE_CHANGE`: ``compliant`` or
        ``not-compliant``."""
        return self._string("current_status")

    @property
    def previous_status(self) -> str:
        """The ``previous_status`` of a :attr:`Kind.DEVICE_COMPLIANCE_CHANGE`."""
        return self._string("previous_status")

    @property
    def fp_ua(self) -> str:
        """The ``fp_ua``, the fingerprint of the user agent of a :attr:`Kind.SESSION_ESTABLISHED`
        or :attr:`Kind.SESSION_PRESENTED`."""
        return self._string("fp_ua")

    @property
    def acr(self) -> str:
        """The ``acr``, the authentication context class reference of a
        :attr:`Kind.SESSION_ESTABLISHED`, as in an ID Token."""
        return self._string("acr")

    @property
    def amr(self) -> list[str]:
        """The ``amr``, the authentication methods references of a
        :attr:`Kind.SESSION_ESTABLISHED`, as in an ID Token; empty if absent."""
        return strings(self._payload.get("amr"))

    @property
    def ext_id(self) -> str:
        """The ``ext_id``, the external session identifier of a :attr:`Kind.SESSION_ESTABLISHED`
        or :attr:`Kind.SESSION_PRESENTED` that correlates it with a broader session, for example a
        SAML one."""
        return self._string("ext_id")

    @property
    def principal(self) -> str:
        """The ``principal`` of a :attr:`Kind.RISK_LEVEL_CHANGE`, the entity whose risk changed:
        ``USER``, ``DEVICE``, ``SESSION``, ``TENANT``, ``ORG_UNIT``, ``GROUP`` or another entity
        of SSF."""
        return self._string("principal")

    @property
    def risk_reason(self) -> str:
        """The ``risk_reason`` of a :attr:`Kind.RISK_LEVEL_CHANGE`."""
        return self._string("risk_reason")

    def _string(self, name: str) -> str:
        return string_member(self._payload, name)

    def __repr__(self) -> str:
        return f"Event({self._kind.value}, {self._event_type!r})"


def _json_text(value: object) -> str:
    """A JSON value as its compact text, with the member names sorted as Go's ``json.Marshal`` does,
    so that the five ports render the same text."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def localized(value: object) -> dict[str, str]:
    """Reads a localizable claim as CAEP defines it (section 2): an object of texts by BCP 47
    language tag. A plain string is kept under the key ``""``, other values as their JSON; ``None``
    gives an empty dict."""
    if value is None:
        return {}
    if isinstance(value, str):
        return {"": value}
    if isinstance(value, dict):
        reasons: dict[str, str] = {}
        for tag, reason in value.items():
            if reason is None:
                continue
            reasons[tag] = reason if isinstance(reason, str) else _json_text(reason)
        return reasons
    return {"": _json_text(value)}


class PayloadBuilder:
    """Assembles the payload of a CAEP event for a transmitter or a test: the common claims of
    CAEP 1.0, section 2, and any event-specific ones.

    Example:
        >>> payload = (new_payload().event_timestamp(datetime.now(tz=UTC)).initiating_entity("admin")
        ...     .reason_admin("en", "Policy violation").build())
    """

    def __init__(self) -> None:
        self._claims: Claims = {}

    def event_timestamp(self, at: datetime) -> PayloadBuilder:
        """Sets ``event_timestamp``, in seconds since the epoch."""
        self._claims["event_timestamp"] = int(at.timestamp())
        return self

    def initiating_entity(self, entity: str) -> PayloadBuilder:
        """Sets ``initiating_entity``: ``admin``, ``user``, ``policy`` or ``system``."""
        self._claims["initiating_entity"] = entity
        return self

    def reason_admin(self, language: str, reason: str) -> PayloadBuilder:
        """Adds a ``reason_admin`` in the language, a BCP 47 tag such as ``en``."""
        return self._localized("reason_admin", language, reason)

    def reason_user(self, language: str, reason: str) -> PayloadBuilder:
        """Adds a ``reason_user`` in the language."""
        return self._localized("reason_user", language, reason)

    def _localized(self, name: str, language: str, text: str) -> PayloadBuilder:
        # The reasons are kept as the dict of a decoded payload, so that localized() reads them
        # back whether the payload was built or received.
        reasons = self._claims.get(name)
        if not isinstance(reasons, dict):
            reasons = {}
            self._claims[name] = reasons
        reasons[language] = text
        return self

    def claim(self, name: str, value: Any) -> PayloadBuilder:
        """Sets an event-specific claim such as ``credential_type`` or ``current_level``; ``None``
        removes it."""
        if value is None:
            self._claims.pop(name, None)
        else:
            self._claims[name] = value
        return self

    def build(self) -> Claims:
        """The payload as claims, a copy, to pass to :meth:`easyssf.core.SetBuilder.event`."""
        return copy.deepcopy(self._claims)


def new_payload() -> PayloadBuilder:
    """Starts an empty payload."""
    return PayloadBuilder()
