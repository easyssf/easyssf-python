"""The RISC 1.0 events: the kinds of section 2 and typed access to their few attributes (the
``reason`` of an account-disabled, the ``new-value`` of an identifier-changed, the
``credential_type`` of a credential-compromise). The port of ``ssf/risc`` of the Go port and of
``org.easyssf.core.risc``."""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from typing import Final

from . import event_types
from .claims import Claims, event_timestamp, object_member, string_member
from .event_types import EventTypes
from .token import EventToken

__all__ = ["KNOWN", "Event", "Kind"]


class Kind(Enum):
    """One of the events of RISC 1.0, section 2, or :attr:`OTHER` for an event type in the RISC
    namespace this version does not know. New kinds are added as RISC defines events, so do not
    match over them exhaustively; implement the receiver's RISC handler instead."""

    OTHER = "Other"
    """An event type in the RISC namespace this version does not know."""
    ACCOUNT_CREDENTIAL_CHANGE_REQUIRED = "AccountCredentialChangeRequired"
    """The account has to change its credential, for example after a leak elsewhere (section 2.1)."""
    ACCOUNT_PURGED = "AccountPurged"
    """The account was permanently deleted (section 2.2)."""
    ACCOUNT_DISABLED = "AccountDisabled"
    """The account was disabled, see :attr:`Event.reason` (section 2.3)."""
    ACCOUNT_ENABLED = "AccountEnabled"
    """The account was enabled again (section 2.4)."""
    IDENTIFIER_CHANGED = "IdentifierChanged"
    """The identifier of the subject, an email address or phone number, changed to
    :attr:`Event.new_value` (section 2.5)."""
    IDENTIFIER_RECYCLED = "IdentifierRecycled"
    """The identifier was given to someone else (section 2.6)."""
    CREDENTIAL_COMPROMISE = "CredentialCompromise"
    """A credential of the subject was found compromised, see :attr:`Event.credential_type`
    (section 2.7)."""
    OPT_IN = "OptIn"
    """The account takes part in the RISC exchange (section 2.8.1)."""
    OPT_OUT_INITIATED = "OptOutInitiated"
    """The user asked to leave the RISC exchange (section 2.8.2)."""
    OPT_OUT_CANCELLED = "OptOutCancelled"
    """The user withdrew the request to leave (section 2.8.3)."""
    OPT_OUT_EFFECTIVE = "OptOutEffective"
    """The account left the RISC exchange (section 2.8.4)."""
    RECOVERY_ACTIVATED = "RecoveryActivated"
    """The account went through a recovery flow (section 2.9)."""
    RECOVERY_INFORMATION_CHANGED = "RecoveryInformationChanged"
    """The recovery information of the account changed (section 2.10)."""
    SESSIONS_REVOKED = "SessionsRevoked"
    """All sessions of the account were revoked (section 2.11). Deprecated by RISC in favour of
    CAEP's session-revoked, still sent by some transmitters."""

    @property
    def event_type(self) -> str:
        """The event type URI of the kind, ``""`` for :attr:`OTHER`."""
        for kind, uri in KNOWN:
            if kind is self:
                return uri
        return ""

    @property
    def is_opt_out_state(self) -> bool:
        """Whether this is one of the opt-in and opt-out events of section 2.8, which report the
        participation of the account in the exchange rather than a risk."""
        return self in (Kind.OPT_IN, Kind.OPT_OUT_INITIATED, Kind.OPT_OUT_CANCELLED, Kind.OPT_OUT_EFFECTIVE)

    @classmethod
    def of(cls, event_type: str) -> Kind | None:
        """The kind of RISC event of an event type URI or alias: :attr:`OTHER` for an unknown
        event type in the RISC namespace, ``None`` if the event type is not a RISC event."""
        if not event_types.is_risc_event(event_type):
            return None
        uri = event_types.resolve(event_type)
        for kind, known in KNOWN:
            if known == uri:
                return kind
        return cls.OTHER

    def __str__(self) -> str:
        """The name of the kind: ``AccountDisabled``, ..., ``Other``."""
        return self.value


KNOWN: Final[tuple[tuple[Kind, str], ...]] = (
    (Kind.ACCOUNT_CREDENTIAL_CHANGE_REQUIRED, EventTypes.RISC_ACCOUNT_CREDENTIAL_CHANGE_REQUIRED),
    (Kind.ACCOUNT_PURGED, EventTypes.RISC_ACCOUNT_PURGED),
    (Kind.ACCOUNT_DISABLED, EventTypes.RISC_ACCOUNT_DISABLED),
    (Kind.ACCOUNT_ENABLED, EventTypes.RISC_ACCOUNT_ENABLED),
    (Kind.IDENTIFIER_CHANGED, EventTypes.RISC_IDENTIFIER_CHANGED),
    (Kind.IDENTIFIER_RECYCLED, EventTypes.RISC_IDENTIFIER_RECYCLED),
    (Kind.CREDENTIAL_COMPROMISE, EventTypes.RISC_CREDENTIAL_COMPROMISE),
    (Kind.OPT_IN, EventTypes.RISC_OPT_IN),
    (Kind.OPT_OUT_INITIATED, EventTypes.RISC_OPT_OUT_INITIATED),
    (Kind.OPT_OUT_CANCELLED, EventTypes.RISC_OPT_OUT_CANCELLED),
    (Kind.OPT_OUT_EFFECTIVE, EventTypes.RISC_OPT_OUT_EFFECTIVE),
    (Kind.RECOVERY_ACTIVATED, EventTypes.RISC_RECOVERY_ACTIVATED),
    (Kind.RECOVERY_INFORMATION_CHANGED, EventTypes.RISC_RECOVERY_INFORMATION_CHANGED),
    (Kind.SESSIONS_REVOKED, EventTypes.RISC_SESSIONS_REVOKED),
)
"""The known kinds and their event type URIs, in the order of the specification."""


class Event:
    """A RISC 1.0 event of a SET, with typed access to the few attributes RISC defines. Most RISC
    events have no attributes; :attr:`payload` is the event as received for anything else.

    The subject of the event is the ``sub_id`` of the SET, the subject of the event context in a
    handler.
    """

    __slots__ = ("_event_type", "_kind", "_payload")

    def __init__(self, event_type: str, kind: Kind, payload: Claims) -> None:
        self._event_type = event_type
        self._kind = kind
        self._payload = payload

    @classmethod
    def of(cls, event_type: str, payload: Claims | None = None) -> Event | None:
        """The RISC event with the given type (URI or alias) and payload; ``None`` if the type is
        not a RISC event. Lenient: no payload is an empty one."""
        kind = Kind.of(event_type)
        if kind is None:
            return None
        return cls(event_types.resolve(event_type), kind, {} if payload is None else payload)

    @classmethod
    def in_token(cls, token: EventToken) -> list[Event]:
        """The RISC events of a SET, in the order of their event type URIs (sorted, as the Go port
        does, so that the order is the same whatever the transmitter sent). A payload that is not
        a JSON object is read as an empty one."""
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

    @property
    def reason(self) -> str:
        """The ``reason`` of an :attr:`Kind.ACCOUNT_DISABLED`: ``hijacking`` or ``bulk-account``."""
        return self._string("reason")

    @property
    def new_value(self) -> str:
        """The ``new-value`` of an :attr:`Kind.IDENTIFIER_CHANGED`, the new identifier."""
        return self._string("new-value")

    @property
    def credential_type(self) -> str:
        """The ``credential_type`` of a :attr:`Kind.CREDENTIAL_COMPROMISE`, one of the values of
        CAEP's credential-change (``password``, ``pin``, ``x509``, ...)."""
        return self._string("credential_type")

    @property
    def event_timestamp(self) -> datetime | None:
        """The ``event_timestamp`` of a :attr:`Kind.CREDENTIAL_COMPROMISE`, when the transmitter
        discovered the compromise. RISC defines seconds since the epoch; a value that is clearly
        milliseconds is accepted too. ``None`` if absent."""
        return event_timestamp(self._payload.get("event_timestamp"))

    @property
    def reason_admin(self) -> str:
        """The ``reason_admin`` of a :attr:`Kind.CREDENTIAL_COMPROMISE`, the reason for
        administrators. RISC leaves the type open; a localizable object as CAEP defines it is
        returned as its JSON text."""
        return self._text("reason_admin")

    @property
    def reason_user(self) -> str:
        """The ``reason_user`` of a :attr:`Kind.CREDENTIAL_COMPROMISE`, the reason for the end
        user."""
        return self._text("reason_user")

    def _string(self, name: str) -> str:
        return string_member(self._payload, name)

    def _text(self, name: str) -> str:
        """A claim as text: a string as it is, anything else as its compact JSON with the member
        names sorted as Go's ``json.Marshal`` does, ``""`` if absent."""
        value = self._payload.get(name)
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)

    def __repr__(self) -> str:
        return f"Event({self._kind.value}, {self._event_type!r})"
