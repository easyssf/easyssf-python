"""SCIM Events (RFC 9967): the operations, the scim subject (a SCIM resource named by its ``uri``,
``id`` and ``externalId``) and typed access to the ``attributes`` and ``data`` members of the
payload. The port of ``ssf/scim`` of the Go port and of ``org.easyssf.core.scim``."""

from __future__ import annotations

from enum import Enum
from typing import Final

from . import event_types
from .claims import Claims, object_member, string_member, strings
from .event_types import EventTypes
from .subject import Subject, SubjectIdentifier
from .token import EventToken

__all__ = ["KNOWN", "Event", "Operation", "ScimSubject", "is_scim_event"]


class Operation(Enum):
    """What a SCIM Event (RFC 9967) reports, independent of whether its payload carries the
    resource (full) or only names the attributes that changed (notice). The specification may add
    operations; do not match over them exhaustively."""

    UNKNOWN = "Unknown"
    """Not a SCIM Event."""
    FEED_ADD = "FeedAdd"
    """The resource joined the event feed (section 2.3.1), it is not necessarily new."""
    FEED_REMOVE = "FeedRemove"
    """The resource left the event feed (section 2.3.2), it was not necessarily deleted."""
    CREATE = "Create"
    """The resource was created (section 2.4.1)."""
    PATCH = "Patch"
    """The resource was modified with SCIM PATCH (section 2.4.2)."""
    PUT = "Put"
    """The resource was replaced with SCIM PUT (section 2.4.3)."""
    DELETE = "Delete"
    """The resource was deleted, and thereby removed from the feed (section 2.4.4)."""
    ACTIVATE = "Activate"
    """The resource was activated, for example its account may be logged in to (section 2.4.5)."""
    DEACTIVATE = "Deactivate"
    """The resource was deactivated, typically its user may no longer have an active session
    (section 2.4.6)."""
    ASYNC_RESPONSE = "AsyncResponse"
    """An asynchronous SCIM request completed (section 2.5.1.3)."""

    @property
    def event_types(self) -> tuple[str, ...]:
        """The event type URIs that report this operation, one or, for the provisioning operations
        with a notice and a full variant, two; none for :attr:`UNKNOWN`."""
        return tuple(uri for operation, uri in KNOWN if operation is self)

    @property
    def is_provisioning(self) -> bool:
        """Whether this is one of the provisioning operations of section 2.4, which report a
        change of the resource at the SCIM service provider."""
        return self not in (Operation.UNKNOWN, Operation.FEED_ADD, Operation.FEED_REMOVE, Operation.ASYNC_RESPONSE)

    @classmethod
    def of(cls, event_type: str) -> Operation:
        """The operation an event type URI or alias reports, :attr:`UNKNOWN` if it is not a SCIM
        Event."""
        uri = event_types.resolve(event_type)
        for operation, known in KNOWN:
            if known == uri:
                return operation
        return cls.UNKNOWN

    def __str__(self) -> str:
        """The name of the operation: ``FeedAdd``, ``Create``, ..., ``Unknown``."""
        return self.value


KNOWN: Final[tuple[tuple[Operation, str], ...]] = (
    (Operation.FEED_ADD, EventTypes.SCIM_FEED_ADD),
    (Operation.FEED_REMOVE, EventTypes.SCIM_FEED_REMOVE),
    (Operation.CREATE, EventTypes.SCIM_PROV_CREATE_NOTICE),
    (Operation.CREATE, EventTypes.SCIM_PROV_CREATE_FULL),
    (Operation.PATCH, EventTypes.SCIM_PROV_PATCH_NOTICE),
    (Operation.PATCH, EventTypes.SCIM_PROV_PATCH_FULL),
    (Operation.PUT, EventTypes.SCIM_PROV_PUT_NOTICE),
    (Operation.PUT, EventTypes.SCIM_PROV_PUT_FULL),
    (Operation.DELETE, EventTypes.SCIM_PROV_DELETE),
    (Operation.ACTIVATE, EventTypes.SCIM_PROV_ACTIVATE),
    (Operation.DEACTIVATE, EventTypes.SCIM_PROV_DEACTIVATE),
    (Operation.ASYNC_RESPONSE, EventTypes.SCIM_MISC_ASYNC_RESPONSE),
)
"""The operations and the event type URIs that report them, in the order of RFC 9967."""


def is_scim_event(event_type: str) -> bool:
    """Whether the event type (URI or alias) is one of SCIM Events, i.e. reports a known
    :class:`Operation`; unlike :func:`easyssf.core.event_types.is_scim_event` this does not accept
    an unknown event type in the SCIM namespace."""
    return Operation.of(event_type) is not Operation.UNKNOWN


class ScimSubject:
    """The subject of a SCIM Event (RFC 9967, section 2.1): a SCIM resource named by a ``scim``
    subject identifier. The identifier carries the relative ``uri`` of the resource (its resource
    type endpoint plus its id, for example ``/Users/2b2f880af6674ac284bae9381673d462``), the
    ``externalId`` and ``id`` of the resource if known, and possibly further attributes of the
    resource that are unique at the SCIM service provider, such as ``userName``.

    Named ``ScimSubject`` so that it does not clash with :class:`easyssf.core.Subject`, the subject
    of a SET.
    """

    __slots__ = ("_identifier",)

    def __init__(self, identifier: SubjectIdentifier) -> None:
        self._identifier = identifier

    @classmethod
    def from_identifier(cls, identifier: SubjectIdentifier | None) -> ScimSubject | None:
        """The SCIM subject of an identifier, ``None`` if the identifier is ``None`` or not of
        format ``scim``."""
        if identifier is None or not identifier.is_scim:
            return None
        return cls(identifier)

    @classmethod
    def of(cls, subject: Subject | None) -> ScimSubject | None:
        """The SCIM subject of a SET's subject, ``None`` if the subject is not a ``scim``
        identifier (nor a complex subject whose user is one)."""
        if subject is None:
            return None
        return cls.from_identifier(subject.user_identifier)

    @property
    def identifier(self) -> SubjectIdentifier:
        """The ``scim`` subject identifier as received."""
        return self._identifier

    @property
    def uri(self) -> str:
        """The relative path of the resource at the SCIM service provider, which RFC 9967
        requires; ``""`` if the transmitter left it out nevertheless."""
        return self._identifier.claim("uri")

    @property
    def resource_type(self) -> str:
        """The resource type endpoint of the :attr:`uri`, for example ``Users`` or ``Groups``;
        ``""`` if the uri has no such segment."""
        segments = self._segments()
        if len(segments) < 2:
            return ""
        return segments[-2]

    @property
    def id(self) -> str:
        """The id of the resource: the ``id`` attribute of the identifier or, if absent, the last
        segment of the :attr:`uri`; ``""`` if there is neither."""
        resource_id = self._identifier.claim("id")
        if resource_id:
            return resource_id
        segments = self._segments()
        return segments[-1] if segments else ""

    @property
    def external_id(self) -> str:
        """The ``externalId`` of the resource, the identifier the receiver's domain knows it by;
        ``""`` if absent."""
        return self._identifier.claim("externalId")

    def attribute(self, name: str) -> str:
        """A further attribute of the identifier, such as ``userName``; ``""`` if absent or not a
        non-empty string."""
        return self._identifier.claim(name)

    @property
    def claims(self) -> Claims:
        """All members of the identifier as received, including ``format``."""
        return self._identifier.claims

    def _segments(self) -> list[str]:
        uri = self.uri
        if not uri:
            return []
        path = uri.split("?", 1)[0]
        return [segment for segment in path.split("/") if segment]

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ScimSubject) and other._identifier == self._identifier

    def __hash__(self) -> int:
        return hash(self._identifier)

    def __repr__(self) -> str:
        return f"ScimSubject({self._identifier.claims!r})"


class Event:
    """A SCIM Event (RFC 9967) of a SET, with typed access to the common payload attributes of
    section 2.2: the resource as :attr:`data` in full mode, the modified :attr:`attributes` in
    notice mode, and the ETag :attr:`version` of the resource after the event. The ``txn`` that
    groups the SETs of one transaction is a claim of the :class:`easyssf.core.EventToken`.

    A SET may carry several SCIM Events; RFC 9967 then has them arise from the same change of the
    same resource, so they share the :attr:`subject`.
    """

    __slots__ = ("_event_type", "_operation", "_payload", "_subject")

    def __init__(self, event_type: str, operation: Operation, subject: ScimSubject | None, payload: Claims) -> None:
        self._event_type = event_type
        self._operation = operation
        self._subject = subject
        self._payload = payload

    @classmethod
    def of(cls, event_type: str, subject: ScimSubject | None = None, payload: Claims | None = None) -> Event | None:
        """The event with the given type (URI or alias), the SCIM subject of the SET (``None`` if
        it has none) and the payload; ``None`` if the type is not one of SCIM Events. Lenient: no
        payload is an empty one."""
        operation = Operation.of(event_type)
        if operation is Operation.UNKNOWN:
            return None
        return cls(event_types.resolve(event_type), operation, subject, {} if payload is None else payload)

    @classmethod
    def in_token(cls, token: EventToken) -> list[Event]:
        """The SCIM Events of a SET, in the order of their event type URIs (sorted, as the Go port
        does, so that the order is the same whatever the transmitter sent). A payload that is not
        a JSON object is read as an empty one."""
        subject = ScimSubject.of(Subject.from_claims(token.subject_id))
        events = []
        for event_type in sorted(token.events):
            event = cls.of(event_type, subject, object_member(token.events, event_type))
            if event is not None:
                events.append(event)
        return events

    @property
    def event_type(self) -> str:
        """The event type URI."""
        return self._event_type

    @property
    def operation(self) -> Operation:
        """What the event reports."""
        return self._operation

    @property
    def subject(self) -> ScimSubject | None:
        """The SCIM resource the event is about, ``None`` if the ``sub_id`` of the SET is not a
        ``scim`` subject identifier (which RFC 9967 requires, but a handler should expect)."""
        return self._subject

    @property
    def payload(self) -> Claims:
        """The event payload as received."""
        return self._payload

    @property
    def is_full(self) -> bool:
        """Whether the payload carries the resource as :attr:`data`: the event type ends in
        ``:full``."""
        return self._event_type.endswith(":full")

    @property
    def is_notice(self) -> bool:
        """Whether the payload only names the modified :attr:`attributes`: the event type ends in
        ``:notice``. A receiver may fetch the resource from the SCIM service provider with a GET of
        the subject's uri."""
        return self._event_type.endswith(":notice")

    @property
    def data(self) -> Claims | None:
        """The ``data`` of a full event: the representation of the created or replaced resource,
        or the PatchOp applied; ``None`` if absent."""
        return object_member(self._payload, "data")

    @property
    def attributes(self) -> list[str]:
        """The ``attributes`` of a notice event: the paths of the attributes created, modified or
        removed; empty if absent."""
        return strings(self._payload.get("attributes"))

    @property
    def version(self) -> str:
        """The ETag ``version`` of the resource after the event."""
        return string_member(self._payload, "version")

    @property
    def method(self) -> str:
        """The HTTP ``method`` of the request an :attr:`Operation.ASYNC_RESPONSE` reports on,
        ``""`` for other events."""
        return string_member(self._payload, "method")

    @property
    def status(self) -> str:
        """The HTTP ``status`` of the request an :attr:`Operation.ASYNC_RESPONSE` reports on, as a
        string like the SCIM bulk response has it; ``""`` for other events."""
        return string_member(self._payload, "status")

    @property
    def response(self) -> Claims | None:
        """The SCIM error ``response`` of a failed request an :attr:`Operation.ASYNC_RESPONSE`
        reports on, with ``scimType`` and ``detail``; ``None`` if the request succeeded or for
        other events."""
        return object_member(self._payload, "response")

    def __repr__(self) -> str:
        return f"Event({self._operation.value}, {self._event_type!r})"
