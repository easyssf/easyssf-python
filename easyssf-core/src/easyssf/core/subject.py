"""Subjects of SETs: subject identifiers (RFC 9493) and complex subjects (SSF 1.0, section 5)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Final

from .claims import Claims, object_member, string_member

__all__ = [
    "ALL_SESSIONS",
    "MEMBERS",
    "Format",
    "Member",
    "Subject",
    "SubjectIdentifier",
]


class Format:
    """Subject identifier formats of RFC 9493 and the ``scim`` format of SCIM Events (RFC 9967).

    An open set: any format is represented by :class:`SubjectIdentifier`, these are known by name.
    """

    ACCOUNT: Final = "account"
    """An ``acct:`` URI (RFC 7565)."""
    EMAIL: Final = "email"
    """An email address."""
    ISS_SUB: Final = "iss_sub"
    """An issuer and the subject at that issuer."""
    OPAQUE: Final = "opaque"
    """An identifier that does not tell what it names."""
    PHONE_NUMBER: Final = "phone_number"
    """E.164."""
    DID: Final = "did"
    """A decentralized identifier."""
    URI: Final = "uri"
    """A URI."""
    ALIASES: Final = "aliases"
    """Several identifiers that name the same subject."""
    SCIM: Final = "scim"
    """A SCIM resource named by its relative uri, with its externalId and id if known (RFC 9967, 2.1)."""
    COMPLEX: Final = "complex"
    """Marks a complex subject (SSF 1.0, section 5)."""


class Member:
    """The members of a complex subject (SSF 1.0, section 5)."""

    USER: Final = "user"
    SESSION: Final = "session"
    DEVICE: Final = "device"
    APPLICATION: Final = "application"
    TENANT: Final = "tenant"
    ORG_UNIT: Final = "org_unit"
    GROUP: Final = "group"


MEMBERS: Final[tuple[str, ...]] = (
    Member.USER,
    Member.SESSION,
    Member.DEVICE,
    Member.APPLICATION,
    Member.TENANT,
    Member.ORG_UNIT,
    Member.GROUP,
)
"""The members of a complex subject :class:`Subject` gives access to, in the order of SSF 1.0."""

ALL_SESSIONS: Final = "ALL"
"""The session identifier Keycloak uses to refer to all sessions of a user."""

_VALUE_MEMBER: Final[dict[str, str]] = {
    Format.ISS_SUB: "sub",
    Format.EMAIL: "email",
    Format.OPAQUE: "id",
    Format.ACCOUNT: "uri",
    Format.URI: "uri",
    Format.SCIM: "uri",
    Format.PHONE_NUMBER: "phone_number",
    Format.DID: "url",
}


class SubjectIdentifier:
    """A subject identifier (RFC 9493): a format and the members that format defines.

    Any format is represented, the ones of RFC 9493 and the ``scim`` format are known by name.
    """

    __slots__ = ("_claims", "_format")

    def __init__(self, fmt: str, claims: Claims) -> None:
        self._format = fmt
        self._claims = claims

    @classmethod
    def from_claims(cls, identifier: Claims | None) -> SubjectIdentifier | None:
        """Reads an identifier. Lenient: ``None`` if it has no non-blank string ``format``."""
        fmt = string_member(identifier, "format")
        if not fmt or identifier is None:
            return None
        return cls(fmt, identifier)

    @property
    def format(self) -> str:
        """The format, never empty."""
        return self._format

    @property
    def claims(self) -> Claims:
        """The members of the identifier as received, including ``format``."""
        return self._claims

    def is_format(self, fmt: str) -> bool:
        """Whether the identifier has the given format."""
        return self._format == fmt

    @property
    def is_iss_sub(self) -> bool:
        """Whether the format is ``iss_sub``."""
        return self.is_format(Format.ISS_SUB)

    @property
    def is_email(self) -> bool:
        """Whether the format is ``email``."""
        return self.is_format(Format.EMAIL)

    @property
    def is_opaque(self) -> bool:
        """Whether the format is ``opaque``."""
        return self.is_format(Format.OPAQUE)

    @property
    def is_scim(self) -> bool:
        """Whether the format is ``scim``."""
        return self.is_format(Format.SCIM)

    def claim(self, name: str) -> str:
        """A member of the identifier, ``""`` if absent or not a non-blank string."""
        return string_member(self._claims, name)

    @property
    def issuer(self) -> str:
        """The issuer of an ``iss_sub`` identifier, ``""`` for other formats."""
        return self.claim("iss") if self.is_iss_sub else ""

    @property
    def value(self) -> str:
        """The member that identifies the subject within its format.

        ``sub`` of ``iss_sub``, ``email``, ``id`` of ``opaque``, ``uri`` of ``account``, ``uri`` and
        ``scim``, ``phone_number``, ``url`` of ``did``. ``""`` for ``aliases`` and unknown formats.
        """
        member = _VALUE_MEMBER.get(self._format)
        return self.claim(member) if member else ""

    @property
    def aliases(self) -> list[SubjectIdentifier]:
        """The identifiers of an ``aliases`` identifier, empty for other formats."""
        if not self.is_format(Format.ALIASES):
            return []
        identifiers = self._claims.get("identifiers")
        if not isinstance(identifiers, list):
            return []
        result = []
        for element in identifiers:
            alias = SubjectIdentifier.from_claims(element if isinstance(element, dict) else None)
            if alias is not None:
                result.append(alias)
        return result

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SubjectIdentifier) and other._format == self._format and other._claims == self._claims

    def __hash__(self) -> int:
        return hash((self._format, _hashable(self._claims)))

    def __repr__(self) -> str:
        return f"SubjectIdentifier({self._claims!r})"


def _hashable(value: object) -> object:
    if isinstance(value, dict):
        return tuple(sorted((k, _hashable(v)) for k, v in value.items()))
    if isinstance(value, list):
        return tuple(_hashable(v) for v in value)
    return value


class Subject:
    """The subject of a SET (its ``sub_id`` claim): a simple subject identifier (RFC 9493), or a
    complex subject whose members (user, session, device, tenant, ...) are identifiers.

    :attr:`user_identifier` and :attr:`session` are the two members the receiver acts on, and
    :attr:`issuer`, :attr:`sub`, :attr:`session_id`, :attr:`email` and :attr:`opaque_id` are
    shortcuts to their most common values. Everything else is available through :meth:`member`
    and :attr:`raw`.

    Keycloak reports the revocation of all sessions of a user with a session member whose
    identifier is :data:`ALL_SESSIONS`. Such a subject is resolved like one that names only the
    user: it has no session.

    :meth:`empty` is the subject of a SET that carried none.
    """

    __slots__ = ("_identifier", "_members", "_raw")

    def __init__(
        self,
        raw: Claims | None = None,
        identifier: SubjectIdentifier | None = None,
        members: tuple[tuple[str, SubjectIdentifier], ...] = (),
    ) -> None:
        self._raw = raw
        self._identifier = identifier
        self._members = members

    @classmethod
    def empty(cls) -> Subject:
        """The subject of a SET that carried none."""
        return cls()

    @classmethod
    def from_claims(cls, subject_id: Claims | None) -> Subject:
        """Resolves the given ``sub_id`` claim; lenient, empty for ``None`` or an empty object."""
        if not subject_id:
            return cls.empty()
        fmt = subject_id.get("format")
        has_format = isinstance(fmt, str)
        # Early SSF drafts used complex subjects without a format member
        is_complex = fmt == Format.COMPLEX or (not has_format and _has_object_members(subject_id))
        if not is_complex:
            return cls(subject_id, SubjectIdentifier.from_claims(subject_id))
        members = []
        for name in sorted(subject_id):
            identifier = SubjectIdentifier.from_claims(object_member(subject_id, name))
            if identifier is not None:
                members.append((name, identifier))
        subject = cls(subject_id, None, tuple(members))
        session = subject.session
        if session is not None and subject.user is not None and session.is_opaque and session.value == ALL_SESSIONS:
            subject = cls(subject_id, None, subject._members_without(Member.SESSION))
        return subject

    @property
    def raw(self) -> Claims | None:
        """The subject identifier as received, ``None`` if the SET carried none."""
        return self._raw

    @property
    def identifier(self) -> SubjectIdentifier | None:
        """The identifier of a simple subject, ``None`` for a complex subject or none."""
        return self._identifier

    @property
    def members(self) -> Iterator[tuple[str, SubjectIdentifier]]:
        """The members of a complex subject, by name in alphabetical order; a simple subject has none."""
        return iter(self._members)

    @property
    def member_names(self) -> list[str]:
        """The names of the members of a complex subject, whether or not :meth:`member` can read
        them; empty for a simple subject."""
        if self._identifier is not None or not self._raw:
            return []
        return [name for name in sorted(self._raw) if name != "format" and isinstance(self._raw[name], dict)]

    @property
    def is_complex(self) -> bool:
        """Whether this is a complex subject."""
        return len(self._members) > 0

    def member(self, name: str) -> SubjectIdentifier | None:
        """The member of a complex subject with the given name, ``None`` if absent."""
        for member_name, identifier in self._members:
            if member_name == name:
                return identifier
        return None

    @property
    def user(self) -> SubjectIdentifier | None:
        """The ``user`` member of a complex subject."""
        return self.member(Member.USER)

    @property
    def session(self) -> SubjectIdentifier | None:
        """The ``session`` member of a complex subject."""
        return self.member(Member.SESSION)

    @property
    def device(self) -> SubjectIdentifier | None:
        """The ``device`` member of a complex subject."""
        return self.member(Member.DEVICE)

    @property
    def application(self) -> SubjectIdentifier | None:
        """The ``application`` member of a complex subject."""
        return self.member(Member.APPLICATION)

    @property
    def tenant(self) -> SubjectIdentifier | None:
        """The ``tenant`` member of a complex subject."""
        return self.member(Member.TENANT)

    @property
    def org_unit(self) -> SubjectIdentifier | None:
        """The ``org_unit`` member of a complex subject."""
        return self.member(Member.ORG_UNIT)

    @property
    def group(self) -> SubjectIdentifier | None:
        """The ``group`` member of a complex subject."""
        return self.member(Member.GROUP)

    @property
    def user_identifier(self) -> SubjectIdentifier | None:
        """The identifier that names the user: the user member of a complex subject, or the
        identifier of a simple subject unless it is opaque, which may as well name a session (see
        :attr:`opaque_id`). ``None`` if the subject does not name a user."""
        if self._identifier is not None:
            return None if self._identifier.is_opaque else self._identifier
        return self.user

    @property
    def issuer(self) -> str:
        """The issuer of the user, from an ``iss_sub`` identifier."""
        user = self.user_identifier
        return user.issuer if user is not None else ""

    @property
    def sub(self) -> str:
        """The identifier of the user at the issuer: ``sub`` of an ``iss_sub`` identifier, or the
        ``id`` of an opaque user of a complex subject."""
        user = self.user_identifier
        if user is None or not (user.is_iss_sub or user.is_opaque):
            return ""
        return user.value

    @property
    def session_id(self) -> str:
        """The identifier of the session."""
        session = self.session
        return session.value if session is not None else ""

    @property
    def email(self) -> str:
        """The email address of the user, from an ``email`` identifier."""
        user = self.user_identifier
        return user.value if user is not None and user.is_email else ""

    @property
    def opaque_id(self) -> str:
        """The identifier of a simple opaque subject, which does not tell whether it names a user
        or a session."""
        if self._identifier is not None and self._identifier.is_opaque:
            return self._identifier.value
        return ""

    @property
    def is_empty(self) -> bool:
        """Whether the SET carried no subject identifier that could be resolved."""
        return self._identifier is None and not self._members

    @property
    def has_user(self) -> bool:
        """Whether this subject identifies a user (as opposed to only a session)."""
        return self.user_identifier is not None

    def without_session(self) -> Subject:
        """This subject without its session, i.e. widened to the user."""
        if self.session is None:
            return self
        return Subject(self._raw, self._identifier, self._members_without(Member.SESSION))

    def _members_without(self, name: str) -> tuple[tuple[str, SubjectIdentifier], ...]:
        return tuple(m for m in self._members if m[0] != name)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Subject) and other._raw == self._raw and other._members == self._members

    def __hash__(self) -> int:
        return hash((_hashable(self._raw), self._members))

    def __repr__(self) -> str:
        return f"Subject({self._raw!r})"


def _has_object_members(obj: Claims) -> bool:
    return any(isinstance(value, dict) for value in obj.values())
