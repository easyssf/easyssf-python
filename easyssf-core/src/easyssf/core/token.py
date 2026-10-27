"""Security Event Tokens (RFC 8417) with the SSF profile claims: the verified token and the
builder that makes the claims of one."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from . import event_types
from .claims import Claims, as_int, audiences, object_member, string_member

__all__ = ["EventToken", "SetBuilder", "SubjectCompatibilityMode", "new_jti", "new_set"]


def new_jti() -> str:
    """A random, 128 bit, hex-encoded SET identifier."""
    return secrets.token_hex(16)


class EventToken:
    """A verified Security Event Token (SET, RFC 8417) with the SSF profile claims. Immutable."""

    __slots__ = ("_aud", "_claims", "_events", "_iat", "_iss", "_jti", "_subject_id", "_txn")

    def __init__(
        self,
        *,
        jti: str,
        iss: str,
        iat: int,
        aud: list[str],
        events: Claims,
        subject_id: Claims | None,
        txn: str,
        claims: Claims,
    ) -> None:
        self._jti = jti
        self._iss = iss
        self._iat = iat
        self._aud = aud
        self._events = events
        self._subject_id = subject_id
        self._txn = txn
        self._claims = claims

    @classmethod
    def from_claims(cls, claims: Claims | None) -> EventToken | None:
        """Builds a token from decoded claims.

        Lenient: ``None`` if the claims lack a non-blank ``jti``, a string ``iss``, a numeric
        ``iat`` or a non-empty ``events`` object (RFC 8417, section 2.2). The verifier applies the
        rules that produce error codes; this only shapes the result.
        """
        if not claims:
            return None
        jti = string_member(claims, "jti")
        if not jti:
            return None
        iss = claims.get("iss")
        if not isinstance(iss, str):
            return None
        iat = as_int(claims.get("iat"))
        if iat is None:
            return None
        events = object_member(claims, "events")
        if not events:
            return None
        subject_id = object_member(claims, "sub_id") or None
        txn = claims.get("txn")
        return cls(
            jti=jti,
            iss=iss,
            iat=iat,
            aud=audiences(claims.get("aud")),
            events=events,
            subject_id=subject_id,
            txn=txn if isinstance(txn, str) else "",
            claims=claims,
        )

    @property
    def jti(self) -> str:
        """The ``jti`` claim, the identifier of the SET, unique per issuer."""
        return self._jti

    @property
    def issuer(self) -> str:
        """The ``iss`` claim, the issuer of the SET (the transmitter)."""
        return self._iss

    @property
    def issued_at_seconds(self) -> int:
        """The ``iat`` claim, seconds since the epoch."""
        return self._iat

    @property
    def issued_at(self) -> datetime:
        """The ``iat`` claim as a point in time (UTC)."""
        return datetime.fromtimestamp(self._iat, tz=UTC)

    @property
    def audience(self) -> list[str]:
        """The ``aud`` claim, a single value as a list of one, empty if the claim was absent."""
        return self._aud

    @property
    def events(self) -> Claims:
        """The ``events`` claim: event payloads keyed by event type URI."""
        return self._events

    @property
    def subject_id(self) -> Claims | None:
        """The top-level ``sub_id`` claim SSF 1.0 requires, ``None`` if absent or empty."""
        return self._subject_id

    @property
    def txn(self) -> str:
        """The ``txn`` claim, the transaction identifier that groups SETs (RFC 8417, section 2.2),
        ``""`` if absent."""
        return self._txn

    @property
    def claims(self) -> Claims:
        """All claims of the SET as received. Do not modify them."""
        return self._claims

    @property
    def idempotency_key(self) -> str:
        """The key that identifies this SET across deliveries: the issuer and the ``jti``, which is
        only unique per issuer (RFC 8417, section 2.2).

        A handler that has side effects outside the receiver's stores uses it to make them
        idempotent, because a SET may be handled more than once: after a handler failed, or on
        another instance after the one that handled it died before recording the success.
        """
        return f"{self._iss}::{self._jti}"

    def __repr__(self) -> str:
        return f"EventToken(iss={self._iss!r}, jti={self._jti!r}, events={list(self._events)!r})"


class SubjectCompatibilityMode(Enum):
    """Which convention for the subject of a SET a peer follows.

    SSF 1.0 requires a top-level ``sub_id`` claim in every SET, including those of the CAEP and
    RISC event types defined before it; earlier drafts put the subject into the event payload
    instead. A receiver validates by it, a transmitter would emit by it.
    """

    STRICT = "strict"
    """SSF 1.0: a SET without a top-level ``sub_id`` is rejected as ``invalid_request``. The default."""
    LEGACY = "legacy"
    """Makes the top-level ``sub_id`` optional, for transmitters that follow earlier drafts; the
    event context then reads the ``subject`` member of the event payload."""

    def __str__(self) -> str:
        """The name used in configuration: ``strict`` or ``legacy``."""
        return self.value


class SetBuilder:
    """Assembles the claims of a Security Event Token (RFC 8417, section 2.2) for a transmitter or
    a test: ``iss``, ``jti``, ``iat``, ``aud``, ``sub_id``, ``txn`` and ``events``. The builder
    gives the claims; a signer such as :mod:`easyssf.core.signing` turns them into a SET.

    Example:
        >>> claims = (new_set("https://idp.example")
        ...     .audience("https://app.example")
        ...     .subject(email("alice@example.com"))
        ...     .event("CaepSessionRevoked", {"event_timestamp": 1700000000})
        ...     .claims())
    """

    def __init__(self, issuer: str) -> None:
        self._claims: Claims = {"iss": issuer, "jti": new_jti(), "iat": int(datetime.now(tz=UTC).timestamp())}
        self._events: Claims = {}
        self._errors: list[str] = []

    def jti(self, jti: str) -> SetBuilder:
        """Sets the identifier of the SET instead of the random one."""
        self._claims["jti"] = jti
        return self

    def issued_at(self, issued_at: datetime | int) -> SetBuilder:
        """Sets ``iat``, in seconds since the epoch, instead of now."""
        self._claims["iat"] = issued_at if isinstance(issued_at, int) else int(issued_at.timestamp())
        return self

    def audience(self, *audience: str) -> SetBuilder:
        """Sets ``aud``: one string for one audience, an array for several, as RFC 8417, section
        2.2 allows both; none removes the claim."""
        if not audience:
            self._claims.pop("aud", None)
        elif len(audience) == 1:
            self._claims["aud"] = audience[0]
        else:
            self._claims["aud"] = list(audience)
        return self

    def subject(self, subject: Claims | None) -> SetBuilder:
        """Sets ``sub_id``, a subject identifier or complex subject built with
        :mod:`easyssf.core.subjects`; ``None`` removes it."""
        if subject is None:
            self._claims.pop("sub_id", None)
        else:
            self._claims["sub_id"] = subject
        return self

    def txn(self, txn: str) -> SetBuilder:
        """Sets the transaction identifier (RFC 8417, section 2.2); ``""`` removes it."""
        if not txn:
            self._claims.pop("txn", None)
        else:
            self._claims["txn"] = txn
        return self

    def event(self, event_type: str, payload: Claims | None = None) -> SetBuilder:
        """Adds an event: ``event_type`` is an alias such as ``CaepSessionRevoked`` or an event
        type URI, ``payload`` its claims (an empty object if ``None``).

        A SET with several events is allowed by RFC 8417 but SSF 1.0, section 6, has a transmitter
        send one event per SET.
        """
        if not event_type:
            self._errors.append("event type must not be empty")
            return self
        self._events[event_types.resolve(event_type)] = {} if payload is None else payload
        return self

    def claim(self, name: str, value: Any) -> SetBuilder:
        """Sets any other claim, for example the ones of a profile; ``None`` removes it. The events
        are set with :meth:`event`."""
        if value is None:
            self._claims.pop(name, None)
        else:
            self._claims[name] = value
        return self

    def claims(self) -> Claims:
        """The claims of the SET, a copy.

        Raises:
            ValueError: if ``iss``, ``jti`` or ``iat`` is missing or no event was added: a SET must
                have an ``events`` claim with at least one member (RFC 8417, section 2.2).
        """
        if self._errors:
            raise ValueError("; ".join(self._errors))
        missing = [name for name in ("iss", "jti", "iat") if self._claims.get(name) in (None, "")]
        if missing:
            raise ValueError(f"SET lacks {missing}")
        if not self._events:
            raise ValueError("SET has no event")
        claims = dict(self._claims)
        claims["events"] = {event_type: dict(payload) for event_type, payload in self._events.items()}
        return claims


def new_set(issuer: str) -> SetBuilder:
    """Starts a SET of the issuer with a random ``jti`` and ``iat`` now."""
    return SetBuilder(issuer)
