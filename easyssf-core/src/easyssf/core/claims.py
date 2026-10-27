"""JSON claims as decoded by ``json.loads`` and the lenient accessors that read them.

The claims of a SET, an event payload, a subject identifier and a stream configuration are all
plain JSON objects. Nothing here raises for input that does not fit: an accessor returns ``""``,
``None`` or an empty list, and the verifier applies the rules that produce error codes.
"""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from typing import Any, TypeAlias

__all__ = [
    "Claims",
    "as_int",
    "audiences",
    "event_timestamp",
    "is_object",
    "object_member",
    "parse_claims",
    "string_member",
    "strings",
]

Claims: TypeAlias = dict[str, Any]
"""A JSON object as decoded by ``json.loads``: the claims of a SET, an event payload, a subject
identifier. Numbers are ``int`` or ``float``, nested objects are ``Claims``-shaped dicts."""

_MILLISECONDS_THRESHOLD = 100_000_000_000


def string_member(obj: Claims | None, name: str) -> str:
    """The member with the given name if it is a non-blank string, ``""`` otherwise."""
    if not obj:
        return ""
    value = obj.get(name)
    if isinstance(value, str) and value.strip():
        return value
    return ""


def is_object(value: object) -> bool:
    """Whether the value is a JSON object (a dict)."""
    return isinstance(value, dict)


def object_member(obj: Claims | None, name: str) -> Claims | None:
    """The member with the given name if it is a JSON object, ``None`` otherwise."""
    if not obj:
        return None
    value = obj.get(name)
    return value if isinstance(value, dict) else None


def as_int(value: object) -> int | None:
    """A JSON number as an integer, ``None`` if the value is not a finite number.

    ``bool`` is a number to Python but not to JSON, so ``True`` is not ``1`` here.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        return int(value)
    return None


def strings(value: object) -> list[str]:
    """A JSON array of strings; other values give an empty list, non-string elements are skipped."""
    if not isinstance(value, list):
        return []
    return [element for element in value if isinstance(element, str)]


def audiences(aud: object) -> list[str]:
    """An ``aud`` claim as a list: a string as a list of one, an array of its strings, empty otherwise."""
    if isinstance(aud, str):
        return [aud]
    if isinstance(aud, list):
        return strings(aud)
    return []


def event_timestamp(value: object) -> datetime | None:
    """An ``event_timestamp`` claim of an event payload as a point in time.

    CAEP 1.0 (section 2) and RISC 1.0 (section 2.7) define it as a JSON number of seconds since
    the epoch; a value that is clearly milliseconds is read as such, as some transmitters send
    milliseconds. ``None`` if the value is not a number.
    """
    number = as_int(value)
    if number is None:
        return None
    if number > _MILLISECONDS_THRESHOLD:
        number //= 1000
    return datetime.fromtimestamp(number, tz=UTC)


def parse_claims(data: bytes | str) -> Claims:
    """Decodes a JSON object; raises ``ValueError`` if the data is not a JSON object."""
    decoded = json.loads(data)
    if not isinstance(decoded, dict):
        raise ValueError("expected a JSON object")
    return decoded
