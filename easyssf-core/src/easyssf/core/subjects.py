"""Constructors for subject identifiers (RFC 9493) as they appear in the ``sub_id`` claim of a SET
and in requests to add or remove subjects of a stream; the ``SsfSubjectIdentifiers`` of the Java
library. They return the JSON object, so they can be nested, serialized and resolved."""

from __future__ import annotations

from collections.abc import Mapping

from .claims import Claims
from .subject import Format, Member

__all__ = [
    "account",
    "aliases",
    "complex_members",
    "complex_subject",
    "did",
    "email",
    "iss_sub",
    "opaque",
    "phone_number",
    "scim",
    "uri",
]


def iss_sub(issuer: str, sub: str) -> Claims:
    """A subject identified by its issuer and its identifier at that issuer."""
    return {"format": Format.ISS_SUB, "iss": issuer, "sub": sub}


def email(address: str) -> Claims:
    """A subject identified by an email address."""
    return {"format": Format.EMAIL, "email": address}


def opaque(identifier: str) -> Claims:
    """A subject identified by an opaque identifier."""
    return {"format": Format.OPAQUE, "id": identifier}


def account(acct_uri: str) -> Claims:
    """A subject identified by an ``acct:`` URI (RFC 7565)."""
    return {"format": Format.ACCOUNT, "uri": acct_uri}


def phone_number(number: str) -> Claims:
    """A subject identified by a telephone number in E.164 format."""
    return {"format": Format.PHONE_NUMBER, "phone_number": number}


def did(url: str) -> Claims:
    """A subject identified by a decentralized identifier."""
    return {"format": Format.DID, "url": url}


def uri(value: str) -> Claims:
    """A subject identified by a URI."""
    return {"format": Format.URI, "uri": value}


def scim(resource_uri: str, external_id: str = "") -> Claims:
    """A SCIM resource (RFC 9967), the subject of SCIM Events.

    ``resource_uri`` is the relative path of the resource, for example ``/Users/2b2f880a``;
    ``external_id`` is added as ``externalId`` when not empty.
    """
    identifier: Claims = {"format": Format.SCIM, "uri": resource_uri}
    if external_id:
        identifier["externalId"] = external_id
    return identifier


def aliases(*identifiers: Claims) -> Claims:
    """A subject with several identifiers that all name it."""
    return {"format": Format.ALIASES, "identifiers": list(identifiers)}


def complex_members(members: Mapping[str, Claims]) -> Claims:
    """A complex subject with the given members (user, session, device, tenant, ...), each a
    subject identifier."""
    identifier: Claims = {"format": Format.COMPLEX}
    identifier.update(members)
    return identifier


def complex_subject(user: Claims | None = None, session: Claims | None = None) -> Claims:
    """A subject made up of a user and a session, either may be ``None``."""
    members: dict[str, Claims] = {}
    if user is not None:
        members[Member.USER] = user
    if session is not None:
        members[Member.SESSION] = session
    return complex_members(members)
