"""The transmitter configuration metadata published at ``.well-known/ssf-configuration`` (SSF 1.0,
section 7.1)."""

from __future__ import annotations

from typing import Final

from .claims import Claims, string_member, strings
from .delivery import DeliveryMethod

__all__ = ["SPEC_VERSION_1_0", "TransmitterMetadata"]

SPEC_VERSION_1_0: Final = "1_0"
"""The ``spec_version`` of the final SSF 1.0 specification."""


class TransmitterMetadata:
    """The metadata of a transmitter: its issuer, the location of its JWK Set if any, and all
    members of the metadata document."""

    __slots__ = ("_claims", "_issuer", "_jwks_uri")

    def __init__(self, issuer: str, jwks_uri: str | None, claims: Claims | None = None) -> None:
        self._issuer = issuer
        self._jwks_uri = jwks_uri or None
        self._claims: Claims = {} if claims is None else claims

    @property
    def issuer(self) -> str:
        """The transmitter issuer."""
        return self._issuer

    @property
    def jwks_uri(self) -> str | None:
        """The location of the transmitter's JWK Set, ``None`` if the metadata has none."""
        return self._jwks_uri

    @property
    def claims(self) -> Claims:
        """All members of the metadata document."""
        return self._claims

    @property
    def spec_version(self) -> str:
        """The version of the specification the transmitter implements (``spec_version``), ``""``
        if the transmitter does not say."""
        return string_member(self._claims, "spec_version")

    @property
    def delivery_methods_supported(self) -> list[str]:
        """The delivery method URIs the transmitter supports (``delivery_methods_supported``),
        empty if the transmitter does not say."""
        return strings(self._claims.get("delivery_methods_supported"))

    def supports_delivery_method(self, method: DeliveryMethod) -> bool:
        """Whether the transmitter supports the delivery method; ``True`` as well if it does not
        say which methods it supports."""
        supported = self.delivery_methods_supported
        return not supported or method.uri in supported

    @property
    def critical_subject_members(self) -> list[str]:
        """The members of a complex subject the transmitter requires to be understood
        (``critical_subject_members``), empty if none."""
        return strings(self._claims.get("critical_subject_members"))

    @property
    def authorization_schemes(self) -> list[Claims]:
        """The authorization schemes of the management endpoints (``authorization_schemes``), each
        with a ``spec_urn``, empty if the transmitter does not say."""
        array = self._claims.get("authorization_schemes")
        if not isinstance(array, list):
            return []
        return [element for element in array if isinstance(element, dict)]

    @property
    def default_subjects(self) -> str:
        """Which subjects a stream receives events for by default (``default_subjects``): ``ALL``
        or ``NONE``, ``""`` if the transmitter does not say."""
        return string_member(self._claims, "default_subjects")

    @property
    def configuration_endpoint(self) -> str:
        """The endpoint to create, read, update and delete streams, ``""`` if absent."""
        return string_member(self._claims, "configuration_endpoint")

    @property
    def status_endpoint(self) -> str:
        """The endpoint to read and update the status of a stream, ``""`` if absent."""
        return string_member(self._claims, "status_endpoint")

    @property
    def add_subject_endpoint(self) -> str:
        """The endpoint to add subjects to a stream, ``""`` if absent."""
        return string_member(self._claims, "add_subject_endpoint")

    @property
    def remove_subject_endpoint(self) -> str:
        """The endpoint to remove subjects from a stream, ``""`` if absent."""
        return string_member(self._claims, "remove_subject_endpoint")

    @property
    def verification_endpoint(self) -> str:
        """The endpoint to request a verification event, ``""`` if absent."""
        return string_member(self._claims, "verification_endpoint")

    def __repr__(self) -> str:
        return f"TransmitterMetadata(issuer={self._issuer!r}, jwks_uri={self._jwks_uri!r})"
