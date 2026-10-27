"""Verification of Security Event Tokens: the ``Verifier`` protocol, ``JwtVerifier`` that checks
the signature of a SET against the transmitter's JWK Set and applies every claim rule of RFC 8417
and the SSF profile with the error codes of RFC 8935, and ``IssuerRoutingVerifier`` for several
transmitters. The port of ``receiver/set.go`` (a module named ``set`` would shadow the builtin).

joserfc checks the signature only. The header is read with ``jws.extract_compact`` first so that
``typ``, ``alg`` and ``kid`` failures carry our error codes, then ``jws.deserialize_compact`` is
restricted to the one algorithm the header names and given the one key selected from the JWK Set.
Every claim rule is applied in :meth:`JwtVerifier._validate_claims`: a SET has no ``exp`` (RFC
8417, section 2.2), and a JWT library's claim validation would reject every SET.
"""

from __future__ import annotations

import base64
import binascii
import inspect
import warnings
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Final, Protocol, TypeAlias

from joserfc import jws
from joserfc.errors import BadSignatureError, JoseError
from joserfc.jwk import Key, KeySet, OKPKey, RSAKey
from joserfc.jws import JWSRegistry

from easyssf.core import Claims, EventToken, SubjectCompatibilityMode, as_int, audiences, object_member, parse_claims
from easyssf.core import string_member as _string_member
from easyssf.core.signing import SECEVENT_JWT_TYPE

from .errors import Clock, ErrorCode, RejectedError, system_clock
from .jwks import JwkSetSource

__all__ = [
    "MAX_SET_SIZE",
    "SECEVENT_JWT_TYPE",
    "SUPPORTED_ALGORITHMS",
    "ExpectedAudiencesProvider",
    "IssuerRoutingVerifier",
    "JwtVerifier",
    "Verifier",
    "VerifierOptions",
    "default_verifier_options",
    "rsa_key_bits",
    "supported_algorithm",
    "unverified_issuer",
    "unverified_payload",
]

MAX_SET_SIZE: Final = 256 * 1024
"""The maximum size of a SET in bytes. An endpoint does not need to read more than one byte
beyond it."""

SUPPORTED_ALGORITHMS: Final[tuple[str, ...]] = (
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
    "Ed25519",
)
"""The asymmetric signature algorithms SETs may be signed with: the RSA, RSA-PSS and ECDSA
algorithms of RFC 7518, section 3, and EdDSA with an Ed25519 key (RFC 8037), also under the name
``Ed25519`` that RFC 9864 gives it. ``EdDSA`` and ``Ed25519`` are one algorithm here: accepting
either accepts SETs under both names."""

_EDDSA_NAMES: Final = frozenset({"EdDSA", "Ed25519"})
_JWS_HEADER_LIMIT: Final = 8 * 1024
_JWS_SIGNATURE_LIMIT: Final = 4 * 1024


class Verifier(Protocol):
    """Verifies an encoded Security Event Token (RFC 8417): its signature and claims, in JWS
    compact serialization."""

    async def verify(self, encoded_set: str) -> EventToken:
        """The verified SET.

        Raises:
            RejectedError: the SET is invalid, with the error code of RFC 8935.
            TransmitterUnavailableError: the keys could not be obtained.
        """
        ...


def supported_algorithm(name: str) -> str | None:
    """The algorithm with the given JWS name if it is one of the :data:`SUPPORTED_ALGORITHMS`,
    ``None`` otherwise; surrounding whitespace is ignored."""
    name = name.strip()
    return name if name in SUPPORTED_ALGORITHMS else None


def _same_algorithm(one: str, other: str) -> bool:
    """Whether two algorithm names name the same algorithm: ``EdDSA`` is ``Ed25519``."""
    return one == other or (one in _EDDSA_NAMES and other in _EDDSA_NAMES)


ExpectedAudiencesProvider: TypeAlias = Callable[[], Sequence[str] | Awaitable[Sequence[str]]]
"""Supplies the audiences a SET must be addressed to, consulted for every SET: for example the
audience of a stream once it is registered. Any audience is accepted while it returns none. Sync
or async. It raises a ``TransmitterUnavailableError`` while the audiences are not known yet (the
stream is not registered), so that the SET is delivered again later, or a ``RejectedError`` for
SETs that cannot be checked at all."""


@dataclass(frozen=True, slots=True)
class VerifierOptions:
    """How a :class:`JwtVerifier` verifies SETs; the Java setters. Read for every SET. Start from
    :func:`default_verifier_options` and ``dataclasses.replace`` what differs."""

    expected_audiences: Sequence[str] = ()
    """The audiences a SET must be addressed to; it has to be addressed to at least one of them.
    Any audience is accepted while this is empty and no provider is set."""
    expected_audiences_provider: ExpectedAudiencesProvider | None = None
    """Supplies the audiences instead of :attr:`expected_audiences`."""
    accepted_algorithms: Sequence[str] = ("RS256",)
    """The JWS algorithms SETs may be signed with, ``RS256`` by default; only the
    :data:`SUPPORTED_ALGORITHMS` are allowed."""
    min_rsa_key_size: int = 2048
    """The minimum size of RSA signing keys in bits, 0 to accept any. 2048 by default."""
    require_type_header: bool = True
    """Whether a SET must have a ``typ`` header of ``secevent+jwt`` (RFC 8417, section 2.3)."""
    subject_compatibility: SubjectCompatibilityMode = SubjectCompatibilityMode.STRICT
    """How strictly the subject of a SET is validated: ``STRICT`` requires the top-level
    ``sub_id`` claim of SSF 1.0, ``LEGACY`` accepts SETs of transmitters following earlier
    drafts, which put the subject into the event payload."""
    clock_skew: timedelta = timedelta(minutes=1)
    """How far in the future a SET may be issued according to the local clock."""
    clock: Clock = system_clock
    """The clock ``iat`` is checked against."""


def default_verifier_options() -> VerifierOptions:
    """The defaults: RS256, 2048 bit keys, ``typ`` required, strict subjects, one minute of skew."""
    return VerifierOptions()


class JwtVerifier:
    """A :class:`Verifier` that verifies SET signatures against the transmitter's JWK Set and
    validates the claims required by RFC 8417 and the SSF profile (``NimbusSsfSetVerifier`` in
    Java, ``JwtSsfSetVerifier`` in .NET and Rust).

    Args:
        issuer: the issuer every SET must be issued by.
        keys: where the transmitter's keys come from.
        options: how SETs are verified, :func:`default_verifier_options` if ``None``.

    Raises:
        ValueError: ``options.accepted_algorithms`` is empty or names an algorithm that is not
            asymmetric.
    """

    def __init__(self, issuer: str, keys: JwkSetSource, options: VerifierOptions | None = None) -> None:
        options = options if options is not None else default_verifier_options()
        if not options.accepted_algorithms:
            raise ValueError("accepted_algorithms must not be empty")
        for algorithm in options.accepted_algorithms:
            if supported_algorithm(algorithm) is None:
                raise ValueError(f"not an asymmetric signature algorithm: {algorithm}")
        self._issuer = issuer
        self._keys = keys
        self._options = options

    @property
    def issuer(self) -> str:
        """The issuer every SET must be issued by."""
        return self._issuer

    @property
    def options(self) -> VerifierOptions:
        """How SETs are verified."""
        return self._options

    @property
    def keys(self) -> JwkSetSource:
        """Where the transmitter's keys come from."""
        return self._keys

    async def verify(self, encoded_set: str) -> EventToken:
        """Verifies the signature against the JWK Set and validates the claims.

        Raises:
            RejectedError: the SET is invalid, with the error code of RFC 8935.
            TransmitterUnavailableError: the keys could not be obtained.
        """
        encoded_set = encoded_set.strip()
        if not encoded_set:
            raise RejectedError(ErrorCode.INVALID_REQUEST, "The SET is empty")
        parts = encoded_set.split(".")
        if len(parts) != 3 or not parts[0] or not parts[1]:
            raise RejectedError(ErrorCode.INVALID_REQUEST, "The SET is not a JWS in compact serialization")
        if not parts[2]:
            raise RejectedError(ErrorCode.INVALID_REQUEST, "The SET is not a signed JWT")
        try:
            compact = jws.extract_compact(encoded_set.encode("ascii"), registry=_registry(None))
        except (JoseError, ValueError) as error:
            raise RejectedError(ErrorCode.INVALID_REQUEST, f"The SET is not a signed JWT: {error}") from error
        header = compact.protected
        # RFC 8417, section 2.3
        if self._options.require_type_header and _string_member(header, "typ").lower() != SECEVENT_JWT_TYPE:
            raise RejectedError(
                ErrorCode.INVALID_REQUEST, f"The SET must be typed with a typ header of {SECEVENT_JWT_TYPE}"
            )
        named = _string_member(header, "alg")
        algorithm = supported_algorithm(named)
        if algorithm is None or not any(_same_algorithm(algorithm, a) for a in self._options.accepted_algorithms):
            raise RejectedError(
                ErrorCode.INVALID_KEY, f"The SET is signed with the algorithm {named!r}, which is not accepted"
            )
        key = await self._select_key(_string_member(header, "kid"), algorithm)
        try:
            with warnings.catch_warnings():
                # joserfc deprecates the name EdDSA (RFC 9864); the SET names it, not we
                warnings.simplefilter("ignore")
                compact = jws.deserialize_compact(encoded_set, key, registry=_registry(algorithm))
        except BadSignatureError as error:
            raise RejectedError(ErrorCode.INVALID_KEY, "The signature of the SET is invalid") from error
        except (JoseError, ValueError) as error:
            raise RejectedError(ErrorCode.INVALID_REQUEST, f"The SET is not a signed JWT: {error}") from error
        try:
            claims = parse_claims(compact.payload)
        except ValueError as error:
            raise RejectedError(
                ErrorCode.INVALID_REQUEST, f"The payload of the SET is not a JSON object: {error}"
            ) from error
        return await self._validate_claims(claims)

    async def _expected_audiences(self) -> Sequence[str]:
        provider = self._options.expected_audiences_provider
        if provider is None:
            return self._options.expected_audiences
        expected = provider()
        if inspect.isawaitable(expected):
            return await expected
        return expected

    async def _select_key(self, kid: str, algorithm: str) -> Key:
        keys = await self._keys.jwk_set(False)
        key = self._matching(keys, kid, algorithm)
        if key is not None:
            return key
        if kid:
            # the transmitter may have rotated its keys since the JWK Set was fetched
            keys = await self._keys.jwk_set(True)
            key = self._matching(keys, kid, algorithm)
            if key is not None:
                return key
        raise RejectedError(ErrorCode.INVALID_KEY, "The SET is signed with an unknown key")

    def _matching(self, keys: KeySet, kid: str, algorithm: str) -> Key | None:
        candidates: list[Key] = []
        for key in keys.keys:
            if kid and key.kid != kid:
                continue
            if key.get("use") == "enc":
                continue
            if key.alg and not _same_algorithm(key.alg, algorithm):
                continue
            if not _key_type_matches(key, algorithm):
                continue
            bits = rsa_key_bits(key)
            if self._options.min_rsa_key_size > 0 and 0 < bits < self._options.min_rsa_key_size:
                continue
            candidates.append(key)
        # without a kid only an unambiguous JWK Set is usable
        if (kid and candidates) or (not kid and len(candidates) == 1):
            return candidates[0]
        return None

    async def _validate_claims(self, claims: Claims) -> EventToken:
        if claims.get("iss") != self._issuer:
            raise RejectedError(ErrorCode.INVALID_ISSUER, "The SET was not issued by the expected transmitter")
        expected = await self._expected_audiences()
        if "aud" in claims and not _well_formed_audience(claims["aud"]):
            raise RejectedError(ErrorCode.INVALID_REQUEST, "The aud claim of the SET is malformed")
        if expected and not any(audience in expected for audience in audiences(claims.get("aud"))):
            raise RejectedError(ErrorCode.INVALID_AUDIENCE, "The SET is not addressed to this receiver")
        if not _string_member(claims, "jti"):
            raise RejectedError(ErrorCode.INVALID_REQUEST, "The SET has no jti claim")
        issued_at = as_int(claims.get("iat"))
        if issued_at is None:
            raise RejectedError(ErrorCode.INVALID_REQUEST, "The SET has no iat claim")
        if issued_at > int(self._options.clock().timestamp()) + int(self._options.clock_skew.total_seconds()):
            raise RejectedError(ErrorCode.INVALID_REQUEST, "The SET was issued in the future")
        if not object_member(claims, "events"):
            raise RejectedError(ErrorCode.INVALID_REQUEST, "The SET has no events claim")
        if self._options.subject_compatibility is SubjectCompatibilityMode.STRICT and not object_member(
            claims, "sub_id"
        ):
            raise RejectedError(
                ErrorCode.INVALID_REQUEST,
                "The SET has no top-level sub_id claim, which SSF 1.0 requires (the subject compatibility mode "
                "legacy accepts SETs of transmitters that put the subject into the event)",
            )
        token = EventToken.from_claims(claims)
        if token is None:
            raise RejectedError(ErrorCode.INVALID_REQUEST, "The SET lacks jti, iss, iat or events")
        return token

    def __repr__(self) -> str:
        return f"JwtVerifier(issuer={self._issuer!r})"


def rsa_key_bits(key: Key) -> int:
    """The size of an RSA key in bits, 0 for other key types."""
    if isinstance(key, RSAKey):
        return int(key.public_key.key_size)
    return 0


def _key_type_matches(key: Key, algorithm: str) -> bool:
    kty = key.key_type
    if kty == "RSA":
        return algorithm.startswith(("RS", "PS"))
    if kty == "EC":
        return algorithm.startswith("ES")
    if kty == "OKP" and isinstance(key, OKPKey):
        return algorithm in _EDDSA_NAMES and key.curve_name == "Ed25519"
    return False


def _well_formed_audience(aud: object) -> bool:
    if isinstance(aud, str):
        return True
    return isinstance(aud, list) and all(isinstance(element, str) for element in aud)


def _registry(algorithm: str | None) -> JWSRegistry:
    """A joserfc registry restricted to the one algorithm, with the limits of a SET instead of
    joserfc's: unknown header parameters are ignored as RFC 7515, section 4, says, and a SET may
    be as large as :data:`MAX_SET_SIZE`."""
    registry = JWSRegistry(algorithms=[algorithm] if algorithm else None, strict_check_header=False)
    registry.max_header_length = _JWS_HEADER_LIMIT
    registry.max_payload_length = MAX_SET_SIZE
    registry.max_signature_length = _JWS_SIGNATURE_LIMIT
    return registry


def unverified_payload(encoded_set: str) -> Claims | None:
    """The claims of a SET before it is verified, to decide how to verify it. Nothing read this
    way is trusted. ``None`` if the SET cannot be parsed."""
    parts = encoded_set.strip().split(".")
    if len(parts) < 2:
        return None
    try:
        raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        return parse_claims(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def unverified_issuer(encoded_set: str) -> str:
    """The ``iss`` claim of a SET before it is verified, to decide how to verify it. Nothing read
    this way is trusted. ``""`` if the SET cannot be parsed or has no issuer."""
    return _string_member(unverified_payload(encoded_set), "iss")


class IssuerRoutingVerifier:
    """A :class:`Verifier` for the SETs of several transmitters: the ``iss`` claim of a SET
    selects the verifier of that transmitter, which then verifies the SET, including its issuer.
    A SET of an unknown issuer is rejected.

    Args:
        verifiers: the verifier of each transmitter by its issuer.
    """

    __slots__ = ("_verifiers",)

    def __init__(self, verifiers: Mapping[str, Verifier]) -> None:
        self._verifiers = dict(verifiers)

    @property
    def issuers(self) -> list[str]:
        """The issuers the verifier knows."""
        return list(self._verifiers)

    async def verify(self, encoded_set: str) -> EventToken:
        """Verifies the SET with the verifier of its issuer."""
        verifier = self._verifiers.get(unverified_issuer(encoded_set))
        if verifier is None:
            raise RejectedError(ErrorCode.INVALID_ISSUER, "The SET was not issued by a known transmitter")
        return await verifier.verify(encoded_set)

    def __repr__(self) -> str:
        return f"IssuerRoutingVerifier(issuers={list(self._verifiers)!r})"
