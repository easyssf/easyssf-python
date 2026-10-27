"""Signing keys and signing helpers for tests: keys the receiver accepts, keys it must reject,
and JWSs signed with whatever a test needs, with no minimum key size and no algorithm check."""

from __future__ import annotations

import base64
import json
import threading
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from joserfc import jws
from joserfc.jwk import RSAKey

from easyssf.core import Claims, parse_claims
from easyssf.core.signing import SECEVENT_JWT_TYPE, Signer

if TYPE_CHECKING:
    from joserfc.jwk import ECKey, OKPKey

__all__ = ["SigningKey", "claims_of", "generate_key", "shared_key", "sign", "sign_with", "unsigned"]


@dataclass(frozen=True, slots=True)
class SigningKey:
    """An RSA key a transmitter signs with."""

    key_id: str
    """The ``kid`` the signed tokens carry."""
    key: RSAKey
    """The private key."""

    def with_key_id(self, key_id: str) -> SigningKey:
        """The same key under another ``kid``."""
        return replace(self, key_id=key_id)

    def public_jwk(self) -> Claims:
        """The public key as a JWK with the ``kid`` and ``use``."""
        jwk = self.key.as_dict(private=False)
        jwk["kid"] = self.key_id
        jwk["use"] = "sig"
        return jwk

    def signer(self, algorithm: str = "RS256") -> Signer:
        """The key as a :class:`~easyssf.core.signing.Signer`, for SETs built with
        :func:`easyssf.core.new_set`. Refuses a key below 2048 bits, as the signer does."""
        return Signer(self.key, algorithm, self.key_id)


def generate_key(bits: int, key_id: str) -> SigningKey:
    """Makes a fresh key of the given size, for SETs the receiver must reject
    (``generate_key(1024, "weak")``) or ones of another transmitter. :func:`shared_key` is faster."""
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return SigningKey(key_id, RSAKey.generate_key(bits))


_shared_lock = threading.Lock()
_shared: SigningKey | None = None


def shared_key() -> SigningKey:
    """The 2048 bit key every default transmitter of the process signs with: generating one takes
    a while, and the tests do not depend on the keys of two transmitters differing."""
    global _shared  # noqa: PLW0603
    with _shared_lock:
        if _shared is None:
            _shared = generate_key(2048, "test-key")
        return _shared


def sign(key: SigningKey, typ: str | None, claims: Claims) -> str:
    """Signs the claims with ``RS256``; ``typ`` is the ``typ`` header, left out if ``None`` or
    ``""``. ``SECEVENT_JWT_TYPE`` makes a SET."""
    return sign_with(key, "RS256", typ, claims)


def sign_with(key: SigningKey | ECKey | OKPKey, algorithm: str, typ: str | None, claims: Claims) -> str:
    """Signs the claims as a JWS in compact serialization with any algorithm of RFC 7518 that fits
    the key: ``RS256``, ``PS256``, ``ES256``, ``EdDSA``, ... No minimum key size, unlike
    :class:`~easyssf.core.signing.Signer`: tests need to sign with keys the receiver has to reject."""
    import warnings

    if isinstance(key, SigningKey):
        protected: dict[str, str] = {"alg": algorithm, "kid": key.key_id}
        private = key.key
    else:
        protected = {"alg": algorithm}
        if key.kid:
            protected["kid"] = key.kid
        private = key  # type: ignore[assignment]
    if typ:
        protected["typ"] = typ
    payload = json.dumps(claims, separators=(",", ":")).encode()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return jws.serialize_compact(protected, payload, private, algorithms=[algorithm])


def unsigned(claims: Claims, typ: str | None = SECEVENT_JWT_TYPE) -> str:
    """The claims as an unsecured JWT (RFC 7519, section 6): ``alg`` of ``none``, no signature."""
    header: dict[str, str] = {"alg": "none"}
    if typ:
        header["typ"] = typ
    return _b64(json.dumps(header, separators=(",", ":")).encode()) + "." + _b64(_dump(claims)) + "."


def claims_of(compact: str) -> Claims:
    """The claims of a JWS in compact serialization, without any verification.

    Raises:
        ValueError: if it is not a JWS whose payload is a JSON object.
    """
    parts = compact.split(".")
    if len(parts) != 3:
        raise ValueError("not a JWS in compact serialization")
    return parse_claims(_unb64(parts[1]))


def _dump(claims: Claims) -> bytes:
    return json.dumps(claims, separators=(",", ":")).encode()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
