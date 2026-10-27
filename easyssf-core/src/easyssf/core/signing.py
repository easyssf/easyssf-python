"""Signs SETs and other JWTs: the transmitter side of the SET, for the test transmitter, the
examples and anyone who sends SETs, over joserfc (install ``easyssf-core[signing]``). The receiver
does not need it."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Final

from .claims import Claims

if TYPE_CHECKING:
    from joserfc.jwk import ECKey, OKPKey, RSAKey

    SigningKey = RSAKey | ECKey | OKPKey

__all__ = ["JWT_TYPE", "SECEVENT_JWT_TYPE", "Signer", "jwk_set"]

SECEVENT_JWT_TYPE: Final = "secevent+jwt"
"""The ``typ`` of a SET (RFC 8417, section 2.3)."""
JWT_TYPE: Final = "JWT"
"""The ``typ`` of a plain JWT (RFC 7519, section 5.1)."""

_RSA_ALGORITHMS: Final[tuple[str, ...]] = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512")
_EC_ALGORITHM_BY_CURVE: Final = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}
_MIN_RSA_BITS: Final = 2048


def _require_joserfc() -> None:
    try:
        import joserfc  # noqa: F401
    except ImportError as error:  # pragma: no cover - depends on the environment
        raise ImportError("easyssf.core.signing needs joserfc: install easyssf-core[signing]") from error


class Signer:
    """Signs claims with one private key under one algorithm and key id. Safe for concurrent use.

    Args:
        key: a private ``RSAKey``, ``ECKey`` (P-256, P-384 or P-521) or ``OKPKey`` (Ed25519) of
            joserfc.
        algorithm: a signature algorithm of RFC 7518 that fits the key (``RS256``, ``PS256``,
            ``ES256``, ``EdDSA``, ...); ``""`` picks ``RS256`` for RSA, the ES algorithm of the
            curve for EC, ``EdDSA`` for Ed25519.
        key_id: the ``kid`` the SETs carry, so that the receiver finds the key in the JWK Set; it
            must not be empty. The ``kid`` of the key when not given.

    Raises:
        ValueError: for an RSA key below 2048 bits, as RFC 7518, section 3.3 demands (the receivers
            reject its SETs anyway), an algorithm that does not fit the key, an empty key id or a
            public key.
    """

    def __init__(self, key: SigningKey, algorithm: str = "", key_id: str = "") -> None:
        _require_joserfc()
        from joserfc.jwk import ECKey, OKPKey, RSAKey

        if not isinstance(key, RSAKey | ECKey | OKPKey):
            raise ValueError(f"signing: unsupported key type {type(key).__name__}")
        key_id = key_id or (key.kid or "")
        if not key_id:
            raise ValueError("signing: the key id must not be empty")
        if not key.is_private:
            raise ValueError("signing: a private key is needed")
        if isinstance(key, RSAKey):
            bits = key.raw_value.key_size
            if bits < _MIN_RSA_BITS:
                raise ValueError(f"signing: the RSA key has {bits} bits, {_MIN_RSA_BITS} are the minimum")
            fallback: str = "RS256"
            allowed: tuple[str, ...] = _RSA_ALGORITHMS
        elif isinstance(key, ECKey):
            curve = key.curve_name
            if curve not in _EC_ALGORITHM_BY_CURVE:
                raise ValueError(f"signing: unsupported curve {curve}")
            fallback = _EC_ALGORITHM_BY_CURVE[curve]
            allowed = (fallback,)
        else:
            if key.curve_name != "Ed25519":
                raise ValueError(f"signing: unsupported curve {key.curve_name}")
            fallback, allowed = "EdDSA", ("EdDSA",)
        algorithm = algorithm or fallback
        if algorithm not in allowed:
            raise ValueError(f"signing: algorithm {algorithm} does not fit the {type(key).__name__}")
        self._key = key
        self._algorithm = algorithm
        self._key_id = key_id

    @property
    def algorithm(self) -> str:
        """The signature algorithm."""
        return self._algorithm

    @property
    def key_id(self) -> str:
        """The ``kid`` the signed tokens carry."""
        return self._key_id

    @property
    def key(self) -> SigningKey:
        """The private key."""
        return self._key

    def public_jwk(self) -> Claims:
        """The public key as a JWK with the ``kid``, ``alg`` and ``use`` the receiver matches on."""
        jwk = self._key.as_dict(private=False)
        jwk["kid"] = self._key_id
        jwk["alg"] = self._algorithm
        jwk["use"] = "sig"
        return jwk

    def sign(self, claims: Claims) -> str:
        """Signs the claims as a SET: a JWS in compact serialization with ``typ secevent+jwt``
        (RFC 8417, section 2.3) and the ``kid``."""
        return self.sign_typed(SECEVENT_JWT_TYPE, claims)

    def sign_typed(self, typ: str, claims: Claims) -> str:
        """Signs the claims as a JWT with the given ``typ`` header, left out if ``""``."""
        from joserfc import jws

        protected: dict[str, str] = {"alg": self._algorithm, "kid": self._key_id}
        if typ:
            protected["typ"] = typ
        payload = json.dumps(claims, separators=(",", ":")).encode()
        return jws.serialize_compact(protected, payload, self._key, algorithms=[self._algorithm])


def jwk_set(*signers: Signer) -> Claims:
    """A JWK Set of the public keys of the signers, to publish at the ``jwks_uri``."""
    return {"keys": [signer.public_jwk() for signer in signers]}
