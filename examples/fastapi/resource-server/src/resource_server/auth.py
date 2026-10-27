"""Validates the access tokens of the identity provider, the part Spring Security's resource
server support plays in the Java example: the signature against the keys of the issuer, ``iss``
and ``exp``. The identity provider is the SSF transmitter and signs access tokens and SETs with
the same keys, so the :class:`~easyssf.receiver.jwks.JwkSetSource` of the receiver's transmitter
is reused; it refreshes the keys when a token names one it does not know. The claims are left on
the request (``request.state.access_token``) for the routes and for the revocation dependency of
the receiver, which reads ``iss``, ``sub``, ``sid`` and ``iat`` from them. The ``auth.go`` of the
Go example."""

from __future__ import annotations

import time
import warnings
from datetime import UTC, datetime
from typing import Annotated, Final

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from joserfc import jws
from joserfc.errors import BadSignatureError, JoseError
from joserfc.jwk import Key, KeySet
from joserfc.jws import JWSRegistry

from easyssf.core import Claims, as_int, parse_claims, string_member
from easyssf.receiver.jwks import JwkSetSource
from easyssf.receiver.revocation import TokenClaims

__all__ = [
    "ACCEPTED_ALGORITHMS",
    "AccessToken",
    "AccessTokens",
    "AuthError",
    "bearer_token",
    "token_claims",
    "token_of",
]

ACCEPTED_ALGORITHMS: Final[tuple[str, ...]] = (
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "EdDSA",
)
"""The algorithms an access token may be signed with, the list of the Go example."""

_EXPIRY_LEEWAY: Final = 30  # seconds
_HTTP_UNAUTHORIZED: Final = 401

bearer_token: Final = HTTPBearer(
    auto_error=False, scheme_name="OAuth2 access token", description="An access token of the identity provider"
)
"""Reads the bearer token of the ``Authorization`` header (and documents the scheme in OpenAPI);
without ``auto_error``, so that the challenges below are the ones of RFC 6750 rather than
FastAPI's generic 403."""


class AuthError(Exception):
    """An access token that is not acceptable; the message is the ``error_description`` of the
    challenge."""


class AccessToken:
    """The claims of a validated access token.

    Args:
        claims: the verified claims.
    """

    __slots__ = ("_claims",)

    def __init__(self, claims: Claims) -> None:
        self._claims = dict(claims)

    @property
    def claims(self) -> Claims:
        """The claims, a copy."""
        return dict(self._claims)

    def string(self, claim: str) -> str:
        """A string claim, ``""`` if absent or not a string."""
        return string_member(self._claims, claim)

    def time(self, claim: str) -> datetime | None:
        """A numeric date claim (``iat``, ``exp``), ``None`` if absent."""
        seconds = as_int(self._claims.get(claim))
        return datetime.fromtimestamp(seconds, tz=UTC) if seconds is not None else None

    def token_claims(self) -> TokenClaims:
        """The claims the revocation check of the receiver reads."""
        return TokenClaims(
            issuer=self.string("iss"),
            subject=self.string("sub"),
            session_id=self.string("sid"),
            issued_at=self.time("iat"),
        )

    def __repr__(self) -> str:
        return f"AccessToken(sub={self.string('sub')!r}, sid={self.string('sid')!r})"


class AccessTokens:
    """Validates the access tokens of one issuer with its keys.

    Args:
        issuer: the issuer every token must be issued by.
        keys: the keys of the issuer, the ``keys`` of the receiver's transmitter.
    """

    def __init__(self, issuer: str, keys: JwkSetSource) -> None:
        self._issuer = issuer
        self._keys = keys

    async def validate(self, token: str) -> AccessToken:
        """Checks the token and returns its claims: signed with a key of the issuer (fetching the
        keys again once for an unknown ``kid``, as identity providers rotate them), issued by the
        expected issuer and not expired. The audience is not checked, see below.

        Raises:
            AuthError: the token is not acceptable.
        """
        try:
            compact = jws.extract_compact(token.encode("ascii"), registry=_registry(None))
        except (JoseError, ValueError, UnicodeEncodeError) as error:
            raise AuthError(f"the token is not a signed JWT: {error}") from error
        header = compact.protected
        algorithm = string_member(header, "alg")
        if algorithm not in ACCEPTED_ALGORITHMS:
            raise AuthError(f"the token is signed with the algorithm {algorithm!r}, which is not accepted")
        kid = string_member(header, "kid")
        key = _key(await self._keys.jwk_set(False), kid)
        if key is None:
            # the identity provider rotated its keys: fetch them again, rate limited by the source
            key = _key(await self._keys.jwk_set(True), kid)
        if key is None:
            raise AuthError("the token is signed with an unknown key")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")  # joserfc deprecates the name EdDSA (RFC 9864)
                compact = jws.deserialize_compact(token, key, registry=_registry(algorithm))
        except BadSignatureError as error:
            raise AuthError("the signature of the token is invalid") from error
        except (JoseError, ValueError) as error:
            raise AuthError(f"the token is not a signed JWT: {error}") from error
        try:
            claims = parse_claims(compact.payload)
        except ValueError as error:
            raise AuthError("the payload of the token is not a JSON object") from error
        if string_member(claims, "iss") != self._issuer:
            raise AuthError("the token was not issued by the expected issuer")
        # which audience an access token carries depends on the identity provider and its
        # configuration, so this example does not check it; a real resource server does
        expires_at = as_int(claims.get("exp"))
        if expires_at is None or int(time.time()) > expires_at + _EXPIRY_LEEWAY:
            raise AuthError("the token expired")
        return AccessToken(claims)

    async def require_access_token(
        self, request: Request, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_token)]
    ) -> AccessToken:
        """A dependency that requires a valid access token in the ``Authorization`` header and
        leaves it on ``request.state.access_token``; it answers 401 with a ``WWW-Authenticate``
        challenge (RFC 6750, section 3) otherwise: a bare ``Bearer`` without a bearer token,
        ``invalid_token`` with the reason for one that is not acceptable. The token itself is
        read by FastAPI's :class:`~fastapi.security.HTTPBearer`.

        Example:
            >>> @app.get("/api/me", dependencies=[Depends(access_tokens.require_access_token)])
        """
        if credentials is None or not credentials.credentials.strip():
            raise HTTPException(_HTTP_UNAUTHORIZED, headers={"WWW-Authenticate": "Bearer"})
        try:
            token = await self.validate(credentials.credentials.strip())
        except AuthError as error:
            description = str(error).replace('"', "'")
            raise HTTPException(
                _HTTP_UNAUTHORIZED,
                detail=str(error),
                headers={"WWW-Authenticate": f'Bearer error="invalid_token", error_description="{description}"'},
            ) from error
        request.state.access_token = token
        return token

    def __repr__(self) -> str:
        return f"AccessTokens(issuer={self._issuer!r})"


def token_of(request: Request) -> AccessToken | None:
    """The validated access token of the request, ``None`` if :meth:`AccessTokens.require_access_token`
    did not run."""
    token = getattr(request.state, "access_token", None)
    return token if isinstance(token, AccessToken) else None


def token_claims(request: Request) -> TokenClaims | None:
    """The extractor for :func:`easyssf.fastapi.revocation_dependency`: the claims of the
    request's access token, ``None`` without one."""
    token = token_of(request)
    return token.token_claims() if token is not None else None


def _registry(algorithm: str | None) -> JWSRegistry:
    """A joserfc registry restricted to the accepted algorithms, or to the one the header names,
    with unknown header parameters ignored (RFC 7515, section 4)."""
    return JWSRegistry(algorithms=[algorithm] if algorithm else list(ACCEPTED_ALGORITHMS), strict_check_header=False)


def _key(keys: KeySet, kid: str) -> Key | None:
    """The signing key with the given ``kid``, ``None`` if the set has none."""
    for key in keys.keys:
        if key.kid == kid and key.get("use") != "enc":
            return key
    return None
