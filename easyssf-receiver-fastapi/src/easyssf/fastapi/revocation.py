"""Rejecting the access tokens that security events revoked, for a resource server on FastAPI: a
dependency for ``Depends`` on the routes that need it, and the ASGI
:class:`~easyssf.receiver.revocation.RevocationMiddleware` of the receiver for the whole
application. Neither validates tokens: ``extract`` reads the claims the authentication of the
application left on the request, so both work with any of it (an OAuth2 dependency of your own,
a JWT middleware, ...). A request without claims passes; whether anonymous requests are allowed
is for the application to decide."""

from __future__ import annotations

import inspect
import logging
from collections.abc import Awaitable, Callable
from typing import Final, TypeAlias

from fastapi import HTTPException, Request

from easyssf.receiver.revocation import (
    REVOKED_WWW_AUTHENTICATE,
    TokenClaims,
    TokenRevocationStore,
    reject_if_revoked,
)
from easyssf.receiver.revocation import RevocationMiddleware as _RevocationMiddleware

__all__ = [
    "REVOKED_WWW_AUTHENTICATE",
    "RequestTokenClaimsExtractor",
    "RevocationMiddleware",
    "revocation_dependency",
]

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_UNAVAILABLE: Final = 503
_log: Final = logging.getLogger("easyssf.fastapi.revocation")

RequestTokenClaimsExtractor: TypeAlias = Callable[[Request], "TokenClaims | Awaitable[TokenClaims | None] | None"]
"""Reads the :class:`~easyssf.receiver.revocation.TokenClaims` of the access token a request
carries, as left on it (``request.state``, say) by the dependency or middleware that validated
it; ``None`` for a request without a token. Sync or async."""


class RevocationMiddleware(_RevocationMiddleware):
    """The raw ASGI :class:`easyssf.receiver.revocation.RevocationMiddleware`, for the whole
    application: it rejects requests whose access token was revoked with 401 Unauthorized and the
    ``WWW-Authenticate`` challenge of :data:`REVOKED_WWW_AUTHENTICATE`, answers 503 when the store
    fails, and lets everything else through. Add it with the store and the extractor as keyword
    arguments, after (that is, inside) the middleware that validates the access token and leaves
    its claims on the scope::

        app.add_middleware(RevocationMiddleware, store=receiver.token_revocation_store, extract=token_claims)

    where ``extract`` reads the :class:`~easyssf.receiver.revocation.TokenClaims` from the ASGI
    scope (``scope["state"]`` is what ``request.state`` writes to) and is sync or async. For the
    routes that need it only, :func:`revocation_dependency` reads the :class:`fastapi.Request`
    instead.
    """


def revocation_dependency(
    store: TokenRevocationStore, extract: RequestTokenClaimsExtractor
) -> Callable[[Request], Awaitable[None]]:
    """A dependency for ``Depends`` that rejects a request whose access token was revoked with
    401 Unauthorized and the ``WWW-Authenticate`` challenge of
    :data:`~easyssf.receiver.revocation.REVOKED_WWW_AUTHENTICATE` (RFC 6750, section 3.1), and
    answers 503 Service Unavailable when the store fails: a store that cannot answer must not let
    a revoked token through. Put it after the dependency that validates the token and leaves its
    claims where ``extract`` reads them.

    Args:
        store: the revocations, :attr:`~easyssf.receiver.receiver.Receiver.token_revocation_store`.
        extract: reads the claims of the request's token, ``None`` for a request without one.

    Example:
        >>> reject_revoked = revocation_dependency(receiver.token_revocation_store, token_claims_of)
        >>> @app.get("/api/me", dependencies=[Depends(require_access_token), Depends(reject_revoked)])
        ... async def me(request: Request) -> dict[str, str]: ...
    """

    async def reject_revoked(request: Request) -> None:
        claims = extract(request)
        if inspect.isawaitable(claims):
            claims = await claims
        try:
            rejected = await reject_if_revoked(store, claims)
        except Exception as error:
            _log.exception("The revocation store failed, rejecting the request")
            raise HTTPException(_HTTP_UNAVAILABLE, detail="revocation check failed") from error
        if rejected:
            _log.debug("Rejecting a revoked access token", extra={"subject": claims.subject if claims else ""})
            raise HTTPException(_HTTP_UNAUTHORIZED, headers={"WWW-Authenticate": REVOKED_WWW_AUTHENTICATE})

    return reject_revoked
