"""The easyssf receiver for FastAPI: the push endpoint as a router, the rejection of revoked access
tokens as a dependency or middleware, and the receiver's lifecycle as a lifespan, plus its health
as a route. The Python counterpart of the Rust ``easyssf-receiver-axum`` crate.

Example:
    >>> from fastapi import Depends, FastAPI, Request
    >>> from easyssf.fastapi import health_router, push_router_for, receiver_lifespan, revocation_dependency
    >>>
    >>> receiver = Receiver(config)
    >>> app = FastAPI(lifespan=receiver_lifespan(receiver))
    >>> app.include_router(push_router_for(receiver))  # POST /ssf/push, or easyssf.receiver.push.endpoint-path
    >>> app.include_router(health_router(receiver))  # GET /health
    >>> reject_revoked = revocation_dependency(receiver.token_revocation_store, lambda request: request.state.token)
    >>> @app.get("/api/orders", dependencies=[Depends(require_access_token), Depends(reject_revoked)])
    ... async def orders() -> list[str]: ...
"""

from .lifecycle import DEFAULT_HEALTH_PATH, health_router, receiver_lifespan
from .push import DEFAULT_PUSH_PATH, into_response, push_router, push_router_for
from .revocation import (
    REVOKED_WWW_AUTHENTICATE,
    RequestTokenClaimsExtractor,
    RevocationMiddleware,
    revocation_dependency,
)

__all__ = [
    "DEFAULT_HEALTH_PATH",
    "DEFAULT_PUSH_PATH",
    "REVOKED_WWW_AUTHENTICATE",
    "RequestTokenClaimsExtractor",
    "RevocationMiddleware",
    "health_router",
    "into_response",
    "push_router",
    "push_router_for",
    "receiver_lifespan",
    "revocation_dependency",
]
