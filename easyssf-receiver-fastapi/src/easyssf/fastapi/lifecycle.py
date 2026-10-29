"""The lifecycle of the receiver on FastAPI: ``receiver_lifespan`` starts and stops the receiver
with the application, ``health_router`` serves its health."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Final

from fastapi import APIRouter, FastAPI
from fastapi.responses import JSONResponse
from starlette.types import Lifespan

from easyssf.receiver.receiver import Receiver
from easyssf.receiver.transmitter import HealthStatus

__all__ = ["DEFAULT_HEALTH_PATH", "health_router", "receiver_lifespan"]

DEFAULT_HEALTH_PATH: Final = "/health"
"""Where :func:`health_router` mounts the endpoint by default."""

_HTTP_OK: Final = 200
_HTTP_UNAVAILABLE: Final = 503


def receiver_lifespan(receiver: Receiver, inner: Lifespan[Any] | None = None) -> Lifespan[Any]:
    """A lifespan for ``FastAPI(lifespan=...)`` that starts the receiver when the application
    starts (the streams are registered and polling begins in the background) and closes it when
    the application shuts down (the acknowledgements it owes are sent, the HTTP client it made for
    itself is closed, a given one stays open). With ``inner``, the
    lifespan of the application, the receiver starts after ``inner`` entered and stops before it
    exits, so that the handlers find what the application set up, and whatever ``inner`` yields
    becomes the state of the application.

    Example:
        >>> app = FastAPI(lifespan=receiver_lifespan(receiver))
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[Any]:
        if inner is None:
            async with receiver:
                yield None
            return
        async with inner(app) as state, receiver:
            yield state

    return lifespan


def health_router(receiver: Receiver, path: str = DEFAULT_HEALTH_PATH) -> APIRouter:
    """A router with ``GET path`` answering :meth:`~easyssf.receiver.receiver.Receiver.health` as
    JSON (:meth:`~easyssf.receiver.receiver.ReceiverHealth.to_mapping`): 200 while the receiver is
    healthy or degraded (no contact with a transmitter yet, the application starts without it),
    503 when it is unhealthy (a poll failed, a stream cannot be used).

    Example:
        >>> app.include_router(health_router(receiver))  # GET /health
    """
    router = APIRouter()

    @router.get(path, name="easyssf-health")
    async def health() -> JSONResponse:
        current = await receiver.health()
        status = _HTTP_UNAVAILABLE if current.status is HealthStatus.UNHEALTHY else _HTTP_OK
        return JSONResponse(current.to_mapping(), status_code=status)

    return router
