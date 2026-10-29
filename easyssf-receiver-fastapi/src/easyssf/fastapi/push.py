"""The push endpoint (RFC 8935) as a FastAPI router: ``push_router`` mounts a
:class:`~easyssf.receiver.push.PushHandler` at a path, ``push_router_for`` the one of a configured
:class:`~easyssf.receiver.receiver.Receiver` at ``easyssf.receiver.push.endpoint-path``. The
status and header behaviour is that of :func:`easyssf.receiver.asgi.push_app`; the Rust
``easyssf-receiver-axum`` crate is the model."""

from __future__ import annotations

import logging
from typing import Final

from fastapi import APIRouter, Request, Response

from easyssf.receiver.errors import ErrorCode
from easyssf.receiver.push import MAX_SET_SIZE, PUSH_CONTENT_LANGUAGE, PUSH_CONTENT_TYPE, PushHandler, PushResponse
from easyssf.receiver.receiver import Receiver

__all__ = ["DEFAULT_PUSH_PATH", "into_response", "push_router", "push_router_for"]

DEFAULT_PUSH_PATH: Final = "/ssf/push"
"""Where :func:`push_router` mounts the endpoint by default."""

_HTTP_TOO_LARGE: Final = 413
_log: Final = logging.getLogger("easyssf.fastapi")


def push_router(push_handler: PushHandler, path: str = DEFAULT_PUSH_PATH) -> APIRouter:
    """A router with ``POST path`` serving the push endpoint: the SET is the body
    (``application/secevent+jwt``), the transmitter authenticates with its ``Authorization`` header
    and the SET with its signature, so the route belongs outside the authentication of the
    application. The response carries the status of
    :meth:`~easyssf.receiver.push.PushHandler.handle` and, with an error document, the
    ``Content-Type`` and ``Content-Language`` headers of RFC 8935, section 2.3. A body beyond
    :data:`~easyssf.receiver.push.MAX_SET_SIZE` is answered with 413 without being read in full.
    The route is left out of the OpenAPI schema: it is for the transmitter, not for the users of
    the API.

    Example:
        >>> app.include_router(push_router(receiver.push_handler))  # POST /ssf/push
    """
    router = APIRouter()

    @router.post(path, include_in_schema=False, name="easyssf-push")
    async def push(request: Request) -> Response:
        declared = request.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > MAX_SET_SIZE:
            return into_response(_too_large())
        # read up to one byte beyond the limit, as the raw ASGI app does, whatever the size of the
        # chunks the server hands over: no more is needed to reject the request, and a transmitter
        # cannot make the endpoint buffer anything it likes
        body = b""
        async for chunk in request.stream():
            body += chunk[: MAX_SET_SIZE + 1 - len(body)]
            if len(body) > MAX_SET_SIZE:
                break
        response = await push_handler.handle(request.headers.get("authorization"), body)
        return into_response(response)

    return router


def push_router_for(receiver: Receiver) -> APIRouter:
    """A router with the push endpoint of a configured receiver, at
    :attr:`~easyssf.receiver.receiver.Receiver.push_endpoint_path`
    (``easyssf.receiver.push.endpoint-path``, ``/ssf/push`` by default).

    Example:
        >>> app.include_router(push_router_for(receiver))
    """
    path = receiver.push_endpoint_path
    _log.info("Receiving SSF security events at %s", path, extra={"path": path})
    return push_router(receiver.push_handler, path)


def into_response(push_response: PushResponse) -> Response:
    """The response of the push handler as a FastAPI response: its status and, with an error
    document, the body as :data:`~easyssf.receiver.push.PUSH_CONTENT_TYPE` with the
    :data:`~easyssf.receiver.push.PUSH_CONTENT_LANGUAGE` header (RFC 8935, section 2.3); no
    headers of the two without a body."""
    content = push_response.body_bytes
    if content is None:
        return Response(status_code=push_response.status)
    return Response(
        content=content,
        status_code=push_response.status,
        media_type=PUSH_CONTENT_TYPE,
        headers={"Content-Language": PUSH_CONTENT_LANGUAGE},
    )


def _too_large() -> PushResponse:
    """The response of :meth:`~easyssf.receiver.push.PushHandler.handle` to a SET beyond the limit."""
    return PushResponse.error(_HTTP_TOO_LARGE, ErrorCode.INVALID_REQUEST, "The SET is too large")
