"""The push endpoint as an ASGI 3 application, for any ASGI server or framework: mount
:func:`push_app` at the push endpoint path (``/ssf/push`` by default). No framework is needed;
the FastAPI and Litestar distributions add the idiomatic pieces."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any, TypeAlias

from .push import MAX_SET_SIZE, PUSH_CONTENT_LANGUAGE, PUSH_CONTENT_TYPE, PushHandler

__all__ = ["AsgiApp", "push_app"]

Scope: TypeAlias = MutableMapping[str, Any]
Receive: TypeAlias = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send: TypeAlias = Callable[[MutableMapping[str, Any]], Awaitable[None]]
AsgiApp: TypeAlias = Callable[[Scope, Receive, Send], Awaitable[None]]
"""An ASGI 3 application."""

_METHOD_NOT_ALLOWED = 405


def push_app(push_handler: PushHandler) -> AsgiApp:
    """An ASGI 3 application serving the push endpoint: ``POST`` with the SET as body
    (``application/secevent+jwt``), any other method is answered with 405. The body is read up to
    one byte beyond :data:`~easyssf.receiver.push.MAX_SET_SIZE`; the response carries the status
    of :meth:`~easyssf.receiver.push.PushHandler.handle` and, with an error document, the
    ``Content-Type`` and ``Content-Language`` headers of RFC 8935. Lifespan events are
    acknowledged, so the app can be served on its own.

    Example:
        >>> app = push_app(receiver.push_handler)   # uvicorn.run(app, port=8080)
        >>> fastapi_app.mount("/ssf/push", app)     # or under a framework
    """

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                await send({"type": message["type"] + ".complete"})
                if message["type"] == "lifespan.shutdown":
                    return
        if scope["type"] != "http":
            raise RuntimeError(f"the push endpoint serves HTTP, not {scope['type']}")
        if scope["method"] != "POST":
            await _respond(send, _METHOD_NOT_ALLOWED, [(b"allow", b"POST")], b"")
            return
        # read up to one byte beyond the limit, whatever the size of the chunks the server hands
        # over: no more is needed to reject the request, and a transmitter cannot make the endpoint
        # buffer anything it likes
        body = b""
        while len(body) <= MAX_SET_SIZE:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body += message.get("body", b"")[: MAX_SET_SIZE + 1 - len(body)]
            if not message.get("more_body", False):
                break
        authorization = next(
            (value.decode("latin-1") for name, value in scope.get("headers", []) if name.lower() == b"authorization"),
            None,
        )
        response = await push_handler.handle(authorization, body)
        content = response.body_bytes
        headers: list[tuple[bytes, bytes]] = []
        if content is not None:
            headers = [
                (b"content-type", PUSH_CONTENT_TYPE.encode()),
                (b"content-language", PUSH_CONTENT_LANGUAGE.encode()),
            ]
        await _respond(send, response.status, headers, content or b"")

    return app


async def _respond(send: Send, status: int, headers: list[tuple[bytes, bytes]], body: bytes) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [*headers, (b"content-length", str(len(body)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": body})
