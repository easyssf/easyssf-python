"""The push endpoint as a WSGI application, for sync frameworks and servers: mount
:func:`push_wsgi_app` at the push endpoint path. The receiver is asyncio based, so the app needs a
runner that executes the coroutine of :meth:`~easyssf.receiver.push.PushHandler.handle` on the
event loop the receiver lives on; the Flask distribution provides one over a loop thread."""

from __future__ import annotations

from collections.abc import Callable, Coroutine, Iterable
from typing import Any, TypeAlias

from .push import MAX_SET_SIZE, PUSH_CONTENT_LANGUAGE, PUSH_CONTENT_TYPE, PushHandler, PushResponse

__all__ = ["CoroutineRunner", "WsgiApp", "push_wsgi_app"]

StartResponse: TypeAlias = Callable[[str, list[tuple[str, str]]], Any]
WsgiApp: TypeAlias = Callable[[dict[str, Any], StartResponse], Iterable[bytes]]
"""A WSGI application (PEP 3333)."""
CoroutineRunner: TypeAlias = Callable[[Coroutine[Any, Any, PushResponse]], PushResponse]
"""Runs the coroutine of a push request to completion and returns its result: ``asyncio.run``
for a receiver without background work, or ``lambda c: asyncio.run_coroutine_threadsafe(c,
loop).result()`` for the loop thread the receiver runs on."""

_REASONS = {
    202: "Accepted",
    400: "Bad Request",
    401: "Unauthorized",
    405: "Method Not Allowed",
    413: "Content Too Large",
    500: "Internal Server Error",
    503: "Service Unavailable",
}


def push_wsgi_app(push_handler: PushHandler, run: CoroutineRunner) -> WsgiApp:
    """A WSGI application serving the push endpoint: ``POST`` with the SET as body, any other
    method is answered with 405. The body is read up to one byte beyond
    :data:`~easyssf.receiver.push.MAX_SET_SIZE`; the response carries the status of
    :meth:`~easyssf.receiver.push.PushHandler.handle` and, with an error document, the
    ``Content-Type`` and ``Content-Language`` headers of RFC 8935.

    Args:
        push_handler: the handler of the receiver.
        run: executes the coroutine of a request on the receiver's event loop, see
            :data:`CoroutineRunner`. With ``asyncio.run`` every request gets a loop of its own,
            which suits a receiver that only handles pushed SETs (no poller, no stream
            management); a receiver with background work runs on a loop thread, and the runner
            submits to it with ``asyncio.run_coroutine_threadsafe``.
    """

    def app(environ: dict[str, Any], start_response: StartResponse) -> Iterable[bytes]:
        if environ.get("REQUEST_METHOD") != "POST":
            start_response(_status(405), [("Allow", "POST"), ("Content-Length", "0")])
            return [b""]
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        limit = MAX_SET_SIZE + 1
        body = environ["wsgi.input"].read(min(length, limit) if length > 0 else limit)
        response = run(push_handler.handle(environ.get("HTTP_AUTHORIZATION"), body))
        content = response.body_bytes or b""
        headers = [("Content-Length", str(len(content)))]
        if response.body is not None:
            headers = [("Content-Type", PUSH_CONTENT_TYPE), ("Content-Language", PUSH_CONTENT_LANGUAGE), *headers]
        start_response(_status(response.status), headers)
        return [content]

    return app


def _status(status: int) -> str:
    return f"{status} {_REASONS.get(status, '')}".rstrip()
