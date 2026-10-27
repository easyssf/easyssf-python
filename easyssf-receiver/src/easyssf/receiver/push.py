"""Push delivery (RFC 8935): the ``Authorization`` header and the body in, the status and the
error document out. ``PushHandler.handle`` is what every framework adapter calls;
``easyssf.receiver.asgi`` and ``easyssf.receiver.wsgi`` mount it. The port of ``receiver/push.go``.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, TypeAlias

from easyssf.core import Claims, DeliveryMethod

from .errors import (
    ErrorCode,
    HandlingError,
    InProgressError,
    RejectedError,
    StoreError,
    TransmitterUnavailableError,
)
from .metrics import SetOutcome
from .processor import Processor
from .verifier import MAX_SET_SIZE, unverified_issuer

__all__ = [
    "AUTHENTICATION_FAILED",
    "MAX_SET_SIZE",
    "PUSH_CONTENT_LANGUAGE",
    "PUSH_CONTENT_TYPE",
    "ExpectedAuthorizationHeaders",
    "PushHandler",
    "PushResponse",
]

PUSH_CONTENT_TYPE: Final = "application/json"
"""The content type of an error document."""
PUSH_CONTENT_LANGUAGE: Final = "en"
"""The language of the description in the error document, sent as ``Content-Language`` header
(RFC 8935, section 2.3)."""
AUTHENTICATION_FAILED: Final = "authentication_failed"
"""The error code of a push request whose transmitter could not be authenticated (RFC 8935,
section 2.4)."""

_HTTP_ACCEPTED: Final = 202
_HTTP_BAD_REQUEST: Final = 400
_HTTP_UNAUTHORIZED: Final = 401
_HTTP_TOO_LARGE: Final = 413
_HTTP_INTERNAL_ERROR: Final = 500
_HTTP_UNAVAILABLE: Final = 503


@dataclass(frozen=True, slots=True)
class PushResponse:
    """The response to a push request (RFC 8935, section 2.2 to 2.4)."""

    status: int
    """The HTTP status."""
    body: Claims | None = None
    """The JSON error document (``err`` and ``description``), ``None`` if the response has no
    body; send it with the :data:`PUSH_CONTENT_TYPE` and :data:`PUSH_CONTENT_LANGUAGE` headers."""

    @property
    def is_accepted(self) -> bool:
        """Whether the SET was accepted."""
        return self.status == _HTTP_ACCEPTED

    @property
    def body_bytes(self) -> bytes | None:
        """The error document as JSON, ``None`` if the response has no body."""
        if self.body is None:
            return None
        return json.dumps(self.body, separators=(",", ":")).encode()

    @classmethod
    def error(cls, status: int, code: str, description: str) -> PushResponse:
        """A response with an error document."""
        return cls(status, {"err": code, "description": description})


ExpectedAuthorizationHeaders: TypeAlias = Callable[[str], str]
"""The ``Authorization`` header a transmitter has to send, by the issuer of its SETs; ``""`` for
none."""


class PushHandler:
    """Handles SETs delivered using HTTP push (RFC 8935). Frameworks call :meth:`handle` with the
    ``Authorization`` header and the body and send the returned response;
    :func:`easyssf.receiver.asgi.push_app` and :func:`easyssf.receiver.wsgi.push_wsgi_app` do
    that for ASGI and WSGI.

    A SET is verified and handled before it is acknowledged with 202 Accepted. Invalid SETs are
    rejected with 400 Bad Request and an error document. When the SET could not be processed for a
    reason the transmitter is not responsible for (its keys are temporarily not retrievable, an
    event handler failed) a 5xx status asks it to deliver the SET again.

    The processing runs in a task of its own, shielded from the cancellation of the caller, so
    that a transmitter that disconnects does not cancel the handlers; an exception in a handler
    becomes a 500 and the dedup store releases the claim.

    Args:
        processor: the processor the SETs go to.
        expected_authorization_header: the ``Authorization`` header every request must carry,
            exactly; ``""`` accepts any request. See :meth:`by_issuer` for several transmitters.
    """

    def __init__(self, processor: Processor, expected_authorization_header: str = "") -> None:
        self._processor = processor
        self._fixed = expected_authorization_header.strip()
        self._by_issuer: ExpectedAuthorizationHeaders | None = None
        self._metrics = processor.metrics
        self._log: logging.Logger = processor.logger
        self._tasks: set[asyncio.Task[object]] = set()

    @classmethod
    def by_issuer(cls, processor: Processor, expected: ExpectedAuthorizationHeaders) -> PushHandler:
        """A handler for a receiver with several transmitters: the ``Authorization`` header a
        transmitter has to send is looked up by the issuer of the SET, which is read before the
        SET is verified."""
        handler = cls(processor)
        handler._by_issuer = expected
        return handler

    @property
    def processor(self) -> Processor:
        """The processor the SETs go to."""
        return self._processor

    async def handle(
        self, authorization_header: str | None, body: bytes | str, delivery: DeliveryMethod = DeliveryMethod.PUSH
    ) -> PushResponse:
        """Handles a push request: the ``Authorization`` header of the request (``None`` or ``""``
        if none) and the body, the SET in JWS compact serialization. Never raises for a request;
        a cancellation of the caller leaves the processing running and is raised."""
        given = authorization_header or ""
        if self._by_issuer is None and not _authenticated(self._fixed, given):
            self._metrics.set_received("", delivery, SetOutcome.UNAUTHENTICATED)
            return PushResponse.error(
                _HTTP_UNAUTHORIZED, AUTHENTICATION_FAILED, "The transmitter could not be authenticated"
            )
        raw = body.encode() if isinstance(body, str) else body
        if len(raw) > MAX_SET_SIZE:
            return PushResponse.error(_HTTP_TOO_LARGE, ErrorCode.INVALID_REQUEST, "The SET is too large")
        try:
            encoded_set = raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            return PushResponse.error(_HTTP_BAD_REQUEST, ErrorCode.INVALID_REQUEST, "The SET is not UTF-8")
        if self._by_issuer is not None:
            issuer = unverified_issuer(encoded_set)
            expected = self._by_issuer(issuer) if issuer else ""
            if not _authenticated(expected, given):
                self._metrics.set_received(issuer, delivery, SetOutcome.UNAUTHENTICATED)
                return PushResponse.error(
                    _HTTP_UNAUTHORIZED, AUTHENTICATION_FAILED, "The transmitter could not be authenticated"
                )
        # detached from the request: a transmitter that disconnects does not cancel the handlers
        task = asyncio.create_task(self._processor.process(encoded_set, delivery), name="easyssf-push")
        self._tasks.add(task)
        task.add_done_callback(self._finished)
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            raise
        except RejectedError as rejected:
            self._log.debug("Rejecting SET", extra={"code": rejected.code, "description": rejected.description})
            return PushResponse.error(_HTTP_BAD_REQUEST, rejected.code, rejected.description)
        except TransmitterUnavailableError as error:
            self._log.warning("Could not verify SET, asking the transmitter to deliver it again: %s", error)
            return PushResponse(_HTTP_UNAVAILABLE)
        except InProgressError:
            # temporary: the transmitter delivers the SET again
            return PushResponse(_HTTP_UNAVAILABLE)
        except StoreError as error:
            self._log.error("The dedup store failed, asking the transmitter to deliver the SET again: %s", error)
            return PushResponse(_HTTP_INTERNAL_ERROR)
        except HandlingError:
            # logged per handler by the processor
            return PushResponse(_HTTP_INTERNAL_ERROR)
        except Exception as error:
            # an error wrapped by a handler or store of the application
            wrapped = RejectedError.of(error)
            if wrapped is not None:
                return PushResponse.error(_HTTP_BAD_REQUEST, wrapped.code, wrapped.description)
            if TransmitterUnavailableError.of(error) is not None:
                return PushResponse(_HTTP_UNAVAILABLE)
            self._log.error("Processing the SET failed, asking the transmitter to deliver it again", exc_info=error)
            return PushResponse(_HTTP_INTERNAL_ERROR)
        return PushResponse(_HTTP_ACCEPTED)

    def _finished(self, task: asyncio.Task[object]) -> None:
        self._tasks.discard(task)
        if not task.cancelled():
            # retrieved, so that a result nobody awaits (the caller was cancelled) is not reported
            # by the event loop as never retrieved
            task.exception()

    def __repr__(self) -> str:
        mode = "by issuer" if self._by_issuer is not None else ("fixed header" if self._fixed else "open")
        return f"PushHandler({mode})"


def _authenticated(expected: str, given: str) -> bool:
    if not expected:
        return True
    return hmac.compare_digest(expected.encode(), given.encode())
