"""The errors of the receiver and the clock its components measure time by.

Every error is an exception class under :class:`EasyssfError`; callers catch types, never match
messages. A :class:`RejectedError` says the SET is invalid and carries the RFC 8935 error code,
a :class:`TransmitterUnavailableError` is temporary, the others say what kept a verified SET
from being handled.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Final, TypeAlias

__all__ = [
    "Clock",
    "ConfigurationError",
    "EasyssfError",
    "ErrorCode",
    "HandlingError",
    "InProgressError",
    "RejectedError",
    "StoreError",
    "TransmitterUnavailableError",
    "system_clock",
]

Clock: TypeAlias = Callable[[], datetime]
"""The time now, a timezone-aware ``datetime``; tests replace it with a ``ManualClock``."""


def system_clock() -> datetime:
    """The system clock: now in UTC."""
    return datetime.now(tz=UTC)


class ErrorCode:
    """The error codes of RFC 8935, section 2.4, and ``invalid_state`` of SSF 1.0, section 8.1.4.1,
    reported to the transmitter when a SET is rejected. Decided by the receiver, not by the JWT
    library.

    An open set: the specification may add codes, so a :class:`RejectedError` carries any string
    and nothing switches over these exhaustively.
    """

    INVALID_REQUEST: Final = "invalid_request"
    """The SET is malformed or lacks a claim."""
    INVALID_KEY: Final = "invalid_key"
    """The SET is signed with a key the receiver does not accept."""
    INVALID_ISSUER: Final = "invalid_issuer"
    """The SET was issued by another transmitter."""
    INVALID_AUDIENCE: Final = "invalid_audience"
    """The SET is not addressed to this receiver."""
    INVALID_STATE: Final = "invalid_state"
    """The state of a verification event is not the expected one."""


class EasyssfError(Exception):
    """The base of every error the receiver raises."""


class RejectedError(EasyssfError):
    """A SET is invalid; the transmitter must not deliver it again. Carries the error code
    reported to the transmitter (RFC 8935, section 2.4).

    Args:
        code: the RFC 8935 error code, one of :class:`ErrorCode` or a newer one.
        description: for the error document and the log.
    """

    def __init__(self, code: str, description: str) -> None:
        super().__init__(code, description)
        self.code = code
        """The RFC 8935 error code."""
        self.description = description
        """The description for the error document and the log."""

    def __str__(self) -> str:
        """The description with the code in parentheses."""
        return f"{self.description} ({self.code})"

    @classmethod
    def of(cls, exc: BaseException | None) -> RejectedError | None:
        """The rejection in the given exception or its chain of causes, ``None`` if the SET was
        not rejected (the transmitter was unavailable, say)."""
        found = _find(exc, cls)
        return found if isinstance(found, cls) else None


class TransmitterUnavailableError(EasyssfError):
    """The transmitter's metadata or keys cannot be obtained. Unlike an invalid SET this is a
    temporary condition: the SET should be delivered again later.

    Args:
        cause: the underlying error, ``None`` if there is none.
        message: what could not be obtained.
    """

    def __init__(self, cause: BaseException | None, message: str) -> None:
        super().__init__(message)
        self.message = message
        """What could not be obtained."""
        self.cause = cause
        """The underlying error, ``None`` if there is none."""
        self.__cause__ = cause

    def __str__(self) -> str:
        """The message, followed by the cause if there is one."""
        if self.cause is not None:
            return f"{self.message}: {self.cause}"
        return self.message

    @classmethod
    def of(cls, exc: BaseException | None) -> TransmitterUnavailableError | None:
        """The unavailability in the given exception or its chain of causes, ``None`` if the
        transmitter was not unavailable."""
        found = _find(exc, cls)
        return found if isinstance(found, cls) else None


class InProgressError(EasyssfError):
    """Another instance is handling the SET; leave it for a redelivery."""

    def __init__(self) -> None:
        super().__init__("the SET is being handled by another instance")


class HandlingError(EasyssfError):
    """One or more handlers failed; the SET must be delivered again.

    Args:
        handler: the name of the first handler that failed, see ``handler_name``.
        cause: the error of the first handler that failed.
        failed: how many handlers failed, at least one.
    """

    def __init__(self, handler: str, cause: BaseException, failed: int = 1) -> None:
        super().__init__(handler, cause, failed)
        self.handler = handler
        """The name of the first handler that failed."""
        self.cause = cause
        """The error of the first handler that failed."""
        self.failed = failed
        """How many handlers failed."""
        self.__cause__ = cause

    def __str__(self) -> str:
        """How many handlers failed and what the first one failed with."""
        return f"{self.failed} handler(s) failed for the SET, the first ({self.handler}) with: {self.cause}"


class StoreError(EasyssfError):
    """The dedup store failed.

    Args:
        cause: the error of the store.
    """

    def __init__(self, cause: BaseException) -> None:
        super().__init__(cause)
        self.cause = cause
        """The error of the store."""
        self.__cause__ = cause

    def __str__(self) -> str:
        """What the store failed with."""
        return f"the dedup store failed: {self.cause}"


class ConfigurationError(EasyssfError):
    """A receiver configuration is invalid; lists every failure, each prefixed with the key of
    the setting, so that a user fixes them all at once.

    Args:
        failures: what is wrong, one entry per failure.
    """

    def __init__(self, failures: list[str]) -> None:
        super().__init__(failures)
        self.failures = list(failures)
        """What is wrong, one entry per failure."""

    def __str__(self) -> str:
        """The failures, one per line."""
        return "the SSF receiver configuration is invalid:\n  " + "\n  ".join(self.failures)


def _find(exc: BaseException | None, of_type: type[BaseException]) -> BaseException | None:
    """The first exception of the given type in the chain of causes of ``exc``, following
    ``__cause__`` and the implicit ``__context__`` as a traceback does."""
    seen: set[int] = set()
    current = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, of_type):
            return current
        seen.add(id(current))
        if current.__cause__ is not None:
            current = current.__cause__
        elif not current.__suppress_context__:
            current = current.__context__
        else:
            current = None
    return None
