"""Waiting for a condition in asyncio tests, the ``Eventually`` of the Java and .NET tests."""

from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Awaitable, Callable
from datetime import timedelta

__all__ = ["during", "eventually"]

_POLL_INTERVAL = 0.01


async def _holds(condition: Callable[[], bool | Awaitable[bool]]) -> bool:
    result = condition()
    if inspect.isawaitable(result):
        return bool(await result)
    return bool(result)


async def eventually(
    condition: Callable[[], bool | Awaitable[bool]],
    timeout: float | timedelta = 5.0,
    what: str = "the condition",
) -> None:
    """Waits until ``condition`` holds, polling it every 10 milliseconds for at most ``timeout``
    seconds. Fails with ``what`` if it does not hold in time.

    Raises:
        AssertionError: when the timeout passes.
    """
    seconds = timeout.total_seconds() if isinstance(timeout, timedelta) else timeout
    deadline = time.monotonic() + seconds
    while not await _holds(condition):
        if time.monotonic() > deadline:
            raise AssertionError(f"Timed out waiting for: {what}")
        await asyncio.sleep(_POLL_INTERVAL)


async def during(
    condition: Callable[[], bool | Awaitable[bool]],
    duration: float | timedelta = 0.2,
    what: str = "the condition",
) -> None:
    """Checks that ``condition`` keeps holding for ``duration`` seconds, polling it every 10
    milliseconds. Fails with ``what`` otherwise.

    Raises:
        AssertionError: when the condition stops holding.
    """
    seconds = duration.total_seconds() if isinstance(duration, timedelta) else duration
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not await _holds(condition):
            raise AssertionError(f"Stopped holding: {what}")
        await asyncio.sleep(_POLL_INTERVAL)
