"""The four conformance plans against the receiver under test, the app served over https on the
receiver port; the Ssf10Push/Poll and CaepInterop10Push/Poll ReceiverConformanceTests of the Java
library, conformance/plans_test.go of the Go port. Skipped unless EASYSSF_CONFORMANCE_TESTS=true:
a plan takes minutes and needs Docker."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, replace
from datetime import UTC, datetime

import pytest
import uvicorn

from easyssf.conformance import (
    CAEP_INTEROP_10_POLL,
    CAEP_INTEROP_10_PUSH,
    SSF10_POLL,
    SSF10_PUSH,
    PlanDefinition,
    Runner,
    Suite,
    SuiteModules,
    close_shared_suite,
    cts_app,
    default_receiver_settings,
    receiver_tls_files,
    run_plan,
    shared_suite,
)
from easyssf.core import DeliveryMethod

CONFORMANCE_TESTS = "EASYSSF_CONFORMANCE_TESTS"

pytestmark = [
    pytest.mark.skipif(
        os.environ.get(CONFORMANCE_TESTS) != "true",
        reason=f"Set {CONFORMANCE_TESTS}=true to run the conformance suite in Docker (minutes per plan)",
    ),
    pytest.mark.timeout(3600),
]

log = logging.getLogger("easyssf.conformance.tests")


@pytest.fixture(scope="module", autouse=True)
def suite_lifecycle() -> Iterator[None]:
    """Stops the shared suite once the plans of this module ran."""
    yield
    close_shared_suite()


def report(message: str) -> None:
    """Prints the progress of a plan with a timestamp (shown with ``pytest -s``) and logs it."""
    print(f"{datetime.now(tz=UTC).isoformat(timespec='seconds')} {message}", flush=True)
    log.info(message)


@dataclass(frozen=True, slots=True)
class ReceiverUnderTest:
    suite: Suite
    runner: Runner


@contextlib.asynccontextmanager
async def receiver_under_test(plan: PlanDefinition) -> AsyncIterator[ReceiverUnderTest]:
    """Starts the suite (once per process) and the receiver under test for the plan on the
    receiver port, reachable by the suite at its push URL."""
    suite = await shared_suite(log)
    settings = replace(
        default_receiver_settings(),
        push_url=suite.receiver_push_url,
        delivery=DeliveryMethod.POLL if plan.delivery_mode == "poll" else DeliveryMethod.PUSH,
    )
    client = suite.http_client()
    runner = Runner(settings, client, log)
    certificate, key = receiver_tls_files()
    server = uvicorn.Server(
        uvicorn.Config(
            cts_app(runner, SuiteModules(settings, client)),
            host="0.0.0.0",
            port=suite.settings.receiver_port,
            ssl_certfile=str(certificate),
            ssl_keyfile=str(key),
            log_level="warning",
            lifespan="off",
        )
    )
    serving = asyncio.create_task(server.serve(), name="easyssf-conformance-receiver")
    while not server.started:
        if serving.done():
            serving.result()
            raise RuntimeError("the receiver under test did not start")
        await asyncio.sleep(0.05)
    try:
        yield ReceiverUnderTest(suite, runner)
    finally:
        if runner.current is not None:
            await runner.current.stop()
        server.should_exit = True
        await serving
        await client.aclose()


async def test_ssf10_push_plan():
    async with receiver_under_test(SSF10_PUSH) as receiver:
        await run_plan(receiver.suite, SSF10_PUSH, receiver.runner, report)


async def test_ssf10_poll_plan():
    async with receiver_under_test(SSF10_POLL) as receiver:
        await run_plan(receiver.suite, SSF10_POLL, receiver.runner, report)


async def test_caep_interop_10_push_plan():
    async with receiver_under_test(CAEP_INTEROP_10_PUSH) as receiver:
        await run_plan(receiver.suite, CAEP_INTEROP_10_PUSH, receiver.runner, report)


async def test_caep_interop_10_poll_plan():
    async with receiver_under_test(CAEP_INTEROP_10_POLL) as receiver:
        await run_plan(receiver.suite, CAEP_INTEROP_10_POLL, receiver.runner, report)
