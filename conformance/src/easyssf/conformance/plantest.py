"""Runs a plan of the OpenID conformance suite against a receiver under test; the port of
``plantest.go`` and the ``AbstractReceiverConformanceTest`` of the Java library."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import Callable
from datetime import timedelta
from typing import Final

from easyssf.core import DeliveryMethod

from .plan import PlanDefinition
from .run import Run, Runner
from .scenario import expectation_for_module
from .suite import Suite

__all__ = ["MODULE_TIMEOUT", "receiver_log", "run_plan"]

MODULE_TIMEOUT: Final = timedelta(minutes=8)
"""How long a module of a plan may take."""

_log: Final = logging.getLogger("easyssf.conformance.plan")


async def run_plan(
    suite: Suite, plan: PlanDefinition, runner: Runner, log: Callable[[str], None] | None = None
) -> None:
    """Runs a plan against the receiver under test: creates the plan in the suite and runs every
    module of it, playing the scenario the module expects with the runner of the receiver under
    test, which has to be reachable by the suite at :attr:`~.suite.Suite.receiver_push_url`.

    The modules run one after another; pytest has no subtests, so the failures are collected and
    raised together at the end. A module fails with the failures and warnings the suite logged, the
    receiver's log and the link to the suite's log page.

    Args:
        suite: the running suite.
        plan: the plan to run.
        runner: the runner of the receiver under test.
        log: where progress is reported; the ``easyssf.conformance.plan`` logger by default.

    Raises:
        AssertionError: with every module that did not pass, or whose run did not end as expected.
        SuiteApiError: if the suite could not be called.
    """
    report = log if log is not None else _log.info
    config, alias = plan.config()
    api = suite.api_client()
    try:
        created = await api.create_plan(plan.name, plan.variant(), config)
        report(f"Created plan {plan.name} {plan.variant()} with {len(created.modules)} modules: {created.url}")
        issuer = f"{suite.base_url}/test/a/{alias}"
        delivery = DeliveryMethod.POLL if plan.delivery_mode == "poll" else DeliveryMethod.PUSH
        failures: list[str] = []
        for module in created.modules:
            expectation = expectation_for_module(module.name)
            module_id = await api.start_module(created, module)
            report(
                f"Module {module} {module_id} is waiting for the receiver: "
                f"{suite.base_url}/log-detail.html?log={module_id}"
            )
            run = await runner.start(expectation.scenario, issuer, delivery, expectation.idle_timeout)
            await _wait_until_ended(run, MODULE_TIMEOUT)
            report(f"Receiver run {run.id} ended with {run.status}:\n{receiver_log(run)}")
            result = await api.await_result(created, module, module_id, MODULE_TIMEOUT)
            if not result.finished_with("PASSED"):
                report(f"Full log of the failed module {module}:\n{json.dumps(list(result.logs), indent=2)}")
                failures.append(
                    f"{result.summary()}\nReceiver run {run.id} ended with {run.status}:\n{receiver_log(run)}"
                )
            elif run.status is not expectation.run_status:
                failures.append(
                    f"status of the receiver run for {module}: {run.status}, expected {expectation.run_status}"
                )
            else:
                report(f"Module {module} PASSED")
        if failures:
            raise AssertionError(
                f"{len(failures)} of {len(created.modules)} modules of plan {plan} failed:\n\n" + "\n\n".join(failures)
            )
    finally:
        await api.aclose()


async def _wait_until_ended(run: Run, timeout: timedelta) -> None:
    """Waits until the run ended, at most ``timeout``; a run that is still active then is left
    to the next one, which stops it."""
    with contextlib.suppress(TimeoutError):
        async with asyncio.timeout(timeout.total_seconds()):
            await run.wait()


def receiver_log(run: Run) -> str:
    """The log of a run, one line per entry, indented for a failure message."""
    return "".join(f"  {entry.time.isoformat(timespec='seconds')} {entry.message}\n" for entry in run.log)
