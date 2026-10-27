"""What the receiver does with its stream in a test run, which scenario a test module of the suite
gets, and how its run is expected to end; the port of ``scenario.go``. :class:`RunStatus` lives
here, next to the expectations that name it, because ``run.py`` builds on the scenarios."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from typing import Final

__all__ = [
    "DEFAULT_IDLE_TIMEOUT",
    "PAUSING_IDLE_TIMEOUT",
    "SCENARIOS",
    "ModuleExpectation",
    "RunStatus",
    "Scenario",
    "expectation_for_module",
    "scenario_for_module",
    "scenario_from_alias",
]


class Scenario(Enum):
    """What the receiver does with its stream in a test run. All scenarios create the stream,
    check its issuer, and delete it at the end; the ones that keep the stream read its
    configuration and status, verify it and accept the events the transmitter delivers until none
    arrives for a while. The value is the alias used in the API."""

    CAEP_INTEROP = "caep-interop"
    """Fits the CAEP interop plan and most tests of the default plan."""
    CREATE_DELETE = "create-delete"
    """Creates and deletes the stream, nothing else."""
    STREAM_MANAGEMENT = "stream-management"
    """Additionally updates and replaces the stream configuration (receiver happy path test of the
    default plan)."""
    STATUS_UPDATE = "status-update"
    """Additionally pauses and enables the stream (stream status test of the default plan)."""
    REMOVE_SUBJECT = "remove-subject"
    """Additionally removes a subject from the stream (removed subject test of the default plan)."""

    @property
    def alias(self) -> str:
        """The name used in the API, e.g. ``caep-interop``."""
        return self.value

    def __str__(self) -> str:
        """The alias."""
        return self.value


SCENARIOS: Final[tuple[Scenario, ...]] = tuple(Scenario)
"""All scenarios, in order."""


def scenario_from_alias(alias: str) -> Scenario:
    """The scenario with the given alias (``caep-interop``) or name (``CaepInterop``),
    case-insensitive.

    Raises:
        ValueError: for an unknown scenario.
    """
    wanted = alias.strip().lower()
    for scenario in Scenario:
        if wanted in (scenario.alias, scenario.alias.replace("-", "")):
            return scenario
    raise ValueError(f"unknown scenario {alias!r}")


_MODULE_SCENARIOS: Final[dict[str, Scenario]] = {
    "openid-ssf-receiver-happypath": Scenario.STREAM_MANAGEMENT,
    "openid-ssf-receiver-stream-create-delete": Scenario.CREATE_DELETE,
    "openid-ssf-receiver-stream-status-update": Scenario.STATUS_UPDATE,
    "openid-ssf-receiver-removed-subject-event": Scenario.REMOVE_SUBJECT,
}
"""The test modules of the suite's receiver plans that need another scenario than
:attr:`Scenario.CAEP_INTEROP`, which fits all tests that just expect a stream to be created,
verified, fed and deleted."""


def scenario_for_module(module_name: str) -> Scenario:
    """The scenario the receiver plays for a test module of the suite, e.g.
    ``openid-ssf-receiver-stream-create-delete``."""
    return _MODULE_SCENARIOS.get(module_name, Scenario.CAEP_INTEROP)


class RunStatus(Enum):
    """Where a run of the receiver under test stands."""

    STARTING = "STARTING"
    RUNNING = "RUNNING"
    FINISHED = "FINISHED"
    REFUSED_STREAM = "REFUSED_STREAM"
    FAILED = "FAILED"
    STOPPED = "STOPPED"

    @property
    def is_active(self) -> bool:
        """Whether the run is starting or running."""
        return self in (RunStatus.STARTING, RunStatus.RUNNING)

    def __str__(self) -> str:
        """The name, as the API shows it."""
        return self.value


DEFAULT_IDLE_TIMEOUT: Final = timedelta(seconds=5)
"""How long the receiver waits for further events before it deletes the stream, in the runs the
plan tests start. The suite delivers the events of most modules back to back (gaps of at most about
2 seconds), so this is far below the configured idle timeout of a manual run."""

PAUSING_IDLE_TIMEOUT: Final = timedelta(seconds=30)
"""The idle timeout for the modules that pause between events on purpose: 20 seconds token
lifetime in the access token expiry test, 15 seconds in the transmitter-initiated status change
test."""


@dataclass(frozen=True, slots=True)
class ModuleExpectation:
    """What the receiver does for a test module of the suite's receiver plans and how its run is
    expected to end."""

    scenario: Scenario
    """The scenario the receiver plays."""
    run_status: RunStatus
    """The status the run has to end with."""
    idle_timeout: timedelta
    """How long the run waits for further events before it deletes the stream."""


_MODULE_OUTCOMES: Final[dict[str, tuple[RunStatus, timedelta]]] = {
    # the transmitter's issuer differs from the one the stream is created at
    "openid-ssf-receiver-stream-issuer-mismatch": (RunStatus.REFUSED_STREAM, DEFAULT_IDLE_TIMEOUT),
    "openid-ssf-receiver-access-token-expiry": (RunStatus.FINISHED, PAUSING_IDLE_TIMEOUT),
    "openid-ssf-receiver-transmitter-initiated-status-change": (RunStatus.FINISHED, PAUSING_IDLE_TIMEOUT),
}


def expectation_for_module(module_name: str) -> ModuleExpectation:
    """The expectation for a module, by its name."""
    run_status, idle_timeout = _MODULE_OUTCOMES.get(module_name, (RunStatus.FINISHED, DEFAULT_IDLE_TIMEOUT))
    return ModuleExpectation(scenario_for_module(module_name), run_status, idle_timeout)
