"""The part of the suite's REST API the tests use: creating plans, starting modules and reading
their state and log; the port of ``api.go``. On an ``httpx.AsyncClient`` that trusts the suite's
certificate."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Final
from urllib.parse import quote

import httpx

__all__ = ["TERMINAL_STATES", "ApiClient", "ModuleResult", "Plan", "PlanModule", "SuiteApiError"]

TERMINAL_STATES: Final[frozenset[str]] = frozenset({"FINISHED", "INTERRUPTED"})
"""The states a module does not leave again."""

_REQUEST_TIMEOUT: Final = timedelta(minutes=2)
_REPLAY_ATTEMPTS: Final = 4
_MAX_PROBLEMS: Final = 20


class SuiteApiError(Exception):
    """A call to the conformance suite failed: it could not be reached, answered with an
    unexpected status, or a module did not reach the expected state in time."""


@dataclass(frozen=True, slots=True)
class PlanModule:
    """A module of a plan with the variant the plan assigns to it."""

    name: str
    """The name of the test module, e.g. ``openid-ssf-receiver-happypath``."""
    variant: dict[str, str] = field(default_factory=dict)
    """The variant of the module, empty if the plan assigns none."""

    def __str__(self) -> str:
        """The name, with the variant if there is one."""
        if not self.variant:
            return self.name
        return f"{self.name} {self.variant}"


@dataclass(frozen=True, slots=True)
class Plan:
    """A created plan."""

    id: str
    """The id of the plan in the suite."""
    name: str
    """The name of the test plan."""
    variant: dict[str, str]
    """The variant the plan was created with."""
    modules: tuple[PlanModule, ...]
    """The modules of the plan, in the order the suite runs them."""
    url: str
    """The plan's page in the suite."""


@dataclass(frozen=True, slots=True)
class ModuleResult:
    """The outcome of a module run as the suite reports it."""

    plan: Plan
    module: PlanModule
    module_id: str
    status: str
    """The status of the module, ``FINISHED`` once it ended."""
    result: str
    """The result the suite reports (``PASSED``, ``FAILED``, ``WARNING``, ...), ``UNKNOWN`` if none."""
    logs: tuple[dict[str, Any], ...]
    """The log entries of the module as the suite returns them."""
    url: str
    """The module's log page in the suite."""

    def finished_with(self, expected: str) -> bool:
        """Whether the module finished with the expected result (``PASSED``, ...)."""
        return self.status == "FINISHED" and self.result == expected

    def problems(self) -> list[str]:
        """The failures and warnings the suite logged."""
        return [_format_log_entry(entry) for entry in self.logs if entry.get("result") in ("FAILURE", "WARNING")]

    def summary(self) -> str:
        """The result with the problems, for a failure message."""
        lines = [
            f"Conformance module {self.module} of plan {self.plan.name} {self.plan.variant}: "
            f"status {self.status}, result {self.result} ({self.url})"
        ]
        problems = self.problems()
        if not problems:
            lines.append("  no failures or warnings logged")
        lines.extend("  " + problem for problem in problems[:_MAX_PROBLEMS])
        return "\n".join(lines)


def _format_log_entry(entry: dict[str, Any]) -> str:
    def text(*names: str) -> str:
        for name in names:
            value = entry.get(name)
            if isinstance(value, str) and value:
                return value
        return ""

    formatted = f"{text('result')} {text('src', 'condition')}: {text('msg', 'message', 'error')}"
    for detail in ("url", "match", "detail", "requirements"):
        value = entry.get(detail)
        if value is not None:
            formatted += f" {detail}={json.dumps(value, separators=(',', ':'))}"
    return formatted


class ApiClient:
    """Calls the suite at ``base_url`` with ``client``, which has to trust its certificate.

    Args:
        base_url: the URL of the suite, without a trailing slash.
        client: the client the suite is called with.
    """

    def __init__(self, base_url: str, client: httpx.AsyncClient) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = client

    @property
    def base_url(self) -> str:
        """The URL of the suite."""
        return self._base_url

    @property
    def client(self) -> httpx.AsyncClient:
        """The client the suite is called with."""
        return self._client

    async def aclose(self) -> None:
        """Closes the client."""
        await self._client.aclose()

    async def wait_until_available(self, timeout: timedelta) -> None:
        """Waits until the suite answers ``/api/runner/available``.

        Raises:
            SuiteApiError: if it does not within the timeout.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout.total_seconds()
        last: Exception | None = None
        while loop.time() < deadline:
            try:
                status, _ = await self._send("GET", "/api/runner/available", None, True)
            except SuiteApiError as error:
                last = error
            else:
                if status == 200:
                    return
                last = SuiteApiError(f"the conformance suite returned HTTP {status}")
            await asyncio.sleep(2)
        raise SuiteApiError(f"the conformance suite did not become available at {self._base_url}: {last}")

    async def create_plan(self, plan_name: str, variant: dict[str, str], config: bytes) -> Plan:
        """Creates a plan and returns its id together with the modules it consists of.

        Raises:
            SuiteApiError: if the suite could not be called or answered unexpectedly.
        """
        path = f"/api/plan?planName={quote(plan_name, safe='')}&variant={quote(json.dumps(variant), safe='')}"
        body = await self._expect_json("POST", path, config, 201, True)
        plan_id = body.get("id")
        if not isinstance(plan_id, str) or not plan_id:
            raise SuiteApiError(f"conformance suite API response lacks 'id': {body}")
        modules: list[PlanModule] = []
        for element in body.get("modules") or []:
            module = element if isinstance(element, dict) else {}
            name = module.get("testModule")
            if not isinstance(name, str) or not name:
                raise SuiteApiError(f"conformance suite API response lacks 'testModule': {module}")
            modules.append(PlanModule(name, _string_map(module.get("variant"))))
        return Plan(
            plan_id, plan_name, dict(variant), tuple(modules), f"{self._base_url}/plan-detail.html?plan={plan_id}"
        )

    async def start_module(self, plan: Plan, module: PlanModule) -> str:
        """Creates and starts a module of a plan. Returns the id of the module once the module
        waits for the receiver under test or has finished already.

        Raises:
            SuiteApiError: if the suite could not be called, answered unexpectedly or the module
                did not reach the waiting state in time.
        """
        path = (
            f"/api/runner?test={quote(module.name, safe='')}&plan={quote(plan.id, safe='')}"
            f"&variant={quote(json.dumps(module.variant), safe='')}"
        )
        created = await self._expect_json("POST", path, None, 201, True)
        module_id = created.get("id")
        if not isinstance(module_id, str) or not module_id:
            raise SuiteApiError(f"conformance suite API response lacks 'id': {created}")
        info = await self._wait_for_state(module_id, timedelta(minutes=2), "CONFIGURED", "WAITING")
        if info.get("status") == "CONFIGURED":
            # not replayed, as a lost response would start the module a second time
            await self._expect_json("POST", f"/api/runner/{quote(module_id, safe='')}", None, 200, False)
            await self._wait_for_state(module_id, timedelta(minutes=2), "WAITING")
        return module_id

    async def await_result(self, plan: Plan, module: PlanModule, module_id: str, timeout: timedelta) -> ModuleResult:
        """Waits until the module ended and returns its result with its log.

        Raises:
            SuiteApiError: if the module did not end in time or the suite could not be called.
        """
        info = await self._wait_for_state(module_id, timeout)
        logs: list[dict[str, Any]] = []
        try:
            status, body = await self._send("GET", f"/api/log/{quote(module_id, safe='')}", None, True)
        except SuiteApiError:
            status, body = 0, b""
        if status == 200:
            try:
                parsed = json.loads(body)
            except ValueError:
                parsed = None
            if isinstance(parsed, list):
                logs = [entry for entry in parsed if isinstance(entry, dict)]
        result = info.get("result")
        return ModuleResult(
            plan=plan,
            module=module,
            module_id=module_id,
            status=str(info.get("status") or ""),
            result=result if isinstance(result, str) and result else "UNKNOWN",
            logs=tuple(logs),
            url=f"{self._base_url}/log-detail.html?log={module_id}",
        )

    async def info(self, module_id: str) -> dict[str, Any]:
        """The state of a module.

        Raises:
            SuiteApiError: if the suite could not be called or answered unexpectedly.
        """
        return await self._expect_json("GET", f"/api/info/{quote(module_id, safe='')}", None, 200, True)

    async def _wait_for_state(self, module_id: str, timeout: timedelta, *states: str) -> dict[str, Any]:
        """Waits until the module is in one of the states or in a terminal one."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout.total_seconds()
        last: dict[str, Any] | None = None
        last_error: Exception | None = None
        while loop.time() < deadline:
            try:
                info = await self.info(module_id)
            except SuiteApiError as error:
                last_error = error
            else:
                last = info
                status = info.get("status")
                if status in TERMINAL_STATES or status in states:
                    return info
            await asyncio.sleep(1)
        message = f"timed out waiting for module {module_id} to reach {list(states)}; last info: {last}"
        if last_error is not None:
            message += f": {last_error}"
        raise SuiteApiError(message)

    async def _expect_json(
        self, method: str, path: str, body: bytes | None, expected: int, replayable: bool
    ) -> dict[str, Any]:
        status, response = await self._send(method, path, body, replayable)
        if status != expected:
            raise SuiteApiError(
                f"conformance suite API {method} {path} returned HTTP {status}: {response.decode('utf-8', 'replace')}"
            )
        try:
            parsed = json.loads(response)
        except ValueError as error:
            raise SuiteApiError(f"conformance suite API {method} {path} answered with invalid JSON: {error}") from error
        if not isinstance(parsed, dict):
            raise SuiteApiError(f"conformance suite API {method} {path} did not answer with a JSON object")
        return parsed

    async def _send(self, method: str, path: str, body: bytes | None, replayable: bool) -> tuple[int, bytes]:
        """Sends a request; the suite occasionally drops a connection, so transient failures of
        replayable requests are retried."""
        attempts = _REPLAY_ATTEMPTS if replayable else 1
        target = self._base_url + path
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        last: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                response = await self._client.request(
                    method, target, headers=headers, content=body, timeout=_REQUEST_TIMEOUT.total_seconds()
                )
            except (httpx.TransportError, TimeoutError) as error:
                last = error
            else:
                return response.status_code, response.content
            if attempt < attempts:
                await asyncio.sleep(attempt)
        raise SuiteApiError(f"conformance suite API request failed: {target}: {last}")

    def __repr__(self) -> str:
        return f"ApiClient({self._base_url!r})"


def _string_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(name): v if isinstance(v, str) else json.dumps(v) for name, v in value.items()}
