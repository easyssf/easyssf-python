"""The HTTP API of the receiver under test as a raw ASGI 3 application: starts test runs and
receives the SETs the suite pushes; the ``CtsController`` of the Java receiver and the port of
``cts.go``. Serve it with uvicorn over https (see ``cli.py``) so that the suite can push to it."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, MutableMapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, TypeAlias
from urllib.parse import parse_qs

from easyssf.core import DeliveryMethod
from easyssf.receiver import MAX_SET_SIZE, PUSH_CONTENT_LANGUAGE, PUSH_CONTENT_TYPE

from .api import SuiteApiError
from .modules import Module, SuiteModules
from .run import LogEntry, ReceivedSet, Run, Runner
from .scenario import SCENARIOS, RunStatus, Scenario, scenario_from_alias

__all__ = ["USAGE", "AsgiApp", "ModuleRunView", "RunView", "cts_app"]

Scope: TypeAlias = MutableMapping[str, Any]
Receive: TypeAlias = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send: TypeAlias = Callable[[MutableMapping[str, Any]], Awaitable[None]]
AsgiApp: TypeAlias = Callable[[Scope, Receive, Send], Awaitable[None]]
"""An ASGI 3 application."""

USAGE: Final = """easyssf receiver under test for the OpenID conformance suite
POST /cts/runs/auto                  start the run the test module waiting in the suite expects
     ?issuer=<issuer>                optional: a test instance of the suite, default the configured issuer
GET  /cts/suite/modules              the test modules running in the suite and the scenario each gets
POST /cts/runs?scenario=<scenario>   start a run (stops the current one), scenarios: {scenarios}
     &issuer=<issuer>                optional: the test instance of the suite, default the configured issuer
     &delivery=push|poll             optional: default the configured delivery
GET  /cts/runs/current               what the current run did so far
POST /cts/runs/current/stop          stop the current run and delete its stream
POST /ssf/push                       push endpoint for the suite
"""
"""What ``GET /`` answers."""

_JSON: Final = "application/json"


@dataclass(frozen=True, slots=True)
class RunView:
    """A :class:`~.run.Run` as the API shows it."""

    id: str
    scenario: str
    issuer: str
    delivery: str
    status: RunStatus
    stream_id: str
    started_at: datetime
    log: tuple[LogEntry, ...]
    received_sets: tuple[ReceivedSet, ...]

    @classmethod
    def of(cls, run: Run) -> RunView:
        """The view of a run."""
        return cls(
            id=run.id,
            scenario=run.scenario.alias,
            issuer=run.issuer,
            delivery=str(run.delivery),
            status=run.status,
            stream_id=run.stream_id,
            started_at=run.started_at,
            log=tuple(run.log),
            received_sets=tuple(run.received_sets),
        )

    def to_mapping(self) -> dict[str, Any]:
        """The view as JSON, with the keys of the Go port."""
        mapping: dict[str, Any] = {
            "id": self.id,
            "scenario": self.scenario,
            "issuer": self.issuer,
            "delivery": self.delivery,
            "status": self.status.value,
            "startedAt": self.started_at.isoformat(),
            "log": [entry.to_mapping() for entry in self.log],
            "receivedSets": [received.to_mapping() for received in self.received_sets],
        }
        if self.stream_id:
            mapping["streamId"] = self.stream_id
        return mapping


@dataclass(frozen=True, slots=True)
class ModuleRunView:
    """A run started for the module waiting in the suite."""

    module: Module
    run: RunView

    def to_mapping(self) -> dict[str, Any]:
        """The view as JSON."""
        return {"module": self.module.to_mapping(), "run": self.run.to_mapping()}


def cts_app(runner: Runner, modules: SuiteModules) -> AsgiApp:
    """The ASGI application of the receiver under test: the endpoints of :data:`USAGE`.
    Lifespan events are acknowledged, so the app can be served on its own."""

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                await send({"type": message["type"] + ".complete"})
                if message["type"] == "lifespan.shutdown":
                    return
        if scope["type"] != "http":
            raise RuntimeError(f"the receiver under test serves HTTP, not {scope['type']}")
        request = _Request(runner, modules, scope, receive, send)
        route = _ROUTES.get(request.path)
        if route is None:
            await request.problem(404, f"No such endpoint: {request.path}")
            return
        allowed, handle = route
        if request.method != allowed:
            await request.respond(405, [(b"allow", allowed.encode())], b"")
            return
        await handle(request)

    return app


class _Request:
    """One request to the app: what it asks for and how it is answered."""

    __slots__ = ("_receive", "_send", "modules", "query", "runner", "scope")

    def __init__(self, runner: Runner, modules: SuiteModules, scope: Scope, receive: Receive, send: Send) -> None:
        self.runner = runner
        self.modules = modules
        self.scope = scope
        self._receive = receive
        self._send = send
        query_string = scope.get("query_string", b"").decode("latin-1")
        self.query = {name: values[0] for name, values in parse_qs(query_string).items()}

    @property
    def method(self) -> str:
        return str(self.scope["method"])

    @property
    def path(self) -> str:
        return str(self.scope["path"])

    def header(self, name: bytes) -> str | None:
        return next(
            (value.decode("latin-1") for key, value in self.scope.get("headers", []) if key.lower() == name), None
        )

    async def body(self, limit: int) -> bytes | None:
        """The body, read up to one message beyond ``limit`` bytes; ``None`` if the client left."""
        body = b""
        while len(body) <= limit:
            message = await self._receive()
            if message["type"] == "http.disconnect":
                return None
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
        return body

    async def respond(self, status: int, headers: list[tuple[bytes, bytes]], body: bytes) -> None:
        await self._send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [*headers, (b"content-length", str(len(body)).encode())],
            }
        )
        await self._send({"type": "http.response.body", "body": body})

    async def json(self, status: int, body: Any) -> None:
        await self.respond(status, [(b"content-type", _JSON.encode())], json.dumps(body).encode())

    async def problem(self, status: int, message: str) -> None:
        await self.json(status, {"status": status, "message": message})


_Handler: TypeAlias = Callable[[_Request], Awaitable[None]]


async def _usage(request: _Request) -> None:
    text = USAGE.format(scenarios=[scenario.alias for scenario in SCENARIOS])
    await request.respond(200, [(b"content-type", b"text/plain; charset=utf-8")], text.encode())


async def _start_run(request: _Request) -> None:
    try:
        scenario = scenario_from_alias(request.query.get("scenario") or Scenario.CAEP_INTEROP.alias)
    except ValueError as error:
        await request.problem(400, str(error))
        return
    delivery: DeliveryMethod | None = None
    if request.query.get("delivery"):
        delivery = DeliveryMethod.from_name(request.query["delivery"])
        if delivery is None:
            await request.problem(400, "delivery must be push or poll")
            return
    try:
        run = await request.runner.start(scenario, request.query.get("issuer", ""), delivery)
    except ValueError as error:
        await request.problem(400, str(error))
        return
    await request.json(202, RunView.of(run).to_mapping())


async def _start_auto(request: _Request) -> None:
    try:
        instance = request.modules.test_instance(request.query.get("issuer", ""))
    except ValueError as error:
        await request.problem(400, str(error))
        return
    try:
        waiting = await request.modules.waiting(instance)
    except SuiteApiError as error:
        await request.problem(502, str(error))
        return
    if not waiting:
        await request.problem(
            404,
            f"No test module is waiting for the receiver in the conformance suite at {instance.suite}; "
            "start one there first",
        )
        return
    if len(waiting) > 1:
        names = ", ".join(f"{module.name} ({module.issuer})" for module in waiting)
        await request.problem(
            409, f"Several test modules are waiting for the receiver: {names}; pick one with ?issuer=<issuer>"
        )
        return
    module = waiting[0]
    try:
        run = await request.runner.start(scenario_from_alias(module.scenario), module.issuer, module.delivery_method)
    except ValueError as error:
        await request.problem(400, str(error))
        return
    await request.json(202, ModuleRunView(module, RunView.of(run)).to_mapping())


async def _suite_modules(request: _Request) -> None:
    try:
        instance = request.modules.test_instance(request.query.get("issuer", ""))
    except ValueError as error:
        await request.problem(400, str(error))
        return
    try:
        running = await request.modules.running(instance)
    except SuiteApiError as error:
        await request.problem(502, str(error))
        return
    await request.json(200, [module.to_mapping() for module in running])


async def _current(request: _Request) -> None:
    run = request.runner.current
    if run is None:
        await request.problem(404, "No run was started yet")
        return
    await request.json(200, RunView.of(run).to_mapping())


async def _stop(request: _Request) -> None:
    run = request.runner.current
    if run is None:
        await request.problem(404, "No run was started yet")
        return
    await run.stop()
    await request.json(200, RunView.of(run).to_mapping())


async def _push(request: _Request) -> None:
    push_headers = [
        (b"content-type", PUSH_CONTENT_TYPE.encode()),
        (b"content-language", PUSH_CONTENT_LANGUAGE.encode()),
    ]
    run = request.runner.current
    if run is None or not run.is_active:
        await request.respond(
            503, push_headers, b'{"err":"invalid_request","description":"No conformance run is active"}'
        )
        return
    body = await request.body(MAX_SET_SIZE)
    if body is None:
        return
    response = await run.push(request.header(b"authorization"), body)
    content = response.body_bytes
    await request.respond(response.status, push_headers if content is not None else [], content or b"")


_ROUTES: Final[dict[str, tuple[str, _Handler]]] = {
    "/": ("GET", _usage),
    "/cts/runs": ("POST", _start_run),
    "/cts/runs/auto": ("POST", _start_auto),
    "/cts/suite/modules": ("GET", _suite_modules),
    "/cts/runs/current": ("GET", _current),
    "/cts/runs/current/stop": ("POST", _stop),
    "/ssf/push": ("POST", _push),
}
