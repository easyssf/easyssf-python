"""Looks up the test modules running in the conformance suite, so that a run can be started for
the module that waits for the receiver without knowing its name; the port of ``modules.go``. The
suite is the one the transmitter issuer belongs to: a test instance is ``<suite>/test/a/<alias>``.
Its API (``/api/runner/running``, ``/api/info/<id>``) needs no login with the suite's dev profile,
as the local suite runs it."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, ClassVar, Final
from urllib.parse import quote

import httpx

from easyssf.core import DeliveryMethod

from .api import SuiteApiError
from .receiver_settings import ReceiverSettings
from .scenario import scenario_for_module

__all__ = ["WAITING", "Module", "SuiteModules", "TestInstance", "parse_test_instance"]

WAITING: Final = "WAITING"
"""The status of a module that waits for the receiver to act."""

_TEST_INSTANCE: Final = re.compile(r"^(https?://.+?)/test/a/([^/?#]+)/?$")


@dataclass(frozen=True, slots=True)
class Module:
    """A test module running in the suite."""

    id: str
    """The id of the module in the suite."""
    name: str
    """The name of the test module, e.g. ``openid-ssf-receiver-stream-create-delete``."""
    alias: str
    """The alias of the test instance the module runs under."""
    status: str
    """The status reported by the suite; :data:`WAITING` means it waits for the receiver."""
    delivery: str
    """The delivery mode of the module's variant, ``""`` if it has none."""
    issuer: str
    """The transmitter issuer the receiver has to use for this module."""
    scenario: str
    """The alias of the scenario the receiver plays for the module."""
    log_url: str
    """The suite's log page of the module."""

    @property
    def is_waiting(self) -> bool:
        """Whether the module waits for the receiver."""
        return self.status == WAITING

    @property
    def delivery_method(self) -> DeliveryMethod | None:
        """The delivery method of the module's variant, ``None`` if it has none."""
        return DeliveryMethod.from_name(self.delivery)

    def to_mapping(self) -> dict[str, Any]:
        """The module as the API shows it, with the keys of the Go port."""
        mapping: dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "alias": self.alias,
            "status": self.status,
            "issuer": self.issuer,
            "scenario": self.scenario,
            "logUrl": self.log_url,
        }
        if self.delivery:
            mapping["delivery"] = self.delivery
        return mapping


@dataclass(frozen=True, slots=True)
class TestInstance:
    """The suite and the alias a transmitter issuer refers to."""

    __test__: ClassVar[bool] = False  # not a test class, although pytest would take the name for one

    suite: str
    """The URL of the suite, with a trailing slash."""
    alias: str
    """The alias of the test instance."""

    def issuer(self, alias: str) -> str:
        """The issuer of the test instance with the given alias in the same suite."""
        return f"{self.suite}test/a/{alias}"


def parse_test_instance(issuer: str) -> TestInstance:
    """Parses a transmitter issuer of the form ``<suite>/test/a/<alias>``.

    Raises:
        ValueError: if the issuer is not a test instance of the conformance suite.
    """
    match = _TEST_INSTANCE.match(issuer.strip())
    if match is None:
        raise ValueError(
            f"the transmitter issuer {issuer!r} is not a test instance of the conformance suite "
            "(<suite>/test/a/<alias>)"
        )
    return TestInstance(match.group(1) + "/", match.group(2))


class SuiteModules:
    """Looks up modules with ``client``, which has to trust the suite's certificate.

    Args:
        settings: the settings of the receiver under test, for the configured issuer.
        client: the client the suite is called with.
    """

    def __init__(self, settings: ReceiverSettings, client: httpx.AsyncClient) -> None:
        self._settings = settings
        self._client = client

    def test_instance(self, issuer: str) -> TestInstance:
        """The test instance of the given issuer, or of the configured one if it is ``""``.

        Raises:
            ValueError: if no issuer is given and none is configured, or the issuer is not a test
                instance of the suite.
        """
        if not issuer.strip():
            issuer = self._settings.issuer
            if not issuer:
                raise ValueError("the transmitter issuer must be set when no issuer is given")
        return parse_test_instance(issuer)

    async def running(self, instance: TestInstance) -> list[Module]:
        """All modules currently running in the suite, in the order the suite lists them.

        Raises:
            SuiteApiError: if the suite could not be reached or answered unexpectedly.
        """
        ids = await self._get(f"{instance.suite}api/runner/running")
        modules: list[Module] = []
        for module_id in ids if isinstance(ids, list) else []:
            if not isinstance(module_id, str):
                continue
            info = await self._get(f"{instance.suite}api/info/{quote(module_id, safe='')}")
            modules.append(_module_of(instance, module_id, info if isinstance(info, dict) else {}))
        return modules

    async def waiting(self, instance: TestInstance) -> list[Module]:
        """The modules waiting for the receiver that a run should be started for: the ones
        running under the alias of the test instance, or, if there is none, all waiting modules
        of the suite (another alias than configured may have been used to create the plan).

        Raises:
            SuiteApiError: if the suite could not be reached or answered unexpectedly.
        """
        waiting = [module for module in await self.running(instance) if module.is_waiting]
        of_instance = [module for module in waiting if module.alias == instance.alias]
        return of_instance if of_instance else waiting

    async def _get(self, target: str) -> Any:
        try:
            response = await self._client.get(target, headers={"Accept": "application/json"})
        except (httpx.TransportError, TimeoutError) as error:
            raise SuiteApiError(f"the conformance suite could not be reached at {target}: {error}") from error
        if response.status_code != 200:
            raise SuiteApiError(
                f"the conformance suite API {target} returned HTTP {response.status_code}: {response.text}"
            )
        try:
            return json.loads(response.content)
        except ValueError as error:
            raise SuiteApiError(f"the conformance suite API {target} answered with invalid JSON: {error}") from error

    def __repr__(self) -> str:
        return f"SuiteModules(issuer={self._settings.issuer!r})"


def _module_of(instance: TestInstance, module_id: str, info: dict[str, Any]) -> Module:
    name = _string(info.get("testName"))
    alias = _string(info.get("alias")) or instance.alias
    variant = info.get("variant")
    delivery = _string(variant.get("ssf_delivery_mode")) if isinstance(variant, dict) else ""
    return Module(
        id=module_id,
        name=name,
        alias=alias,
        status=_string(info.get("status")),
        delivery=delivery,
        issuer=instance.issuer(alias),
        scenario=scenario_for_module(name).alias,
        log_url=f"{instance.suite}log-detail.html?log={module_id}",
    )


def _string(value: Any) -> str:
    return value if isinstance(value, str) else ""
