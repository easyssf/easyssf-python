"""The receiver test plans of the OpenID conformance suite and the configurations they are created
with; the port of ``plan.go``. The configurations are the ``suite-config/*.json`` files shipped
inside this package."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Final

from .resources import resource_path

__all__ = [
    "CAEP_INTEROP_10_POLL",
    "CAEP_INTEROP_10_PUSH",
    "PLANS",
    "SSF10_POLL",
    "SSF10_PUSH",
    "PlanDefinition",
    "suite_config",
]

_SUITE_CONFIG_DIR: Final = "suite-config"


@dataclass(frozen=True, slots=True)
class PlanDefinition:
    """A receiver test plan of the OpenID conformance suite, with the variant and the
    configuration (in ``suite-config/``) the tests create it with. All of them use
    ``ssf_auth_mode=dynamic`` and ``client_auth_type=client_secret_basic``."""

    name: str
    """The name of the test plan in the suite."""
    delivery_mode: str
    """``push`` or ``poll``."""
    config_file: str
    """The name of the suite configuration file in ``suite-config/``."""

    def variant(self) -> dict[str, str]:
        """The variant the plan is created with."""
        return {
            "ssf_delivery_mode": self.delivery_mode,
            "ssf_auth_mode": "dynamic",
            "client_auth_type": "client_secret_basic",
        }

    def config(self) -> tuple[bytes, str]:
        """The suite configuration of the plan, and its alias.

        Raises:
            ValueError: if the configuration is not JSON or has no alias.
        """
        data = suite_config(self.config_file)
        try:
            parsed = json.loads(data)
        except ValueError as error:
            raise ValueError(f"{self.config_file}: {error}") from error
        alias = parsed.get("alias") if isinstance(parsed, dict) else None
        if not isinstance(alias, str) or not alias:
            raise ValueError(f"{self.config_file} has no alias")
        return data, alias

    def __str__(self) -> str:
        """The name and the delivery mode."""
        return f"{self.name} ({self.delivery_mode})"


SSF10_PUSH: Final = PlanDefinition("openid-ssf-receiver-test-plan", "push", "receiver-ssf1.0-push.json")
"""The default receiver plan with push delivery."""
SSF10_POLL: Final = PlanDefinition("openid-ssf-receiver-test-plan", "poll", "receiver-ssf1.0-poll.json")
"""The default receiver plan with poll delivery."""
CAEP_INTEROP_10_PUSH: Final = PlanDefinition(
    "openid-ssf-receiver-caep-test-plan", "push", "receiver-ssf1.0-caepiop1.0-push.json"
)
"""The CAEP interop plan with push delivery."""
CAEP_INTEROP_10_POLL: Final = PlanDefinition(
    "openid-ssf-receiver-caep-test-plan", "poll", "receiver-ssf1.0-caepiop1.0-poll.json"
)
"""The CAEP interop plan with poll delivery."""

PLANS: Final[tuple[PlanDefinition, ...]] = (SSF10_PUSH, SSF10_POLL, CAEP_INTEROP_10_PUSH, CAEP_INTEROP_10_POLL)
"""The four plans."""


def suite_config(name: str) -> bytes:
    """The suite configuration with the given file name, for example ``easyssf-receiver.json``,
    the one of the manual runs.

    Raises:
        FileNotFoundError: if there is no such configuration.
    """
    return resource_path(_SUITE_CONFIG_DIR, name).read_bytes()
