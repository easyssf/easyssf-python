"""The suite images and ports the conformance tests start the suite with, taken from ``CTS_*``
environment variables; the port of ``settings.go``.

The images are the suite release easyssf is tested with, release-v5.3.2 of 2026-10-09, the first
release with the SSF receiver tests as they are on master (the poll race of release-v5.3.1
included), pinned by the digest of its multi-platform image: the single place to change them, the
same digests as in the Java, Go, .NET and Rust repositories.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final

__all__ = [
    "DEFAULT_RECEIVER_PORT",
    "DEFAULT_SUITE_IMAGE",
    "DEFAULT_SUITE_MONGODB_IMAGE",
    "DEFAULT_SUITE_NGINX_IMAGE",
    "DEFAULT_SUITE_PORT",
    "Settings",
    "settings_from_environment",
]

DEFAULT_SUITE_IMAGE: Final = "registry.gitlab.com/openid/conformance-suite@sha256:c795df1b151e0c2f2e40f17a2470991cc38bc91628449e9bb090e2372fe8b822"  # noqa: E501
"""The conformance suite image."""

DEFAULT_SUITE_NGINX_IMAGE: Final = "registry.gitlab.com/openid/conformance-suite/nginx@sha256:607458218abb58204201e4d283af90177d6b542535a99a21041d399a1505a6a0"  # noqa: E501
"""Its nginx image."""

DEFAULT_SUITE_MONGODB_IMAGE: Final = "mongo@sha256:dc28ed5a9d0fc616903c3f463bb1e53b92b49f441721b91926e87d90bf957ce8"
"""Its MongoDB image. The suite's own compose file runs MongoDB 6.0.13, as the suite does in
production; for the tests a current release, with far fewer known vulnerabilities, works just as
well: ``mongo:9.0.4``, pinned by digest. Not older: MongoDB 8.0 and newer refuse to start on a Linux
kernel from 6.19 up to 7.0.13 (a tcmalloc incompatibility, SERVER-121912), and before 9.0.4 they
took Ubuntu's 7.0 kernels, the ones of GitHub's runners since October 2026, for 7.0.0
(SERVER-131779)."""

DEFAULT_SUITE_PORT: Final = 18443
"""The host port the suite listens on. Fixed, as the suite has to know its own URL before it
starts."""

DEFAULT_RECEIVER_PORT: Final = 9444
"""The port the receiver under test listens on. Fixed, as the suite reaches it by its push URL."""


@dataclass(frozen=True, slots=True)
class Settings:
    """How the conformance tests start the suite and expose the system under test."""

    suite_image: str = DEFAULT_SUITE_IMAGE
    """The conformance suite image."""
    suite_nginx_image: str = DEFAULT_SUITE_NGINX_IMAGE
    """Its nginx image."""
    suite_mongodb_image: str = DEFAULT_SUITE_MONGODB_IMAGE
    """Its MongoDB image."""
    suite_port: int = DEFAULT_SUITE_PORT
    """The host port of the suite."""
    receiver_port: int = DEFAULT_RECEIVER_PORT
    """The port of the receiver under test."""
    receiver_push_url: str = ""
    """The push URL the suite is to deliver to, when the default of
    ``https://<host as seen from the suite>:<receiver port>/ssf/push`` does not fit."""


def settings_from_environment() -> Settings:
    """The settings from ``CTS_SUITE_IMAGE``, ``CTS_SUITE_NGINX_IMAGE``, ``CTS_SUITE_MONGODB_IMAGE``,
    ``CTS_SUITE_PORT``, ``CTS_RECEIVER_PORT`` and ``CTS_RECEIVER_PUSH_URL``, with the defaults for
    what is not set."""
    return Settings(
        suite_image=_env("CTS_SUITE_IMAGE", DEFAULT_SUITE_IMAGE),
        suite_nginx_image=_env("CTS_SUITE_NGINX_IMAGE", DEFAULT_SUITE_NGINX_IMAGE),
        suite_mongodb_image=_env("CTS_SUITE_MONGODB_IMAGE", DEFAULT_SUITE_MONGODB_IMAGE),
        suite_port=_env_int("CTS_SUITE_PORT", DEFAULT_SUITE_PORT),
        receiver_port=_env_int("CTS_RECEIVER_PORT", DEFAULT_RECEIVER_PORT),
        receiver_push_url=_env("CTS_RECEIVER_PUSH_URL", ""),
    )


def _env(name: str, fallback: str) -> str:
    value = os.environ.get(name, "").strip()
    return value if value else fallback


def _env_int(name: str, fallback: int) -> int:
    try:
        value = int(_env(name, ""))
    except ValueError:
        return fallback
    return value if value > 0 else fallback
