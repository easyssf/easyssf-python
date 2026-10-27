"""The OpenID conformance suite the tests run against, started with testcontainers-python like
``docker-compose-prebuilt.yml`` of the suite's repository does: MongoDB, the suite and its nginx in
front; the port of ``suite.go``.

The suite has to know its public URL before it starts, so nginx is bound to a fixed host port and
the suite's URL is ``https://localhost:<port>``. The system under test on the Docker host is
reached from the containers as ``host.docker.internal``: testcontainers-python has no port
forwarding sidecar (``host.testcontainers.internal`` of testcontainers-go), so the suite container
gets ``host.docker.internal`` mapped to the host gateway (``extra_hosts``), which Docker Desktop
resolves by itself and Docker on Linux needs told. See :class:`~.settings.Settings` for the images
and ports.
"""

from __future__ import annotations

import asyncio
import logging
import os
import ssl
import tempfile
from datetime import timedelta
from typing import Final

import httpx
from testcontainers.core.container import DockerContainer
from testcontainers.core.network import Network
from testcontainers.core.wait_strategies import PortWaitStrategy

from .api import ApiClient
from .resources import USER_AGENT, trusting_ssl_context
from .settings import Settings, settings_from_environment

__all__ = ["SYSTEM_UNDER_TEST_HOST", "Suite", "close_shared_suite", "shared_suite"]

_log: Final = logging.getLogger("easyssf.conformance.suite")

SYSTEM_UNDER_TEST_HOST: Final = "host.docker.internal"
"""The host under which the suite reaches the system under test on the Docker host."""

_MONGODB_PORT: Final = 27017
_SUITE_PORT: Final = 8080
_NGINX_PORT: Final = 8443
_NGINX_CERTIFICATE_PATH: Final = "/etc/ssl/certs/nginx-selfsigned.crt"
_SUITE_STARTUP: Final = timedelta(minutes=4)
_CONTAINER_STARTUP: Final = timedelta(minutes=2)


class Suite:
    """The running conformance suite. Start it with :meth:`start`, stop it with :meth:`close`;
    the containers are removed by the Testcontainers reaper otherwise."""

    def __init__(self, settings: Settings, network: Network, logger: logging.Logger) -> None:
        self._settings = settings
        self._network = network
        self._log = logger
        self._base_url = f"https://localhost:{settings.suite_port}"
        self._containers: list[DockerContainer] = []
        self._certificate_pem = b""
        self._certificate_file = ""

    @classmethod
    async def start(cls, settings: Settings | None = None, logger: logging.Logger | None = None) -> Suite:
        """Starts the suite and waits until its API is available. The container work of
        testcontainers blocks and runs in a worker thread.

        Args:
            settings: the images and ports; :func:`~.settings.settings_from_environment` if ``None``.
            logger: where the start is logged; ``easyssf.conformance.suite`` by default.

        Raises:
            RuntimeError: if a container did not start or the suite did not become available.
        """
        settings = settings if settings is not None else settings_from_environment()
        log = logger if logger is not None else _log
        log.info("Starting conformance suite", extra={"image": settings.suite_image})
        suite = await asyncio.to_thread(cls._start_containers, settings, log)
        api = suite.api_client()
        try:
            await api.wait_until_available(_SUITE_STARTUP)
        except Exception as error:
            suite.close()
            raise RuntimeError(str(error)) from error
        finally:
            await api.aclose()
        log.info("Conformance suite is available at %s", suite.base_url, extra={"url": suite.base_url})
        return suite

    @classmethod
    def _start_containers(cls, settings: Settings, log: logging.Logger) -> Suite:
        network = Network().create()
        suite = cls(settings, network, log)
        try:
            suite._run(
                "mongodb",
                DockerContainer(settings.suite_mongodb_image)
                .with_exposed_ports(_MONGODB_PORT)
                .waiting_for(PortWaitStrategy(_MONGODB_PORT).with_startup_timeout(_CONTAINER_STARTUP)),
                "could not start MongoDB for the conformance suite",
            )
            suite._run(
                "server",
                DockerContainer(settings.suite_image)
                .with_exposed_ports(_SUITE_PORT)
                .with_envs(
                    BASE_URL=suite.base_url,
                    BASE_MTLS_URL=suite.base_url,
                    MONGODB_HOST="mongodb",
                    # The suite pins MongoDB's feature compatibility version to the one it runs in
                    # production (6.0) and refuses to start otherwise. The tests run a current
                    # MongoDB, so the suite is told not to touch the version (an empty target
                    # skips the step).
                    OPENID_MONGODB_TARGETFEATURECOMPATIBILITYVERSION="",
                    # the dev profile needs no login
                    SPRING_PROFILES_ACTIVE="dev",
                    OIDC_GOOGLE_CLIENTID="google-client",
                    OIDC_GOOGLE_SECRET="google-secret",
                    OIDC_GITLAB_CLIENTID="gitlab-client",
                    OIDC_GITLAB_SECRET="gitlab-secret",
                )
                # the suite reaches the system under test on the Docker host as host.docker.internal
                .with_kwargs(extra_hosts={SYSTEM_UNDER_TEST_HOST: "host-gateway"})
                .waiting_for(PortWaitStrategy(_SUITE_PORT).with_startup_timeout(_SUITE_STARTUP)),
                "could not start the conformance suite",
            )
            nginx = suite._run(
                "nginx",
                DockerContainer(settings.suite_nginx_image)
                .with_bind_ports(f"{_NGINX_PORT}/tcp", settings.suite_port)
                .waiting_for(PortWaitStrategy(_NGINX_PORT).with_startup_timeout(_CONTAINER_STARTUP)),
                "could not start the nginx of the conformance suite",
            )
            suite._certificate_pem = _nginx_certificate(nginx)
        except BaseException:
            suite.close()
            raise
        return suite

    def _run(self, alias: str, container: DockerContainer, failure: str) -> DockerContainer:
        container.with_network(self._network).with_network_aliases(alias)
        self._log.info("Starting container %s (%s)", alias, container.image, extra={"container": alias})
        try:
            container.start()
        except Exception as error:
            # the container may exist although it did not become ready
            self._containers.append(container)
            logs = _logs_of(container)
            self._log.error("%s: %s\n%s", failure, error, logs, extra={"container": alias})
            raise RuntimeError(f"{failure}: {error}") from error
        self._containers.append(container)
        return container

    @property
    def base_url(self) -> str:
        """The URL under which the tests reach the suite, also the base of the issuers of its
        test instances (``<base>/test/a/<alias>``)."""
        return self._base_url

    @property
    def settings(self) -> Settings:
        """The settings the suite was started with."""
        return self._settings

    @property
    def system_under_test_host(self) -> str:
        """The host under which the suite reaches the system under test."""
        return SYSTEM_UNDER_TEST_HOST

    @property
    def receiver_push_url(self) -> str:
        """The URL under which the suite reaches the push endpoint of the receiver under test:
        :attr:`~.settings.Settings.receiver_push_url`, or
        ``https://<system under test host>:<receiver port>/ssf/push``."""
        if self._settings.receiver_push_url:
            return self._settings.receiver_push_url
        return f"https://{self.system_under_test_host}:{self._settings.receiver_port}/ssf/push"

    @property
    def certificate_pem(self) -> bytes:
        """The TLS certificate of the suite, PEM."""
        return self._certificate_pem

    def ssl_context(self) -> ssl.SSLContext:
        """A client TLS context that trusts the suite's certificate and nothing else. The
        self-signed certificate of nginx names its host in the Common Name only, so the host name
        is not checked, the certificate itself is pinned instead."""
        return trusting_ssl_context(self._certificate_pem, verify_hostname=False)

    def http_client(self) -> httpx.AsyncClient:
        """A new HTTP client for the receiver under test that trusts the suite's certificate, for
        calling the transmitter the suite emulates. A new one per call: an ``httpx.AsyncClient``
        belongs to the event loop it first sent on, and every test has a loop of its own."""
        return httpx.AsyncClient(verify=self.ssl_context(), headers={"User-Agent": USER_AGENT})

    def api_client(self) -> ApiClient:
        """A new client of the suite's API, on a new :meth:`http_client`."""
        return ApiClient(self._base_url, self.http_client())

    def certificate_file(self) -> str:
        """The TLS certificate of the suite as a PEM file, for the trust store of a system under
        test that reads one; removed by :meth:`close`."""
        if not self._certificate_file:
            handle, path = tempfile.mkstemp(prefix="conformance-suite-", suffix=".pem")
            with os.fdopen(handle, "wb") as file:
                file.write(self._certificate_pem)
            self._certificate_file = path
        return self._certificate_file

    def close(self) -> None:
        """Stops the containers and removes the network. Blocks."""
        for container in reversed(self._containers):
            try:
                container.stop()
            except Exception as error:  # best effort, the reaper removes what is left
                self._log.warning("Could not stop container: %s", error)
        self._containers.clear()
        try:
            self._network.remove()
        except Exception as error:  # best effort
            self._log.warning("Could not remove the network: %s", error)
        if self._certificate_file:
            with _suppress_os_error():
                os.remove(self._certificate_file)
            self._certificate_file = ""

    def __repr__(self) -> str:
        return f"Suite({self._base_url!r})"


class _suppress_os_error:  # noqa: N801 - a tiny context manager
    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: object) -> bool:
        return exc_type is not None and issubclass(exc_type, OSError)


def _nginx_certificate(nginx: DockerContainer) -> bytes:
    result = nginx.exec(["cat", _NGINX_CERTIFICATE_PATH])
    if result.exit_code != 0:
        raise RuntimeError(
            f"could not read the TLS certificate of the conformance suite from {_NGINX_CERTIFICATE_PATH}: "
            f"{result.output.decode('utf-8', 'replace')}"
        )
    pem = result.output
    if b"-----BEGIN CERTIFICATE-----" not in pem:
        raise RuntimeError(f"the TLS certificate of the conformance suite at {_NGINX_CERTIFICATE_PATH} is not PEM")
    return pem


def _logs_of(container: DockerContainer) -> str:
    try:
        stdout, stderr = container.get_logs()
    except Exception:  # the container may not exist
        return ""
    return (stdout + stderr).decode("utf-8", "replace")[-4000:]


_shared: Suite | None = None


async def shared_suite(logger: logging.Logger | None = None) -> Suite:
    """The one suite the plan tests of a process share, started on first use with
    :func:`~.settings.settings_from_environment`. :func:`close_shared_suite` stops it."""
    global _shared  # noqa: PLW0603 - the one suite of the process
    if _shared is None:
        _shared = await Suite.start(settings_from_environment(), logger)
    return _shared


def close_shared_suite() -> None:
    """Stops the shared suite, if one was started."""
    global _shared  # noqa: PLW0603 - the one suite of the process
    if _shared is not None:
        _shared.close()
        _shared = None
