"""The TLS material of the receiver under test and the test CA, shipped inside this package, and
the HTTP client that trusts the suite; the port of ``resources.go``. The suite only accepts https
push endpoints and does not check the certificate, so a self-signed one for ``localhost``,
``host.testcontainers.internal`` and ``host.docker.internal`` does."""

from __future__ import annotations

import ssl
from pathlib import Path
from typing import Final

import httpx

__all__ = [
    "USER_AGENT",
    "new_http_client",
    "receiver_certificate_pem",
    "receiver_key_pem",
    "receiver_ssl_context",
    "receiver_tls_files",
    "resource_path",
    "test_ca_path",
    "test_ca_pem",
    "trusting_ssl_context",
]

USER_AGENT: Final = "easyssf-receiver-conformance"
"""The ``User-Agent`` the receiver under test calls the suite with."""

_PACKAGE_DIR: Final = Path(__file__).resolve().parent


def resource_path(*parts: str) -> Path:
    """The path of a file shipped inside this package, for example
    ``resource_path("suite-config", "easyssf-receiver.json")``."""
    return _PACKAGE_DIR.joinpath(*parts)


def receiver_tls_files() -> tuple[Path, Path]:
    """The TLS certificate and private key of the receiver under test, ``tls/receiver.pem`` and
    ``tls/receiver-key.pem``, as paths for a server that reads files."""
    return resource_path("tls", "receiver.pem"), resource_path("tls", "receiver-key.pem")


def test_ca_path() -> Path:
    """The CA that issued the receiver's certificate, ``test-ca.pem``, as a path."""
    return resource_path("test-ca.pem")


def receiver_certificate_pem() -> bytes:
    """The TLS certificate of the receiver under test, ``tls/receiver.pem``."""
    return receiver_tls_files()[0].read_bytes()


def receiver_key_pem() -> bytes:
    """The private key of the receiver under test, ``tls/receiver-key.pem``."""
    return receiver_tls_files()[1].read_bytes()


def test_ca_pem() -> bytes:
    """The CA that issued the receiver's certificate, ``test-ca.pem``."""
    return test_ca_path().read_bytes()


def receiver_ssl_context() -> ssl.SSLContext:
    """The server TLS context of the receiver under test: its certificate and key, TLS 1.2 and up.

    Raises:
        ssl.SSLError: if the certificate and key do not load.
    """
    certificate, key = receiver_tls_files()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(certificate), str(key))
    return context


def trusting_ssl_context(
    trusted_pem: bytes | None, trust_all: bool = False, verify_hostname: bool = False
) -> ssl.SSLContext:
    """The client TLS context the receiver calls the suite (and the suite's API) with: trusting
    exactly the given certificate, for any host name if ``verify_hostname`` is false (the
    self-signed certificate of a locally running suite is issued for ``localhost``, not
    ``localhost.emobix.co.uk``, and the one of the Testcontainers-started suite names its host in
    the Common Name only), or any certificate at all if ``trust_all`` is set, only for a suite
    running locally. ``None`` without ``trust_all`` uses the system roots."""
    if trust_all:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if trusted_pem is None:
        return ssl.create_default_context()
    context = ssl.create_default_context(cadata=trusted_pem.decode("ascii"))
    context.check_hostname = verify_hostname
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def new_http_client(
    trusted_pem: bytes | None, trust_all: bool = False, verify_hostname: bool = False
) -> httpx.AsyncClient:
    """An ``httpx.AsyncClient`` for the suite with the context of :func:`trusting_ssl_context`.
    Calls carry the ``User-Agent`` :data:`USER_AGENT`."""
    return httpx.AsyncClient(
        verify=trusting_ssl_context(trusted_pem, trust_all, verify_hostname), headers={"User-Agent": USER_AGENT}
    )
