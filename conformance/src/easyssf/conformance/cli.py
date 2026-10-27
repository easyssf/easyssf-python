"""The receiver under test for the OpenID conformance suite, run by hand against a suite of your
own: the ``CtsApplication`` of the Java library and the port of ``cmd/cts/main.go``. The ``cts``
script serves :func:`~.app.cts_app` with uvicorn over https with the certificate of the package (or
the one named by ``CTS_TLS_CERTIFICATE`` and ``CTS_TLS_KEY``), trusts the certificate of the suite
in ``CTS_SUITE_CERTIFICATE`` (or any, with ``CTS_TRUST_ALL=true``), and takes its settings from
``CTS_*`` variables: ``CTS_TRANSMITTER_ISSUER``, ``CTS_AUTH_MODE`` (dynamic|static),
``CTS_CLIENT_ID``, ``CTS_CLIENT_SECRET``, ``CTS_CLIENT_AUTH`` (basic|post), ``CTS_ACCESS_TOKEN``,
``CTS_DELIVERY`` (push|poll), ``CTS_PUSH_URL``, ``CTS_RUN_IDLE_TIMEOUT``.

    uv run cts                      # from the workspace
    curl -sk -X POST https://localhost:9443/cts/runs/auto
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from dataclasses import replace
from pathlib import Path
from typing import Final

import uvicorn

from easyssf.core import DeliveryMethod
from easyssf.receiver import parse_duration

from .app import cts_app
from .modules import SuiteModules
from .receiver_settings import AuthMode, default_receiver_settings
from .resources import new_http_client, receiver_tls_files
from .run import Runner

__all__ = ["DEFAULT_ISSUER", "DEFAULT_LISTEN", "main"]

DEFAULT_ISSUER: Final = "https://localhost.emobix.co.uk:8443/test/a/easyssf-receiver-python-test"
"""The test instance of the local suite the receiver plays against by default."""
DEFAULT_LISTEN: Final = ":9443"
"""Where the receiver under test listens by default."""
_DEFAULT_SUITE_CERTIFICATE: Final = "certs/conformance-suite.pem"


def _env(name: str, fallback: str) -> str:
    value = os.environ.get(name, "").strip()
    return value if value else fallback


def main(argv: list[str] | None = None) -> int:
    """Runs the receiver under test until interrupted; the ``cts`` script."""
    parser = argparse.ArgumentParser(
        prog="cts", description="easyssf receiver under test for the OpenID conformance suite"
    )
    parser.add_argument(
        "--listen", default=DEFAULT_LISTEN, help=f"address to listen on, [host]:port (default {DEFAULT_LISTEN})"
    )
    arguments = parser.parse_args(argv)
    host, port = _parse_listen(arguments.listen)
    logging.basicConfig(
        level=logging.DEBUG, stream=sys.stderr, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    log = logging.getLogger("easyssf.conformance.cts")

    settings = default_receiver_settings()
    settings = replace(
        settings,
        issuer=_env("CTS_TRANSMITTER_ISSUER", DEFAULT_ISSUER),
        auth=replace(
            settings.auth,
            mode=AuthMode.from_name(_env("CTS_AUTH_MODE", AuthMode.DYNAMIC.value)),
            client_id=_env("CTS_CLIENT_ID", settings.auth.client_id),
            client_secret=_env("CTS_CLIENT_SECRET", settings.auth.client_secret),
            authenticate_with_request_body=_env("CTS_CLIENT_AUTH", "basic") == "post",
            access_token=_env("CTS_ACCESS_TOKEN", ""),
        ),
        delivery=DeliveryMethod.POLL if _env("CTS_DELIVERY", "push") == "poll" else DeliveryMethod.PUSH,
        push_url=_env("CTS_PUSH_URL", "https://localhost:9443/ssf/push"),
    )
    try:
        settings = replace(settings, idle_timeout=parse_duration(_env("CTS_RUN_IDLE_TIMEOUT", "30s")))
    except ValueError:
        log.warning("CTS_RUN_IDLE_TIMEOUT is not a duration, using %s", settings.idle_timeout)

    # the certificate of a locally running suite, trusted for any host name: it is issued for
    # localhost, not localhost.emobix.co.uk
    trusted: bytes | None = None
    certificate_file = _env("CTS_SUITE_CERTIFICATE", _DEFAULT_SUITE_CERTIFICATE)
    if certificate_file:
        try:
            trusted = Path(certificate_file).read_bytes()
        except OSError:
            trusted = None
        if trusted is None or b"-----BEGIN CERTIFICATE-----" not in trusted:
            trusted = None
            log.warning(
                "No certificate of the conformance suite at %s, the system roots are used; "
                "run fetch-suite-certificate.sh for a local suite",
                certificate_file,
            )
    client = new_http_client(trusted, trust_all=_env("CTS_TRUST_ALL", "false") == "true")
    runner = Runner(settings, client, log)
    modules = SuiteModules(settings, client)

    certificate, key = receiver_tls_files()
    tls_certificate, tls_key = _env("CTS_TLS_CERTIFICATE", ""), _env("CTS_TLS_KEY", "")
    if tls_certificate and tls_key:
        certificate, key = Path(tls_certificate), Path(tls_key)
    log.info(
        "The receiver under test listens on %s:%d, issuer %s, delivery %s, push URL %s",
        host,
        port,
        settings.issuer,
        settings.delivery,
        settings.push_url,
    )
    uvicorn.run(
        cts_app(runner, modules),
        host=host,
        port=port,
        ssl_certfile=str(certificate),
        ssl_keyfile=str(key),
        log_level="info",
        lifespan="off",
    )
    return 0


def _parse_listen(listen: str) -> tuple[str, int]:
    host, separator, port = listen.rpartition(":")
    if not separator:
        host, port = "", listen
    try:
        return host or "0.0.0.0", int(port)
    except ValueError:
        raise SystemExit(f"cts: not an address to listen on: {listen!r} (expected [host]:port)") from None


if __name__ == "__main__":
    sys.exit(main())
