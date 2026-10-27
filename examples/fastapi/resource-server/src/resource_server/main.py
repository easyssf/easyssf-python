"""A resource server: every request to the API needs an access token of the identity provider.
The SSF receiver adds the push endpoint and rejects the access tokens of sessions the identity
provider revoked. The identity provider is both the issuer of the access tokens and the SSF
transmitter: any transmitter that supports CAEP session-revoked events does; the defaults fit
the Keycloak of ``examples/keycloak``. The port of the Spring Boot ``example-resource-server``
after the Go example.

    uv run resource-server          # PUSH stream of the client example-resource-server
    uv run resource-server --poll   # POLL stream of the client example-poll-receiver

``SSF_TRANSMITTER_ISSUER``, ``SSF_TOKEN_URI``, ``SSF_CLIENT_ID``, ``SSF_CLIENT_SECRET`` and
``SSF_PUSH_URL`` override the defaults. The application contains no SSF code apart from the
receiver configuration in ``config`` and the handler that logs the events; ``auth`` validates
the access tokens, which Spring Security does for the Java example.
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Any, Final

import httpx
import uvicorn
from fastapi import Depends, FastAPI, Request

from easyssf.core import event_types
from easyssf.fastapi import health_router, push_router_for, receiver_lifespan, revocation_dependency
from easyssf.receiver.config import ReceiverConfig
from easyssf.receiver.event import EventContext
from easyssf.receiver.receiver import Receiver

from .auth import AccessTokens, token_claims, token_of
from .config import receiver_config

__all__ = ["DEFAULT_LISTEN", "create_app", "main"]

DEFAULT_LISTEN: Final = ":8081"
"""Where the application listens by default."""

_log: Final = logging.getLogger("resource_server")


async def audit(context: EventContext) -> None:
    """The application's own handler, on top of the built-in revocation of access tokens: logs
    every event."""
    for event_type in context.event_types:
        subject = context.subject_for(event_type)
        _log.info(
            "Security event",
            extra={
                "event": event_types.alias_of(event_type),
                "user": subject.sub,
                "session": subject.session_id,
                "delivery": str(context.delivery_method),
                "idempotency_key": context.idempotency_key,
            },
        )


def create_app(
    poll: bool = False, config: ReceiverConfig | None = None, http_client: httpx.AsyncClient | None = None
) -> FastAPI:
    """The application: the receiver started and stopped with it, ``GET /api/me`` behind the
    validation of the access token and the rejection of revoked ones, ``GET /health`` and the push
    endpoint at ``easyssf.receiver.push.endpoint-path``.

    Args:
        poll: the poll profile, a POLL stream of the client ``example-poll-receiver``.
        config: the receiver configuration, :func:`~resource_server.config.receiver_config` if
            ``None``; for tests against another transmitter.
        http_client: the client the receiver calls the transmitter with, for tests; a new one if
            ``None``.
    """
    config = config if config is not None else receiver_config(poll)
    # the receiver: the push endpoint, the stream at the transmitter, the revocation store and
    # the handler that revokes the access tokens
    receiver = Receiver(config, handlers=[audit], http_client=http_client)
    app = FastAPI(title="example-resource-server", lifespan=receiver_lifespan(receiver))
    app.state.receiver = receiver

    # validates the access tokens with the keys of the transmitter and leaves their claims on the
    # request; the revocation dependency then rejects the tokens of revoked sessions and users
    transmitter = receiver.transmitters[0]
    assert transmitter.keys is not None  # the receiver gave every transmitter its keys
    access_tokens = AccessTokens(config.transmitter_issuer, transmitter.keys)
    reject_revoked = revocation_dependency(receiver.token_revocation_store, token_claims)

    @app.get("/api/me", dependencies=[Depends(access_tokens.require_access_token), Depends(reject_revoked)])
    async def me(request: Request) -> dict[str, Any]:
        """The user of the access token, as the Java example shows it."""
        token = token_of(request)
        assert token is not None  # the dependency ran
        issued_at, expires_at = token.time("iat"), token.time("exp")
        return {
            "username": token.string("preferred_username"),
            "subject": token.string("sub"),
            "sessionId": token.string("sid"),
            "tokenIssuedAt": issued_at.isoformat().replace("+00:00", "Z") if issued_at else "",
            "tokenExpiresAt": expires_at.isoformat().replace("+00:00", "Z") if expires_at else "",
        }

    app.include_router(health_router(receiver))
    # the push endpoint the transmitter delivers to, at easyssf.receiver.push.endpoint-path
    app.include_router(push_router_for(receiver))
    return app


class _KeyValueFormatter(logging.Formatter):
    """Appends the ``extra`` attributes of a record as ``key=value``, as the text handler of Go's
    ``slog`` prints them, so that the stream id, the jti and the subject show up in the log."""

    _STANDARD = frozenset({*logging.LogRecord("", 0, "", 0, "", None, None).__dict__, "message", "asctime", "taskName"})

    def format(self, record: logging.LogRecord) -> str:
        line = super().format(record)
        fields = " ".join(f"{key}={value}" for key, value in record.__dict__.items() if key not in self._STANDARD)
        return f"{line} {fields}" if fields else line


def _configure_logging() -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_KeyValueFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[handler])
    logging.getLogger("easyssf").setLevel(logging.DEBUG)


def _parse_listen(listen: str) -> tuple[str, int]:
    host, separator, port = listen.rpartition(":")
    if not separator:
        host, port = "", listen
    try:
        return host or "0.0.0.0", int(port)  # every interface, as the Go example
    except ValueError:
        raise SystemExit(f"resource-server: not an address to listen on: {listen!r} (expected [host]:port)") from None


def main(argv: list[str] | None = None) -> int:
    """Runs the application until interrupted; the ``resource-server`` script."""
    parser = argparse.ArgumentParser(
        prog="resource-server", description="an OAuth2 resource server with an SSF receiver"
    )
    parser.add_argument(
        "--poll", action="store_true", help="the poll profile: register a POLL stream and poll for events"
    )
    parser.add_argument("--listen", default=DEFAULT_LISTEN, help=f"address to listen on (default {DEFAULT_LISTEN})")
    arguments = parser.parse_args(argv)
    _configure_logging()
    host, port = _parse_listen(arguments.listen)
    app = create_app(arguments.poll)
    _log.info(
        "The example resource server listens",
        extra={"addr": arguments.listen, "push": app.state.receiver.push_endpoint_path, "poll": arguments.poll},
    )
    uvicorn.run(app, host=host, port=port, log_level="info", log_config=None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
