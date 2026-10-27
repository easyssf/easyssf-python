"""The receiver configuration of the example: the application registers its own stream on
startup with the client credentials of its OAuth2 client, the transmitter assigns the audience.
The defaults are the clients of the realm in ``examples/keycloak``; the ``receiverConfig`` of the
Go example."""

from __future__ import annotations

import os
from datetime import timedelta

from easyssf.receiver.config import STREAM_MANAGEMENT_RECEIVER, OAuth2Config, ReceiverConfig, default_receiver_config

__all__ = ["DEFAULT_ISSUER", "DEFAULT_PUSH_URL", "PUSH_AUTHORIZATION_HEADER", "receiver_config"]

DEFAULT_ISSUER = "http://localhost:8080/realms/ssf-demo"
"""The Keycloak realm of ``examples/keycloak``, the issuer of the access tokens and the SSF transmitter."""
DEFAULT_PUSH_URL = "http://host.docker.internal:8081/ssf/push"
"""How Keycloak in Docker reaches the push endpoint of this application on the Docker host."""
PUSH_AUTHORIZATION_HEADER = "Bearer example-resource-server-push-secret"
"""The ``Authorization`` header the stream is created with; the transmitter sends it with every SET."""

_PUSH_CLIENT = ("example-resource-server", "example-resource-server-secret")
_POLL_CLIENT = ("example-poll-receiver", "example-poll-receiver-secret")


def _env(name: str, fallback: str) -> str:
    value = os.environ.get(name, "")
    return value if value else fallback


def receiver_config(poll: bool) -> ReceiverConfig:
    """The configuration of the receiver: a stream managed by the receiver that requests
    ``CaepSessionRevoked``, PUSH delivery to :data:`DEFAULT_PUSH_URL` with the expected
    authorization header, or with ``poll`` a POLL stream of the client ``example-poll-receiver``
    polled every two seconds; the client credentials grant with the scopes ``ssf.read`` and
    ``ssf.manage``; revocations kept for ten minutes, at least the lifetime of an access token.
    ``SSF_TRANSMITTER_ISSUER``, ``SSF_TOKEN_URI``, ``SSF_CLIENT_ID``, ``SSF_CLIENT_SECRET`` and
    ``SSF_PUSH_URL`` override the defaults."""
    issuer = _env("SSF_TRANSMITTER_ISSUER", DEFAULT_ISSUER)
    # the poll profile: a second client, with a POLL stream the application polls
    client_id, client_secret = _POLL_CLIENT if poll else _PUSH_CLIENT
    config = default_receiver_config()
    config.transmitter_issuer = issuer
    # a transmitter on plain http, as the compose setup is, is accepted for development only
    config.allow_insecure_http = issuer.startswith("http://")
    config.stream.management = STREAM_MANAGEMENT_RECEIVER
    config.stream.events_requested = ["CaepSessionRevoked"]
    config.stream.description = "example-resource-server"
    # how the transmitter reaches the push endpoint; a transmitter may restrict the push URLs it
    # accepts for a client. The stream is created with this authorization header, the transmitter
    # sends it with every SET
    config.push.delivery_endpoint_url = _env("SSF_PUSH_URL", DEFAULT_PUSH_URL)
    config.push.expected_auth_header = PUSH_AUTHORIZATION_HEADER
    config.oauth2 = OAuth2Config(
        token_uri=_env("SSF_TOKEN_URI", issuer + "/protocol/openid-connect/token"),
        client_id=_env("SSF_CLIENT_ID", client_id),
        client_secret=_env("SSF_CLIENT_SECRET", client_secret),
        scopes=["ssf.read", "ssf.manage"],
    )
    # at least the lifetime of an access token (5 minutes in the compose setup)
    config.revocation.ttl = timedelta(minutes=10)
    if poll:
        config.delivery_method = "poll"
        config.stream.description = "example-resource-server (poll)"
        config.poll.interval = timedelta(seconds=2)
    return config
