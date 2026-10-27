"""An OAuth2 resource server on FastAPI: every request to the API needs an access token of the
identity provider, and the SSF receiver rejects the access tokens of sessions the identity
provider revoked. The port of the Spring Boot ``example-resource-server`` after the Go
``examples/resource-server``; ``config`` is the receiver configuration, ``auth`` validates the
access tokens, ``main`` assembles the application and runs it."""

from .auth import AccessToken, AccessTokens, AuthError, token_claims, token_of
from .config import receiver_config
from .main import create_app, main

__all__ = [
    "AccessToken",
    "AccessTokens",
    "AuthError",
    "create_app",
    "main",
    "receiver_config",
    "token_claims",
    "token_of",
]
