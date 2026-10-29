# easyssf-receiver-fastapi

The [easyssf](https://github.com/easyssf/easyssf-python) SSF receiver for FastAPI: the push
endpoint as a router, the rejection of revoked access tokens as a dependency or middleware, and
the receiver's lifecycle as a lifespan, with its health as a route. The Python counterpart of the
Rust `easyssf-receiver-axum` crate. Everything else, the configuration, the handlers, the stream
management and polling, is `easyssf-receiver`; see its [README](../README.md).

```sh
uv add easyssf-receiver-fastapi      # or: pip install easyssf-receiver-fastapi
```

## The receiver with the application

`receiver_lifespan` starts the receiver when the application starts (streams are registered and
polling begins in the background) and closes it on shutdown (the acknowledgements it owes are
sent, the HTTP client it made for itself is closed). With a lifespan of your own, the receiver
starts after yours entered and stops before it exits, so the handlers find what the application
set up:

```python
from fastapi import FastAPI
from easyssf.fastapi import receiver_lifespan
from easyssf.receiver import Receiver, ReceiverConfig

receiver = Receiver(ReceiverConfig.from_mapping(settings["easyssf"]["receiver"]), handlers=[audit])
app = FastAPI(lifespan=receiver_lifespan(receiver))  # or receiver_lifespan(receiver, my_lifespan)
```

## The push endpoint

`push_router_for` mounts `POST easyssf.receiver.push.endpoint-path` (`/ssf/push` by default),
`push_router(handler, path)` any push handler at any path. The transmitter authenticates with its
`Authorization` header and the SET with its signature, so the route belongs outside the
authentication of the application; it is left out of the OpenAPI schema. The response is the
one of RFC 8935: `202` for an accepted SET, `400` with an error document (`application/json`,
`Content-Language: en`) for an invalid one, `401` for a transmitter that could not be
authenticated, `413` for a body beyond 256 KiB, `503` or `500` to have the SET delivered again.

```python
from easyssf.fastapi import push_router_for

app.include_router(push_router_for(receiver))
```

## Rejecting revoked access tokens

The receiver's revocation handler records the sessions and users that `CaepSessionRevoked`
events name in `receiver.token_revocation_store`. `revocation_dependency` turns the store into a
dependency that answers `401` with `WWW-Authenticate: Bearer error="invalid_token",
error_description="The token was revoked"` for a token of a revoked session or user, and `503`
when the store cannot answer (it fails closed). It does not validate tokens: `extract` reads the
claims the authentication of the application left on the request, `None` for a request without
one.

```python
from datetime import UTC, datetime
from fastapi import Depends, Request
from easyssf.fastapi import revocation_dependency
from easyssf.receiver import TokenClaims


def token_claims(request: Request) -> TokenClaims | None:
    token = getattr(request.state, "token", None)  # left there by your authentication dependency
    if token is None:
        return None
    return TokenClaims(
        issuer=token["iss"],
        subject=token["sub"],
        session_id=token.get("sid", ""),
        issued_at=datetime.fromtimestamp(token["iat"], tz=UTC),
    )


reject_revoked = revocation_dependency(receiver.token_revocation_store, token_claims)


@app.get("/api/orders", dependencies=[Depends(require_access_token), Depends(reject_revoked)])
async def orders() -> list[str]: ...
```

For the whole application, the raw ASGI `RevocationMiddleware` of the receiver does the same from
the scope, added after (inside) the middleware that validates the tokens:

```python
from easyssf.fastapi import RevocationMiddleware

app.add_middleware(
    RevocationMiddleware,
    store=receiver.token_revocation_store,
    extract=lambda scope: scope["state"].get("token_claims"),
)
```

## Health

`health_router` serves `receiver.health()` as JSON at `/health`: `200` while the receiver is
healthy or degraded (no contact with a transmitter yet; the application starts without it),
`503` when it is unhealthy (a poll failed, a stream cannot be used).

```python
from easyssf.fastapi import health_router

app.include_router(health_router(receiver))  # or health_router(receiver, path="/ready")
```

## Example

[`examples/fastapi/resource-server`](../examples/fastapi/resource-server) is an OAuth2 resource
server on FastAPI against the Keycloak of [`examples/keycloak`](../examples/keycloak): it
registers its stream, validates access tokens with the keys of the transmitter and rejects them
once their session was revoked; see [`examples/README.md`](../examples/README.md).
