# Example: resource server on FastAPI

An OAuth2 resource server that rejects access tokens once their Keycloak session was revoked. The
identity provider is both the issuer of the access tokens and the SSF transmitter: on startup the
application registers a stream for CAEP `session-revoked` events with the service account of its
Keycloak client, Keycloak pushes the SET when a session ends, and the receiver's revocation
store makes the next API call with that session's token fail. The port of the Spring Boot
`example-resource-server` of the Java library, not published.

The application contains no SSF specific code apart from the receiver configuration
(`config.py`) and a handler that logs the events (`main.py`): `easyssf.fastapi` adds the push
endpoint, the lifespan and the revocation dependency, `auth.py` reads the bearer token with FastAPI's
`HTTPBearer` and validates it with the transmitter's keys, which Spring Security does for the Java
example.

## Run

Start the Keycloak of [`examples/keycloak`](../../keycloak) first (`docker compose up`, realm
`ssf-demo`, users `tester` / `test` and `bob` / `bob`). Then, from this folder or the workspace
root:

```sh
uv run resource-server            # PUSH stream of the client example-resource-server, listens on :8081
uv run resource-server --poll     # POLL stream of the client example-poll-receiver, polled every 2 s
```

| Endpoint | |
|---|---|
| `GET /api/me` | The user of the access token; `401` without a valid token or once its session was revoked |
| `GET /health` | The health of the receiver: transmitter, stream and, with `--poll`, the poller; `503` when unhealthy |
| `POST /ssf/push` | The push endpoint Keycloak delivers to, authenticated with the header the stream was registered with |

`SSF_TRANSMITTER_ISSUER`, `SSF_TOKEN_URI`, `SSF_CLIENT_ID`, `SSF_CLIENT_SECRET` and `SSF_PUSH_URL`
override the defaults, which are the clients of the `ssf-demo` realm; `SSF_PUSH_URL` is how the
transmitter reaches the application (`http://host.docker.internal:8081/ssf/push` for Keycloak in
Docker) and must be allowed by `ssf.validPushUrls` of the client. `--listen` changes the address.

## Try it

[`resource-server.http`](resource-server.http) runs the walk-through from the HTTP client of
IntelliJ IDEA or VS Code's REST Client (hosts in `http-client.env.json`, environment `local`): log
in, call the API, end the session in Keycloak, call the API again and see the token rejected
within a few seconds. The same steps with `curl` are in [`examples/README.md`](../../README.md).

## Test

```sh
uv run pytest examples/fastapi/resource-server      # from the workspace root, in-process, no Keycloak
```

The tests run the application against the in-process `easyssf.testing.TestTransmitter`: the
stream is registered, a pushed (or polled) SET revokes the session, `/api/me` answers `200`
before and `401` after.
