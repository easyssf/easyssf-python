# Examples

An application that receives security events from a Keycloak SSF transmitter: the Python port of
the [Spring Boot examples](https://github.com/easyssf/easyssf/tree/main/easyssf-receiver-spring-boot-examples)
of the Java library after the Go ones, on the same Keycloak realm. Not published: they are
workspace members for `uv run`, nothing imports them.

| | Port | |
|---|---|---|
| [`keycloak/`](keycloak) | 8080 | Docker Compose setup: Keycloak 26.8 with the `ssf` feature and a pre-configured `ssf-demo` realm, the same files as in the Java, Go and Rust repositories |
| [`fastapi/resource-server/`](fastapi/resource-server) | 8081 | OAuth2 resource server on FastAPI. Rejects access tokens once their Keycloak session was revoked. Has a `--poll` profile. |

The OIDC client (a web application that ends its local session once the Keycloak session was
revoked) and the SCIM provisioning example (a directory mirrored from SCIM Events) of the Java and
Go repositories are not ported yet.

The resource server contains no SSF specific code apart from its receiver configuration
([`config.py`](fastapi/resource-server/src/resource_server/config.py)) and a handler that logs
the events: `Receiver` assembles the receiver, `easyssf.fastapi` mounts the push endpoint, starts
and stops the receiver with the application and rejects what the events revoked. What Spring
Security does for the Java example is application code here:
[`auth.py`](fastapi/resource-server/src/resource_server/auth.py) validates the access tokens with
the keys of the transmitter. The application manages its own stream: on startup it authenticates
with the service account of its Keycloak client and registers a PUSH stream for it (`Created SSF
stream …`), after a restart it finds it again (`Using existing SSF stream …`). If you delete a
stream in the admin console, the application creates a new one on its next start.

## 1. Start Keycloak

```sh
cd examples/keycloak
docker compose up
```

- Admin console: <http://localhost:8080> (`admin` / `admin`), realm `ssf-demo`
- Users: `tester` / `test` and `bob` / `bob`

The database lives in `keycloak/data` and survives `docker compose down`; the realm is only
imported into an empty database, so delete `data/` to re-import `ssf-demo-realm.json`. The
clients are `example-resource-server`, `example-poll-receiver` and `example-oidc-client`, each
with a service account that may manage streams (`ssf.read`, `ssf.manage`) and the push URL of its
application in `ssf.validPushUrls`; `example-cli` is a public client for `curl`.

## 2. Resource server

```sh
uv run resource-server
```

```sh
KC=http://localhost:8080/realms/ssf-demo/protocol/openid-connect

# log in as tester and call the API
TOKENS=$(curl -s $KC/token -d grant_type=password -d client_id=example-cli -d username=tester -d password=test)
ACCESS_TOKEN=$(echo "$TOKENS" | jq -r .access_token)
REFRESH_TOKEN=$(echo "$TOKENS" | jq -r .refresh_token)

curl -i localhost:8081/api/me -H "Authorization: Bearer $ACCESS_TOKEN"    # 200

# end the session in Keycloak ...
curl $KC/logout -d client_id=example-cli -d refresh_token=$REFRESH_TOKEN

# ... the access token has not expired, but is rejected within a few seconds
curl -i localhost:8081/api/me -H "Authorization: Bearer $ACCESS_TOKEN"    # 401, error="invalid_token"
```

The log of the resource server shows the stream it registered on startup and the event:

```
INFO easyssf.receiver: Created SSF stream stream=2872c36e-… delivery=urn:ietf:rfc:8935 endpoint=http://host.docker.internal:8081/ssf/push events=['CaepSessionRevoked'] audience=['example-resource-server/2872c36e-…']
DEBUG easyssf.receiver: Received SET jti=177a0265-… transmitter=http://localhost:8080/realms/ssf-demo delivery=push events=['CaepSessionRevoked']
INFO easyssf.receiver: revoked access tokens of session event=CaepSessionRevoked session=Q1k9hXB3… issuer=http://localhost:8080/realms/ssf-demo
INFO resource_server: Security event event=CaepSessionRevoked user=ddabc458-… session=Q1k9hXB3… delivery=push idempotency_key=http://localhost:8080/realms/ssf-demo::177a0265-…
DEBUG easyssf.fastapi.revocation: Rejecting a revoked access token subject=ddabc458-…
```

The same walk-through as requests for the HTTP client of IntelliJ IDEA or VS Code's REST Client:
[`resource-server.http`](fastapi/resource-server/resource-server.http) (hosts in
`http-client.env.json`, environment `local`).

`GET /health` is the health of the receiver: its transmitter, stream and, with `--poll`, the
poller (503 when unhealthy). The application works with any SSF transmitter that sends CAEP
`session-revoked` events and is the issuer of the access tokens: `SSF_TRANSMITTER_ISSUER`,
`SSF_TOKEN_URI`, `SSF_CLIENT_ID`, `SSF_CLIENT_SECRET` and `SSF_PUSH_URL` override the defaults,
which are the clients of the `ssf-demo` realm. `SSF_PUSH_URL` is how the transmitter reaches the
application; for Keycloak in Docker it must be allowed by `ssf.validPushUrls` of the client.
`--listen` changes the address (`:8081` by default).

### POLL delivery

With `--poll` the resource server does not register a PUSH stream for its own client. It
authenticates with the service account of the client `example-poll-receiver` instead, registers a
POLL stream for it and polls Keycloak for events every two seconds:

```sh
uv run resource-server --poll
```

```
INFO easyssf.receiver: Created SSF stream stream=73a8317b-… delivery=urn:ietf:rfc:8936 endpoint=http://localhost:8080/realms/ssf-demo/ssf/transmitter/receivers/example-poll-receiver/streams/73a8317b-…/poll events=['CaepSessionRevoked'] audience=['example-poll-receiver/73a8317b-…']
DEBUG easyssf.receiver: Received SET jti=d3422c0b-… transmitter=http://localhost:8080/realms/ssf-demo delivery=poll events=['CaepSessionRevoked']
INFO easyssf.receiver: revoked access tokens of session event=CaepSessionRevoked session=H1CSi6Kx… issuer=http://localhost:8080/realms/ssf-demo
```

The `curl` commands work the same way. Keycloak keeps pushing to the PUSH stream of
`example-resource-server` in the meantime (streams survive a restart of the application), which
the application rejects in this profile (`Rejecting SET code=invalid_audience`).

### Tests

`uv run pytest examples` runs the application against the in-process `TestTransmitter` of
`easyssf-test`, no Keycloak needed: the stream registration, a pushed and a polled
session-revoked event, and the `401` challenges of RFC 6750.
