# easyssf-python

Building blocks for the
[OpenID Shared Signals Framework (SSF)](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)
in Python, for applications that receive security events: a **receiver** library on asyncio that
mounts on any web framework through ASGI or WSGI, and an in-process **test transmitter**.
Integrations for FastAPI, Litestar and Flask and database stores on SQLAlchemy are next. A port of
[easyssf for Java](https://github.com/easyssf/easyssf), following the layout of
[easyssf-go](https://github.com/easyssf/easyssf-go), [easyssf-dotnet](https://github.com/easyssf/easyssf-dotnet)
and [easyssf-rust](https://github.com/easyssf/easyssf-rust); the five share their test suites, their
database tables and their configuration keys.

**Turn a Python application into an SSF receiver without implementing SET validation, metadata
discovery, PUSH and POLL delivery, stream management and replay protection yourself.** Reacting to
a security event is a function:

```python
from easyssf.receiver import Receiver, ReceiverConfig, for_event


async def session_revoked(event):
    subject = event.subject
    ...  # end what you hold for subject.session_id or subject.sub


config = ReceiverConfig.from_mapping(settings["easyssf"]["receiver"])
receiver = Receiver(config, handlers=[for_event("CaepSessionRevoked", session_revoked)])
await receiver.start()  # registers the stream, starts polling
app.mount(receiver.push_endpoint_path, push_app(receiver.push_handler))  # POST /ssf/push
```

Version 0.6.0 is at feature parity with [easyssf 0.6.0 for Java](https://github.com/easyssf/easyssf);
the version follows the Java library, and below 1.0 a release may break the API when the
CHANGELOG says so. Python 3.11 or later, Apache-2.0.

## Distributions

One `uv` workspace, one `easyssf` namespace:

| Distribution | Import | Holds |
|---|---|---|
| `easyssf-core` | `easyssf.core` | The vocabulary: SETs (`EventToken`, the `new_set` builder), subjects, delivery methods, stream configuration, transmitter metadata; `easyssf.core.event_types` the event type URIs with aliases; `easyssf.core.caep`, `.risc`, `.scim` the typed events; `easyssf.core.signing` signs SETs (`easyssf-core[signing]`) |
| `easyssf-receiver` | `easyssf.receiver` | The receiver: verification, de-duplication with a lease, push and poll, stream management, typed handlers, token revocation, session termination, metrics; `ReceiverConfig` and `Receiver`, which assembles a receiver from it; `PushHandler`, mounted on any framework with `easyssf.receiver.asgi.push_app` or `easyssf.receiver.wsgi.push_wsgi_app`; `RevocationMiddleware` |
| `easyssf-receiver-sqlalchemy` (planned) | `easyssf.sqlalchemy` | The three tables shared with Java, Go, .NET and Rust, on SQLAlchemy 2 |
| `easyssf-receiver-fastapi`, `-litestar`, `-flask` (planned) | `easyssf.fastapi`, `.litestar`, `.flask` | The push route, the revocation middleware or guard and the lifecycle of each framework |
| `easyssf-test` | `easyssf.testing` | `TestTransmitter`: signs SETs, serves metadata and the JWK Set, issues tokens, emulates stream management and the poll endpoint, in-process through the `httpx.AsyncClient` it hands out, no socket involved |
| `conformance/` (not published) | `easyssf.conformance` | Runs the OpenID conformance suite's SSF receiver test plans against the receiver, with the suite started by testcontainers-python, see [Conformance](#conformance) |

## What it does

- **Verifies a SET** (RFC 8417): signature against the transmitter's JWK Set, `typ`, `iss`, `aud`,
  `jti`, `iat`, `events` and the top-level `sub_id` SSF 1.0 requires. Rejections carry the error
  codes of RFC 8935 (`invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`).
  joserfc checks the signature only; every claim rule is the library's, because a SET has no
  `exp` and a JWT library's claim validation would reject every SET.
- **Caches the JWK Set** and fetches it again when a SET names a key it does not know, rate
  limited so that bogus SETs cannot make the receiver flood the transmitter.
- Accepts only asymmetric signature algorithms (`RS256` by default) and RSA keys of at least 2048
  bits.
- Resolves **subjects** (RFC 9493): every simple format, complex subjects, aliases, the `scim`
  format, and the conventions of early SSF drafts and of Keycloak behind explicit modes.
- Knows the **event types** of SSF, CAEP, RISC and SCIM Events (RFC 9967) by URI and by alias
  (`CaepSessionRevoked`), and lets you register aliases for vendor specific types. The **typed
  handlers** `CaepHandler`, `RiscHandler` and `ScimHandler` dispatch by kind with typed access to
  the payload (`event.credential_type`, `event.reason_admin`, `event.data`).
- **Receives pushed SETs** (RFC 8935): checks the transmitter's `Authorization` header in constant
  time, verifies, **skips SETs it has already processed** (`jti` de-duplication with a lease and
  claim renewal, so a SET another instance is handling is left alone and one abandoned by a crash
  is taken over), hands verified events to the handlers, answers `202`, `400` with an error
  document, `401`, `413`, `500` or `503`. The handlers run shielded from the request, so a
  transmitter that disconnects does not cancel them, and an exception in one is a failed handler.
- **Polls for SETs** (RFC 8936): short or long polling, acknowledgements and error reports ride on
  the next request and wait in a `PollAckStore` until it succeeded, invalid SETs are reported with
  their error code, `Retry-After` and `429` are honoured, the acknowledgements owed are flushed on
  shutdown.
- **Discovers the transmitter** from its `.well-known/ssf-configuration`, at the SSF location and
  at the one OpenID providers tend to use, and holds its issuer and endpoints to `https` unless a
  loopback address or `allow-insecure-http` says otherwise.
- **Manages its stream** (SSF 1.0, section 8.1): looks a stream up by id, or reuses, updates or
  creates the stream it wants, in the background with retries, learns the audience of the SETs
  and the poll endpoint from it, refuses a stream the transmitter created with another issuer,
  validates **verification events** by stream and state, and deletes the stream on shutdown when
  asked. The management and poll endpoints are called with a fixed token or one obtained with the
  **client credentials grant**, renewed ahead of its expiry and after a `401`.
- **Revokes access tokens and sessions**: `session-revoked` events fill a `TokenRevocationStore`;
  `RevocationMiddleware` (ASGI) and `reject_if_revoked` reject tokens with that `sid` or that
  `sub` issued up to the event. A `SessionTerminator` ends server-side sessions as the event
  arrives; `subject_matches` tells which sessions belong to the subject of an event, `scim`
  subjects included.
- **Shares its state between instances** through the store protocols `JtiDedupStore`,
  `TokenRevocationStore` and `PollAckStore`: in memory by default, in the tables of the Java
  library once `easyssf-receiver-sqlalchemy` lands, so that a SET pushed to one instance is
  handled once and acknowledged by whichever instance polls next.
- Records **metrics** through the `Metrics` protocol under the Java names and reports its
  **health** per transmitter: metadata resolved, stream registered, last poll.

## Getting started

```sh
uv add easyssf-receiver            # or: pip install easyssf-receiver
```

The configuration keys are those of the Spring Boot starter and the .NET options, in kebab-case
(snake_case is accepted too), under `easyssf.receiver`; `ReceiverConfig.from_mapping` reads them
from any mapping, a parsed YAML, TOML or JSON file, with durations as `"30s"` or `"24h"`:

```yaml
easyssf:
  receiver:
    transmitter-issuer: https://idp.example/realms/demo   # required
    expected-audience: https://my-app.example             # or let the receiver register the stream
    push:
      expected-auth-header: "Bearer ${SSF_PUSH_SECRET}"   # recommended
```

```python
import yaml
from easyssf.receiver import Receiver, ReceiverConfig, TokenClaims, for_event
from easyssf.receiver.asgi import push_app
from easyssf.receiver.revocation import RevocationMiddleware

with open("application.yaml") as file:
    config = ReceiverConfig.from_mapping(yaml.safe_load(file)["easyssf"]["receiver"])

receiver = Receiver(config, handlers=[for_event("CaepCredentialChange", credentials_changed)])
# the configuration is validated, every failure at once (ConfigurationError)

await receiver.start()  # registers the stream, starts polling
...
await receiver.stop()  # sends the acknowledgements it owes

push = push_app(receiver.push_handler)  # an ASGI app for POST /ssf/push


# after the middleware that validates the access token and leaves its claims on the scope
def token_claims(scope):
    claims = scope.get("jwt_claims")
    return (
        TokenClaims(
            issuer=claims["iss"],
            subject=claims["sub"],
            session_id=claims.get("sid", ""),
            issued_at=datetime.fromtimestamp(claims["iat"], tz=UTC),
        )
        if claims
        else None
    )


api = RevocationMiddleware(api, receiver.token_revocation_store, token_claims)
health = await receiver.health()  # HEALTHY, DEGRADED or UNHEALTHY, per transmitter
```

`Receiver` is also an async context manager (`async with receiver:` starts and stops it). The
handlers may be `async def` or plain functions (which run in a worker thread), or objects with an
`async handle(context)` method; `for_event` filters by event type, alias or URI.

To poll instead of being pushed to, and to let the receiver register its own stream:

```yaml
easyssf:
  receiver:
    transmitter-issuer: https://idp.example/realms/demo
    delivery-method: poll
    stream:
      management: receiver
      events-requested: [CaepSessionRevoked, CaepCredentialChange]
    poll:
      long-polling: true
    oauth2:
      token-uri: https://idp.example/realms/demo/protocol/openid-connect/token
      client-id: my-app
      client-secret: "..."
```

The audience of the stream is learned from the registration, so `expected-audience` is not needed;
until the stream is registered, SETs are left for redelivery (`503`). Several transmitters go under
`easyssf.receiver.transmitters.<name>`, each with the same settings; the one at `easyssf.receiver`
is named `default`, and the push endpoint authenticates each by its own header.
`transmitter_customizers=` replaces parts of any transmitter before it is assembled.

Every setting, with its default, is documented on `ReceiverConfig` and its sub-dataclasses; the
keys are those of the
[.NET configuration table](https://github.com/easyssf/easyssf-dotnet#configuration) in
kebab-case. The HTTP timeout of `easyssf.receiver.http.timeout` applies per call, so that a long
poll can wait longer; a timeout on the `httpx.AsyncClient` passed as `http_client=` caps every call.

A management, metadata or JWK Set call that fails with a connection error or a `408`, `429`,
`500`, `502`, `503` or `504` is tried again, twice by default, after a quarter of a second
doubling up to five seconds or the `Retry-After` the transmitter sends
(`easyssf.receiver.http.retry.max-retries`, `initial-backoff`, `max-backoff`; `max-retries: 0`
turns it off). Poll requests are not retried: the poller has its interval and pauses on
`Retry-After`. The stream registrar keeps retrying a failed registration regardless.

Every endpoint of a transmitter, configured or taken from its metadata or stream, must use
`https`, or `http` on loopback (`allow-insecure-http` lifts that, for development only). A
redirect is followed only within the origin of the request, the same scheme, host and port, and
only to a scheme the policy allows: an `https` endpoint cannot send the receiver's token to
`http`, to another host or to another port.

Every call to a transmitter goes through an `Authorizer`: the bearer token of its
`TokenProvider`, and the headers of `easyssf.receiver.headers` (an API key, a tenant), which are
sent with every call including those for metadata and keys. For headers on particular endpoints
only, or anything else a transmitter wants, compose `StaticHeaders`, `EndpointHeaders` and your
own `AuthorizerFunc` with `Authorizers` and give the result to the `StreamClient` and `Poller` of
a transmitter in a customizer.

### Any framework

`PushHandler.handle(authorization_header, body)` returns a `PushResponse` with a status and an
optional JSON body. The processing is shielded from the request's cancellation, so a transmitter
that disconnects does not cancel the handlers:

```python
response = await receiver.push_handler.handle(request.headers.get("authorization"), await request.body())
# send response.status and, if not None, response.body as application/json with Content-Language: en
```

`easyssf.receiver.asgi.push_app` and `easyssf.receiver.wsgi.push_wsgi_app` do exactly that as a
raw ASGI or WSGI application. Assembling the parts by hand reads like the plain Java section of
the Java README: a `JwtVerifier` over a `JwkSetSource`, a `Processor` with a `JtiDedupStore` and
handlers, a `PushHandler` over the processor, a `StreamClient` with a `StreamRegistrar`, a
`Poller`; see `easyssf-receiver/tests/test_processor.py`, `test_stream.py` and `test_poll.py`.

### Typed handlers

```python
from easyssf.core import caep
from easyssf.receiver import CaepHandler, EventContext, caep_handler


class StepUp(CaepHandler):
    async def on_assurance_level_change(self, event: caep.Event, context: EventContext) -> None:
        if event.change_direction == "decrease":
            ...  # require a step-up for context.subject.sub to event.current_level


receiver = Receiver(config, handlers=[caep_handler(StepUp())])
```

`risc_handler` and `scim_handler` do the same for RISC 1.0 and SCIM Events; a handler that also
defines `on_caep_event` (`on_risc_event`, `on_scim_event`) sees every event of its family first and
dispatches with `dispatch_caep_event` when it wants to.

### Ending sessions

An application whose sessions are not access tokens (an OIDC client with a session cookie) gives
the receiver a `SessionTerminator` over its session store; `subject_matches` compares the subject
of an event with the claims of the ID token a user logged in with:

```python
from easyssf.receiver import subject_matches


async def terminate_sessions(subject):
    ended = 0
    for session_id, session in sessions.items():
        if subject_matches(subject, session.id_token_claims, session.username):
            sessions.end(session_id)
            ended += 1
    return ended


receiver = Receiver(config, session_terminator=terminate_sessions)
```

`easyssf.receiver.session-termination` says which events end which sessions (`CaepSessionRevoked`
ends the session named, `CaepCredentialChange` all sessions of the user) and how a `scim` subject
is matched (`externalId` and `id` with `sub`, `userName` with `preferred_username` by default).

### Sharing state between instances

A SET is pushed to one instance of an application. The receiver keeps the processed SETs, the
revocations and the acknowledgements a poller owes in the `JtiDedupStore`, `TokenRevocationStore`
and `PollAckStore` it is given (`dedup_store=`, `revocation_store=`, `poll_ack_store=`), in memory
by default. `easyssf-receiver-sqlalchemy` will keep them in the database of the application, in
the tables of the Java library (`EASYSSF_PROCESSED_SET`, `EASYSSF_REVOCATION`, `EASYSSF_POLL_ACK`),
so that a SET pushed to one instance is handled once and acknowledged by whichever instance polls
next; until then, implement the three protocols over your own data access.

## Testing your receiver

`easyssf.testing.TestTransmitter` signs SETs, serves its metadata and JWK Set, hands out access
tokens and emulates the stream management and poll endpoints, all in-process through the
`httpx.AsyncClient` it hands out: give it to the receiver as its HTTP client, no socket is involved.

```python
from easyssf.core.subjects import complex_subject, iss_sub, opaque
from easyssf.testing import TestTransmitter, eventually

transmitter = TestTransmitter()
receiver = Receiver(config_for(transmitter.issuer), http_client=transmitter.client)
encoded_set = transmitter.set(
    "CaepSessionRevoked", complex_subject(iss_sub(transmitter.issuer, "alice"), opaque("session-1"))
)
# POST encoded_set to /ssf/push, or transmitter.queue_set(encoded_set) for a polling receiver
await eventually(lambda: len(transmitter.acknowledged_sets) == 1, timeout=5, what="the acknowledgement")
```

`transmitter.set_available(False)` simulates an outage, `transmitter.expire_access_tokens()` a
rejected token, `transmitter.set_long_poll_hold(delta)` a transmitter that holds long polls,
`client_for(a, b)` routes to several transmitters, `generate_key(1024, "weak")` makes keys a
receiver has to reject, `sign` and `sign_with` sign claims with any key and algorithm, `unsigned`
makes an `alg: none` token.

A SET of your own is built with `new_set` and signed with `easyssf.core.signing`, which the test
transmitter uses too (`transmitter.signer`):

```python
from easyssf.core import caep, new_set
from easyssf.core.signing import Signer

claims = (
    new_set(issuer)
    .audience("https://app.example")
    .subject(complex_subject(iss_sub(issuer, "alice"), opaque("session-1")))
    .event(
        "CaepSessionRevoked",
        caep.new_payload().event_timestamp(datetime.now(tz=UTC)).initiating_entity("admin").build(),
    )
    .claims()
)
signer = Signer(private_key, "RS256", "key-1")  # a joserfc RSAKey, ECKey or OKPKey
encoded_set = signer.sign(claims)  # typ secevent+jwt, kid key-1
```

## Conformance

The receiver is tested against the OpenID conformance suite's SSF and CAEP receiver test plans,
with push and poll delivery. [`conformance/`](conformance) is a workspace member of its own: the
receiver under test that plays the stream operations a test module expects, the suite started in
Docker by testcontainers-python, and the four plan tests. They are skipped unless asked for, as a
plan takes minutes:

```sh
EASYSSF_CONFORMANCE_TESTS=true uv run pytest conformance/tests/test_plans.py -v
```

See [`conformance/README.md`](conformance/README.md) for the plans, the suite image
(`release-v5.3.2`, pinned by digest, the same as in the Java, Go, .NET and Rust repositories) and
manual runs against a suite of your own.

## Not included (yet)

- A transmitter: this is a receiver library. `new_set` and `easyssf.core.signing` make and sign
  SETs for tests and small senders; the stream management and delivery of a transmitter are not
  here.
- An OpenTelemetry or Prometheus implementation of `Metrics`; it is a small protocol, implement
  it over your meter.
- The SQLAlchemy stores and the FastAPI, Litestar and Flask integrations, and the ports of the
  Spring Boot examples (resource server, OIDC client, SCIM provisioning): next.

## Build

```sh
uv sync --all-packages                        # the workspace, every member, the dev tools
uv run pytest                                 # everything, in-process, no network, no Docker
uv run ruff check . && uv run ruff format --check .
uv run mypy easyssf-core/src easyssf-receiver/src easyssf-test/src conformance/src
```

See [AGENTS.md](AGENTS.md) for the layout, the porting rules and the conventions of the code.
