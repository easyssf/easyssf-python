# easyssf-python for coding agents

Read this first, then the [README](README.md) for what the library does. This file holds what is
not obvious from the code: what the repository is, how it relates to the Java original and the
Go, .NET and Rust ports, the conventions it follows, and the commands that matter.

## What this is

Python building blocks for the OpenID Shared Signals Framework (SSF 1.0) with CAEP, RISC and SCIM
Events (RFC 9967): a framework independent, asyncio based **receiver** library, integrations for
Flask, FastAPI, Litestar and SQLAlchemy, and an in-process test transmitter. The code sits in the
authentication path of its users, so correctness of verification beats convenience everywhere.
Receiver only, no transmitter. Apache-2.0. Status: pre-1.0, the version follows the Java library
(0.6.0), breaking changes are acceptable when the CHANGELOG says so.

This is a port of [easyssf for Java](https://github.com/easyssf/easyssf), following the playbook
of [easyssf-go](https://github.com/easyssf/easyssf-go), [easyssf-rust](https://github.com/easyssf/easyssf-rust)
and [easyssf-dotnet](https://github.com/easyssf/easyssf-dotnet). The Java code is the reference
for protocol behaviour, names and tests; **the Go code is the closest in shape and the one to port
from** (one receiver package, options structs, a test transmitter over an in-process transport);
the Rust code is the second opinion. Local checkouts are expected at `../easyssf`, `../easyssf-go`,
`../easyssf-rust` and `../easyssf-dotnet`. On a protocol matter the Java code and the
specification win; on a Python matter this file wins.

One uv workspace, one `easyssf` namespace package (PEP 420, no `easyssf/__init__.py` anywhere).
Distributions, in dependency order:

| Distribution | Imports as | Holds | Port of | Depends on |
|---|---|---|---|---|
| `easyssf-core` | `easyssf.core` | The vocabulary: claims helpers, SETs (`EventToken`, `SetBuilder`), subjects, `DeliveryMethod`, `StreamConfiguration`, `TransmitterMetadata`, event types with aliases, the typed CAEP, RISC and SCIM events; `easyssf.core.signing` signs SETs (extra `easyssf-core[signing]`, joserfc) | Go `ssf`, `ssf/eventtypes`, `ssf/{caep,risc,scim}`, `ssf/signing` | stdlib |
| `easyssf-receiver` | `easyssf.receiver` | The receiver: verification, de-duplication, push and poll, stream management, typed handlers, revocation, session termination, metrics, `ReceiverConfig`, `Transmitter`, `Receiver`; `easyssf.receiver.asgi` and `.wsgi` mount the push endpoint on any framework | Go `receiver` | core, joserfc, httpx |
| `easyssf-test` | `easyssf.testing` | `TestTransmitter`: signs SETs, serves metadata and JWK Set, issues tokens, emulates stream management and the poll endpoint, in-process through an `httpx` transport; `eventually`, `during`, `ManualClock`, signing helpers | Go `ssftest` | core, joserfc, httpx |
| `easyssf-receiver-sqlalchemy` (later) | `easyssf.sqlalchemy` | The three tables shared with Java, Go, .NET and Rust, on SQLAlchemy 2 (sync and async engines) | Go `receiver/sqlstore` | receiver, sqlalchemy |
| `easyssf-receiver-fastapi` | `easyssf.fastapi` | `push_router` / `push_router_for` (the push endpoint as an `APIRouter`), `revocation_dependency` for `Depends` and the ASGI `RevocationMiddleware`, `receiver_lifespan` for `FastAPI(lifespan=...)`, `health_router` | Rust `easyssf-receiver-axum` | receiver, fastapi |
| `easyssf-receiver-flask`, `-litestar` (later) | `easyssf.flask`, `easyssf.litestar` | The push route, the revocation middleware / guard, the lifecycle hooks of each framework | Rust `easyssf-receiver-axum` / `-actix-web` | receiver, the framework |
| `conformance/` (`easyssf-conformance`, not published) | `easyssf.conformance` | The OpenID conformance suite started with testcontainers-python, the receiver under test that plays the scenarios, the four plan tests (`EASYSSF_CONFORMANCE_TESTS=true`) and the `cts` script for manual runs | Go `conformance` | receiver, test, testcontainers, uvicorn |
| `examples/*` (`example-fastapi-resource-server`, not published) | `resource_server` | `examples/fastapi/resource-server`: the OAuth2 resource server on FastAPI that rejects access tokens once their Keycloak session was revoked (`config.py` the receiver configuration, `auth.py` the access token validation, `main.py` the app and the `resource-server` script); `examples/keycloak` the compose setup with the `ssf-demo` realm shared with the other repositories; the OIDC client and SCIM provisioning examples are not ported yet | Go `examples/resource-server` | receiver, fastapi, uvicorn |

New protocol behaviour goes into `easyssf-receiver`, new vocabulary into `easyssf-core`, framework
code only into the framework distributions, database code into `easyssf-receiver-sqlalchemy`.

## Build and test

```sh
uv sync --all-packages                        # the workspace with every member and the dev group
uv run pytest                                 # everything, in-process, no network, no Docker
uv run pytest easyssf-receiver/tests/test_verifier.py -k rejects   # one file, the negative tests
uv run ruff check . && uv run ruff format --check .   # CI fails on either
uv run mypy easyssf-core/src easyssf-receiver/src easyssf-test/src easyssf-receiver-fastapi/src conformance/src examples/fastapi/resource-server/src
cd conformance && EASYSSF_CONFORMANCE_TESTS=true uv run pytest tests/test_plans.py -v   # the suite in Docker, minutes per plan
```

- The tests need no network and no Docker: `TestTransmitter` answers in-process through the
  `httpx.AsyncClient` it hands out (`transmitter.client`), whose transport routes the transmitter's
  host to its handler and refuses every other host; `easyssf.testing.client_for(a, b)` routes to
  several. Time-dependent tests use `eventually`, `during` and a `ManualClock` moved by hand; no
  `asyncio.sleep` of more than a few milliseconds in a test.
- `easyssf.testing.shared_key()` is one 2048 bit RSA key per process: generating one takes long
  enough that the tests would crawl otherwise. `generate_key` always makes a fresh key, for SETs
  the receiver must reject.
- pytest runs with `asyncio_mode = "auto"`: an `async def test_...` just works, fixtures too.
- The conformance package is a workspace member; `uv run pytest` from the root runs its
  Docker-free tests (the scenarios against the test transmitter), the plan tests skip themselves
  unless `EASYSSF_CONFORMANCE_TESTS=true`. Run the plans only when a change touches stream
  management, polling, verification or the harness, and say so; the suite images are pinned by
  digest in `conformance/src/easyssf/conformance/settings.py`, the same as in the other repositories.
- `scratch/` is ignored by git: put plans, notes and throwaway scripts there, not into the tree.
- Do not commit, push, tag or publish unless asked.

## Porting

- The Go package maps to the distribution, the Go file to the module: `receiver/set.go` is
  `easyssf/receiver/verifier.py` (a module named `set` would shadow the builtin), `receiver/event.go`
  is `easyssf/receiver/event.py`, `ssf/token.go` is `easyssf/core/token.py`. Split a module that
  would exceed about 800 lines.
- Port a Go type with its tests, the negative tests (the SET that must be rejected) before the
  positive ones, and keep the test names as sentences in snake_case:
  `test_rejects_set_signed_with_unknown_key` for `TestRejectsSETSignedWithUnknownKey`, so that the
  five suites can be compared. One test module per Go test file: `receiver/set_test.go` is
  `easyssf-receiver/tests/test_verifier.py`.
- Names follow Go minus the package prefix, in PEP 8 case: `receiver.Verifier` is
  `easyssf.receiver.Verifier`, `receiver.JTIDedupStore` is `JtiDedupStore`, `receiver.Context` is
  `EventContext` (a `Context` says nothing in Python), `ssf.Claims` is `Claims`. Acronyms are
  words: `JwkSetSource`, `HttpJwkSetSource`, `jti`, `set_id`. Go getters are properties
  (`token.issuer`), predicates are `is_` properties (`subject.is_complex`), builders keep their
  chainable methods.
- `schema.sql` and `migration/*.sql` of `easyssf-receiver-sqlalchemy` will be copies of the Java
  files, byte for byte; CI compares them. Change them in the Java repository first.

## Code conventions

- **Python 3.11 and up**, fully typed (`py.typed`, `mypy --strict` clean), `ruff` clean with the
  rules of the root `pyproject.toml` (line length 120, Google docstrings). Every public name has a
  docstring that starts with what it is; modules list their public names in `__all__` and the
  package `__init__` re-exports the public API of its modules.
- **asyncio throughout.** Everything that does I/O or waits is `async def`: the store protocols,
  `Verifier.verify`, `PushHandler.handle`, `Receiver.start`/`stop` (also `async with receiver:`).
  Background work (`StreamRegistrar`, `Poller`, `Transmitter`, `Receiver`) runs as `asyncio.Task`s
  owned by the component: `start()` returns at once, `stop()` cancels and awaits them. No threads
  in the library; a sync callable a user hands in as a handler or session terminator runs in a
  worker thread through `asyncio.to_thread`, an async one is awaited. Sync adapters for sync
  frameworks (Flask) live in the framework distribution and run the receiver in a loop of their own.
- **Raw claims are `dict[str, Any]`** (`easyssf.core.Claims`), decoded with `json.loads`: Python
  integers are exact, so there is no `json.Number`; the accessors (`string_member`,
  `object_member`, `as_int`, `strings`, `audiences`, `event_timestamp`) read what any JSON decoder
  produces and reject `bool` where a number is expected. Typed accessors sit on top. Dicts keep
  insertion order; where Go sorts member names, keep the order received unless the Go code says why
  it sorts.
- **Lenient factories return `None`** (`EventToken.from_claims`, `SubjectIdentifier.from_claims`),
  no exceptions in library code for input that does not fit. Errors are exception classes in
  `easyssf.receiver.errors`: `RejectedError(code, description)` carries the RFC 8935 code,
  `TransmitterUnavailableError` is temporary, `InProgressError`, `HandlingError`, `StoreError`,
  `StreamError(status, ...)`, `IssuerMismatchError`, `ConfigurationError(failures)`; callers catch
  types, never match messages. Enumerations the specification may extend are open: subject formats,
  error codes and event type URIs are `str` constants (grouped in a class of constants where Go has
  a `const (...)` block), and the typed events keep an `OTHER` kind. Closed sets are `enum.Enum`
  (`DeliveryMethod`, `SubjectCompatibilityMode`, `StreamRegistrarState`, `ProcessingOutcome`).
- **Interfaces are `typing.Protocol`s with async methods**: `Verifier`, `JwkSetSource`,
  `JtiDedupStore`, `TokenRevocationStore`, `PollAckStore`, `SessionTerminator`, `TokenProvider`,
  `Authorizer`, `Handler`. Every protocol has an in-memory implementation and, where it holds state
  that must survive a restart, a SQLAlchemy one (later). The HTTP client is `httpx.AsyncClient`;
  tests give one with an in-process transport.
- **Options are dataclasses** (`VerifierOptions`, `ProcessorOptions`, `PollerOptions`, with
  defaults), read when the work is done. `Receiver` takes its parts as keyword arguments
  (`handlers=`, `http_client=`, `clock=`, `metrics=`, `dedup_store=`, `session_terminator=`,
  `transmitter_customizers=`, `logger=`) over a `ReceiverConfig`, a dataclass tree whose keys are
  those of the Java starter and the .NET options: `ReceiverConfig.from_mapping(d)` reads kebab-case
  (and snake_case) keys from any mapping (a parsed YAML, TOML or JSON file, `easyssf.receiver`
  being the root), durations as `"30s"`, `"24h"` or seconds. `ReceiverConfig.validate()` reports
  every failure at once with its key and is pure: it changes nothing, aliases are registered by
  `Receiver.__init__` after the whole configuration passed. Keep it that way.
- **joserfc checks the signature only.** The header is read with `jws.extract_compact` first so
  that `typ`, `alg` and `kid` failures carry our error codes, then `jws.deserialize_compact` is
  restricted to the one algorithm the header names and given the one key selected from the JWK
  Set. Every claim rule and every error code of RFC 8935 is in `JwtVerifier._validate_claims`,
  because a SET has no `exp` and a JWT library's claim validation would reject every SET.
- **A dropped request must not cancel the handlers.** `PushHandler.handle` runs the processing in
  a task shielded from the caller's cancellation (`asyncio.shield` over a task the handler owns); an
  exception in a handler is caught by the processor, counted as a failed handler and becomes a 500,
  and the dedup store releases the claim.
- **Time is `datetime` with `tzinfo=UTC`** and durations are `timedelta`. Components that measure
  time take a `Clock` (`Callable[[], datetime]`, `system_clock` by default) the tests move by hand.
- **Calls to the transmitter go through `exchange`/`send` in `transmitter.py`**: a per-call timeout
  (`DEFAULT_HTTP_TIMEOUT`, `easyssf.receiver.http.timeout`; a long poll gets its hold plus
  `LONG_POLL_MARGIN`), the `Authorizer` of the transmitter (the bearer token of its `TokenProvider`
  plus `easyssf.receiver.headers`), retries per `RetryOptions` on connection errors and 408/429/5xx
  (not for poll requests), one more try with a new token after a 401 when the authorizer implements
  `TokenInvalidator`. httpx does not follow redirects by default and the receiver follows them by
  hand through `UriPolicy.check_redirect`: same origin only (scheme, host, effective port), scheme
  per policy. Never pass `follow_redirects=True`.
- **`Transmitter` is a plain mutable dataclass** that `Receiver.__init__` fills from the
  configuration and `transmitter_customizers` may change. `Receiver` keeps them in configuration
  order, `default` first.
- **Logging** is `logging.getLogger("easyssf.receiver")` and friends with `extra={...}` attributes
  (`jti`, `transmitter`, `event` as alias). Metrics are the `Metrics` protocol under the Java names,
  `NoopMetrics` by default; an OpenTelemetry implementation is a separate distribution.
- **Protocol facts carry their source.** Docstrings cite the specification and section (`SSF 1.0
  8.1.4.1`, `RFC 9967, section 2.4`) and name the real-world deviation they tolerate. Keep that habit.
- **Strict by default, lenient by configuration.** The receiver rejects what the specification
  forbids and tolerates older drafts or known transmitter quirks only behind an explicit mode
  (`SubjectCompatibilityMode.LEGACY`, `allow-insecure-http`).
- **Handlers are idempotent** and a SET that any handler fails on is delivered again. State that
  must survive a restart belongs in a store protocol with an in-memory and a SQLAlchemy
  implementation.
- Dataclasses are `frozen=True` unless something mutates them; `slots=True` where no one subclasses.
  Secrets (`client_secret`, `expected_auth_header`, tokens) never appear in `__repr__` or logs.

## Where things are

The Java test classes and their Python files, so that the five suites can be compared:

| Java tests | Go file | Python test module |
|---|---|---|
| `NimbusSsfSetVerifierTests`, `SsfTransmitterMetadataResolverTests` | `receiver/set_test.go`, `receiver/transmitter_test.go` | `easyssf-receiver/tests/test_verifier.py`, `test_transmitter.py` |
| `InMemorySsfJtiDedupStoreTests`, `SsfSetProcessorTests`, `SsfPushHandlerTests` | `receiver/dedup_test.go`, `processor_test.go`, `push_test.go` | `test_dedup.py`, `test_processor.py`, `test_push.py` |
| `SsfStreamManagementTests`, `SsfStreamVerificationTests` | `receiver/stream_test.go` | `test_stream.py` |
| `SsfPollerTests`, `SsfPollerRateLimitTests` | `receiver/poll_test.go` | `test_poll.py` |
| `SsfTransmittersTests`, the hosting tests of .NET | `receiver/transmitter_test.go`, `receiver_test.go` | `test_transmitter.py`, `test_receiver.py` |
| `SsfSessionTerminationEventHandlerTests`, `SsfSubjectClaimsMatcherTests` | `receiver/session_test.go` | `test_session.py` |
| `SsfCaepEventHandlerTests`, `SsfRiscEventHandlerTests`, `SsfScimEventHandlerTests` | `receiver/typed_handlers_test.go`, `ssf/{caep,risc,scim}/*_test.go` | `test_typed_handlers.py`, `easyssf-core/tests/test_{caep,risc,scim}.py` |
| `AbstractJdbcSsfStoresTests`, `AbstractJdbcSharedReceiversTests` | `receiver/sqlstore/*_test.go` | `easyssf-receiver-sqlalchemy/tests/` (later) |
| `ConformanceSuiteModulesTests`, `ConformanceRunLocalTransmitterTests`, the four plan tests | `conformance/modules_test.go`, `run_test.go`, `plans_test.go` | `conformance/tests/test_modules.py`, `test_run.py`, `test_plans.py` |

Not included, on purpose, as in the other ports: a transmitter, an OpenTelemetry `Metrics`
implementation, session store integrations beyond `SessionTerminator` and `subject_matches`.
Subject formats that RFC 9493 dropped (`jwt_id`, `saml_assertion_id`) are not supported.

## Documentation that changes with the code

- `README.md` is the user document. A new setting, alias, subject format or handler is documented
  there in the same change.
- `CHANGELOG.md` follows Keep a Changelog; add to the `Unreleased` section in the voice of the
  existing entries.
