# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the version follows the Java library.

## [Unreleased]

### Changed

- A SET whose claim was taken over by another instance while the handlers ran (they outlived
  the `dedup.lease`) is no longer acknowledged by the late instance: `Processor.process` raises
  `InProgressError`, the push endpoint answers `503` and the poller does not acknowledge, so that
  the acknowledgement comes from the instance that records the success, and a failure there is
  not hidden from the transmitter. `JtiDedupStore.processed` returns whether it recorded the
  success (`False` when the claim was taken over), which closes the gap between the last renewal
  and the record. The Java, Go, .NET and Rust ports still return the result of the handlers in
  this case.
- `Receiver.stop()` stops every transmitter even when one fails to, and raises the first failure
  afterwards; `Receiver.aclose()` closes the receiver's own HTTP clients even when `stop()` fails.
- `ReceiverConfig.from_mapping` reports a key it does not know as a configuration failure, with
  the key it resembles (`push.expected-auth-headers: unknown setting, did you mean
  'expected-auth-header'?`), instead of ignoring it silently as the Spring Boot, .NET and Go
  bindings do; `from_mapping(..., strict=False)` restores that behaviour.
- `Receiver` owns the HTTP clients it makes itself: `Receiver.aclose()` stops the receiver and
  closes the `httpx.AsyncClient` it created when none was given, and the one that adds the
  configured `user-agent`; a client given as `http_client=` stays open. `async with receiver:`
  and `receiver_lifespan` close the receiver on exit; `stop()` alone leaves it ready for another
  `start()`. `Receiver.closed` tells, and `start()` on a closed receiver raises `RuntimeError`.
- `Receiver.start()` rolls back when a transmitter fails to start: the transmitters started before
  it are stopped again and the receiver is left stopped, so that `start()` can be tried again
  instead of doing nothing.
- The distributions pin each other to the `0.6` series (`easyssf-core>=0.6,<0.7`,
  `easyssf-receiver>=0.6,<0.7`), and CI installs the built wheels in a clean environment.

### Fixed

- `UriPolicy.is_loopback` took any host that starts with `127.` for a loopback address, so that
  `http://127.attacker.example/` was exempt from the https requirement; it now uses the parsed IP
  address (`127.0.0.0/8`, `::1`) and the `localhost` names only.
- The ASGI push app and the FastAPI push router buffer no more than one byte beyond
  `MAX_SET_SIZE` of a request body, whatever the size of the chunks the server hands over; before,
  one large chunk was appended in full before the limit was checked.

### Added

- The port of easyssf 0.6.0 for Java to Python, after the Go, .NET and Rust ports: `easyssf-core`
  (the vocabulary), `easyssf-receiver` (the asyncio receiver), `easyssf-test` (the in-process test
  transmitter) and the conformance harness on testcontainers-python.
- `easyssf-receiver-fastapi` (`easyssf.fastapi`): the push endpoint as an `APIRouter`
  (`push_router`, `push_router_for`), the rejection of revoked access tokens as a dependency
  (`revocation_dependency`) or as the ASGI `RevocationMiddleware`, the receiver's lifecycle as a
  lifespan (`receiver_lifespan`) and its health as a route (`health_router`).
- `examples/fastapi/resource-server`, the port of the Spring Boot resource server example after
  the Go one: an OAuth2 resource server on FastAPI against the Keycloak of `examples/keycloak`
  that registers its stream (push, or `--poll`) and rejects access tokens once their session was
  revoked.
