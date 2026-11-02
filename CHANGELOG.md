# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the version follows the Java library.

## [Unreleased]

## [0.7.0] - 2026-11-02

The first release: the port of easyssf 0.7.0 for Java to Python, after the Go, .NET and Rust
ports, at feature parity with the Java library.

### Added

- `easyssf-core` (`easyssf.core`, the vocabulary: SETs, subjects, stream configuration, transmitter
  metadata and the typed CAEP, RISC and SCIM events), `easyssf-receiver` (`easyssf.receiver`, the
  asyncio receiver: verification, de-duplication, push and poll, stream management, typed
  handlers, token revocation and session termination) and `easyssf-test` (`easyssf.testing`, the
  in-process test transmitter). The distributions pin each other to the `0.7` series
  (`easyssf-core>=0.7,<0.8`).
- `easyssf-receiver-fastapi` (`easyssf.fastapi`): the push endpoint as an `APIRouter`
  (`push_router`, `push_router_for`), the rejection of revoked access tokens as a dependency
  (`revocation_dependency`) or as the ASGI `RevocationMiddleware`, the receiver's lifecycle as a
  lifespan (`receiver_lifespan`) and its health as a route (`health_router`).
- The hardening of easyssf 0.7.0 for Java: `StreamClient` checks the issuer of every stream
  configuration the transmitter returns (SSF 1.0, section 8.1.1) and raises `IssuerMismatchError`;
  `StreamRegistrar` deletes a stream it created with the wrong issuer and leaves an existing one
  alone. Every poll request passes the URI policy check, the acknowledgements `Poller.stop()`
  flushes included. A SET the poll response lists under a key other than its `jti` (RFC 8936,
  section 2.4) is reported to the transmitter as `invalid_request` under that key. A response
  body larger than `easyssf.receiver.http.max-response-size` (`4MB` by default, bound as Spring's
  `DataSize`: `DataSize`, `parse_data_size`, `format_data_size`) fails the call with
  `ResponseTooLargeError`, counts as the transmitter being unavailable and is not tried again.
- A SET whose claim was taken over by another instance while the handlers ran (they outlived the
  `dedup.lease`) is not acknowledged by the late instance: `Processor.process` raises
  `InProgressError`, the push endpoint answers `503` and the poller does not acknowledge, so that
  the acknowledgement comes from the instance that records the success. `JtiDedupStore.processed`
  returns whether it recorded the success, and only an explicit `True` acknowledges. The Java,
  Go, .NET and Rust ports return the result of the handlers in this case.
- `ReceiverConfig.from_mapping` reports a key it does not know as a configuration failure, with
  the key it resembles (`push.expected-auth-headers: unknown setting, did you mean
  'expected-auth-header'?`), where the Spring Boot, .NET and Go bindings ignore it;
  `from_mapping(..., strict=False)` ignores it as well.
- `Receiver` owns the HTTP clients it makes itself: `Receiver.aclose()` stops the receiver and
  closes them, a client given as `http_client=` stays open; `async with receiver:` and
  `receiver_lifespan` close the receiver on exit. `Receiver.start()` rolls back when a transmitter
  fails to start, and `Receiver.stop()` stops every transmitter even when one fails to.
- The conformance harness (`conformance/`, not published): the OpenID conformance suite's four SSF
  receiver test plans against the receiver, with the suite started by testcontainers-python.
- `examples/fastapi/resource-server`, the port of the Spring Boot resource server example after
  the Go one: an OAuth2 resource server on FastAPI against the Keycloak of `examples/keycloak`
  that registers its stream (push, or `--poll`) and rejects access tokens once their session was
  revoked.

[Unreleased]: https://github.com/easyssf/easyssf-python/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/easyssf/easyssf-python/releases/tag/v0.7.0
