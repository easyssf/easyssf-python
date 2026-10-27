# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the version follows the Java library.

## [Unreleased]

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
