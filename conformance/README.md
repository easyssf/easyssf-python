# easyssf conformance tests

Runs easyssf-python against the [OpenID conformance suite](https://gitlab.com/openid/conformance-suite),
the port of `easyssf-test-conformance` and `easyssf-receiver-spring-boot-conformance-tests` of the
Java library and of the `conformance` module of easyssf-go. A workspace member of its own
(`easyssf-conformance`, imported as `easyssf.conformance`, not published), so that the Docker
client it needs stays out of the library. It consists of

- the **receiver under test** (`Run`, `Runner`, `cts_app`, and the `cts` script to run it by
  hand): a small application that acts as the SSF receiver the suite tests with its
  `openid-ssf-receiver-caep-test-plan` and `openid-ssf-receiver-test-plan`. The suite emulates a
  transmitter and an authorization server; the receiver plays the stream operations the tests
  expect and accepts the events they deliver. Every test of the suite emulates a transmitter with
  new signing keys under the same issuer, so every test run gets a fresh receiver assembled from
  the parts of `easyssf.receiver` (see `Run`): token, verifier, de-duplication and stream are per
  run.
- the **automated conformance tests** (`tests/test_plans.py`): four tests of a few lines that run
  the plans against that receiver. `Suite` starts the suite with
  [testcontainers-python](https://testcontainers-python.readthedocs.io), `run_plan` creates a
  plan, runs every module and asserts the result the suite reports.
- the **scenarios against the test transmitter** (`tests/test_run.py`), which run with
  `uv run pytest` like any other test and need no Docker.

## Automated tests

The plan tests are skipped unless `EASYSSF_CONFORMANCE_TESTS=true`; a plan takes a few minutes, as
each module waits for the receiver to deliver, verify and fall idle.

```sh
EASYSSF_CONFORMANCE_TESTS=true uv run pytest conformance/tests/test_plans.py -v --timeout 3600   # all four plans
EASYSSF_CONFORMANCE_TESTS=true uv run pytest conformance/tests/test_plans.py -v --timeout 3600 -k caep_interop_10_push
```

| Test | Plan | Variant | Suite configuration |
|---|---|---|---|
| `test_ssf10_push_plan` | `openid-ssf-receiver-test-plan` | `ssf_delivery_mode=push` | `suite-config/receiver-ssf1.0-push.json` |
| `test_ssf10_poll_plan` | `openid-ssf-receiver-test-plan` | `ssf_delivery_mode=poll` | `suite-config/receiver-ssf1.0-poll.json` |
| `test_caep_interop_10_push_plan` | `openid-ssf-receiver-caep-test-plan` | `ssf_delivery_mode=push` | `suite-config/receiver-ssf1.0-caepiop1.0-push.json` |
| `test_caep_interop_10_poll_plan` | `openid-ssf-receiver-caep-test-plan` | `ssf_delivery_mode=poll` | `suite-config/receiver-ssf1.0-caepiop1.0-poll.json` |

All plans use `ssf_auth_mode=dynamic` and `client_auth_type=client_secret_basic`. A test names its
`PlanDefinition`, `run_plan` creates it in the suite and runs the modules of the plan one after
another, so the modules follow the suite version in use; pytest has no subtests, so the failures
are collected and reported together at the end. `expectation_for_module` maps a module to the
scenario the receiver plays (see [Scenarios](#scenarios)) and the status its run has to end with;
a failed module fails with the failures and warnings the suite logged, the receiver's log and the
link to the suite's log page.

The suite configurations, the TLS material of the receiver (`tls/`) and the test CA
(`test-ca.pem`) live inside the package, `src/easyssf/conformance/`, so that they ship with it;
`resources.py` exposes their paths.

### The suite

The suite is started with testcontainers-python (MongoDB, the suite and its nginx, like
`docker-compose-prebuilt.yml` of the suite's repository), so Docker is all that is needed. The suite
has to know its own URL before it starts, so nginx is bound to a fixed host port
(`https://localhost:18443`, where the suite's UI shows the plans while the tests run), and the suite
reaches the receiver on the Docker host as `host.docker.internal`.

**Different from the Go, Java, .NET and Rust harnesses:** those reach the receiver through the
`host.testcontainers.internal` port forwarding sidecar of their Testcontainers; testcontainers-python
has no such sidecar. The suite container therefore gets `host.docker.internal` mapped to the host
gateway (`extra_hosts={"host.docker.internal": "host-gateway"}`), which Docker Desktop resolves by
itself and Docker on Linux (GitHub's runners) needs told, and the default push URL is
`https://host.docker.internal:<receiver port>/ssf/push`. The receiver's certificate in `tls/` names
`host.docker.internal` as well.

| Environment variable | Default | |
|---|---|---|
| `CTS_SUITE_IMAGE` | `registry.gitlab.com/openid/conformance-suite@sha256:…` (`release-v5.3.2`, pinned by digest) | the suite image |
| `CTS_SUITE_NGINX_IMAGE` | `registry.gitlab.com/openid/conformance-suite/nginx@sha256:…` (`release-v5.3.2`, pinned by digest) | its nginx image |
| `CTS_SUITE_MONGODB_IMAGE` | `mongo@sha256:…` (`9.0.4`, pinned by digest; the suite itself runs 6.0.13 in production, older 8.x and 9.x releases do not start on current Ubuntu kernels) | its MongoDB image |
| `CTS_SUITE_PORT` | `18443` | host port of the Testcontainers-started suite |
| `CTS_RECEIVER_PORT` | `9444` | port of the receiver under test |
| `CTS_RECEIVER_PUSH_URL` | `https://host.docker.internal:<receiver port>/ssf/push` | the push URL the receiver registers |

The images are the ones `settings.py` names, the last suite release pinned by digest, the same as
in the Java, Go, .NET and Rust repositories: the single place to change them.

The receiver under test serves `https` with the certificate in `tls/` (issued by `test-ca.pem` for
`localhost`, `host.testcontainers.internal`, `host.docker.internal` and `127.0.0.1`), on uvicorn;
the suite only accepts `https` push endpoints and does not check the certificate. The receiver
trusts the suite's self-signed certificate, read from the nginx container and pinned as the only
trusted certificate of its `ssl.SSLContext`: it names its host in the Common Name only, so the host
name is not checked, the certificate chain is.

## Manual runs

Against a suite of your own, for example the [local
suite](https://gitlab.com/openid/conformance-suite/-/wikis/Developers/Build-&-Run) at
`https://localhost.emobix.co.uk:8443`:

1. Create a test plan in the suite from `src/easyssf/conformance/suite-config/easyssf-receiver.json`
   (alias `easyssf-receiver-python-test`), with the authentication variant `dynamic` and client
   authentication `client_secret_basic`.
2. Save the suite's certificate so that the receiver trusts it:
   `./fetch-suite-certificate.sh` writes `certs/conformance-suite.pem`.
3. Start the receiver under test: `uv run cts` (port 9443, `--listen` changes it). It takes
   its settings from `CTS_*` variables: `CTS_TRANSMITTER_ISSUER` (the test instance,
   `https://localhost.emobix.co.uk:8443/test/a/easyssf-receiver-python-test` by default),
   `CTS_DELIVERY` (`push` or `poll`), `CTS_PUSH_URL` (`https://localhost:9443/ssf/push`),
   `CTS_AUTH_MODE`, `CTS_CLIENT_ID`, `CTS_CLIENT_SECRET`, `CTS_CLIENT_AUTH`, `CTS_ACCESS_TOKEN`,
   `CTS_SUITE_CERTIFICATE`, `CTS_TRUST_ALL`, `CTS_TLS_CERTIFICATE` / `CTS_TLS_KEY` for a certificate
   of your own (mkcert), `CTS_RUN_IDLE_TIMEOUT`.
4. Start a test module in the suite; it waits for the receiver.
5. Start the run the module expects: `curl -sk -X POST https://localhost:9443/cts/runs/auto`. The
   receiver asks the suite which module waits and plays the scenario of that module against the
   module's test instance with the delivery method of its variant. With no waiting module it is a
   `404`, with several a `409` that lists them (`?issuer=<issuer>` picks one).
   `curl -sk https://localhost:9443/cts/suite/modules | jq` shows what runs in the suite.
   To choose the scenario yourself: `curl -sk -X POST 'https://localhost:9443/cts/runs?scenario=caep-interop'`,
   with `&issuer=…&delivery=poll` for another test instance or delivery method than configured.
6. Watch it: `curl -sk https://localhost:9443/cts/runs/current | jq`. The run logs every step and
   every SET, and ends by deleting the stream once no SET arrived for the idle timeout (30
   seconds, long enough for the pauses the tests make).

Starting a run stops the previous one; `POST /cts/runs/current/stop` ends a run early.
[`run-plan.sh`](run-plan.sh) does steps 4 to 6 for every module of a plan (it needs `curl` and
`jq`): `./run-plan.sh -c src/easyssf/conformance/suite-config/receiver-ssf1.0-caepiop1.0-push.json`
creates the plan and runs it module by module, `./run-plan.sh -a 10 <plan id>` continues
automatically.

### Scenarios

| Scenario | What the receiver does | Test modules |
|---|---|---|
| `caep-interop` (default) | create stream, check its issuer, read configuration and status, verify (rejecting a wrong state or stream and requesting again), accept events, delete | all modules of the CAEP interop plan; in the default plan everything except the three below |
| `create-delete` | create and delete only | `stream-create-delete` |
| `stream-management` | as `caep-interop`, plus update and replace the stream | `happypath` (default plan) |
| `status-update` | as `caep-interop`, plus pause and enable the stream after the verification | `stream-status-update` (default plan) |
| `remove-subject` | as `caep-interop`, plus remove the configured subject after the verification | `removed-subject-event` (default plan) |

The `stream-issuer-mismatch` module passes with any scenario: the receiver refuses the stream the
suite created with a foreign `iss`, deletes it and ends the run as `REFUSED_STREAM`. Which module
gets which scenario is defined in `scenario_for_module`, used by `POST /cts/runs/auto` and by the
automated tests alike.

## Endpoints

| | |
|---|---|
| `POST /cts/runs/auto?issuer=…` | starts the run the test module waiting in the suite expects |
| `GET /cts/suite/modules?issuer=…` | the test modules running in the suite, with the scenario the receiver plays for each |
| `POST /cts/runs?scenario=…&issuer=…&delivery=…` | starts a run |
| `GET /cts/runs/current` | the current run: status, stream, log, received SETs |
| `POST /cts/runs/current/stop` | stops the current run and deletes its stream |
| `POST /ssf/push` | the push endpoint the suite delivers to; each run expects its own `Authorization` header, registered with the stream |
