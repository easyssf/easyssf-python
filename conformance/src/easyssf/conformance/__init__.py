"""Runs the OpenID conformance suite's SSF receiver test plans against a receiver under test: the
suite started with testcontainers-python, the scenarios the receiver plays, the plans and the
expected outcome of every module, and the receiver under test itself. The port of
``easyssf-test-conformance`` and ``easyssf-receiver-spring-boot-conformance-tests`` of the Java
library and of the ``conformance`` module of the Go port, a workspace member of its own so that
the Docker client it needs stays out of the library.

The suite emulates a transmitter and an authorization server; the receiver under test
(:class:`Run`, served by :func:`cts_app`) plays the stream operations a test module expects and
accepts the events it delivers. Every test of the suite emulates a transmitter with new signing
keys under the same issuer, so every run gets a fresh receiver assembled from ``easyssf.receiver``:
token, verifier, de-duplication and stream are per run.

The plan tests (``tests/test_plans.py``) are skipped unless ``EASYSSF_CONFORMANCE_TESTS=true``, as a
plan takes minutes and needs Docker; the ``cts`` script runs the receiver under test by hand
against a suite, and ``run-plan.sh`` drives a plan module by module.
"""

from .api import TERMINAL_STATES, ApiClient, ModuleResult, Plan, PlanModule, SuiteApiError
from .app import USAGE, AsgiApp, ModuleRunView, RunView, cts_app
from .modules import WAITING, Module, SuiteModules, TestInstance, parse_test_instance
from .plan import (
    CAEP_INTEROP_10_POLL,
    CAEP_INTEROP_10_PUSH,
    PLANS,
    SSF10_POLL,
    SSF10_PUSH,
    PlanDefinition,
    suite_config,
)
from .plantest import MODULE_TIMEOUT, receiver_log, run_plan
from .receiver_settings import AuthMode, AuthSettings, ReceiverSettings, default_receiver_settings
from .resources import (
    USER_AGENT,
    new_http_client,
    receiver_certificate_pem,
    receiver_key_pem,
    receiver_ssl_context,
    receiver_tls_files,
    resource_path,
    test_ca_path,
    test_ca_pem,
    trusting_ssl_context,
)
from .run import LogEntry, ReceivedSet, Run, Runner
from .scenario import (
    DEFAULT_IDLE_TIMEOUT,
    PAUSING_IDLE_TIMEOUT,
    SCENARIOS,
    ModuleExpectation,
    RunStatus,
    Scenario,
    expectation_for_module,
    scenario_for_module,
    scenario_from_alias,
)
from .settings import (
    DEFAULT_RECEIVER_PORT,
    DEFAULT_SUITE_IMAGE,
    DEFAULT_SUITE_MONGODB_IMAGE,
    DEFAULT_SUITE_NGINX_IMAGE,
    DEFAULT_SUITE_PORT,
    Settings,
    settings_from_environment,
)
from .suite import SYSTEM_UNDER_TEST_HOST, Suite, close_shared_suite, shared_suite

__all__ = [
    "CAEP_INTEROP_10_POLL",
    "CAEP_INTEROP_10_PUSH",
    "DEFAULT_IDLE_TIMEOUT",
    "DEFAULT_RECEIVER_PORT",
    "DEFAULT_SUITE_IMAGE",
    "DEFAULT_SUITE_MONGODB_IMAGE",
    "DEFAULT_SUITE_NGINX_IMAGE",
    "DEFAULT_SUITE_PORT",
    "MODULE_TIMEOUT",
    "PAUSING_IDLE_TIMEOUT",
    "PLANS",
    "SCENARIOS",
    "SSF10_POLL",
    "SSF10_PUSH",
    "SYSTEM_UNDER_TEST_HOST",
    "TERMINAL_STATES",
    "USAGE",
    "USER_AGENT",
    "WAITING",
    "ApiClient",
    "AsgiApp",
    "AuthMode",
    "AuthSettings",
    "LogEntry",
    "Module",
    "ModuleExpectation",
    "ModuleResult",
    "ModuleRunView",
    "Plan",
    "PlanDefinition",
    "PlanModule",
    "ReceivedSet",
    "ReceiverSettings",
    "Run",
    "RunStatus",
    "RunView",
    "Runner",
    "Scenario",
    "Settings",
    "Suite",
    "SuiteApiError",
    "SuiteModules",
    "TestInstance",
    "close_shared_suite",
    "cts_app",
    "default_receiver_settings",
    "expectation_for_module",
    "new_http_client",
    "parse_test_instance",
    "receiver_certificate_pem",
    "receiver_key_pem",
    "receiver_log",
    "receiver_ssl_context",
    "receiver_tls_files",
    "resource_path",
    "run_plan",
    "scenario_for_module",
    "scenario_from_alias",
    "settings_from_environment",
    "shared_suite",
    "suite_config",
    "test_ca_path",
    "test_ca_pem",
    "trusting_ssl_context",
]
