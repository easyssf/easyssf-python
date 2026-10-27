"""ConformanceSuiteModulesTests of the Java library, conformance/modules_test.go of the Go port:
the module lookup against an emulated suite API, the scenarios and expectations, the plans."""

from __future__ import annotations

import json
from dataclasses import replace

import httpx
import pytest

from easyssf.conformance import (
    DEFAULT_IDLE_TIMEOUT,
    PAUSING_IDLE_TIMEOUT,
    PLANS,
    RunStatus,
    Scenario,
    SuiteApiError,
    SuiteModules,
    TestInstance,
    default_receiver_settings,
    expectation_for_module,
    parse_test_instance,
    receiver_ssl_context,
    receiver_tls_files,
    scenario_for_module,
    scenario_from_alias,
    settings_from_environment,
    suite_config,
    trusting_ssl_context,
)
from easyssf.conformance import test_ca_path as ca_path
from easyssf.core import DeliveryMethod

SUITE = "https://suite.example/"
ALIAS = "easyssf-receiver-ssf1_0-caepiop1_0-push"
ISSUER = SUITE + "test/a/" + ALIAS


def info(test_name: str, alias: str, status: str, delivery_mode: str) -> str:
    return json.dumps(
        {"testName": test_name, "alias": alias, "status": status, "variant": {"ssf_delivery_mode": delivery_mode}}
    )


def suite(responses: dict[str, str] | None = None) -> SuiteModules:
    """A suite API that answers the given paths (relative to the suite) with the given bodies and
    everything else with 404."""
    answers = responses or {}

    def handle(request: httpx.Request) -> httpx.Response:
        body = answers.get(request.url.path.lstrip("/"))
        if body is None:
            return httpx.Response(404, text="not found: " + request.url.path)
        return httpx.Response(200, content=body.encode(), headers={"Content-Type": "application/json"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
    return SuiteModules(replace(default_receiver_settings(), issuer=ISSUER), client)


def test_parses_the_test_instance_of_the_issuer():
    instance = parse_test_instance(
        "https://localhost.emobix.co.uk:8443/test/a/easyssf-receiver-ssf1_0-caepiop1_0-push/"
    )
    assert instance.suite == "https://localhost.emobix.co.uk:8443/"
    assert instance.alias == "easyssf-receiver-ssf1_0-caepiop1_0-push"
    assert instance.issuer("other") == "https://localhost.emobix.co.uk:8443/test/a/other"
    assert (
        parse_test_instance("https://suite.example.com/suite/test/a/alias").suite == "https://suite.example.com/suite/"
    )
    with pytest.raises(ValueError, match="not a test instance"):
        parse_test_instance("https://suite.example.com/")


def test_uses_the_configured_issuer_by_default():
    modules = suite()
    assert modules.test_instance("").alias == ALIAS
    assert modules.test_instance(SUITE + "test/a/other").alias == "other"
    unconfigured = SuiteModules(default_receiver_settings(), httpx.AsyncClient())
    with pytest.raises(ValueError, match="issuer must be set"):
        unconfigured.test_instance("")


async def test_lists_the_running_modules_with_their_scenario():
    modules = suite(
        {
            "api/runner/running": '["abc","def"]',
            "api/info/abc": info("openid-ssf-receiver-stream-create-delete", ALIAS, "WAITING", "push"),
            "api/info/def": info("openid-ssf-receiver-happypath", "other", "RUNNING", "poll"),
        }
    )
    running = await modules.running(parse_test_instance(ISSUER))
    assert len(running) == 2
    first = running[0]
    assert first.id == "abc"
    assert first.name == "openid-ssf-receiver-stream-create-delete"
    assert first.alias == ALIAS
    assert first.status == "WAITING"
    assert first.is_waiting
    assert first.delivery_method is DeliveryMethod.PUSH
    assert first.issuer == ISSUER
    assert first.scenario == "create-delete"
    assert first.log_url == SUITE + "log-detail.html?log=abc"
    assert first.to_mapping()["logUrl"] == first.log_url
    second = running[1]
    assert second.delivery_method is DeliveryMethod.POLL
    assert second.issuer == SUITE + "test/a/other"
    assert second.scenario == "stream-management"
    assert not second.is_waiting


async def test_prefers_the_waiting_modules_of_the_configured_alias():
    modules = suite(
        {
            "api/runner/running": '["abc","def","ghi"]',
            "api/info/abc": info("openid-ssf-receiver-happypath", "other", "WAITING", "push"),
            "api/info/def": info("openid-ssf-receiver-stream-create-delete", ALIAS, "WAITING", "push"),
            "api/info/ghi": info("openid-ssf-receiver-removed-subject-event", ALIAS, "RUNNING", "push"),
        }
    )
    waiting = await modules.waiting(parse_test_instance(ISSUER))
    assert [module.id for module in waiting] == ["def"]
    # without a module under the configured alias, any waiting module will do
    waiting = await modules.waiting(TestInstance(SUITE, "unused"))
    assert [module.id for module in waiting] == ["abc", "def"]


async def test_reports_an_unreachable_suite():
    modules = suite()
    with pytest.raises(SuiteApiError, match="returned HTTP 404"):
        await modules.running(parse_test_instance(ISSUER))
    unreachable = SuiteModules(
        default_receiver_settings(),
        httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: (_ for _ in ()).throw(httpx.ConnectError("down")))
        ),
    )
    with pytest.raises(SuiteApiError, match="could not be reached"):
        await unreachable.running(parse_test_instance(ISSUER))


def test_scenarios_and_expectations():
    assert scenario_from_alias("CAEP-INTEROP") is Scenario.CAEP_INTEROP
    assert scenario_from_alias("StreamManagement") is Scenario.STREAM_MANAGEMENT
    assert scenario_from_alias("remove-subject") is Scenario.REMOVE_SUBJECT
    with pytest.raises(ValueError, match="unknown scenario"):
        scenario_from_alias("nope")
    assert scenario_for_module("openid-ssf-receiver-stream-status-update") is Scenario.STATUS_UPDATE
    assert scenario_for_module("anything") is Scenario.CAEP_INTEROP
    mismatch = expectation_for_module("openid-ssf-receiver-stream-issuer-mismatch")
    assert mismatch.run_status is RunStatus.REFUSED_STREAM
    assert mismatch.scenario is Scenario.CAEP_INTEROP
    assert mismatch.idle_timeout == DEFAULT_IDLE_TIMEOUT
    expiry = expectation_for_module("openid-ssf-receiver-access-token-expiry")
    assert expiry.run_status is RunStatus.FINISHED
    assert expiry.idle_timeout == PAUSING_IDLE_TIMEOUT
    assert str(Scenario.CAEP_INTEROP) == "caep-interop"


def test_plans_and_resources():
    for plan in PLANS:
        config, alias = plan.config()
        assert config and alias
        assert plan.variant()["ssf_delivery_mode"] == plan.delivery_mode
        assert plan.variant()["ssf_auth_mode"] == "dynamic"
    assert json.loads(suite_config("easyssf-receiver.json"))["alias"]
    certificate, key = receiver_tls_files()
    assert certificate.is_file() and key.is_file() and ca_path().is_file()
    assert receiver_ssl_context() is not None
    assert trusting_ssl_context(ca_path().read_bytes()).check_hostname is False
    assert trusting_ssl_context(None, trust_all=True).check_hostname is False


def test_settings_from_environment(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CTS_SUITE_PORT", "28443")
    monkeypatch.setenv("CTS_RECEIVER_PORT", "nope")
    monkeypatch.setenv("CTS_RECEIVER_PUSH_URL", " https://receiver.example/ssf/push ")
    settings = settings_from_environment()
    assert settings.suite_port == 28443
    assert settings.receiver_port == 9444
    assert settings.receiver_push_url == "https://receiver.example/ssf/push"
    assert settings.suite_image.startswith("registry.gitlab.com/openid/conformance-suite@sha256:")
