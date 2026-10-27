"""ConformanceRunLocalTransmitterTests of the Java library, conformance/run_test.go of the Go port:
runs the scenarios against the test transmitter of the receiver library, in-process and without
Docker, with POLL delivery so that the transmitter does not have to reach this application, and
once with PUSH delivery, the SETs pushed to the app directly."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import timedelta
from typing import Any

import httpx
import pytest

from easyssf.conformance import Runner, SuiteModules, cts_app, default_receiver_settings
from easyssf.core import DeliveryMethod, string_member
from easyssf.core.subjects import iss_sub, opaque
from easyssf.testing import CLIENT_ID, CLIENT_SECRET, TestTransmitter, eventually

pytestmark = pytest.mark.timeout(120)


class LocalReceiver:
    def __init__(self, transmitter: TestTransmitter, runner: Runner, client: httpx.AsyncClient) -> None:
        self.transmitter = transmitter
        self.runner = runner
        self.client = client

    async def request(self, method: str, path: str, **kwargs: Any) -> tuple[int, Any]:
        response = await self.client.request(method, path, **kwargs)
        try:
            return response.status_code, response.json()
        except ValueError:
            return response.status_code, response.text

    async def start(self, scenario: str, delivery: str = "") -> dict[str, Any]:
        query = f"?scenario={scenario}" + (f"&delivery={delivery}" if delivery else "")
        status, run = await self.request("POST", "/cts/runs" + query)
        assert status == 202, run
        return run

    async def current(self) -> dict[str, Any]:
        _, run = await self.request("GET", "/cts/runs/current")
        return run

    async def await_status(self, status: str) -> dict[str, Any]:
        async def has_status() -> bool:
            return (await self.current())["status"] == status

        await eventually(has_status, 20, "run status " + status)
        return await self.current()

    async def await_stream_and_verification_request(self) -> str:
        await eventually(lambda: len(self.transmitter.verification_requests) > 0, 10, "the verification request")
        assert len(self.transmitter.streams) == 1
        return string_member(self.transmitter.streams[0], "stream_id")

    def audience(self) -> Any:
        return self.transmitter.streams[0]["aud"]

    def verification_event(self, stream_id: str, state: str) -> tuple[str, str]:
        claims = self.transmitter.set_claims_with_payload("SsfStreamVerification", opaque(stream_id), {"state": state})
        claims["aud"] = self.audience()
        return claims["jti"], self.transmitter.sign_set(claims)

    def queue_verification_event(self, stream_id: str, state: str) -> str:
        jti, encoded = self.verification_event(stream_id, state)
        self.transmitter.queue_set(encoded)
        return jti

    def session_revoked(self) -> tuple[str, str]:
        claims = self.transmitter.set_claims("CaepSessionRevoked", iss_sub(self.transmitter.issuer, "alice"))
        claims["aud"] = self.audience()
        return claims["jti"], self.transmitter.sign_set(claims)

    def queue_session_revoked(self) -> str:
        jti, encoded = self.session_revoked()
        self.transmitter.queue_set(encoded)
        return jti

    def acknowledged(self, jti: str) -> bool:
        return jti in self.transmitter.acknowledged_sets

    def reported(self, jti: str) -> bool:
        return any(report.jti == jti for report in self.transmitter.reported_errors)


@pytest.fixture
async def receiver() -> AsyncIterator[LocalReceiver]:
    transmitter = TestTransmitter()
    settings = default_receiver_settings()
    settings = replace(
        settings,
        issuer=transmitter.issuer,
        delivery=DeliveryMethod.POLL,
        poll_interval=timedelta(milliseconds=200),
        idle_timeout=timedelta(seconds=2),
        verification_timeout=timedelta(seconds=5),
        auth=replace(settings.auth, client_id=CLIENT_ID, client_secret=CLIENT_SECRET),
    )
    runner = Runner(settings, transmitter.client)
    app = cts_app(runner, SuiteModules(settings, transmitter.client))
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://cts.example")
    yield LocalReceiver(transmitter, runner, client)
    if runner.current is not None:
        await runner.current.stop()
    await client.aclose()


def log_messages(run: dict[str, Any]) -> list[str]:
    return [entry["message"] for entry in run["log"]]


def contains_entry(messages: list[str], *parts: str) -> bool:
    return any(all(part in message for part in parts) for message in messages)


async def test_plays_the_caep_interop_scenario(receiver: LocalReceiver):
    run = await receiver.start("caep-interop")
    assert run["status"] in ("STARTING", "RUNNING")
    stream_id = await receiver.await_stream_and_verification_request()
    verification = receiver.queue_verification_event(stream_id, receiver.transmitter.verification_requests[0])
    await eventually(lambda: receiver.acknowledged(verification), 5, "the verification acknowledged")
    session_revoked = receiver.queue_session_revoked()
    await eventually(lambda: receiver.acknowledged(session_revoked), 5, "the event acknowledged")
    finished = await receiver.await_status("FINISHED")
    assert receiver.transmitter.streams == [], "stream deleted"
    assert receiver.transmitter.reported_errors == [], "nothing reported"
    messages = log_messages(finished)
    assert contains_entry(messages, "Read stream status")
    assert contains_entry(messages, "Verification event", "accepted")
    assert contains_entry(messages, "Deleted stream " + stream_id)
    assert finished["streamId"] == stream_id
    assert [received["outcome"] for received in finished["receivedSets"]] == ["accepted", "accepted"]
    assert finished["receivedSets"][1]["events"] == ["CaepSessionRevoked"]


async def test_rejects_verification_event_with_wrong_state_and_requests_verification_again(receiver: LocalReceiver):
    await receiver.start("caep-interop")
    stream_id = await receiver.await_stream_and_verification_request()
    wrong = receiver.queue_verification_event(stream_id, "made-up")
    await eventually(lambda: receiver.reported(wrong), 5, "the wrong state reported")
    for report in receiver.transmitter.reported_errors:
        if report.jti == wrong:
            assert report.code == "invalid_state", report
    await eventually(lambda: len(receiver.transmitter.verification_requests) == 2, 5, "a second verification request")
    right = receiver.queue_verification_event(stream_id, receiver.transmitter.verification_requests[1])
    await eventually(lambda: receiver.acknowledged(right), 5, "the right one acknowledged")
    finished = await receiver.await_status("FINISHED")
    assert receiver.transmitter.streams == []
    assert contains_entry(log_messages(finished), "Rejected a verification event, requesting the verification again")


async def test_rejects_verification_event_about_another_stream(receiver: LocalReceiver):
    await receiver.start("caep-interop")
    stream_id = await receiver.await_stream_and_verification_request()
    wrong = receiver.queue_verification_event("another-stream", receiver.transmitter.verification_requests[0])
    await eventually(lambda: receiver.reported(wrong), 5, "the wrong stream reported")
    assert [report.code for report in receiver.transmitter.reported_errors if report.jti == wrong] == [
        "invalid_request"
    ]
    await eventually(lambda: len(receiver.transmitter.verification_requests) == 2, 5, "a second verification request")
    right = receiver.queue_verification_event(stream_id, receiver.transmitter.verification_requests[1])
    await eventually(lambda: receiver.acknowledged(right), 5, "the right one acknowledged")
    await receiver.await_status("FINISHED")


async def test_refuses_stream_with_another_issuer(receiver: LocalReceiver):
    receiver.transmitter.set_stream_issuer("https://other.example")
    await receiver.start("caep-interop")
    run = await receiver.await_status("REFUSED_STREAM")
    assert receiver.transmitter.streams == []
    assert receiver.transmitter.verification_requests == []
    assert contains_entry(log_messages(run), "Refusing the stream")


async def test_creates_and_deletes_the_stream(receiver: LocalReceiver):
    await receiver.start("create-delete")
    run = await receiver.await_status("FINISHED")
    assert receiver.transmitter.streams == []
    assert receiver.transmitter.verification_requests == []
    assert contains_entry(log_messages(run), "Created stream")
    assert contains_entry(log_messages(run), "Deleted stream")


@pytest.mark.parametrize(
    ("scenario", "entry"),
    [
        ("stream-management", "Replaced stream"),
        ("status-update", "Enabling the stream"),
        ("remove-subject", "Removed subject"),
    ],
)
async def test_manages_stream_and_status_and_subjects(receiver: LocalReceiver, scenario: str, entry: str):
    await receiver.start(scenario)
    stream_id = await receiver.await_stream_and_verification_request()
    receiver.queue_verification_event(stream_id, receiver.transmitter.verification_requests[0])
    run = await receiver.await_status("FINISHED")
    assert receiver.transmitter.streams == [], scenario
    assert contains_entry(log_messages(run), entry), log_messages(run)
    if scenario == "remove-subject":
        assert receiver.transmitter.removed_subjects == [{"format": "email", "email": "foo@example.com"}]


async def test_accepts_pushed_sets_of_the_current_run_only(receiver: LocalReceiver):
    await receiver.start("caep-interop", delivery="push")
    stream_id = await receiver.await_stream_and_verification_request()
    run = receiver.runner.current
    assert run is not None and run.delivery is DeliveryMethod.PUSH
    stream = receiver.transmitter.streams[0]
    assert stream["delivery"]["endpoint_url"] == "https://localhost:9443/ssf/push"
    _, wrong = receiver.verification_event(stream_id, "made-up")
    headers = {"Content-Type": "application/secevent+jwt"}
    status, body = await receiver.request("POST", "/ssf/push", content=wrong, headers=headers)
    assert status == 401 and body["err"] == "authentication_failed", "the run expects its own header"
    headers["Authorization"] = run.push_authorization_header
    status, body = await receiver.request("POST", "/ssf/push", content=wrong, headers=headers)
    assert status == 400 and body["err"] == "invalid_state", body
    await eventually(lambda: len(receiver.transmitter.verification_requests) == 2, 5, "a second verification request")
    _, verification = receiver.verification_event(stream_id, receiver.transmitter.verification_requests[1])
    status, body = await receiver.request("POST", "/ssf/push", content=verification, headers=headers)
    assert status == 202, body
    jti, session_revoked = receiver.session_revoked()
    status, _ = await receiver.request("POST", "/ssf/push", content=session_revoked, headers=headers)
    assert status == 202
    status, _ = await receiver.request("POST", "/ssf/push", content=session_revoked, headers=headers)
    assert status == 202, "a redelivery is a duplicate, acknowledged again"
    finished = await receiver.await_status("FINISHED")
    assert receiver.transmitter.streams == []
    outcomes = {received["jti"]: received["outcome"] for received in finished["receivedSets"]}
    assert outcomes[jti] == "accepted"
    assert any(outcome.startswith("rejected with invalid_state") for outcome in outcomes.values())
    status, body = await receiver.request("POST", "/ssf/push", content=session_revoked, headers=headers)
    assert status == 503, "no run is active any more"


async def test_push_endpoint_answers_without_run(receiver: LocalReceiver):
    status, body = await receiver.request(
        "POST", "/ssf/push", content="x", headers={"Content-Type": "application/secevent+jwt"}
    )
    assert status == 503
    assert body == {"err": "invalid_request", "description": "No conformance run is active"}
    status, usage = await receiver.request("GET", "/")
    assert status == 200 and "POST /cts/runs/auto" in usage
    status, _ = await receiver.request("POST", "/cts/runs?scenario=nope")
    assert status == 400, "unknown scenario"
    status, _ = await receiver.request("POST", "/cts/runs?delivery=carrier-pigeon")
    assert status == 400, "unknown delivery"
    status, _ = await receiver.request("POST", "/cts/runs/auto")
    assert status == 400, "the test transmitter is not a test instance of the suite"
    status, _ = await receiver.request("GET", "/cts/runs/current")
    assert status == 404, "no run yet"
    status, _ = await receiver.request("POST", "/cts/runs/current/stop")
    assert status == 404, "no run yet"
    status, _ = await receiver.request("GET", "/cts/runs")
    assert status == 405
    status, _ = await receiver.request("GET", "/nope")
    assert status == 404


async def test_stops_the_current_run_when_another_starts_or_on_request(receiver: LocalReceiver):
    first = await receiver.start("caep-interop")
    await receiver.await_stream_and_verification_request()
    second = await receiver.start("caep-interop")
    assert second["id"] != first["id"]
    await eventually(lambda: len(receiver.transmitter.verification_requests) == 2, 10, "the second run's verification")
    assert len(receiver.transmitter.streams) == 1, "the first stream was deleted, the second created"
    assert receiver.transmitter.streams[0]["description"] == "easyssf conformance run " + second["id"]
    started = time.monotonic()
    status, stopped = await receiver.request("POST", "/cts/runs/current/stop")
    assert status == 200 and stopped["status"] == "STOPPED"
    assert time.monotonic() - started < 5
    assert receiver.transmitter.streams == []
    assert contains_entry(log_messages(stopped), "Run stopped")
