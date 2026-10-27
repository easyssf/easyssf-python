from easyssf.core import (
    POLL_URI,
    PUSH_URI,
    DeliveryMethod,
    EventTypes,
    StreamConfiguration,
    StreamStatus,
    StreamStatusValue,
    TransmitterMetadata,
)


def test_delivery_methods_have_uris_and_names():
    assert DeliveryMethod.PUSH.uri == PUSH_URI
    assert DeliveryMethod.POLL.uri == POLL_URI
    assert str(DeliveryMethod.PUSH) == "push"
    assert DeliveryMethod.from_uri(POLL_URI) is DeliveryMethod.POLL
    assert DeliveryMethod.from_uri("urn:other") is None
    assert DeliveryMethod.from_name(" Poll ") is DeliveryMethod.POLL
    assert DeliveryMethod.from_name("sms") is None


def test_push_stream_carries_endpoint_header_and_resolved_events():
    stream = StreamConfiguration.push(
        "https://app.example/ssf/push", "Bearer s3cret", ["CaepSessionRevoked"], "the app"
    )
    assert stream.delivery_method_uri == PUSH_URI
    assert stream.delivery_endpoint_url == "https://app.example/ssf/push"
    assert stream.claims["delivery"]["authorization_header"] == "Bearer s3cret"
    assert stream.events_requested == [EventTypes.CAEP_SESSION_REVOKED]
    assert stream.description == "the app"
    assert stream.stream_id == ""
    assert stream.audience == []


def test_poll_stream_has_no_endpoint_and_no_header():
    stream = StreamConfiguration.poll([EventTypes.RISC_ACCOUNT_DISABLED])
    assert stream.delivery_method_uri == POLL_URI
    assert stream.delivery_endpoint_url == ""
    assert "authorization_header" not in stream.claims["delivery"]
    assert "description" not in stream.claims


def test_stream_configuration_reads_what_the_transmitter_returns():
    stream = StreamConfiguration(
        {
            "stream_id": "s-1",
            "iss": "https://idp.example",
            "aud": "https://app.example",
            "events_supported": ["a", "b"],
            "events_requested": ["a"],
            "events_delivered": ["a", 1],
            "delivery": {"method": POLL_URI, "endpoint_url": "https://idp.example/poll"},
        }
    )
    assert stream.stream_id == "s-1"
    assert stream.issuer == "https://idp.example"
    assert stream.audience == ["https://app.example"]
    assert stream.events_supported == ["a", "b"]
    assert stream.events_delivered == ["a"]
    assert stream.delivery_endpoint_url == "https://idp.example/poll"
    assert StreamConfiguration().claims == {}
    assert StreamStatus("s-1", StreamStatusValue.PAUSED).reason == ""


def test_transmitter_metadata_reads_the_well_known_document():
    metadata = TransmitterMetadata(
        "https://idp.example",
        "https://idp.example/jwks",
        {
            "spec_version": "1_0",
            "delivery_methods_supported": [PUSH_URI],
            "critical_subject_members": ["user"],
            "authorization_schemes": [{"spec_urn": "urn:ietf:rfc:6749"}, "junk"],
            "default_subjects": "ALL",
            "configuration_endpoint": "https://idp.example/ssf/stream",
            "status_endpoint": "https://idp.example/ssf/status",
            "add_subject_endpoint": "https://idp.example/ssf/add",
            "remove_subject_endpoint": "https://idp.example/ssf/remove",
            "verification_endpoint": "https://idp.example/ssf/verify",
        },
    )
    assert metadata.issuer == "https://idp.example"
    assert metadata.jwks_uri == "https://idp.example/jwks"
    assert metadata.spec_version == "1_0"
    assert metadata.supports_delivery_method(DeliveryMethod.PUSH)
    assert not metadata.supports_delivery_method(DeliveryMethod.POLL)
    assert metadata.critical_subject_members == ["user"]
    assert metadata.authorization_schemes == [{"spec_urn": "urn:ietf:rfc:6749"}]
    assert metadata.default_subjects == "ALL"
    assert metadata.configuration_endpoint == "https://idp.example/ssf/stream"
    assert metadata.status_endpoint == "https://idp.example/ssf/status"
    assert metadata.add_subject_endpoint == "https://idp.example/ssf/add"
    assert metadata.remove_subject_endpoint == "https://idp.example/ssf/remove"
    assert metadata.verification_endpoint == "https://idp.example/ssf/verify"


def test_transmitter_metadata_without_statements_supports_everything():
    metadata = TransmitterMetadata("https://idp.example", None)
    assert metadata.jwks_uri is None
    assert metadata.supports_delivery_method(DeliveryMethod.POLL)
    assert metadata.configuration_endpoint == ""
    assert metadata.authorization_schemes == []
    assert TransmitterMetadata("i", "").jwks_uri is None
