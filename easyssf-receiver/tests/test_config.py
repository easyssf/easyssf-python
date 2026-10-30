import json
from datetime import timedelta

import pytest

from easyssf.core import DeliveryMethod, SubjectCompatibilityMode, event_types
from easyssf.receiver.config import (
    CONFIGURATION_SECTION,
    DEFAULT_SCIM_ATTRIBUTE_CLAIMS,
    STREAM_MANAGEMENT_RECEIVER,
    ReceiverConfig,
    TransmitterConfig,
    default_receiver_config,
    default_transmitter_config,
    format_data_size,
    format_duration,
    parse_data_size,
    parse_duration,
    valid_table_prefix,
)
from easyssf.receiver.errors import ConfigurationError


def test_config_binds_from_json_with_defaults_and_kebab_case_keys():
    config = ReceiverConfig.from_mapping(
        json.loads("""{
        "transmitter-issuer": "https://idp.example/realms/demo",
        "delivery-method": "poll",
        "event-aliases": {"AcmeLoginCfg": "https://events.acme.example/login"},
        "oauth2": {"token-uri": "https://idp.example/token", "client-id": "app", "client-secret": "secret", "scopes": ["ssf.read"], "client-authentication-method": "post"},
        "stream": {"management": "receiver", "events-requested": ["CaepSessionRevoked"]},
        "poll": {"interval": "10s", "long-polling": true, "rate-limit": {"fallback-backoff": "2m"}},
        "set-validation": {"accepted-algorithms": ["RS256", "PS256"], "subject-compatibility": "legacy"},
        "dedup": {"lease": "90s"},
        "http": {"max-response-size": "1MB"},
        "revocation": {"ttl": "48h"},
        "session-termination": {"scim-attribute-claims": {"userName": "sub"}},
        "data": {"initialize-schema": "always", "table-prefix": "app.ssf_"},
        "transmitters": {"okta": {"transmitter-issuer": "https://okta.example", "expected-audience": "app"}}
    }""")
    )
    assert config.delivery is DeliveryMethod.POLL
    assert config.oauth2.scopes == ["ssf.read"]
    assert config.oauth2.authenticates_with_request_body is True
    assert config.stream.management == STREAM_MANAGEMENT_RECEIVER
    assert config.stream.events_requested == ["CaepSessionRevoked"]
    assert config.poll.interval == timedelta(seconds=10)
    assert config.poll.long_polling is True
    assert config.poll.long_polling_hold == timedelta(seconds=30)
    assert config.poll.rate_limit.fallback_backoff == timedelta(minutes=2)
    assert config.effective_accepted_algorithms == ["RS256", "PS256"]
    assert config.dedup.lease == timedelta(seconds=90)
    assert config.dedup.enabled is True
    assert config.http.max_response_size == 1 << 20
    assert config.revocation.ttl == timedelta(hours=48)
    assert config.push.endpoint_path == "/ssf/push"
    assert config.transmitters["okta"].transmitter_issuer == "https://okta.example"
    assert config.transmitters["okta"].expected_audience == "app"
    assert config.transmitters["okta"].delivery is DeliveryMethod.PUSH
    assert len(config.all_transmitters()) == 2
    assert config.session_termination.effective_scim_attribute_claims == [("userName", "sub")]
    assert config.data.table_prefix == "app.ssf_"
    assert config.data.schema_initialization == "always"
    assert config.subject_compatibility is SubjectCompatibilityMode.LEGACY
    assert config.binding_failures == []
    config.validate()
    assert event_types.resolve("AcmeLoginCfg") == "AcmeLoginCfg", "validate registers nothing"
    assert not event_types.is_alias("AcmeLoginCfg")
    assert config.transmitter_names() == ["default", "okta"]
    assert config.all_transmitters()["default"].transmitter_issuer == "https://idp.example/realms/demo"


def test_validation_reports_every_failure():
    config = default_receiver_config()
    config.transmitter_issuer = "http://idp.example"
    config.push.endpoint_path = "ssf"
    config.dedup.capacity = 0
    config.oauth2.token_uri = "https://idp.example/token"
    config.set_validation.accepted_algorithms = ["HS256"]
    config.data.table_prefix = "bad prefix"
    config.data.initialize_schema = "sometimes"
    config.http.max_response_size = 0  # type: ignore[assignment]
    with pytest.raises(ConfigurationError) as raised:
        config.validate()
    message = str(raised.value)
    for expected in [
        "transmitter-issuer",
        "https",
        "expected-audience",
        "oauth2.client-id",
        "accepted-algorithms",
        "push.endpoint-path",
        "dedup",
        "data.table-prefix",
        "data.initialize-schema",
        "http.max-response-size",
    ]:
        assert expected in message, f"missing {expected!r} in {message}"
    assert len(raised.value.failures) == 9
    assert all(failure.startswith(CONFIGURATION_SECTION + ".") for failure in raised.value.failures)
    # poll without an endpoint
    poll = default_receiver_config()
    poll.transmitter_issuer = "https://idp.example"
    poll.delivery_method = "poll"
    poll.expected_audience = "a"
    with pytest.raises(ConfigurationError, match=r"poll\.endpoint-url"):
        poll.validate()
    # a managed push stream needs the delivery endpoint
    managed = default_receiver_config()
    managed.transmitter_issuer = "https://idp.example"
    managed.stream.management = STREAM_MANAGEMENT_RECEIVER
    with pytest.raises(ConfigurationError, match=r"push\.delivery-endpoint-url"):
        managed.validate()


def test_failed_validation_registers_no_alias_so_a_later_configuration_may_map_it_differently():
    invalid = default_receiver_config()
    invalid.transmitter_issuer = "https://idp.example"
    invalid.expected_audience = "app"
    invalid.event_aliases = {"PurityTestAlias": "urn:acme:a"}
    invalid.push.endpoint_path = "no-slash"
    with pytest.raises(ConfigurationError):
        invalid.validate()
    assert event_types.resolve("PurityTestAlias") == "PurityTestAlias", "a failed validation registered the alias"
    later = default_receiver_config()
    later.transmitter_issuer = "https://idp.example"
    later.expected_audience = "app"
    later.event_aliases = {"PurityTestAlias": "urn:acme:b"}
    later.validate()
    assert not event_types.is_alias("PurityTestAlias"), "a passed validation registered the alias"
    event_types.register_alias("PurityTestAlias", "urn:acme:b")
    conflicting = default_receiver_config()
    conflicting.transmitter_issuer = "https://idp.example"
    conflicting.expected_audience = "app"
    conflicting.event_aliases = {"PurityTestAlias": "urn:acme:c"}
    with pytest.raises(ConfigurationError, match=r"event-aliases\.PurityTestAlias"):
        conflicting.validate()


def test_validates_the_transmitters_under_their_own_prefix():
    config = default_receiver_config()
    config.transmitter_issuer = "https://idp.example"
    config.expected_audience = "app"
    config.transmitters = {
        "okta": TransmitterConfig(transmitter_issuer="https://idp.example", expected_audience="app"),
        "default": TransmitterConfig(transmitter_issuer="https://idp.example", expected_audience="app"),
        "": TransmitterConfig(transmitter_issuer="https://blank.example", delivery_method="fax"),
        "weird": TransmitterConfig(
            transmitter_issuer="https://weird.example?x=1",
            transmitter_jwks_url="http://keys.example/jwks",
            transmitter_metadata_url="https://meta.example/#fragment",
            expected_audience="app",
            oauth2=default_transmitter_config().oauth2,
        ),
    }
    config.transmitters["weird"].oauth2.client_authentication_method = "mtls"
    config.transmitters["weird"].set_validation.subject_compatibility = "loose"
    config.transmitters["weird"].poll.endpoint_url = "not-a-url"
    with pytest.raises(ConfigurationError) as raised:
        config.validate()
    failures = raised.value.failures
    assert any("transmitters.default: The transmitter named 'default'" in failure for failure in failures)
    assert any("transmitters: A transmitter under" in failure for failure in failures)
    assert any(
        "The transmitters 'okta' and 'default' have the same issuer https://idp.example" in failure
        for failure in failures
    )
    assert any(
        failure.startswith(f"{CONFIGURATION_SECTION}.transmitters..delivery-method: must be push or poll")
        for failure in failures
    )
    assert any(
        failure
        == f"{CONFIGURATION_SECTION}.transmitters.weird.transmitter-issuer: transmitter issuer must not have a query or fragment: https://weird.example?x=1"
        for failure in failures
    )
    assert any(
        failure.startswith(
            f"{CONFIGURATION_SECTION}.transmitters.weird.transmitter-jwks-url: the JWK Set URL must use https"
        )
        for failure in failures
    )
    assert any(
        failure.startswith(
            f"{CONFIGURATION_SECTION}.transmitters.weird.transmitter-metadata-url: transmitter metadata URL must not have a fragment"
        )
        for failure in failures
    )
    assert any("transmitters.weird.oauth2.client-authentication-method" in failure for failure in failures)
    assert any("transmitters.weird.set-validation.subject-compatibility" in failure for failure in failures)
    assert any(
        failure.startswith(
            f"{CONFIGURATION_SECTION}.transmitters.weird.poll.endpoint-url: the poll endpoint must be an absolute URI with a host: not-a-url"
        )
        for failure in failures
    )
    # insecure http is accepted on loopback and with allow-insecure-http
    loopback = TransmitterConfig(transmitter_issuer="http://localhost:8080/realms/test", expected_audience="app")
    assert loopback.validate("x") == []
    insecure = TransmitterConfig(transmitter_issuer="http://idp.example", expected_audience="app")
    assert insecure.validate("x") == [
        f"{CONFIGURATION_SECTION}.transmitters.x.transmitter-issuer: transmitter issuer must use https: http://idp.example"
    ]
    insecure.allow_insecure_http = True
    assert insecure.validate("x") == []
    assert TransmitterConfig().validate() == [
        f"{CONFIGURATION_SECTION}.transmitter-issuer: The issuer of the SSF transmitter must be configured"
    ]


def test_validation_of_the_receiver_sections():
    config = default_receiver_config()
    config.enabled = False
    config.validate()
    config.enabled = True
    with pytest.raises(
        ConfigurationError,
        match="transmitter-issuer: The issuer of the SSF transmitter must be configured, or transmitters under",
    ):
        config.validate()
    config.transmitter_issuer = "https://idp.example"
    config.set_validation.allow_any_audience = True
    config.http.timeout = timedelta(0)
    config.http.retry.max_retries = -1
    config.revocation.ttl = timedelta(0)
    config.data.ack_delete_batch_size = 0
    config.dedup.enabled = False
    config.dedup.capacity = 0
    with pytest.raises(ConfigurationError) as raised:
        config.validate()
    assert raised.value.failures == [
        f"{CONFIGURATION_SECTION}.http.timeout: must be positive",
        f"{CONFIGURATION_SECTION}.http.retry: max-retries, initial-backoff and max-backoff must not be negative",
        f"{CONFIGURATION_SECTION}.revocation.ttl: must be positive",
        f"{CONFIGURATION_SECTION}.data: ack-retention and ack-delete-batch-size must be positive",
    ]
    poll = default_receiver_config()
    poll.transmitter_issuer = "https://idp.example"
    poll.delivery_method = "poll"
    poll.stream.id = "given"
    poll.poll.long_polling = True
    poll.poll.long_polling_hold = timedelta(0)
    with pytest.raises(
        ConfigurationError, match=r"poll: interval, long-polling-hold and rate-limit\.max-backoff must be positive"
    ):
        poll.validate()
    assert poll.registers_stream
    poll.poll.long_polling = False
    poll.validate()


def test_defaults_are_the_ones_of_the_java_starter():
    config = default_receiver_config()
    assert config.enabled is True
    assert config.delivery_method == "push"
    assert config.delivery is DeliveryMethod.PUSH
    assert config.oauth2.client_authentication_method == "client_secret_basic"
    assert config.oauth2.authenticates_with_request_body is False
    assert config.oauth2.expiry_safety_window == timedelta(seconds=30)
    assert config.stream.management == "none"
    assert config.poll.auto_startup is True
    assert config.poll.interval == timedelta(seconds=10)
    assert config.poll.max_events == 100
    assert config.poll.long_polling_hold == timedelta(seconds=30)
    assert config.poll.rate_limit.max_backoff == timedelta(minutes=5)
    assert config.set_validation.min_rsa_key_size == 2048
    assert config.set_validation.require_type_header is True
    assert config.set_validation.clock_skew == timedelta(minutes=1)
    assert config.subject_compatibility is SubjectCompatibilityMode.STRICT
    assert config.effective_accepted_algorithms == ["RS256"]
    assert config.push.endpoint_path == "/ssf/push"
    assert config.http.timeout == timedelta(seconds=5)
    assert config.http.retry.max_retries == 2
    assert config.http.retry.initial_backoff == timedelta(milliseconds=250)
    assert config.http.retry.max_backoff == timedelta(seconds=5)
    assert config.dedup.capacity == 10_000
    assert config.dedup.retention == timedelta(days=7)
    assert config.dedup.lease == timedelta(seconds=60)
    assert config.revocation.ttl == timedelta(hours=24)
    assert config.session_termination.enabled is True
    assert config.session_termination.effective_scim_attribute_claims == list(DEFAULT_SCIM_ATTRIBUTE_CLAIMS)
    assert config.data.initialize_schema == "embedded"
    assert config.data.schema_initialization == "embedded"
    assert config.data.table_prefix == "EASYSSF_"
    assert config.data.cleanup_interval == timedelta(minutes=15)
    assert config.data.ack_retention == timedelta(days=7)
    assert config.data.ack_delete_batch_size == 100
    assert default_transmitter_config() == TransmitterConfig()
    assert config.all_transmitters() == {}
    assert config.transmitter_names() == []
    assert not config.registers_stream
    # two defaults do not share their sections
    assert default_receiver_config().oauth2 is not default_receiver_config().oauth2


def test_secrets_are_redacted_in_repr():
    config = default_receiver_config()
    config.oauth2.client_secret = "the-client-secret"
    config.transmitter_access_token = "the-access-token"
    config.push.expected_auth_header = "Bearer the-push-secret"
    config.headers = {"X-Api-Key": "the-api-key"}
    text = repr(config)
    assert "the-client-secret" not in text
    assert "the-access-token" not in text
    assert "the-push-secret" not in text
    assert "the-api-key" not in text
    assert "client_id" in text


def test_from_mapping_accepts_snake_case_keys_and_several_transmitters():
    config = ReceiverConfig.from_mapping(
        {
            "transmitter_issuer": "https://idp.example",
            "expected_audience": "app",
            "allow_insecure_http": True,
            "transmitter_access_token": "token",
            "headers": {"X-Tenant": "acme"},
            "understood_subject_members": ["user", "device"],
            "http": {"timeout": 15, "user_agent": "app/1", "retry": {"max_retries": 0, "initial_backoff": "100ms"}},
            "poll": {"initial_delay": "1.5s", "max_events": 5},
            "transmitters": {
                "okta": {"transmitter_issuer": "https://okta.example", "expected_audience": "app"},
                "entra": {
                    "transmitter-issuer": "https://entra.example",
                    "delivery-method": "poll",
                    "poll": {"endpoint-url": "https://entra.example/poll", "long_polling": True},
                    "set_validation": {"allow-any-audience": True},
                },
            },
            "unknown-key": {"ignored": True},
            "data": {"enabled": False, "unknown": 1},
        },
        strict=False,  # the unknown keys are ignored, as the Go binding does
    )
    assert config.transmitter_issuer == "https://idp.example"
    assert config.allow_insecure_http is True
    assert config.transmitter_access_token == "token"
    assert config.headers == {"X-Tenant": "acme"}
    assert config.understood_subject_members == ["user", "device"]
    assert config.http.timeout == timedelta(seconds=15)
    assert config.http.user_agent == "app/1"
    assert config.http.retry.max_retries == 0
    assert config.http.retry.initial_backoff == timedelta(milliseconds=100)
    assert config.http.retry.max_backoff == timedelta(seconds=5)
    assert config.poll.initial_delay == timedelta(seconds=1.5)
    assert config.poll.max_events == 5
    assert config.data.enabled is False
    assert config.transmitter_names() == ["default", "entra", "okta"]
    entra = config.transmitters["entra"]
    assert entra.delivery is DeliveryMethod.POLL
    assert entra.poll.endpoint_url == "https://entra.example/poll"
    assert entra.poll.long_polling is True
    assert entra.poll.long_polling_hold == timedelta(seconds=30)
    assert entra.set_validation.allow_any_audience is True
    assert entra.allow_insecure_http is False
    assert config.transmitters["okta"].transmitter_issuer == "https://okta.example"
    config.validate()
    assert config.all_transmitters()["default"].headers is config.headers
    assert isinstance(config.all_transmitters()["default"], TransmitterConfig)
    assert ReceiverConfig.from_mapping({}) == default_receiver_config()


def test_from_mapping_reports_values_of_the_wrong_type_through_validate():
    config = ReceiverConfig.from_mapping(
        {
            "transmitter-issuer": "https://idp.example",
            "expected-audience": "app",
            "enabled": "yes",
            "oauth2": {"scopes": "ssf.read", "client-id": 7, "expiry-safety-window": "soon"},
            "poll": {"max-events": "many", "interval": True, "rate-limit": "none"},
            "event-aliases": {"A": 1},
            "transmitters": {
                "okta": "https://okta.example",
                "entra": {"transmitter-issuer": "https://entra.example", "expected-audience": "app", "stream": ["x"]},
            },
            "http": {"timeout": None},
        }
    )
    # the defaults are kept where the value did not fit
    assert config.enabled is True
    assert config.oauth2.scopes == []
    assert config.oauth2.client_id == ""
    assert config.poll.max_events == 100
    assert config.poll.interval == timedelta(seconds=10)
    assert config.http.timeout == timedelta(seconds=5)
    assert config.transmitters["entra"].transmitter_issuer == "https://entra.example"
    assert "okta" not in config.transmitters
    with pytest.raises(ConfigurationError) as raised:
        config.validate()
    assert raised.value.failures == [
        f"{CONFIGURATION_SECTION}.oauth2.client-id: must be a string (value: 7)",
        f"{CONFIGURATION_SECTION}.oauth2.scopes: must be a list of strings (value: 'ssf.read')",
        f'{CONFIGURATION_SECTION}.oauth2.expiry-safety-window: must be a duration such as "30s", "24h" or a number of seconds (value: \'soon\')',
        f'{CONFIGURATION_SECTION}.poll.interval: must be a duration such as "30s", "24h" or a number of seconds (value: True)',
        f"{CONFIGURATION_SECTION}.poll.max-events: must be an integer (value: 'many')",
        f"{CONFIGURATION_SECTION}.poll.rate-limit: must be a mapping (value: 'none')",
        f"{CONFIGURATION_SECTION}.enabled: must be true or false (value: 'yes')",
        f"{CONFIGURATION_SECTION}.event-aliases: must be a mapping of strings (value: {{'A': 1}})",
        f"{CONFIGURATION_SECTION}.transmitters.okta: must be a mapping (value: 'https://okta.example')",
        f"{CONFIGURATION_SECTION}.transmitters.entra.stream: must be a mapping (value: ['x'])",
    ]
    # binding failures are reported even when the receiver is disabled
    disabled = ReceiverConfig.from_mapping({"enabled": False, "dedup": {"capacity": "lots"}})
    with pytest.raises(ConfigurationError, match=r"dedup\.capacity: must be an integer"):
        disabled.validate()


def test_from_mapping_reports_unknown_keys_with_the_key_they_resemble():
    # a typo would otherwise leave the push endpoint without the header it expects, silently
    config = ReceiverConfig.from_mapping(
        {
            "transmitter-issuer": "https://idp.example",
            "expected-audience": "app",
            "push": {"expected-auth-headers": "Bearer s3cr3t", "endpoint_path": "/ssf/push"},
            "polling": {"interval": "10s"},
            "transmitters": {"okta": {"transmitter-issuer": "https://okta.example", "exepcted-audience": "app"}},
            "http": {"retry": {"max-retries": 1, "jitter": "none"}},
            "easyssf": {"receiver": {}},
        }
    )
    assert config.push.expected_auth_header == "", "the misspelled key bound nothing"
    with pytest.raises(ConfigurationError) as raised:
        config.validate()
    assert raised.value.failures[:5] == [
        f"{CONFIGURATION_SECTION}.polling: unknown setting, did you mean 'poll'?",
        f"{CONFIGURATION_SECTION}.easyssf: unknown setting",
        f"{CONFIGURATION_SECTION}.push.expected-auth-headers: unknown setting, did you mean 'expected-auth-header'?",
        f"{CONFIGURATION_SECTION}.transmitters.okta.exepcted-audience: unknown setting, did you mean 'expected-audience'?",
        f"{CONFIGURATION_SECTION}.http.retry.jitter: unknown setting",
    ]
    # and the consequence of the typo, which strict binding is there to explain
    assert raised.value.failures[5].startswith(f"{CONFIGURATION_SECTION}.transmitters.okta.expected-audience: ")
    assert len(raised.value.failures) == 6
    # strict=False ignores them, as the Spring Boot, .NET and Go bindings do
    lenient = ReceiverConfig.from_mapping(
        {"transmitter-issuer": "https://idp.example", "expected-audience": "app", "polling": {}}, strict=False
    )
    assert lenient.validate() == []
    # the internal field is no setting
    assert ReceiverConfig.from_mapping({"binding-failures": ["x"]}).binding_failures == [
        f"{CONFIGURATION_SECTION}.binding-failures: unknown setting"
    ]


def test_to_mapping_round_trips_through_from_mapping():
    config = ReceiverConfig.from_mapping(
        {
            "transmitter-issuer": "https://idp.example/realms/demo",
            "delivery-method": "poll",
            "event-aliases": {"AcmeLoginRt": "https://events.acme.example/login"},
            "oauth2": {
                "token-uri": "https://idp.example/token",
                "client-id": "app",
                "client-secret": "secret",
                "scopes": ["ssf.read"],
            },
            "stream": {
                "management": "receiver",
                "events-requested": ["CaepSessionRevoked"],
                "delete-on-shutdown": True,
            },
            "poll": {"interval": "1h30m", "long-polling": True, "rate-limit": {"fallback-backoff": "2m"}},
            "http": {"retry": {"initial-backoff": "250ms"}},
            "set-validation": {
                "accepted-algorithms": ["RS256", "PS256"],
                "subject-compatibility": "legacy",
                "clock-skew": 90,
            },
            "dedup": {"lease": "90s"},
            "session-termination": {"scim-attribute-claims": {"userName": "sub"}},
            "transmitters": {
                "okta": {
                    "transmitter-issuer": "https://okta.example",
                    "expected-audience": "app",
                    "headers": {"X-Api-Key": "k"},
                }
            },
        }
    )
    mapping = config.to_mapping()
    assert mapping["transmitter-issuer"] == "https://idp.example/realms/demo"
    assert mapping["poll"]["interval"] == "1h30m0s"
    assert mapping["poll"]["rate-limit"]["fallback-backoff"] == "2m0s"
    assert mapping["poll"]["initial-delay"] == "0s"
    assert mapping["http"]["retry"]["initial-backoff"] == "250ms"
    assert mapping["set-validation"]["clock-skew"] == "1m30s"
    assert mapping["dedup"]["retention"] == "168h0m0s"
    assert mapping["transmitters"]["okta"]["headers"] == {"X-Api-Key": "k"}
    assert mapping["transmitters"]["okta"]["poll"]["interval"] == "10s"
    assert "binding-failures" not in mapping
    assert "binding_failures" not in mapping
    assert all("_" not in key for key in mapping)
    assert ReceiverConfig.from_mapping(mapping) == config
    assert ReceiverConfig.from_mapping(json.loads(json.dumps(mapping))) == config
    assert default_receiver_config().to_mapping()["enabled"] is True
    assert ReceiverConfig.from_mapping(default_receiver_config().to_mapping()) == default_receiver_config()


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("30s", timedelta(seconds=30)),
        ("24h", timedelta(hours=24)),
        ("1h30m", timedelta(hours=1, minutes=30)),
        ("1h30m15s", timedelta(hours=1, minutes=30, seconds=15)),
        ("250ms", timedelta(milliseconds=250)),
        ("1.5s", timedelta(seconds=1.5)),
        ("-1.5h", timedelta(hours=-1.5)),
        ("+2m", timedelta(minutes=2)),
        ("100us", timedelta(microseconds=100)),
        ("100µs", timedelta(microseconds=100)),
        ("1000ns", timedelta(microseconds=1)),
        (" 10s ", timedelta(seconds=10)),
        ("0", timedelta(0)),
        ("90", timedelta(seconds=90)),
        ("1.5", timedelta(seconds=1.5)),
        (90, timedelta(seconds=90)),
        (0.25, timedelta(seconds=0.25)),
        (timedelta(seconds=7), timedelta(seconds=7)),
    ],
)
def test_parse_duration(text, expected):
    assert parse_duration(text) == expected


@pytest.mark.parametrize("text", ["", "   ", "abc", "10x", "1h30", "s", "-", "1..5s", "10 s", True, None, [10]])
def test_parse_duration_rejects_what_is_not_a_duration(text):
    with pytest.raises((ValueError, TypeError)):
        parse_duration(text)


@pytest.mark.parametrize(
    "duration",
    [
        timedelta(0),
        timedelta(seconds=30),
        timedelta(hours=24),
        timedelta(hours=1, minutes=30),
        timedelta(milliseconds=250),
        timedelta(seconds=1.5),
        timedelta(hours=-1.5),
        timedelta(microseconds=100),
        timedelta(days=7),
        timedelta(minutes=5),
        timedelta(microseconds=1),
    ],
)
def test_format_duration_is_read_back_by_parse_duration(duration):
    text = format_duration(duration)
    assert parse_duration(text) == duration
    assert "_" not in text
    assert text == text.strip()


def test_format_duration_prints_like_go():
    assert format_duration(timedelta(0)) == "0s"
    assert format_duration(timedelta(seconds=90)) == "1m30s"
    assert format_duration(timedelta(hours=1)) == "1h0m0s"
    assert format_duration(timedelta(hours=1, minutes=30)) == "1h30m0s"
    assert format_duration(timedelta(milliseconds=250)) == "250ms"
    assert format_duration(timedelta(seconds=1.5)) == "1.5s"
    assert format_duration(timedelta(hours=-1.5)) == "-1h30m0s"
    assert format_duration(timedelta(microseconds=100)) == "100us"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("4MB", 4 << 20),
        ("512kb", 512 << 10),
        (" 1 GB ", 1 << 30),
        ("10B", 10),
        ("1048576", 1 << 20),
        ("0", 0),
        (2048, 2048),
    ],
)
def test_data_size_binds_like_springs_data_size(text, expected):
    assert parse_data_size(text) == expected


@pytest.mark.parametrize("text", ["", "MB", "-1MB", "4 MiB", "1.5MB", "9999999TB", -1, True, 1.5, None])
def test_parse_data_size_rejects_what_is_not_a_data_size(text):
    with pytest.raises(ValueError):
        parse_data_size(text)


def test_format_data_size_prints_like_go():
    assert format_data_size(4 << 20) == "4MB"
    assert format_data_size(1536) == "1536B"
    assert format_data_size(1536 << 10) == "1536KB"
    assert format_data_size(0) == "0B"
    assert parse_data_size(format_data_size(1536 << 10)) == 1536 << 10


def test_from_mapping_reports_a_malformed_data_size_through_validate():
    config = ReceiverConfig.from_mapping(
        {"transmitter-issuer": "https://idp.example", "http": {"max-response-size": "4MiB"}}
    )
    with pytest.raises(ConfigurationError, match=r"http\.max-response-size: must be a data size"):
        config.validate()


def test_valid_table_prefix():
    assert valid_table_prefix("EASYSSF_")
    assert valid_table_prefix("app.ssf_")
    assert valid_table_prefix("")
    assert not valid_table_prefix("bad prefix")
    assert not valid_table_prefix("app-ssf")
    assert not valid_table_prefix("schéma.")


def test_schema_initialization_and_other_open_names_are_case_and_space_tolerant():
    config = default_transmitter_config()
    config.delivery_method = " Poll "
    assert config.delivery is DeliveryMethod.POLL
    config.delivery_method = ""
    assert config.delivery is DeliveryMethod.PUSH
    config.delivery_method = "fax"
    assert config.delivery is None
    config.set_validation.subject_compatibility = " LEGACY"
    assert config.subject_compatibility is SubjectCompatibilityMode.LEGACY
    config.set_validation.subject_compatibility = ""
    assert config.subject_compatibility is SubjectCompatibilityMode.STRICT
    config.oauth2.client_authentication_method = "Basic"
    assert config.oauth2.authenticates_with_request_body is False
    config.oauth2.client_authentication_method = "CLIENT_SECRET_POST"
    assert config.oauth2.authenticates_with_request_body is True
    config.oauth2.client_authentication_method = ""
    assert config.oauth2.authenticates_with_request_body is False
    config.oauth2.client_authentication_method = "mtls"
    assert config.oauth2.authenticates_with_request_body is None
    data = default_receiver_config().data
    data.initialize_schema = " Never "
    assert data.schema_initialization == "never"
    data.initialize_schema = ""
    assert data.schema_initialization == "embedded"
    data.initialize_schema = "sometimes"
    assert data.schema_initialization is None
    termination = default_receiver_config().session_termination
    termination.scim_attribute_claims = {"userName": "preferred_username", "externalId": "sub"}
    assert termination.effective_scim_attribute_claims == [("externalId", "sub"), ("userName", "preferred_username")]
