"""The settings of a receiver under test: the transmitter to use, how to authenticate at it, the
delivery, the stream and the limits of a run; ``cts.*`` of the Java receiver and the port of
``receiver_settings.go``. Start from :func:`default_receiver_settings` and ``dataclasses.replace``
what differs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum

from easyssf.core import Claims, DeliveryMethod
from easyssf.core.subjects import email

__all__ = ["AuthMode", "AuthSettings", "ReceiverSettings", "default_receiver_settings"]


class AuthMode(Enum):
    """How the receiver authenticates at the emulated transmitter, the Authentication Variant of
    the test plan."""

    DYNAMIC = "dynamic"
    """Obtains an access token with the client credentials grant from the token endpoint of the
    emulated transmitter."""
    STATIC = "static"
    """Sends the configured access token."""

    @classmethod
    def from_name(cls, name: str) -> AuthMode:
        """The mode by its name, case-insensitive; ``DYNAMIC`` for anything else."""
        try:
            return cls(name.strip().lower())
        except ValueError:
            return cls.DYNAMIC

    def __str__(self) -> str:
        """The lowercase name."""
        return self.value


@dataclass(frozen=True, slots=True)
class AuthSettings:
    """The client credentials of the receiver at the emulated transmitter, as configured in the
    test plan (``client.client_id``, ``client.client_secret``, ``client.scope``), or the static
    access token (``ssf.transmitter.access_token``)."""

    mode: AuthMode = AuthMode.DYNAMIC
    """How the receiver authenticates."""
    client_id: str = ""
    """The client id."""
    client_secret: str = field(default="", repr=False)
    """The client secret."""
    scopes: tuple[str, ...] = ()
    """The scopes to request."""
    authenticate_with_request_body: bool = False
    """Sends the credentials in the body (``client_secret_post``) instead of with basic
    authentication, the Client Authentication Type of the test plan."""
    access_token: str = field(default="", repr=False)
    """The static access token of :attr:`AuthMode.STATIC`."""


@dataclass(frozen=True, slots=True)
class ReceiverSettings:
    """The settings of a receiver under test."""

    issuer: str = ""
    """The issuer of the emulated transmitter: the URL of the test instance in the conformance
    suite, with its alias, e.g. ``https://localhost.emobix.co.uk:8443/test/a/easyssf-receiver``."""
    auth: AuthSettings = field(default_factory=AuthSettings)
    """How the receiver authenticates."""
    delivery: DeliveryMethod = DeliveryMethod.PUSH
    """Push or poll, the SSF Delivery Mode of the test plan."""
    push_url: str = "https://localhost:9443/ssf/push"
    """The URL under which the conformance suite reaches the push endpoint of the receiver under
    test. Must be https."""
    poll_interval: timedelta = timedelta(seconds=1)
    """How often the transmitter is polled with poll delivery."""
    events_requested: tuple[str, ...] = ()
    """The event types (alias or URI) the stream requests."""
    subject_to_remove: Claims = field(default_factory=dict)
    """The subject the remove-subject scenario removes from the stream, e.g. one of the subjects
    listed in the SSF valid SubjectId field of the test plan."""
    verification_timeout: timedelta = timedelta(seconds=30)
    """How long to wait for the verification event before going on without it."""
    idle_timeout: timedelta = timedelta(seconds=30)
    """The stream is deleted once no SET arrived for this long. Has to exceed the pauses the tests
    make between events (20 seconds in the access token expiry test, 15 seconds in the
    transmitter-initiated status change test)."""
    max_duration: timedelta = timedelta(minutes=5)
    """A run ends at the latest after this time."""


def default_receiver_settings() -> ReceiverSettings:
    """The settings of the suite configurations in ``suite-config/``: the client
    ``easyssf-receiver``, push delivery, the three CAEP events, ``foo@example.com`` to remove."""
    return ReceiverSettings(
        auth=AuthSettings(
            mode=AuthMode.DYNAMIC,
            client_id="easyssf-receiver",
            client_secret="easyssf-receiver-secret",
            scopes=("ssf.read", "ssf.manage"),
        ),
        delivery=DeliveryMethod.PUSH,
        push_url="https://localhost:9443/ssf/push",
        poll_interval=timedelta(seconds=1),
        events_requested=("CaepSessionRevoked", "CaepCredentialChange", "CaepDeviceComplianceChange"),
        subject_to_remove=email("foo@example.com"),
        verification_timeout=timedelta(seconds=30),
        idle_timeout=timedelta(seconds=30),
        max_duration=timedelta(minutes=5),
    )
