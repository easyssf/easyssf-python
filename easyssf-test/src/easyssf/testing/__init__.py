"""Test support for SSF receivers: the in-process test transmitter, signing helpers, a manual
clock and waiting helpers. The port of ``easyssf-test`` of the Java library."""

from easyssf.core.signing import JWT_TYPE, SECEVENT_JWT_TYPE

from .clock import ManualClock
from .keys import SigningKey, claims_of, generate_key, shared_key, sign, sign_with, unsigned
from .transmitter import (
    ACCESS_TOKEN,
    AUDIENCE,
    CLIENT_ID,
    CLIENT_SECRET,
    InProcessTransport,
    MetadataLocation,
    ReportedError,
    TestTransmitter,
    client_for,
)
from .waiting import during, eventually

__all__ = [
    "ACCESS_TOKEN",
    "AUDIENCE",
    "CLIENT_ID",
    "CLIENT_SECRET",
    "JWT_TYPE",
    "SECEVENT_JWT_TYPE",
    "InProcessTransport",
    "ManualClock",
    "MetadataLocation",
    "ReportedError",
    "SigningKey",
    "TestTransmitter",
    "claims_of",
    "client_for",
    "during",
    "eventually",
    "generate_key",
    "shared_key",
    "sign",
    "sign_with",
    "unsigned",
]
