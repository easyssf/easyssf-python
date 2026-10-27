# easyssf-core

The vocabulary of the [OpenID Shared Signals Framework](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)
for Python: Security Event Tokens (`EventToken`, the `new_set` builder), subjects (RFC 9493, complex
subjects, the `scim` format), delivery methods, stream configuration, transmitter metadata, the
event types of SSF, CAEP, RISC and SCIM Events (RFC 9967) with their aliases, and the typed CAEP,
RISC and SCIM events. No dependencies; `easyssf-core[signing]` adds `easyssf.core.signing`, which
signs SETs with joserfc.

Part of [easyssf-python](https://github.com/easyssf/easyssf-python); the receiver is
`easyssf-receiver`.
