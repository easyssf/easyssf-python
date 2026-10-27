# easyssf-receiver

An SSF receiver for Python on asyncio, independent of any web framework: SET verification (RFC
8417), push (RFC 8935) and poll (RFC 8936) delivery, stream management (SSF 1.0, section 8),
de-duplication, typed CAEP, RISC and SCIM handlers, token revocation and session termination.
`easyssf.receiver.asgi` mounts the push endpoint on any ASGI framework; the Flask, FastAPI and
Litestar distributions add the idiomatic pieces.

See the [README of easyssf-python](https://github.com/easyssf/easyssf-python#readme).
