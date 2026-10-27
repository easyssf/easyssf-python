# easyssf-test

Test support for SSF receivers built with easyssf: `TestTransmitter` signs SETs, serves its metadata
and JWK Set, issues access tokens and emulates stream management and the poll endpoint, in-process
through the `httpx.AsyncClient` it hands out, so a test never opens a socket. Signing helpers make
SETs a receiver must reject, `eventually` and `during` wait for asynchronous outcomes, `ManualClock`
moves time by hand.

See the [README of easyssf-python](https://github.com/easyssf/easyssf-python#readme).
