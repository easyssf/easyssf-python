"""InMemorySsfJtiDedupStoreTests of the Java library, receiver/dedup_test.go of the Go port."""

from datetime import timedelta

from easyssf.core import EventToken
from easyssf.receiver import InMemoryJtiDedupStore, JtiClaimState, JtiDedupStore
from easyssf.testing import ManualClock


def token(jti: str) -> EventToken:
    event_token = EventToken.from_claims({"jti": jti, "iss": "https://t.example", "iat": 1, "events": {"e": {}}})
    assert event_token is not None
    return event_token


async def claim_state(store: JtiDedupStore, set_: EventToken) -> JtiClaimState:
    """Claims and returns the state."""
    return (await store.claim(set_)).state


async def test_claim_in_progress_processed_forget():
    store = InMemoryJtiDedupStore(10)
    set_ = token("1")
    claim = await store.claim(set_)
    assert claim.state is JtiClaimState.GRANTED, "first claim is granted"
    assert claim.is_granted
    assert await claim_state(store, set_) is JtiClaimState.IN_PROGRESS, "second claim is in progress"
    await store.processed(set_, claim)
    assert await claim_state(store, set_) is JtiClaimState.PROCESSED, "processed"
    # forgetting a processed SET does nothing: only an in-progress claim is forgotten
    await store.forget(set_, claim)
    assert await claim_state(store, set_) is JtiClaimState.PROCESSED, "still processed"
    other = token("2")
    claim = await store.claim(other)
    await store.forget(other, claim)
    assert await claim_state(store, other) is JtiClaimState.GRANTED, "forgotten SET is claimed anew"
    assert len(store) == 2


async def test_abandoned_claim_is_taken_over_after_the_lease():
    clock = ManualClock()
    store = InMemoryJtiDedupStore(10, timedelta(seconds=60), clock)
    set_ = token("1")
    first = await store.claim(set_)
    clock.advance(timedelta(seconds=59))
    assert await claim_state(store, set_) is JtiClaimState.IN_PROGRESS, "within the lease"
    clock.advance(timedelta(seconds=2))
    second = await store.claim(set_)
    assert second.state is JtiClaimState.GRANTED, "taken over"
    assert second.token != first.token, "with a token of its own"


async def test_late_holder_can_neither_complete_nor_forget_the_claim_taken_over_from_it():
    clock = ManualClock()
    store = InMemoryJtiDedupStore(10, timedelta(seconds=60), clock)
    set_ = token("1")
    first = await store.claim(set_)
    clock.advance(timedelta(seconds=61))
    second = await store.claim(set_)
    await store.processed(set_, first)
    assert await claim_state(store, set_) is JtiClaimState.IN_PROGRESS, "still held by the second"
    await store.forget(set_, first)
    assert await claim_state(store, set_) is JtiClaimState.IN_PROGRESS, "still held by the second"
    assert await store.renew(set_, first) is None, "the first cannot renew"
    await store.processed(set_, second)
    assert await claim_state(store, set_) is JtiClaimState.PROCESSED, "the second completes"


async def test_renewed_claim_outlives_the_lease():
    clock = ManualClock()
    store = InMemoryJtiDedupStore(10, timedelta(seconds=60), clock)
    set_ = token("1")
    claim = await store.claim(set_)
    clock.advance(timedelta(seconds=40))
    renewed = await store.renew(set_, claim)
    assert renewed is not None, "renewed"
    clock.advance(timedelta(seconds=40))
    assert await claim_state(store, set_) is JtiClaimState.IN_PROGRESS, "the renewed claim holds"
    await store.processed(set_, renewed)
    assert await claim_state(store, set_) is JtiClaimState.PROCESSED, "processed"


async def test_success_of_an_evicted_claim_is_recorded():
    store = InMemoryJtiDedupStore(2)
    first = token("1")
    claim = await store.claim(first)
    await store.claim(token("2"))
    await store.claim(token("3"))
    assert len(store) == 2, "bounded"
    assert await claim_state(store, first) is JtiClaimState.GRANTED, "evicted: claimed anew"
    claim2 = await store.claim(token("4"))
    await store.claim(token("5"))
    await store.processed(token("4"), claim2)
    assert await claim_state(store, token("4")) is JtiClaimState.PROCESSED, (
        "the success of an evicted claim is recorded"
    )
    # the original claim of the first SET was evicted and re-claimed: the old token does not hold
    await store.processed(first, claim)
    assert len(store) == 2, "bounded"


async def test_capacity_evicts_the_oldest_entry():
    store = InMemoryJtiDedupStore(3)
    for jti in ("1", "2", "3"):
        claim = await store.claim(token(jti))
        await store.processed(token(jti), claim)
    assert await claim_state(store, token("1")) is JtiClaimState.PROCESSED, "processed"
    claim = await store.claim(token("4"))
    await store.processed(token("4"), claim)
    assert len(store) == 3, "bounded"
    assert await claim_state(store, token("1")) is JtiClaimState.GRANTED, "the oldest was evicted"
