from easyssf.core import Claims, EventToken, EventTypes, Subject
from easyssf.core.event_types import alias_of
from easyssf.core.scim import KNOWN, Event, Operation, ScimSubject, is_scim_event
from easyssf.core.subjects import complex_subject, email, iss_sub, opaque, scim


def token(sub_id: Claims | None, events: Claims) -> EventToken:
    claims: Claims = {"jti": "1", "iss": "https://t.example", "iat": 1700000000, "events": events}
    if sub_id is not None:
        claims["sub_id"] = sub_id
    event_token = EventToken.from_claims(claims)
    assert event_token is not None
    return event_token


def scim_subject(uri: str) -> ScimSubject:
    subject = ScimSubject.of(Subject.from_claims(scim(uri)))
    assert subject is not None
    return subject


def test_every_scim_event_type_has_an_operation_and_an_alias():
    for operation, event_type in KNOWN:
        assert Operation.of(event_type) is operation
        alias = alias_of(event_type)
        assert alias != event_type, f"{event_type} has no alias"
        assert is_scim_event(alias)
        assert event_type in operation.event_types
        assert str(operation) == operation.value
    assert len(Operation.CREATE.event_types) == 2
    assert len(Operation.DELETE.event_types) == 1
    assert Operation.UNKNOWN.event_types == ()
    assert Operation.of("CaepSessionRevoked") is Operation.UNKNOWN
    assert not is_scim_event("CaepSessionRevoked")
    assert not is_scim_event("urn:ietf:params:scim:event:future")
    assert Operation.CREATE.is_provisioning
    assert Operation.DEACTIVATE.is_provisioning
    assert not Operation.FEED_ADD.is_provisioning
    assert not Operation.FEED_REMOVE.is_provisioning
    assert not Operation.ASYNC_RESPONSE.is_provisioning
    assert not Operation.UNKNOWN.is_provisioning
    assert str(Operation.UNKNOWN) == "Unknown"


def test_full_and_notice_events():
    full = Event.of("ScimProvCreateFull", scim_subject("/Users/1"), {"data": {"userName": "alice"}, "version": 'W/"1"'})
    assert full is not None
    assert full.is_full
    assert not full.is_notice
    assert full.data == {"userName": "alice"}
    assert full.version == 'W/"1"'
    assert full.attributes == []
    assert full.operation is Operation.CREATE
    assert full.subject is not None and full.subject.id == "1"
    notice = Event.of("ScimProvPatchNotice", None, {"attributes": ["emails", "name.familyName", 3]})
    assert notice is not None
    assert notice.is_notice
    assert notice.attributes == ["emails", "name.familyName"]
    assert notice.data is None
    delete = Event.of("ScimProvDelete", None, None)
    assert delete is not None
    assert not delete.is_full
    assert not delete.is_notice
    assert delete.payload == {}
    assert delete.version == ""
    assert delete.subject is None
    async_response = Event.of(
        "ScimMiscAsyncResponse",
        None,
        {"method": "POST", "status": "409", "response": {"scimType": "uniqueness", "detail": "exists"}},
    )
    assert async_response is not None
    assert async_response.method == "POST"
    assert async_response.status == "409"
    assert async_response.response == {"scimType": "uniqueness", "detail": "exists"}
    assert delete.method == "" and delete.status == "" and delete.response is None


def test_finds_all_scim_events_of_a_set_in_order_and_ignores_others():
    events = Event.in_token(
        token(
            scim("/Users/42"),
            {
                EventTypes.SCIM_PROV_CREATE_FULL: {"data": {}},
                EventTypes.CAEP_SESSION_REVOKED: {},
                EventTypes.SCIM_FEED_ADD: {},
            },
        )
    )
    assert [event.operation for event in events] == [Operation.FEED_ADD, Operation.CREATE]
    assert events[1].subject is not None and events[1].subject.uri == "/Users/42"
    assert events[0].subject is events[1].subject
    # the subject is None unless the SET has a scim subject
    assert (
        Event.in_token(token(iss_sub("https://idp.example", "alice"), {EventTypes.SCIM_PROV_DELETE: {}}))[0].subject
        is None
    )
    assert Event.in_token(token(None, {EventTypes.SCIM_PROV_DELETE: {}}))[0].subject is None
    activate = Event.of("ScimProvActivate", None, None)
    assert activate is not None and activate.event_type == EventTypes.SCIM_PROV_ACTIVATE
    assert Event.of("CaepSessionRevoked", None, None) is None


def test_subject():
    subject = scim_subject("/Users/2b2f880a")
    assert subject.resource_type == "Users"
    assert subject.id == "2b2f880a"
    assert subject.external_id == ""
    assert subject.uri == "/Users/2b2f880a"
    subject = scim_subject("https://scim.example/v2/Groups/g1?attributes=members")
    assert subject.resource_type == "Groups"
    assert subject.id == "g1"
    from_id = ScimSubject.of(
        Subject.from_claims({"format": "scim", "uri": "/Users/from-uri", "id": "from-id", "externalId": "ext"})
    )
    assert from_id is not None
    assert from_id.id == "from-id"
    assert from_id.external_id == "ext"
    with_attributes = ScimSubject.of(
        Subject.from_claims({"format": "scim", "uri": "/Users/1", "userName": "alice", "active": True})
    )
    assert with_attributes is not None
    assert with_attributes.attribute("userName") == "alice"
    assert with_attributes.attribute("active") == ""
    assert with_attributes.claims["active"] is True
    assert with_attributes.identifier.format == "scim"
    no_uri = ScimSubject.of(Subject.from_claims({"format": "scim", "externalId": "ext"}))
    assert no_uri is not None
    assert no_uri.uri == ""
    assert no_uri.resource_type == ""
    assert no_uri.id == ""
    assert ScimSubject.of(Subject.from_claims(email("a@b.example"))) is None
    assert ScimSubject.of(Subject.empty()) is None
    assert ScimSubject.of(None) is None
    assert ScimSubject.from_identifier(None) is None
    complex_user = ScimSubject.of(Subject.from_claims(complex_subject(scim("/Users/7"), opaque("s1"))))
    assert complex_user is not None and complex_user.id == "7"
    assert scim_subject("/Users/1") == scim_subject("/Users/1")
    assert scim_subject("/Users/1") != scim_subject("/Users/2")
