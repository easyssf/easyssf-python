import json

import pytest
from joserfc import jws
from joserfc.jwk import ECKey, OKPKey, RSAKey, import_key

from easyssf.core import new_set
from easyssf.core.signing import JWT_TYPE, SECEVENT_JWT_TYPE, Signer, jwk_set


def claims():
    return new_set("https://idp.example").event("CaepSessionRevoked").claims()


def verify(signer, encoded):
    public = import_key(signer.public_jwk(), signer.public_jwk()["kty"])
    signature = jws.deserialize_compact(encoded, public, algorithms=[signer.algorithm])
    return json.loads(signature.payload), signature.protected


@pytest.fixture(scope="module")
def rsa_key():
    return RSAKey.generate_key(2048)


def test_signs_set_with_rsa_key_typed_secevent_jwt_and_key_id(rsa_key):
    signer = Signer(rsa_key, "", "rsa-1")
    assert signer.algorithm == "RS256"
    decoded, header = verify(signer, signer.sign(claims()))
    assert header["kid"] == "rsa-1"
    assert header["typ"] == SECEVENT_JWT_TYPE
    assert decoded["iss"] == "https://idp.example"
    jwk = signer.public_jwk()
    assert jwk["kid"] == "rsa-1" and jwk["alg"] == "RS256" and jwk["use"] == "sig" and "d" not in jwk


def test_signs_with_ecdsa_and_ed25519_keys():
    ec_signer = Signer(ECKey.generate_key("P-256"), "", "ec-1")
    assert ec_signer.algorithm == "ES256"
    ed_signer = Signer(OKPKey.generate_key("Ed25519"), "", "ed-1")
    assert ed_signer.algorithm == "EdDSA"
    for signer in (ec_signer, ed_signer):
        decoded, header = verify(signer, signer.sign_typed(JWT_TYPE, {"sub": "alice"}))
        assert decoded["sub"] == "alice"
        assert header["typ"] == "JWT"
    keys = jwk_set(ec_signer, ed_signer)["keys"]
    assert len(keys) == 2 and keys[0]["kid"] == "ec-1" and keys[1]["alg"] == "EdDSA"
    assert "typ" not in verify(ec_signer, ec_signer.sign_typed("", {"sub": "x"}))[1]


def test_takes_the_key_id_of_the_key_and_other_algorithms_of_the_family(rsa_key):
    key = RSAKey.import_key(rsa_key.as_dict(private=True), parameters={"kid": "from-key"})
    signer = Signer(key, "PS256")
    assert signer.key_id == "from-key" and signer.algorithm == "PS256"
    assert verify(signer, signer.sign(claims()))[1]["alg"] == "PS256"
    assert Signer(ECKey.generate_key("P-521"), "", "ec").algorithm == "ES512"


def test_refuses_weak_keys_mismatched_algorithms_and_missing_key_id(rsa_key):
    with pytest.raises(ValueError, match="2048"):
        Signer(RSAKey.generate_key(1024), "", "weak")
    ec = ECKey.generate_key("P-256")
    with pytest.raises(ValueError, match="does not fit"):
        Signer(ec, "RS256", "ec")
    with pytest.raises(ValueError, match="key id"):
        Signer(ec, "", "")
    with pytest.raises(ValueError, match="private"):
        Signer(RSAKey.import_key(rsa_key.as_dict(private=False)), "", "pub")
    with pytest.raises(ValueError, match="unsupported key type"):
        Signer("not a key", "", "x")  # type: ignore[arg-type]
