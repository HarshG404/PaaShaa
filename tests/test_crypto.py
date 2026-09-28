import pytest

pytest.importorskip("cryptography")
from paashaa.crypto import Vault, hash_password, seal, unseal, verify_password  # noqa: E402


def test_hash_roundtrip():
    h = hash_password("Correct-Horse-9")
    assert verify_password("Correct-Horse-9", h) and not verify_password("wrong", h)
    assert hash_password("x") != hash_password("x")      # unique salts


def test_verify_rejects_garbage():
    assert verify_password("x", "not-a-hash") is False


def test_vault_roundtrip_and_key_persistence(tmp_path):
    p = str(tmp_path / "k")
    v1 = Vault(p); token = v1.encrypt("s3cret")
    assert token != "s3cret" and Vault(p).decrypt(token) == "s3cret"


def test_vault_wrong_key_raises(tmp_path):
    t = Vault(str(tmp_path / "a")).encrypt("x")
    with pytest.raises(ValueError):
        Vault(str(tmp_path / "b")).decrypt(t)


def test_seal_unseal():
    blob = seal(b"data", "pass-phrase-123!")
    assert unseal(blob, "pass-phrase-123!") == b"data"
    with pytest.raises(ValueError):
        unseal(blob, "nope")
    with pytest.raises(ValueError):
        unseal(b"junk", "x")
