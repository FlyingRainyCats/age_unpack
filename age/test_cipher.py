import pytest

from age.cipher import DCPBlowfishCFB


@pytest.fixture
def bf_cfb_cipher():
    return DCPBlowfishCFB(b"test_key")


def test_cipher_encrypt(bf_cfb_cipher):
    cipher = bf_cfb_cipher.encrypt(b"test_data_123456789")
    assert cipher.hex() == "1a52e991e1d274c74e9545b34b320599d1acb3"


def test_cipher_decrypt(bf_cfb_cipher):
    cipher = bf_cfb_cipher.decrypt(bytes.fromhex("1a52e991e1d274c74e9545b34b320599d1acb3"))
    assert cipher == b"test_data_123456789"
