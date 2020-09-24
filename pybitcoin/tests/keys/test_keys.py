from hypothesis import given, strategies as st, assume
from pybitcoin.ecc import secp256k1, Point
import pytest
from pybitcoin.keys import (
    base58check_encode,
    base58check_decode,
    BASE58_ALPHABET,
    Base58DecodeError,
    PrivateKey,
    InvalidKeyError,
)


@given(
    leading_zeros=st.integers(min_value=0, max_value=100),
    data=st.binary(),
)
def test_base58check_encode_decode(leading_zeros, data):
    '''Check if b58c encode & decode are inverses of each other.'''
    payload = b'\x00' * leading_zeros + data

    assert base58check_decode(base58check_encode(payload)) == payload


# TODO: Mark this test as flaky
@given(data=st.text(alphabet=BASE58_ALPHABET))
def test_base58check_decode_bad_check(data):
    '''Check Base58DecodeError is raised if check digits are wrong.'''
    with pytest.raises(Base58DecodeError):
        base58check_decode(data)


@given(k=st.integers(min_value=1, max_value=secp256k1.p - 1))
def test_private_key_k_ok(k):
    p = PrivateKey(k=k)

    assert p.k == k


def test_private_key_k_not_given():
    p = PrivateKey()

    assert 0 < p.k < secp256k1.p


@given(
    k_1=st.integers(max_value=0),
    k_2=st.integers(min_value=secp256k1.p),
)
def test_private_key_k_invalid(k_1, k_2):
    with pytest.raises(InvalidKeyError):
        PrivateKey(k=k_1)

    with pytest.raises(InvalidKeyError):
        PrivateKey(k=k_2)


@given(
    k=st.integers(min_value=1, max_value=secp256k1.p - 1),
    compressed=st.booleans(),
)
def test_generate_public_key(k, compressed):
    prv = PrivateKey(k=k, compressed=compressed)
    pub = prv.generate_public_key()

    assert k * Point.gen() == Point(pub.x, pub.y)
    assert prv.compressed == pub.compressed


@given(
    compressed=st.booleans(),
    testnet=st.booleans(),
)
def test_wif_from_to(compressed, testnet):
    p = PrivateKey(compressed=compressed, testnet=testnet)
    p_ = PrivateKey.from_wif(p.to_wif())

    assert p == p_


def test_from_wif():
    pass
