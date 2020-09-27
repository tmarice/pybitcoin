from unittest.mock import call, patch

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pybitcoin.ecc import Point, secp256k1
from pybitcoin.keys import (
    BASE58_ALPHABET,
    Base58DecodeError,
    InvalidKeyError,
    PrivateKey,
    PublicKey,
    base58check_decode,
    base58check_encode,
    ripemd160,
    sha256,
)
from pybitcoin.tests.ecc.fixtures import POINTS


@given(data=st.binary())
def test_sha256(data):
    digest = sha256(data)

    assert len(digest) == 32


@given(data=st.binary())
def test_ripemd160(data):
    digest = ripemd160(data)

    assert len(digest) == 20


@given(
    leading_zeros=st.integers(min_value=0, max_value=100),
    data=st.binary(),
)
def test_base58check_encode_decode(leading_zeros, data):
    """Check if b58c encode & decode are inverses of each other."""
    payload = b"\x00" * leading_zeros + data

    assert base58check_decode(base58check_encode(payload)) == payload


# TODO: Mark this test as flaky
@given(data=st.text(alphabet=BASE58_ALPHABET))
def test_base58check_decode_bad_check(data):
    """Check Base58DecodeError is raised if check digits are wrong."""
    with pytest.raises(Base58DecodeError):
        base58check_decode(data)


@given(
    good_data=st.text(alphabet=BASE58_ALPHABET),
    bad_data=st.text(alphabet="0OlI", min_size=1),
)
def test_base58check_decode_bad_alphabet(good_data, bad_data):
    data = good_data + bad_data

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
def test_private_key_generate_public_key(k, compressed):
    prv = PrivateKey(k=k, compressed=compressed)
    pub = prv.generate_public_key()

    assert k * Point.gen() == Point(pub.x, pub.y)


@given(
    compressed=st.booleans(),
    testnet=st.booleans(),
)
def test_private_key_wif_from_to(compressed, testnet):
    p = PrivateKey(compressed=compressed, testnet=testnet)
    p_ = PrivateKey.from_wif(p.to_wif())

    assert p == p_


@given(coords=st.sampled_from(POINTS))
def test_public_key_x_y_properties(coords):
    pubk = PublicKey(point=Point(*coords))

    assert (pubk.x, pubk.y) == coords


@given(
    coords=st.sampled_from(POINTS),
    compressed=st.booleans(),
)
def test_public_key_get_data(coords, compressed):
    data = PublicKey(point=Point(*coords))._get_data(compressed=compressed)

    if compressed:
        expected_length = 33
        if coords[1] % 2 == 0:
            expected_prefix = b"\x02"
        else:
            expected_prefix = b"\x03"
    else:
        expected_length = 65
        expected_prefix = b"\x04"

    assert len(data) == expected_length
    assert data[0:1] == expected_prefix


@given(
    coords=st.sampled_from(POINTS),
    compressed=st.booleans(),
)
def test_public_key_get_identifier(coords, compressed):
    pubk = PublicKey(point=Point(*coords))

    with patch("pybitcoin.keys.sha256") as mock_sha256, patch("pybitcoin.keys.ripemd160") as mock_ripemd160:
        pubk.get_identifier(compressed=compressed)

        assert mock_ripemd160.call_count == 1
        assert mock_ripemd160.call_args == call(mock_sha256.return_value)


@given(
    coords=st.sampled_from(POINTS),
    compressed=st.booleans(),
    testnet=st.booleans(),
)
def test_public_key_to_address(coords, compressed, testnet):
    address = PublicKey(Point(*coords), testnet=testnet).to_address(compressed=compressed)

    expected_prefixes = ['1'] if not testnet else ['m', 'n']

    assert address[0] in expected_prefixes
