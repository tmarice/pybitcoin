from hypothesis import given, strategies as st, assume
import pytest
from pybitcoin.keys import base58check_encode, base58check_decode, BASE58_ALPHABET, Base58DecodeError


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
