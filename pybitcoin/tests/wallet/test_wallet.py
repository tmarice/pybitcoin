import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from pybitcoin.mnemonic_code_words import MNEMONIC_CODE_WORDS
from pybitcoin.wallet import validate_mnemonic


@st.composite
def mnemonic_code_words(draw, num_words):
    words = [draw(st.sampled_from(MNEMONIC_CODE_WORDS)) for _ in range(num_words)]

    return ' '.join(words)


@given(
    num_words=st.integers(max_value=100),
    data=st.data(),
)
def test_validate_mnemonic_wrong_number_of_words(num_words, data):
    assume(num_words not in (12, 15, 18, 21, 24))
    words = data.draw(mnemonic_code_words(num_words=num_words))

    with pytest.raises(ValueError, match='Invalid number of mnemonic keywords!'):
        validate_mnemonic(words)


@given(
    num_words=st.sampled_from([11, 14, 17, 20, 23]),
    data=st.data(),
    extra_word=st.text(max_size=10),
)
def test_validate_mnemonic_wrong_words(num_words, data, extra_word):
    assume(extra_word not in MNEMONIC_CODE_WORDS)
    words = data.draw(mnemonic_code_words(num_words=num_words)) + f' {extra_word}'

    with pytest.raises(ValueError, match='Invalid mnemonic keyword'):
        validate_mnemonic(words)


def test_validate_mnemonic_invalid_checksum():
    pass


def test_validate_menmonic_ok_mnemonics():
    pass


def test_hmac_sha512():
    pass


def test_hd_wallet_from_mnemonic():
    pass


def test_hd_wallet_new_invalid_size_bits():
    pass


def test_hd_wallet_new():
    pass
