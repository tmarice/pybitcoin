import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from pybitcoin.keys import BIG
from pybitcoin.mnemonic_code_words import MNEMONIC_CODE_WORDS
from pybitcoin.tests.wallet.fixtures import BIP_32_TEST_VECTORS
from pybitcoin.wallet import HDWallet, KeyStore, hmac_sha512, validate_mnemonic


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


@pytest.mark.parametrize(
    'mnemonic',
    [
        'answer act aspect mansion report own orphan mixed leader gate siren there',
        'educate magnet hub kidney trophy invite amused rival dream jaguar finish mechanic',
        'thumb citizen system submit certain stairs diamond elephant remove butter edge also galaxy umbrella awesome state husband audit agent rotate pulp transfer path harbor',
        'harbor bind butter advance erode enhance rough album photo mandate orbit order teach frown already mistake candy quality nasty split hen fresh agent syrup',
    ],
)
def test_validate_menmonic_ok_mnemonics(mnemonic):
    validate_mnemonic(mnemonic)


@given(key=st.binary(), msg=st.binary())
def test_hmac_sha512(key, msg):
    digest = hmac_sha512(key, msg)

    assert len(digest) == 64


def test_hd_wallet_from_mnemonic():
    pass


def test_hd_wallet_new_invalid_size_bits():
    pass


def test_hd_wallet_new():
    pass


@pytest.mark.parametrize('seed,path,expected_pub, expected_priv', BIP_32_TEST_VECTORS)
def test_key_store_get_key(seed, path, expected_pub, expected_priv):
    seed = seed.to_bytes(32, byteorder=BIG)
    wallet = HDWallet(seed=seed)
    k = wallet._key_store
    k.get_key(path)
