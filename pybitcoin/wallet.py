from pybitcoin.keys import sha256, BIG
from pybitcoin.mnemonic_code_words import REVERSE_MNEMONIC_CODE_WORDS

CHECKSUM_MASKS = {
    4: 15,
    5: 31,
    6: 63,
    7: 127,
    8: 255,
}


def validate_mnemonic(mnemonic):
    words = mnemonic.split(' ')
    num_words = len(words)
    if num_words not in (12, 15, 18, 21, 24):
        raise ValueError('Invalid number of mnemonic keywords!')

    data = 0
    for word in words:
        try:
            index = REVERSE_MNEMONIC_CODE_WORDS[word]
        except KeyError:
            raise ValueError('Invalid mnemonic keyword')

        data <<= 11
        data += index

    checksum_length = num_words // 3
    sequence_num_bytes = num_words * 4 // 3
    sequence = (data >> checksum_length).to_bytes(sequence_num_bytes, BIG)
    input_checksum = data & CHECKSUM_MASKS[checksum_length]

    sequence_checksum = sha256(sequence)
    # Extract only first checksum_length BITS from first BYTE of checksum
    if sequence_checksum[0] >> (8 - checksum_length) != input_checksum:
        raise ValueError('Invalid checksum of mnemonic sequence!')


class HDWallet:
    def __init__(self):
        self._seed = None

    @classmethod
    def from_mnemonic(cls, mnemonic, passphrase):
        validate_mnemonic(mnemonic)
