import hashlib
import hmac
from secrets import randbits

from pybitcoin.ecc import secp256k1
from pybitcoin.keys import BIG, ExtendedPrivateKey, sha256
from pybitcoin.mnemonic_code_words import MNEMONIC_CODE_WORDS, REVERSE_MNEMONIC_CODE_WORDS

CHECKSUM_MASKS = {i: 2 ** i - 1 for i in range(4, 9)}

WORD_MASK = 2 ** 11 - 1

HARDENED_CHILD_INDEX = 2 ** 31


def validate_mnemonic(mnemonic: str):
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


def hmac_sha512(key, msg):
    if 'sha512' not in hashlib.algorithms_available:
        raise Exception('Make sure your OpenSSL version provides SHA-512 algorithm!')
    return hmac.digest(key=key, msg=msg, digest='sha512')


class UseNextIndex(ValueError):
    pass


class KeyStore:
    MASTER = 'm'
    RE_PATH = r"(\d+)'?"

    def __init__(self, root_seed: bytes):
        self._keys = {}

        seed = hmac_sha512(key=b'Bitcoin seed', msg=root_seed)
        k = int.from_bytes(seed[:32], byteorder=BIG)
        chain_code = seed[32:]

        self.master_key = ExtendedPrivateKey(k=k, chain_code=chain_code, compressed=True)

    def get_key(self, path: str):
        indexes = self._get_indexes(path.split('/'))

        key = self.master_key
        for index in indexes:
            key = self._derive_key(parent_key=key, index=index)

        return key

    def _get_indexes(self, levels):
        indexes = []

        if levels[0] != self.MASTER:
            raise ValueError('Invalid key derivation path!')

        for level in levels[1:]:
            if level[-1] == "'":
                indexes.append(int(level[:-1]) + HARDENED_CHILD_INDEX)
            else:
                indexes.append(int(level))

        return indexes

    def _derive_key(self, parent_key: ExtendedPrivateKey, index: int) -> ExtendedPrivateKey:
        if index >= HARDENED_CHILD_INDEX:  # hardened key derivation
            data = b'\x00' + parent_key.k.to_bytes(32, byteorder=BIG)

        else:  # regular derivation
            public_key = parent_key.generate_public_key()
            data = public_key._get_data()

        out = hmac_sha512(key=parent_key.chain_code, msg=data)
        out_l = int.from_bytes(out[:32], byteorder=BIG)
        out_r = out[32:]

        # TODO: handle case if out_l >= secp256k1.p -> proceed with next i
        # TODO: handle case if out_r = 0 -> proceed with next i
        k = (out_l + parent_key.k) % secp256k1.p

        return ExtendedPrivateKey(
            k=k,
            chain_code=out_r,
            depth=parent_key.depth + 1,
            index=index,
            testnet=parent_key.testnet,
            compressed=parent_key.compressed,
        )


class HDWallet:
    def __init__(self, seed: bytes = None, mnemonic: str = None):
        '''Do not use directly, construct using from_mnemonic() or new() methods.'''
        self._seed = seed
        self._mnemonic = mnemonic

        self._key_store = KeyStore(root_seed=self._seed)

    @classmethod
    def from_mnemonic(cls, mnemonic: str, password=''):
        validate_mnemonic(mnemonic)

        seed = hashlib.pbkdf2_hmac(
            hash_name='sha512',
            password=mnemonic.encode('utf-8'),
            salt=b'mnemonic' + password.encode('utf-8'),
            iterations=2048,
            dklen=64,  # 512 bits
        )

        return HDWallet(seed=seed, mnemonic=mnemonic)

    @classmethod
    def new(cls, size_bits=256, password=''):
        if size_bits not in (128, 160, 192, 224, 256):
            raise ValueError('size_bits has to be 128, 160, 192, 224 or 256!')

        entropy = randbits(size_bits)
        entropy_bytes = entropy.to_bytes(size_bits // 8, BIG)
        checksum = sha256(entropy_bytes)
        checksum_length = size_bits // 32
        checksum_part = checksum[0] >> (8 - checksum_length)
        sequence = (entropy << checksum_length) + checksum_part

        mnemonic_words = []
        for _ in range(size_bits * 3 // 32):
            word_index = sequence & WORD_MASK
            mnemonic_words.append(MNEMONIC_CODE_WORDS[word_index])
            sequence >>= 11

        mnemonic = ' '.join(reversed(mnemonic_words))

        return HDWallet.from_mnemonic(mnemonic, password)
