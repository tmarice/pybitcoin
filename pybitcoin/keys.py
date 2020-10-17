import hashlib
from itertools import takewhile
from math import ceil
from secrets import randbelow

from tqdm import tqdm

from pybitcoin.ecc import Point, secp256k1


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def ripemd160(data: bytes) -> bytes:
    if 'ripemd160' not in hashlib.algorithms_available:
        raise Exception('Make sure your OpenSSL version provides ripemd160 algorithm!')
    return hashlib.new('ripemd160', data).digest()


# Byte order bit endian
BIG = 'big'

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BASE58_ALPHABET_REVERSE = {c: i for i, c in enumerate(BASE58_ALPHABET)}


class Base58DecodeError(ValueError):
    pass


def base58check_encode(payload: bytes) -> str:
    result = []
    check = sha256(sha256(payload))[:4]
    data = payload + check
    leading_zeros = sum(1 for _ in takewhile((0).__eq__, data))

    number = int.from_bytes(data, byteorder=BIG)

    while number:
        result.append(BASE58_ALPHABET[number % 58])
        number //= 58

    result += ['1'] * leading_zeros

    return ''.join(reversed(result))


def base58check_decode(data: str) -> bytes:
    if any(c not in BASE58_ALPHABET_REVERSE for c in data):
        raise Base58DecodeError('Given string is not Base58Check encoded!')

    leading_zeros = sum(1 for _ in takewhile('1'.__eq__, data))

    number = 0
    p = 1
    for i, c in enumerate(data[::-1]):
        if c != '1':
            number += BASE58_ALPHABET_REVERSE[c] * p
        p *= 58

    num_bytes = ceil(number.bit_length() / 8)
    bytes_data = number.to_bytes(num_bytes, byteorder=BIG)
    payload = b'\x00' * leading_zeros + bytes_data[:-4]
    check = bytes_data[-4:]

    if sha256(sha256(payload))[:4] != check:
        raise Base58DecodeError('Check does not match')

    return payload


class InvalidKeyError(ValueError):
    pass


class PrivateKey:
    def __init__(self, k: int = None, testnet=False, compressed=False):
        if k is not None and not (0 < k < secp256k1.n):
            raise InvalidKeyError(f'k={k} must be >0 and <{secp256k1.n}')
        self.k = randbelow(secp256k1.n) if k is None else k
        self.testnet = testnet
        self.compressed = compressed

    def __repr__(self):
        return f'PrivateKey(k={hex(self.k)}, testnet={self.testnet}, compressed={self.compressed})'

    def __eq__(self, other):
        return self.k == other.k and self.compressed == other.compressed and self.testnet == other.testnet

    def generate_public_key(self):
        return PublicKey(point=self.k * Point.gen(), testnet=self.testnet)

    def to_wif(self) -> str:
        prefix = b'\xef' if self.testnet else b'\x80'
        key = self.k.to_bytes(32, byteorder=BIG)
        suffix = b'\x01' if self.compressed else b''

        payload = prefix + key + suffix
        return base58check_encode(payload)

    @classmethod
    def from_wif(self, data: str):
        payload = base58check_decode(data)

        prefix = payload[0:1]
        key = payload[1:33]
        suffix = payload[33:34]

        return PrivateKey(
            k=int.from_bytes(key, byteorder=BIG),
            testnet=prefix == b'\xef',
            compressed=suffix == b'\x01',
        )

    @classmethod
    def vanity_address(cls, prefix: str, verbose=False):
        if prefix[0] != '1':
            raise ValueError('Prefix has to start with 1!')

        address = ''
        t = tqdm(disable=not verbose)
        i = 0
        while True:
            for compressed in (True, False):
                prv = PrivateKey(compressed=compressed)
                pub = prv.generate_public_key()
                address = pub.to_address()

                if address.startswith(prefix):
                    return prv

                t.update(i)
                i += 1


class ExtendedPrivateKey(PrivateKey):
    def __init__(self, chain_code: bytes, depth=0, parent_fingerprint=b'\x00\x00\x00\x00', index=0, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.chain_code = chain_code
        self.depth = depth
        self._parent_fingerprint = parent_fingerprint
        self._index = index

    def __repr__(self):
        return f'ExtendedPrivateKey(k={hex(self.k)}, testnet={self.testnet}, compressed={self.compressed})'

    def generate_public_key(self):
        public_key = super().generate_public_key()

        return ExtendedPublicKey.from_public_key(
            public_key,
            chain_code=self.chain_code,
            depth=self.depth,
            parent_fingerprint=self._parent_fingerprint,
            index=self._index,
        )

    def to_wif(self) -> str:
        # TODO: move self.testnet to self.mainnet, this is inverse logic
        version = b'\x04\x88\xAD\xE4' if not self.testnet else b'\x04\x35\x83\x94'
        depth = self.depth.to_bytes(1, byteorder=BIG)
        child_number = self._index.to_bytes(4, byteorder=BIG)
        key = self.k.to_bytes(32, byteorder=BIG)

        payload = version + depth + self._parent_fingerprint + child_number + self.chain_code + b'\x00' + key
        return base58check_encode(payload)

    @classmethod
    def from_wif(self, data: str):
        pass


class PublicKey:
    def __init__(self, point: Point, testnet=False):
        self._point = point
        self._data = None
        self.testnet = testnet

    def __repr__(self):
        return f'PublicKey(x={hex(self.x)}, y={hex(self.y)}, compressed={self.compressed})'

    @property
    def x(self):
        return self._point.x

    @property
    def y(self):
        return self._point.y

    # TODO: rename this
    def _get_data(self, compressed=True):
        if self._data is not None:
            return self._data

        if compressed:
            prefix = b'\x02' if self.y % 2 == 0 else b'\x03'
            self._data = prefix + self.x.to_bytes(32, byteorder=BIG)
        else:
            prefix = b'\x04'
            self._data = prefix + self.x.to_bytes(32, byteorder=BIG) + self.y.to_bytes(32, byteorder=BIG)

        return self._data

    def get_identifier(self, compressed=True) -> bytes:
        return ripemd160(sha256(self._get_data(compressed=compressed)))

    def to_address(self, compressed=True) -> str:
        prefix = b'\x00' if not self.testnet else b'\x6f'
        return base58check_encode(payload=prefix + self.get_identifier(compressed=compressed))

    def to_hex(self, compressed=True) -> str:
        return self._get_data(compressed=compressed).hex()


class ExtendedPublicKey(PublicKey):
    def __init__(self, chain_code: bytes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.chain_code = chain_code

    @classmethod
    def from_public_key(cls, public_key: PublicKey, chain_code: bytes):
        return cls(point=public_key._point, testnet=public_key.testnet, chain_code=chain_code)

    def to_wif(self) -> str:
        pass

    @classmethod
    def from_wif(self, data: str):
        pass
