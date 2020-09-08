import hashlib
from itertools import takewhile
from math import ceil
from secrets import randbelow

from tqdm import tqdm

from pybitcoin.ecc import Point, secp256k1


def sha256(data: bytes) -> bytes:
    m = hashlib.sha256()
    m.update(data)

    return m.digest()


def ripemd160(data: bytes) -> bytes:
    if 'ripemd160' not in hashlib.algorithms_available:
        raise Exception('Make sure your OpenSSL version provides ripemd160 algorithm!')
    m = hashlib.new('ripemd160')
    m.update(data)

    return m.digest()


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
    leading_zeros = sum(1 for _ in takewhile('1'.__eq__, data))

    number = 0
    for i, c in enumerate(data[::-1]):
        if c != '1':
            number += BASE58_ALPHABET_REVERSE[c] * pow(58, i)

    num_bytes = ceil(number.bit_length() / 8)
    bytes_data = number.to_bytes(num_bytes, byteorder=BIG)
    payload = b'\x00' * leading_zeros + bytes_data[:-4]
    check = bytes_data[-4:]

    if sha256(sha256(payload))[:4] != check:
        raise Base58DecodeError('Check does not match')

    return payload


class PrivateKey:
    def __init__(self, k: int = None, testnet=False, compressed=False):
        self.k = randbelow(secp256k1.n) if k is None else k
        self._testnet = testnet
        self._compressed = compressed

    def __repr__(self):
        return f'PrivateKey(k={hex(self.k)}, testnet={self._testnet}, compressed={self._compressed})'

    def generate_public_key(self):
        p = self.k * Point.gen()

        return PublicKey(x=p.x, y=p.y, compressed=self._compressed)

    def to_wif(self) -> str:
        prefix = b'\x6f' if self._testnet else b'\x80'
        key = self.k.to_bytes(32, byteorder=BIG)
        suffix = b'\x01' if self._compressed else b''

        payload = prefix + key + suffix
        return base58check_encode(payload)

    @classmethod
    def from_wif(self, data: str):
        payload = base58check_decode(data)

        prefix = payload[0]
        key = payload[1:33]
        suffix = payload[33:34]

        return PrivateKey(
            k=int.from_bytes(key, byteorder=BIG),
            testnet=prefix == b'\x6f',
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
    def __init__(self, chain_code: bytes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._chain_code = chain_code

    def generate_public_key(self):
        pub = super().generate_public_key()

        return ExtendedPublicKey(x=pub.x, y=pub.y, compressed=pub.compressed, chain_code=self._chain_code)

    def to_wif(self) -> str:
        # TODO: Special packing for WIF
        pass

    @classmethod
    def from_wif(self, data: str):
        pass


class PublicKey:
    # TODO: cache address and hex represenations
    def __init__(self, x: int, y: int, compressed=True):
        self._x = x
        self._y = y
        self._compressed = compressed

        if self._compressed:
            prefix = b'\x02' if self.y % 2 == 0 else b'\x03'
            self._data = prefix + x.to_bytes(32, byteorder=BIG)
        else:
            prefix = b'\x04'
            self._data = prefix + x.to_bytes(32, byteorder=BIG) + y.to_bytes(32, byteorder=BIG)

    def __repr__(self):
        return f'PublicKey(x={hex(self._x)}, y={hex(self._y)}, compressed={self._compressed})'

    def to_address(self) -> str:
        return base58check_encode(payload=b'\x00' + ripemd160(sha256(self._data)))

    def to_hex(self) -> str:
        return self._data.hex()


class ExtendedPublicKey(PublicKey):
    def __init__(self, chain_code: bytes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._chain_code = chain_code

    def to_wif(self) -> str:
        pass

    @classmethod
    def from_wif(self, data: str):
        pass
