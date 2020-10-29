from __future__ import annotations

import hashlib
import hmac
from itertools import takewhile
from math import ceil
from secrets import randbelow

from tqdm import tqdm

from pybitcoin.ecc import Point, secp256k1

HARDENED_CHILD_INDEX = 2 ** 31


def hmac_sha512(key, msg):
    if 'sha512' not in hashlib.algorithms_available:
        raise Exception('Make sure your OpenSSL version provides SHA-512 algorithm!')
    return hmac.digest(key=key, msg=msg, digest='sha512')


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

    def encode(self, prefix=b'', suffix=b''):
        return prefix + self.k.to_bytes(32, byteorder=BIG) + suffix

    def to_wif(self) -> str:
        return base58check_encode(
            self.encode(
                prefix=b'\xef' if self.testnet else b'\x80',
                suffix=b'\x01' if self.compressed else b'',
            )
        )

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


class PublicKey:
    def __init__(self, point: Point, testnet=False):
        self.point = point
        self.testnet = testnet

    def __repr__(self):
        return f'PublicKey(x={hex(self.x)}, y={hex(self.y)})'

    @property
    def x(self):
        return self.point.x

    @property
    def y(self):
        return self.point.y

    def encode(self, compressed=True):
        if compressed:
            prefix = b'\x02' if self.y % 2 == 0 else b'\x03'
            return prefix + self.x.to_bytes(32, byteorder=BIG)
        else:
            prefix = b'\x04'
            return prefix + self.x.to_bytes(32, byteorder=BIG) + self.y.to_bytes(32, byteorder=BIG)

    def get_identifier(self, compressed=True) -> bytes:
        return ripemd160(sha256(self.encode(compressed=compressed)))

    def to_address(self, compressed=True) -> str:
        prefix = b'\x00' if not self.testnet else b'\x6f'
        return base58check_encode(payload=prefix + self.get_identifier(compressed=compressed))

    def to_hex(self, compressed=True) -> str:
        return self.encode(compressed=compressed).hex()


class ExtendedKey:
    VERSIONS = {
        'testnet': b'',
        'mainnet': b'',
    }

    def __init__(self, key, chain_code: bytes, depth=0, parent_fingerprint=b'\x00\x00\x00\x00', index=0):
        self._validate_key(key)

        self.key = key
        self.chain_code = chain_code
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.index = index

    def _validate_key(self, key):
        raise NotImplementedError

    def _get_encoded_key(self):
        raise NotImplementedError

    def _get_version(self):
        return self.VERSIONS['testnet' if self.key.testnet else 'mainnet']

    def to_wif(self) -> str:
        version = self._get_version()
        depth = self.depth.to_bytes(1, byteorder=BIG)
        child_number = self.index.to_bytes(4, byteorder=BIG)
        encoded_key = self._get_encoded_key()

        payload = version + depth + self.parent_fingerprint + child_number + self.chain_code + encoded_key
        return base58check_encode(payload)

    def from_wif(self, data: str):
        pass


class ExtendedPrivateKey(ExtendedKey):
    VERSIONS = {
        'testnet': b'\x04\x35\x83\x94',
        'mainnet': b'\x04\x88\xAD\xE4',
    }

    def __repr__(self):
        return f'ExtendedPrivateKey(key={self.key}, index={self.index}'

    def _validate_key(self, key):
        if not isinstance(key, PrivateKey):
            raise ValueError('Private key must be supplied!')

    def _get_encoded_key(self) -> bytes:
        return self.key.encode(prefix=b'\x00')

    def derive_private_child(self, index: int) -> ExtendedPrivateKey:
        public_key = self.key.generate_public_key()

        if index >= HARDENED_CHILD_INDEX:
            data = self.key.encode(prefix=b'\x00')

        else:
            data = public_key.encode(compressed=True)

        data += index.to_bytes(4, byteorder=BIG)

        out = hmac_sha512(key=self.chain_code, msg=data)
        out_l = int.from_bytes(out[:32], byteorder=BIG)
        out_r = out[32:]

        if out_l >= secp256k1.n:
            raise UseNextIndex

        k = (out_l + self.key.k) % secp256k1.n

        if k == 0:
            raise UseNextIndex

        return ExtendedPrivateKey(
            key=PrivateKey(k=k, testnet=self.key.testnet, compressed=True),
            chain_code=out_r,
            depth=self.depth + 1,
            parent_fingerprint=public_key.get_identifier()[:4],
            index=index,
        )

    def generate_public_key(self):
        return ExtendedPublicKey(
            key=self.key.generate_public_key(),
            chain_code=self.chain_code,
            depth=self.depth,
            parent_fingerprint=self.parent_fingerprint,
            index=self.index,
        )


class ExtendedPublicKey(ExtendedKey):
    VERSIONS = {
        'testnet': b'\x04\x35\x87\xCF',
        'mainnet': b'\x04\x88\xB2\x1E',
    }

    def _get_encoded_key(self) -> bytes:
        return self.key.encode(compressed=True)

    def __repr__(self):
        return f'ExtendedPublicKey(key={self.key}, index={self.index}'

    def _validate_key(self, key):
        if not isinstance(key, PublicKey):
            raise ValueError('Public key must be supplied!')

    def derive_private_child(self, index: int):
        raise RuntimeError('Cannot generate private key from public key!')

    def derive_public_child(self, index: int) -> ExtendedPublicKey:
        if index >= HARDENED_CHILD_INDEX:
            raise ValueError('Cannot derive hardened public keys!')

        data = self.key.encode() + index.to_bytes(4, byteorder=BIG)

        out = hmac_sha512(key=self.chain_code, msg=data)
        out_l = int.from_bytes(out[:32], byteorder=BIG)
        out_r = out[32:]

        if out_l >= secp256k1.n:
            raise UseNextIndex

        child_key_point = PrivateKey(k=out_l).generate_public_key().point + self.key.point
        if child_key_point == Point.inf():
            raise UseNextIndex

        child_key = PublicKey(point=child_key_point, testnet=self.key.testnet)
        return ExtendedPublicKey(
            key=child_key,
            chain_code=out_r,
            depth=self.depth + 1,
            parent_fingerprint=self.key.get_identifier()[:4],
            index=index,
        )


class UseNextIndex(ValueError):
    pass
