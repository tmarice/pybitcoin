import hashlib
from secrets import randbelow

from pybitcoin.ecc import Point, secp256k1


def sha256(data):
    m = hashlib.sha256()
    m.update(data)

    return m.digest()


def ripemd160(data):
    if 'ripemd160' not in hashlib.algorithms_avalable:
        raise Exception('Make sure your OpenSSL version provides ripemd160 algorithm!')
    m = hashlib.new('ripemd160')
    m.update(data)

    return m.digest()


# Byte order bit endian
BIG = 'big'


def base58check_encode(data):
    pass


def base58check_decode(data):
    pass


class PrivateKey:
    def __init__(self, testnet=False, compressed=True):
        self.k = randbelow(secp256k1.n)
        self._testnet = testnet
        self._compressed = compressed

    def generate_public_key(self):
        p = self.k * Point.gen()

        return PublicKey(x=p.x, y=p.y)

    def to_wif(self):
        prefix = b'\xef' if self._testnet else b'\x80'
        key = self.k.to_bytes(32, byteorder=BIG)
        suffix = b'\x01' if self._compressed else b''

        payload = prefix + key + suffix
        checksum = sha256(sha256(payload))

        data = payload + checksum[:4]

        return base58check_encode(data)

    @classmethod
    def from_wif(self, data):
        pass


class PublicKey:
    def __init__(self, x, y=None):
        self.x = x
        if y is None:
            # TODO: calculate y
            self.compressed = True
        else:
            self.y = y
            self.compressed = False

    def get_address(self):
        if self.compressed:
            prefix = b'\x02' if self.y % 2 == 0 else b'\x03'
            data = prefix + self.x.to_bytes(32, byteorder=BIG)
        else:
            prefix = b'\x04'
            data = prefix + self.x.to_bytes(32, byteorder=BIG) + self.y.to_bytes(32, byteorder=BIG)

        return ripemd160(sha256(data))
