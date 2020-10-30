from pybitcoin.keys import BIG
from pybitcoin.script import script_encode

LITTLE = 'little'

MSB = 2 ** 7
VARINT_MASK = 2 ** 7 - 1

def varint_encode(x: int) -> bytes:
    data = b''
    while x:
        number = x & VARINT_MASK
        x >>= 7
        if x:
            number |= MSB
        data += number.to_bytes(1, byteorder=BIG)

    return data


class Vin:
    __slots__ = ['txid', 'vout', 'script_sig', 'sequence']

    def __init__(self, txid: str, vout: int, script_sig: str, sequence: int):
        self.txid = txid
        self.vout = vout
        self.script_sig = script_sig
        self.sequence = sequence

    def serialize(self) -> bytes:
        txid = bytes.from_hex(self.txid)
        vout = self.vout.to_bytes(4, byteorder=LITTLE)
        script_sig_len = varint_encode(len(self.script_sig))
        script_sig = script_encode(self.script_sig)
        sequence = self.sequence.to_bytes(4, byteorder=LITTLE)

        return txid + vout + script_sig_len + script_sig + sequence


class Vout:
    __slots__ = ['value', 'scriptPubKey']

    def __init__(self, value: int, script_pub_key: str):
        self.value = value
        self.script_pub_key = script_pub_key

    def serialize(self) -> bytes:
        value = self.value.to_bytes(8, byteorder=LITTLE)
        script_length = varint_encode(len(self.script_pub_key))
        script = script_encode(self.script_pub_key)

        return value + script_length + script


class Transaction:
    def __init__(self, version=1, locktime=0, vins=[], vouts=[]):
        self.version = version
        self.locktime = locktime
        self.vins = vins
        self.vouts = vouts

    def serialize(self):
        version = self.version.to_bytes(1, byteorder=LITTLE)
        input_count = varint_encode(len(self.vins))
        vins = b''.join(vin.serialize() for vin in self.vins)
        output_count = varint_encode(len(self.vouts))
        vouts = b''.join(vout.serialize() for vout in self.vouts)
        locktime = self.locktime.to_bytes(4, byteorder=LITTLE)

        return version + input_count + vins + output_count + vouts + locktime
