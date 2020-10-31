from __future__ import annotations

from typing import Tuple

from pybitcoin.keys import BIG
from pybitcoin.script import script_decode, script_encode

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


def varint_decode(data: bytes) -> Tuple[int, bytes]:
    '''Returns decoded varint and the remaining unconsumed data'''
    pass


class Vin:
    __slots__ = ['txid', 'vout_index', 'script_sig', 'sequence']

    def __init__(self, txid: str, vout_index: int, script_sig: str, sequence: int):
        self.txid = txid
        self.vout_index = vout_index
        self.script_sig = script_sig
        self.sequence = sequence

    def serialize(self) -> bytes:
        txid = bytes.from_hex(self.txid)
        vout_index = self.vout_index.to_bytes(4, byteorder=LITTLE)
        script_sig_len = varint_encode(len(self.script_sig))
        script_sig = script_encode(self.script_sig)
        sequence = self.sequence.to_bytes(4, byteorder=LITTLE)

        return txid + vout_index + script_sig_len + script_sig + sequence

    @classmethod
    def deserialize(cls, data: bytes) -> Tuple[Vin, bytes]:
        ''' Returns the deserialized vin and the remaining unconsumed data.'''
        # TODO: txid should be str
        txid = data[:32]
        vout_index = int.from_bytes(data[32:36], byteorder=LITTLE)
        script_sig_length, data = varint_decode(data[36:])
        script_sig = script_decode(data[:script_sig_length])
        sequence = int.from_bytes(data[script_sig_length : script_sig_length + 4], byteorder=LITTLE)

        return (
            cls(txid=txid, vout_index=vout_index, script_sig=script_sig, sequence=sequence),
            data[script_sig_length + 4 :],
        )

    def get_vout(self):
        '''Return the corresponding vout'''
        pass


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

    @classmethod
    def deserialize(cls, data: bytes) -> Tuple[Vout, bytes]:
        ''' Returns the deserialized vout and the remaining unconsumed data.'''
        value = int.from_bytes(data[:4], byteorder=LITTLE)
        script_length, data = varint_decode(data[4:])
        script = script_decode(data[:script_length])

        return cls(value=value, script_pub_key=script), data[script_length:]


class Transaction:
    def __init__(self, version=1, locktime=0, vins=[], vouts=[]):
        self.version = version
        self.locktime = locktime
        self.vins = vins
        self.vouts = vouts

    def serialize(self) -> bytes:
        version = self.version.to_bytes(1, byteorder=LITTLE)
        input_count = varint_encode(len(self.vins))
        vins = b''.join(vin.serialize() for vin in self.vins)
        output_count = varint_encode(len(self.vouts))
        vouts = b''.join(vout.serialize() for vout in self.vouts)
        locktime = self.locktime.to_bytes(4, byteorder=LITTLE)

        return version + input_count + vins + output_count + vouts + locktime

    @classmethod
    def deserialize(cls, data: bytes) -> Transaction:
        # TODO: Add data validation
        version = int.from_bytes(data[:4], byteorder=LITTLE)

        vins = []
        input_count, data = varint_decode(data[4:])
        while input_count > 0:
            vin, data = Vin.deserialize(data)
            vins.append(vin)
            input_count -= 1

        vouts = []
        output_count, data = varint_decode(data)
        while output_count > 0:
            vout, data = Vout.deserialize(data)
            vouts.append(vout)
            output_count -= 1

        locktime = int.from_bytes(data, byteorder=LITTLE)

        return cls(version=version, locktime=locktime, vins=vins, vouts=vouts)

    @property
    def fee(self):
        return sum(vin.get_vout().value for vin in self.vins) - sum(vout.value for vout in self.vouts)
