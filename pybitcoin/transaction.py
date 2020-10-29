def varint(x: int) -> bytes:
    '''Encodes the integer using VarInt method.'''
    pass


class Vin:
    __slots__ = ['txid', 'vout', 'script_sig', 'sequence']

    def __init__(self, txid: str, vout: int, script_sig: str, sequence: int):
        self.txid = txid
        self.vout = vout
        self.script_sig = script_sig
        self.sequence = sequence

    def serialize(self) -> bytes:
        pass


class Vout:
    __slots__ = ['value', 'scriptPubKey']

    def __init__(self, value: int, script_pub_key: str):
        self.value = value
        self.script_pub_key = script_pub_key

    def serialize(self) -> bytes:
        value = self.value.to_bytes(8, byteorder='little')
        script_length = varint(len(self.script_pub_key))



class Transaction:
    def __init__(self, version=1, locktime=0, vins=[], vouts=[]):
        self.version = version
        self.locktime = locktime
        self.vins = vins
        self.vouts = vouts
