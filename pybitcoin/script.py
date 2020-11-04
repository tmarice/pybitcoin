from enum import Enum

from pybitcoin.keys import BIG


def script_encode(script: str) -> bytes:
    data = []

    tokens = script.split()
    for token in tokens:
        try:
            encoded_data = OpCodes[token].value
        except KeyError:
            encoded_data = bytes.fromhex(token)
            encoded_data = len(encoded_data).to_bytes(1, byteorder=BIG) + encoded_data
        data.append(encoded_data)

    return b''.join(data)


def script_decode(data: bytes) -> str:
    pass


class OpCodes(Enum):
    OP_0 = b'\x00'
    OP_FALSE = b'\x00'
    OP_PUSHDATA1 = b'\x4c'
    OP_PUSHDATA2 = b'\x4d'
    OP_PUSHDATA4 = b'\x4e'
    OP_1NEGATE = b'\x4f'
    OP_RESERVED = b'\x50'
    OP_1 = b'\x51'
    OP_TRUE = b'\x51'
    OP_2 = b'\x52'
    OP_3 = b'\x53'
    OP_4 = b'\x54'
    OP_5 = b'\x55'
    OP_6 = b'\x56'
    OP_7 = b'\x57'
    OP_8 = b'\x58'
    OP_9 = b'\x59'
    OP_10 = b'\x5a'
    OP_11 = b'\x5b'
    OP_12 = b'\x5c'
    OP_13 = b'\x5d'
    OP_14 = b'\x5e'
    OP_15 = b'\x5f'
    OP_16 = b'\x60'
    # control
    OP_NOP = b'\x61'
    OP_VER = b'\x62'
    OP_IF = b'\x63'
    OP_NOTIF = b'\x64'
    OP_VERIF = b'\x65'
    OP_VERNOTIF = b'\x66'
    OP_ELSE = b'\x67'
    OP_ENDIF = b'\x68'
    OP_VERIFY = b'\x69'
    OP_RETURN = b'\x6a'
    # stack ops
    OP_TOALTSTACK = b'\x6b'
    OP_FROMALTSTACK = b'\x6c'
    OP_2DROP = b'\x6d'
    OP_2DUP = b'\x6e'
    OP_3DUP = b'\x6f'
    OP_2OVER = b'\x70'
    OP_2ROT = b'\x71'
    OP_2SWAP = b'\x72'
    OP_IFDUP = b'\x73'
    OP_DEPTH = b'\x74'
    OP_DROP = b'\x75'
    OP_DUP = b'\x76'
    OP_NIP = b'\x77'
    OP_OVER = b'\x78'
    OP_PICK = b'\x79'
    OP_ROLL = b'\x7a'
    OP_ROT = b'\x7b'
    OP_SWAP = b'\x7c'
    OP_TUCK = b'\x7d'
    # splice ops
    OP_CAT = b'\x7e'
    OP_SUBSTR = b'\x7f'
    OP_LEFT = b'\x80'
    OP_RIGHT = b'\x81'
    OP_SIZE = b'\x82'
    # bit logic
    OP_INVERT = b'\x83'
    OP_AND = b'\x84'
    OP_OR = b'\x85'
    OP_XOR = b'\x86'
    OP_EQUAL = b'\x87'
    OP_EQUALVERIFY = b'\x88'
    OP_RESERVED1 = b'\x89'
    OP_RESERVED2 = b'\x8a'
    # numeric
    OP_1ADD = b'\x8b'
    OP_1SUB = b'\x8c'
    OP_2MUL = b'\x8d'
    OP_2DIV = b'\x8e'
    OP_NEGATE = b'\x8f'
    OP_ABS = b'\x90'
    OP_NOT = b'\x91'
    OP_0NOTEQUAL = b'\x92'
    OP_ADD = b'\x93'
    OP_SUB = b'\x94'
    OP_MUL = b'\x95'
    OP_DIV = b'\x96'
    OP_MOD = b'\x97'
    OP_LSHIFT = b'\x98'
    OP_RSHIFT = b'\x99b'
    OP_BOOLAND = b'\x9a'
    OP_BOOLOR = b'\x9b'
    OP_NUMEQUAL = b'\x9c'
    OP_NUMEQUALVERIFY = b'\x9d'
    OP_NUMNOTEQUAL = b'\x9e'
    OP_LESSTHAN = b'\x9f'
    OP_GREATERTHAN = b'\xa0'
    OP_LESSTHANOREQUAL = b'\xa1'
    OP_GREATERTHANOREQUAL = b'\xa2'
    OP_MIN = b'\xa3'
    OP_MAX = b'\xa4'
    OP_WITHIN = b'\xa5'
    # crypto
    OP_RIPEMD160 = b'\xa6'
    OP_SHA1 = b'\xa7'
    OP_SHA256 = b'\xa8'
    OP_HASH160 = b'\xa9'
    OP_HASH256 = b'\xaa'
    OP_CODESEPARATOR = b'\xab'
    OP_CHECKSIG = b'\xac'
    OP_CHECKSIGVERIFY = b'\xad'
    OP_CHECKMULTISIG = b'\xae'
    OP_CHECKMULTISIGVERIFY = b'\xaf'
    # expansion
    OP_NOP1 = b'\xb0'
    OP_CHECKLOCKTIMEVERIFY = b'\xb1'
    OP_NOP2 = b'\xb1'
    OP_CHECKSEQUENCEVERIFY = b'\xb2'
    OP_NOP3 = b'\xb2'
    OP_NOP4 = b'\xb3'
    OP_NOP5 = b'\xb4'
    OP_NOP6 = b'\xb5'
    OP_NOP7 = b'\xb6'
    OP_NOP8 = b'\xb7'
    OP_NOP9 = b'\xb8'
    OP_NOP10 = b'\xb9'
    OP_INVALIDOPCODE = b'\xff'
