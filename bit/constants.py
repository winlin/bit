# Transactions:
VERSION_1 = 0x01 .to_bytes(4, byteorder='little')
VERSION_2 = 0x02 .to_bytes(4, byteorder='little')
MARKER = b'\x00'
FLAG = b'\x01'
SEQUENCE = 0xFFFFFFFF .to_bytes(4, byteorder='little')
LOCK_TIME = 0x00 .to_bytes(4, byteorder='little')
HASH_TYPE = 0x01 .to_bytes(4, byteorder='little')

# Scripts:
OP_0 = b'\x00'
OP_CHECKLOCKTIMEVERIFY = b'\xb1'
OP_CHECKSIG = b'\xac'
OP_CHECKMULTISIG = b'\xae'
OP_DUP = b'v'
OP_EQUALVERIFY = b'\x88'
OP_HASH160 = b'\xa9'
OP_PUSH_20 = b'\x14'
OP_PUSH_32 = b'\x20'
OP_RETURN = b'\x6a'
OP_EQUAL = b'\x87'

MESSAGE_LIMIT = 80

# Address formats:
BECH32_VERSION_SET = ('bc', 'tb', 'bcrt', 'ltc', 'doge')
BECH32_MAIN_VERSION_SET = BECH32_VERSION_SET[:1]
BECH32_TEST_VERSION_SET = BECH32_VERSION_SET[1:3]
MAIN_PUBKEY_HASH = b'\x00'
MAIN_SCRIPT_HASH = b'\x05'
TEST_PUBKEY_HASH = b'\x6f'
TEST_SCRIPT_HASH = b'\xc4'

# Keys:
MAIN_PRIVATE_KEY = b'\x80'
MAIN_BIP32_PUBKEY = b'\x04\x88\xb2\x1e'
MAIN_BIP32_PRIVKEY = b'\x04\x88\xad\xe4'
TEST_PRIVATE_KEY = b'\xef'
TEST_BIP32_PUBKEY = b'\x045\x87\xcf'
TEST_BIP32_PRIVKEY = b'\x045\x83\x94'
PUBLIC_KEY_UNCOMPRESSED = b'\x04'
PUBLIC_KEY_COMPRESSED_EVEN_Y = b'\x02'
PUBLIC_KEY_COMPRESSED_ODD_Y = b'\x03'
PRIVATE_KEY_COMPRESSED_PUBKEY = b'\x01'

# Litecoin Keys:
LTC_MAIN_PRIVATE_KEY = b'\xb0'
LTC_MAIN_PUBKEY_HASH = b'\x30'
LTC_MAIN_SCRIPT_HASH = b'\x32'

# Dogecoin Keys:
DOGE_MAIN_PRIVATE_KEY = b'\x9e'
DOGE_MAIN_PUBKEY_HASH = b'\x1e'
DOGE_MAIN_SCRIPT_HASH = b'\x16'

# Units:
# https://en.bitcoin.it/wiki/Units
SATOSHI = 1
uBTC = 10 ** 2
mBTC = 10 ** 5
BTC = 10 ** 8

COINS_INFO_MAP = {
    'main': {# btc
        'PRIVATE_KEY_PREFIX': MAIN_PRIVATE_KEY,
        'PRIVATE_KEY_COMPRESSED_PUBKEY': PRIVATE_KEY_COMPRESSED_PUBKEY,
        'PUBKEY_HASH': MAIN_PUBKEY_HASH,
        'SCRIPT_HASH': MAIN_SCRIPT_HASH,
        'BECH32_PREFIX_SET': BECH32_MAIN_VERSION_SET,
    },
    "test": {# btc
        'PRIVATE_KEY_PREFIX': TEST_PRIVATE_KEY,
        'PRIVATE_KEY_COMPRESSED_PUBKEY': PRIVATE_KEY_COMPRESSED_PUBKEY,
        'PUBKEY_HASH': TEST_PUBKEY_HASH,
        'SCRIPT_HASH': TEST_SCRIPT_HASH,
        'BECH32_PREFIX_SET': BECH32_TEST_VERSION_SET,
    },
    "ltc": {
        'PRIVATE_KEY_PREFIX': LTC_MAIN_PRIVATE_KEY,
        'PRIVATE_KEY_COMPRESSED_PUBKEY': PRIVATE_KEY_COMPRESSED_PUBKEY,
        'PUBKEY_HASH': LTC_MAIN_PUBKEY_HASH,
        'SCRIPT_HASH': LTC_MAIN_SCRIPT_HASH,
        'BECH32_PREFIX_SET': ('ltc'),
    },
    "doge": {
        'PRIVATE_KEY_PREFIX': DOGE_MAIN_PRIVATE_KEY,
        'PRIVATE_KEY_COMPRESSED_PUBKEY': PRIVATE_KEY_COMPRESSED_PUBKEY,
        'PUBKEY_HASH': DOGE_MAIN_PUBKEY_HASH,
        'SCRIPT_HASH': DOGE_MAIN_SCRIPT_HASH,
        'BECH32_PREFIX_SET': ('doge'),
    }
}

# 私钥前缀
PREFIX_TO_VERSION = {obj['PRIVATE_KEY_PREFIX']:v for v, obj in COINS_INFO_MAP.items()}