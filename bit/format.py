from coincurve import verify_signature as _vs

from bit.base58 import b58decode_check, b58encode_check
from bit.crypto import ripemd160_sha256, sha256
from bit.curve import x_to_y

from bit.utils import int_to_unknown_bytes, hex_to_bytes, script_push
from bit.base32 import bech32_decode
from bit.constants import (
    PUBLIC_KEY_UNCOMPRESSED,
    PUBLIC_KEY_COMPRESSED_EVEN_Y,
    PUBLIC_KEY_COMPRESSED_ODD_Y,
    COINS_INFO_MAP,
    PREFIX_TO_VERSION,
)


def verify_sig(signature, data, public_key):
    """Verifies some data was signed by the owner of a public key.

    :param signature: The signature to verify.
    :type signature: ``bytes``
    :param data: The data that was supposedly signed.
    :type data: ``bytes``
    :param public_key: The public key.
    :type public_key: ``bytes``
    :returns: ``True`` if all checks pass, ``False`` otherwise.
    """
    return _vs(signature, data, public_key)


def address_to_public_key_hash(address):
    # Raise ValueError if we cannot identify the address.
    get_version(address)
    return b58decode_check(address)[1:]


'''get address version'''
def get_version(address):
    version, _ = bech32_decode(address)
    if version is None:
        version = b58decode_check(address)[:1]
    for v, obj in COINS_INFO_MAP.items():
        if version == obj['PUBKEY_HASH'] or version == obj['SCRIPT_HASH']:
            return v
        if str(version) in obj['BECH32_PREFIX_SET']:
            return v
    raise ValueError('{} does not correspond to a mainnet nor testnet address.'.format(version))

'''get private key version by prefix byte'''
def get_key_version(prefix_byte):
    if prefix_byte in PREFIX_TO_VERSION:
        return PREFIX_TO_VERSION[prefix_byte]
    else:
        raise ValueError('{} not a valid private key.'.format(prefix_byte))

'''get prefix byte by private key version'''
def get_key_prefix(version:str):
    if version in COINS_INFO_MAP:
        return COINS_INFO_MAP[version]['PRIVATE_KEY_PREFIX']
    else:
        raise ValueError('{} not a valid coin version.'.format(version))

'''get public key hash by private key version'''
def get_pubkey_hash_key(version:str):
    if version in COINS_INFO_MAP:
        return COINS_INFO_MAP[version]['PUBKEY_HASH']
    else:
        raise ValueError('{} not a valid coin version.'.format(version))

'''get script hash by private key version'''
def get_script_hash_key(version:str):
    if version in COINS_INFO_MAP:
        return COINS_INFO_MAP[version]['SCRIPT_HASH']
    else:
        raise ValueError('{} not a valid coin version.'.format(version))


def bytes_to_wif(private_key, version='main', compressed=False):
    prefix = get_key_prefix(version)
    if compressed:
        suffix = COINS_INFO_MAP[version]['PRIVATE_KEY_COMPRESSED_PUBKEY']
    else:
        suffix = b''

    private_key = prefix + private_key + suffix

    return b58encode_check(private_key)


def wif_to_bytes(wif):

    private_key = b58decode_check(wif)

    version = get_key_version(private_key[:1])

    # Remove version byte and, if present, compression flag.
    if len(wif) == 52 and private_key[-1:] == COINS_INFO_MAP[version]['PRIVATE_KEY_COMPRESSED_PUBKEY']:
        private_key, compressed = private_key[1:-1], True
    else:
        private_key, compressed = private_key[1:], False

    return private_key, compressed, version


def wif_checksum_check(wif):

    try:
        decoded = b58decode_check(wif)
    except ValueError:
        return False

    if decoded[:1] in PREFIX_TO_VERSION:
        return True

    return False


def public_key_to_address(public_key, version='main'):

    version = get_pubkey_hash_key(version)

    length = len(public_key)

    if length not in (33, 65):
        raise ValueError('{} is an invalid length for a public key.'.format(length))

    return b58encode_check(version + ripemd160_sha256(public_key))


def public_key_to_segwit_address(public_key, version='main'):

    version = get_script_hash_key(version)

    length = len(public_key)

    if length != 33:
        raise ValueError(
            '{} is an invalid length for a public key. Segwit only uses compressed public keys'.format(length)
        )

    return b58encode_check(version + ripemd160_sha256(b'\x00\x14' + ripemd160_sha256(public_key)))


def multisig_to_redeemscript(public_keys, m):

    if m > len(public_keys):
        raise ValueError('Required signatures cannot be more than the total number of public keys.')

    redeemscript = int_to_unknown_bytes(m + 80)

    for key in public_keys:
        length = len(key)

        if length not in (33, 65):
            raise ValueError('At least one of the provided public keys is of invalid length {}.'.format(length))

        redeemscript += script_push(length) + key

    redeemscript += (
        int_to_unknown_bytes(len(public_keys) + 80) + b'\xae'
    )  # Only works for n = len(public_keys) < 17. OK due to P2SH script-length limitation.

    if len(redeemscript) > 520:
        raise ValueError('The redeemScript exceeds the allowed 520-byte limitation with the number of public keys.')

    return redeemscript


def multisig_to_address(public_keys, m, version='main'):
    version = get_script_hash_key(version)

    return b58encode_check(version + ripemd160_sha256(multisig_to_redeemscript(public_keys, m)))


def multisig_to_segwit_address(public_keys, m, version='main'):
    version = get_script_hash_key(version)

    return b58encode_check(version + ripemd160_sha256(b'\x00\x20' + sha256(multisig_to_redeemscript(public_keys, m))))


def segwit_scriptpubkey(witver, witprog):
    """Construct a Segwit scriptPubKey for a given witness program."""
    return bytes([witver + 0x50 if witver else 0, len(witprog)] + witprog)


def public_key_to_coords(public_key):

    length = len(public_key)

    if length == 33:
        flag, x = int.from_bytes(public_key[:1], 'big'), int.from_bytes(public_key[1:], 'big')
        y = x_to_y(x, flag & 1)
    elif length == 65:
        x, y = int.from_bytes(public_key[1:33], 'big'), int.from_bytes(public_key[33:], 'big')
    else:
        raise ValueError('{} is an invalid length for a public key.'.format(length))

    return x, y


def coords_to_public_key(x, y, compressed=True):

    if compressed:
        y = PUBLIC_KEY_COMPRESSED_ODD_Y if y & 1 else PUBLIC_KEY_COMPRESSED_EVEN_Y
        return y + x.to_bytes(32, 'big')

    return PUBLIC_KEY_UNCOMPRESSED + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


def point_to_public_key(point, compressed=True):
    return coords_to_public_key(point.x, point.y, compressed)
