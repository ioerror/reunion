import struct
from hashlib import blake2b as _blake2b
from hashlib import shake_256 as _shake_256
from hkdf import Hkdf as _Hkdf
from highctidh import ctidh as _ctidh
import monocypher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from reunion.constants import DEFAULT_AEAD_NONCE, DEFAULT_ARGON_SALT
from reunion.constants import DEFAULT_HKDF_SALT, DEFAULT_CTIDH_SIZE

ctidh1024 = _ctidh(DEFAULT_CTIDH_SIZE)

def Hash(msg: bytes) -> bytes:
    """
    *Hash* takes *msg* and returns 32 bytes of the *blake2b* digest of the
    message as bytes.

    >>> _hash_preimage = bytes('REUNION is for rendezvous', 'utf-8')
    >>> _hash = Hash(_hash_preimage)
    >>> _hash.hex()
    '1ffb4f05cb3e841d44079afbcc51f62edbd7092294edac59846b8519f48c5a45'
    >>> len(_hash) == 32
    True
    >>> type(_hash) == bytes
    True
    """
    return _blake2b(msg).digest()[:32]

def argon2i(password: bytes, salt: bytes, _iterations: int = 3,
            _wipe: bool=False) -> bytes:
    """
    *argon2i* takes *password* of an arbitrary length encoded as bytes, a 32
    byte *salt*, and returns a 32 byte result encoded as bytes.

    REUNION does not negotiate the other parameters to argon2i.

    >>> argon2i_password = b'REUNION is for rendezvous'
    >>> argon2i_salt = DEFAULT_ARGON_SALT
    >>> argon2i_hash = argon2i(argon2i_password, argon2i_salt)
    >>> argon2i_hash.hex()
    '131f782cae57faa5055277621aec7c3984fbef048c8d183848f3def2697c7acd'
    """
    return monocypher.argon2i_32(
        nb_blocks=100000,
        nb_iterations=_iterations,
        password=password,
        salt=salt,
        key=None,
        ad=None,
        _wipe=_wipe,
    )

def hkdf(key: bytes, salt: bytes, hash=_blake2b):
    """
    *hkdf* wraps a standard HKDF and uses *blake2b* by default.

    >>> from reunion.__vectors__ import hkdf_salt, hkdf_key, hkdf_pdk, hkdf_pdk
    >>> _hkdf_result = hkdf(hkdf_key, hkdf_salt)
    >>> _hkdf_pdk = _hkdf_result.expand(b'', 32)
    >>> hkdf_pdk == _hkdf_pdk
    True
    """
    return _Hkdf(salt=salt, input_key_material=key, hash=hash)

def x25519(sk: bytes, pk: bytes) -> bytes:
    """
    *x25519* performs a Diffie-Hellman key-exchange between two parties that
    results in a 32 byte shared secret. The public key value *pk* should
    already be transformed from an elligator representation to a normal x25519
    public key with *unelligator*.

    >>> sk_seed_a: bytes = bytes.fromhex('a0f5f44533e439e9aced82d38eaab109df03c6f26833530343b1fac080fc6287')
    >>> sk_seed_b: bytes = bytes.fromhex('31a09e46971b29b5a9c59706c973d4f7f00361b442fd08b4724103b0b7f3ab24')
    >>> epk_25519_a, sk_25519_a = generate_hidden_key_pair(sk_seed_a)
    >>> epk_25519_b, sk_25519_b = generate_hidden_key_pair(sk_seed_b)
    >>> pk_25519_a = unelligator(epk_25519_a)
    >>> pk_25519_a.hex()
    'c1e0735aa6568ffc51da59648beb6f8bd26f1467574f3fbfec40986c399b032d'
    >>> pk_25519_b = unelligator(epk_25519_b)
    >>> pk_25519_b.hex()
    '7d5b74eddeff3f1a6b58d5eb9f8304c20b15cf0548eb93f73e400bbbaba60d5c'
    >>> shared_secret_a: bytes = x25519(sk_25519_a, pk_25519_b)
    >>> shared_secret_a.hex()
    '39e7f6f55136fc08032c8f69942351cc9ba48e473e1d9f327d8feb99376a6d36'
    >>> shared_secret_b: bytes = x25519(sk_25519_b, pk_25519_a)
    >>> shared_secret_b.hex()
    '39e7f6f55136fc08032c8f69942351cc9ba48e473e1d9f327d8feb99376a6d36'
    >>> shared_secret_a == shared_secret_b 
    True
    """
    return monocypher.key_exchange(sk, pk)

def aead_encrypt(key: bytes, plaintext: bytes, ad: bytes) -> bytes:
    """
    *aead_encrypt* takes *key*, *msg*, *ad* as bytes and returns *mac* and *ct*
    bytes objects.

    >>> from reunion.__vectors__ import aead_ad, aead_key, aead_pt, aead_ct
    >>> _aead_ct = aead_encrypt(aead_key, aead_pt, aead_ad)
    >>> aead_ct == _aead_ct
    True
    """
    mac, ct = monocypher.lock(key, DEFAULT_AEAD_NONCE, plaintext, associated_data=ad)
    return mac + ct

def aead_decrypt(key: bytes, ciphertext: bytes, ad: bytes) -> bytes:
    """
    *aead_decrypt* takes *key*, *ciphertext*, *ad* as bytes and returns
    *plaintext* as bytes.

    >>> from reunion.__vectors__ import aead_ad, aead_key, aead_pt, aead_ct
    >>> _aead_pt = aead_decrypt(aead_key, aead_ct, aead_ad)
    >>> aead_pt == _aead_pt
    True
    """
    mac, ct = ciphertext[:16], ciphertext[16:]
    return monocypher.unlock(key, DEFAULT_AEAD_NONCE, mac, ct, associated_data=ad)


def unelligator(hidden: bytes) -> bytes:
    """
    *unelligator* takes *hidden* a bytes object that contains a single x25519
    public key encoded with the elligator map; it reverses the map returning a
    bytes object that represents a normal x25519 public key.

    >>> from reunion.__vectors__ import esk_a_seed, esk_b_seed
    >>> from reunion.__vectors__ import epk_a, epk_b
    >>> from reunion.__vectors__ import pk_a, pk_b
    >>> esk_a_seed_dt_copy = bytes(a for a in esk_a_seed)
    >>> esk_b_seed_dt_copy = bytes(b for b in esk_b_seed)
    >>> epk_25519_a, sk_25519_a = generate_hidden_key_pair(esk_a_seed_dt_copy)
    >>> epk_25519_a == epk_a
    True
    >>> epk_25519_b, sk_25519_b = generate_hidden_key_pair(esk_b_seed_dt_copy)
    >>> epk_25519_a == epk_a
    True
    >>> pk_25519_a = unelligator(epk_25519_a)
    >>> pk_25519_a == pk_a
    True
    >>> pk_25519_b = unelligator(epk_25519_b)
    >>> pk_25519_b == pk_b
    True
    """
    return monocypher.elligator_map(hidden)

def generate_hidden_key_pair(seed: bytes) -> bytes:
    """
    *generate_hidden_key_pair* takes a 32 byte object known as *seed* and
    returns a two-tuple consisting of a bytes object containing a x25519 public
    key encoded with the elligator map, and the corresponding bytes object for
    the respective x25519 secret key.

    >>> sk_seed_a: bytes = bytes.fromhex('5aace7eec7f3a5ead537d23cbee29ed1003f3aa73d9a7a97b72d249b9119d409')
    >>> epk_25519_a, sk_25519_a = generate_hidden_key_pair(sk_seed_a)
    >>> epk_25519_a.hex()
    'dd134b5b287d6698f8db9cd58f7f4ccd2293103010fd2e7a11ed984debe2cde6'
    >>> sk_25519_a.hex()
    'd6b067b9b98e9616dde7e9aa52bd75f13493897ec4908230508b5abb293a5140'
    """
    return monocypher.elligator_key_pair(seed)

def generate_ctidh_key_pair(seed: bytes) -> (object, object):
    """
    *generate_hidden_key_pair* takes a 32 byte object known as *seed* and
    returns a two-tuple consisting of a bytes object containing a CTIDH public
    key, and the corresponding bytes object for the respective CTIDH secret key.

    FIXME: it would be nice to upstream this function (and the CSPRNG it uses,
    defined later in this file) to the highctidh library.

    >>> pk, sk = generate_ctidh_key_pair(seed=b'A'*32)
    >>> bytes(pk).hex()
    'a0e897b81374cc17aa917637cda97a56377c9b7bdbe86a53a6f01ce35a0366684568e7de4e38000214a2600ac6a9d07b2379ccccdf0c7ca94ff1288eeb06347101be8cabd24543315eb1d00596d05ebfcde4f13e076bc30635db8aa249b55c992ecb24f9ba128a90b8b1d93420ca8f6454572d4c3b492027b942fb45d1e5a20e'
    >>> bytes(sk).hex()
    '01fffd00ff000000ff03ff00fd00ff00fe00000000ffff0100ffff01ff0200ff0100ffff01010001fffffe0001020001010000ff03000100ff00ff0000fd0000fe0003010100ff0302000000ff000000fe000002010001ffff00000000fe03000001ff0001fe010000010000ff00ff0100ffff00010101000000000000000100ff00'
    """
    rng = highctidh_deterministic_rng(seed)
    sk = ctidh1024.generate_secret_key(rng=rng, context=1)
    pk = ctidh1024.derive_public_key(sk)
    return pk, sk


def prp_encrypt(key: bytes, plaintext: bytes):
    """
    *prp_encrypt* takes *key* and *plaintext* and returns a bytes encoded
    ciphertext of length 32.  It is explictly not authenticated encryption by
    design and should only be used where authentication of ciphertexts is an
    anti-feature.

    This is intended to be implemented with rijndael with a 256 bit block size.
    Currently we use two 128 bit blocks of AES as rijndael is not in the
    standard library; it should be replaced with rijndael.

    >>> prp_key = bytes.fromhex('37620a87ccc74b5e425164371603bd96c794594b7d07e4887bae6c7f08fa9659')
    >>> prp_plaintext = bytes.fromhex('5245554e494f4e20697320666f722052656e64657a766f75732e2e2e20505250')
    >>> prp_ct = bytes.fromhex('a74b26c607e56b1f59a84d91ff738e6b55f94ceedc418118347c2b733e5ebe92')
    >>> _prp_ct = prp_encrypt(prp_key, prp_plaintext)
    >>> prp_ct == _prp_ct
    True
    """
    assert len(key) == 32, len(key)
    assert len(plaintext) == 32, len(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    res = encryptor.update(plaintext) + encryptor.finalize()
    assert len(res) == 32, len(res)
    return res

def prp_decrypt(key: bytes, ciphertext: bytes):
    """
    *prp_decrypt* takes *key* and *ciphertext* and returns a bytes encoded
    plaintext of length 32.  It is explictly not authenticated encryption by
    design and should only be used where authentication of ciphertexts is an
    anti-feature.

    This is intended to be implemented with rijndael with a 256 bit block size.
    Currently we use two 128 bit blocks of AES as rijndael is not in the
    standard library; it should be replaced with rijndael.

    >>> prp_key = bytes.fromhex('37620a87ccc74b5e425164371603bd96c794594b7d07e4887bae6c7f08fa9659')
    >>> prp_plaintext = bytes.fromhex('5245554e494f4e20697320666f722052656e64657a766f75732e2e2e20505250')
    >>> prp_ct = bytes.fromhex('a74b26c607e56b1f59a84d91ff738e6b55f94ceedc418118347c2b733e5ebe92')
    >>> _prp_ct = prp_encrypt(prp_key, prp_plaintext)
    >>> prp_ct == _prp_ct
    True
    >>> _prp_pt = prp_decrypt(prp_key, prp_ct)
    >>> prp_plaintext == _prp_pt
    True
    """
    assert len(ciphertext) == 32, len(ciphertext)
    assert len(key) == 32, len(key)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def highctidh_deterministic_rng(seed: bytes):
    """
    *highctidh_deterministic_rng* takes a *seed* of at least 32 bytes and
    returns a generator suitable for deterministic outputs.

    This function was copied from a file in the examples directory in a branch
    of the public domain highctidh repo, and is used only to enable
    known-answer tests.

    Instantiate a SHAKE-256-based CSPRNG using a seed.  The seed should be at
    least 32 bytes (256 bits).

    Returns a function suitable for the optional rng= argument to
    highctidh.ctidh.generate_secret_key.  This enables deterministic key
    generation when also passing a deterministic context= argument.

    The CSPRNG keeps state internally to be able to provide unique entropy to
    libhighctidh (which calls it many times during the process of generating a
    key).

    It is safe to use the same seed to generate multiple keys if (and only if)
    **distinct** context arguments are passed.

    >>> highctidh_drng_seed = bytes.fromhex('163d228fd8182bdb0e259fbf0ed5a776b47126ba4d61d774cce87f6546f8d677')
    >>> highctidh_context = 1
    >>> det_rng = highctidh_deterministic_rng(highctidh_drng_seed)
    >>> highctidh_1024_priv_key = ctidh1024.generate_secret_key(rng=det_rng, context=highctidh_context) 
    """
    assert len(seed) >= 32, "deterministic seed should be at least 256 bits"
    context_state = {}
    def _shake256_csprng(buf: memoryview, context: int):
        """
        *_shake256_csprng* takes a memoryview *buf* and an integer in *context* and returns
        a function suitable for use with the highctidh determininstic *rng*
        parameter.

        >>> highctidh_drng_seed = bytes.fromhex('163d228fd8182bdb0e259fbf0ed5a776b47126ba4d61d774cce87f6546f8d677')
        >>> highctidh_context = 1
        >>> det_rng = highctidh_deterministic_rng(highctidh_drng_seed)
        >>> highctidh_1024_priv_key = ctidh1024.generate_secret_key(rng=det_rng, context=highctidh_context) 
        """
        # context_state[context] is a counter, incremented on each call,
        # packed to little-endian uint64
        context_state[context] = 1 + context_state.get(context, 0)
        portable_state = struct.pack('<Q', context_state[context])
        # the user provided context packed to little-endian uint64:
        portable_context = struct.pack('<Q', context)
        little_endian_out = _shake_256(
            portable_context + portable_state + seed
        ).digest(len(buf))
        # interpret as little-endian uint32 tuples
        # and pack to native byte order as expected by libhighctidh.
        # This is required to get deterministic keys independent of the
        # endian-ness of the host machine:
        for i in range(0, len(buf), 4):
            portable_uint32 = struct.unpack('<L',little_endian_out[i:i+4])[0]
            buf[i:i+4] = struct.pack(
                '=L', portable_uint32)
    return _shake256_csprng
