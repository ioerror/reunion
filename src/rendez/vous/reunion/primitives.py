import struct
from typing import Any, cast, Callable, Tuple, Optional
from hashlib import blake2b as _blake2b
from hashlib import shake_256 as _shake_256
from hkdf import Hkdf as _Hkdf # type: ignore
from highctidh import ctidh as _ctidh # type: ignore
import monocypher # type: ignore
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from rendez.vous.reunion.constants import DEFAULT_AEAD_NONCE, DEFAULT_ARGON_SALT
from rendez.vous.reunion.constants import DEFAULT_HKDF_SALT, DEFAULT_CTIDH_SIZE

from .types import HKDF

ctidh1024 = _ctidh(DEFAULT_CTIDH_SIZE)

def Hash(msg: bytes) -> bytes:
    """
    *Hash* takes *msg* and returns 32 bytes of the *blake2b* digest of the
    message as bytes.

    note: Python's *blake2b* is blake2b 512 bit and we use only the last 256
    bits of the hash digest.

    >>> from rendez.vous.reunion.__vectors__ import h, h_preimage
    >>> _hash = Hash(h_preimage)
    >>> len(_hash) == 32
    True
    >>> type(_hash) == bytes
    True
    >>> h == _hash
    True
    """
    return _blake2b(msg).digest()[:32]

def argon2i(password: bytes, salt: bytes, _iterations: int = 3,
            _wipe: bool=False) -> bytes:
    """
    *argon2i* takes *password* of an arbitrary length encoded as bytes, a 32
    byte *salt*, and returns a 32 byte result encoded as bytes.

    REUNION does not negotiate the other parameters to argon2i.

    >>> from rendez.vous.reunion.__vectors__ import argon2i_password, argon2i_salt, argon2i_hash
    >>> _argon2i_hash = argon2i(argon2i_password, argon2i_salt)
    >>> argon2i_hash == _argon2i_hash
    True
    """
    return cast(bytes, monocypher.argon2i_32(
        nb_blocks=100000,
        nb_iterations=_iterations,
        password=password,
        salt=salt,
        key=None,
        ad=None,
        _wipe=_wipe,
    ))

def hkdf(key: bytes, salt: bytes, hash: Callable[..., object] =_blake2b) -> HKDF:
    """
    *hkdf* wraps a standard HKDF and uses *blake2b* by default.

    >>> from rendez.vous.reunion.__vectors__ import hkdf_salt, hkdf_key, hkdf_pdk, hkdf_pdk
    >>> _hkdf_result = hkdf(hkdf_key, hkdf_salt)
    >>> _hkdf_pdk = _hkdf_result.expand(b'', 32)
    >>> hkdf_pdk == _hkdf_pdk
    True
    """
    return cast(HKDF, _Hkdf(salt=salt, input_key_material=key, hash=hash))

def x25519(sk: bytes, pk: bytes) -> bytes:
    """
    *x25519* performs a Diffie-Hellman key-exchange between two parties that
    results in a 32 byte shared secret. The public key value *pk* should
    already be transformed from an elligator representation to a normal x25519
    public key with *unelligator*.

    >>> from rendez.vous.reunion.__vectors__ import x25519_sk_seed_a, x25519_sk_seed_b
    >>> epk_25519_a, sk_25519_a = generate_hidden_key_pair(x25519_sk_seed_a)
    >>> epk_25519_b, sk_25519_b = generate_hidden_key_pair(x25519_sk_seed_b)
    >>> pk_25519_a = unelligator(epk_25519_a)
    >>> pk_25519_b = unelligator(epk_25519_b)
    >>> shared_secret_a: bytes = x25519(sk_25519_a, pk_25519_b)
    >>> shared_secret_b: bytes = x25519(sk_25519_b, pk_25519_a)
    >>> shared_secret_a == shared_secret_b 
    True
    """
    return cast(bytes, monocypher.key_exchange(sk, pk))

def aead_encrypt(key: bytes, plaintext: bytes, ad: bytes) -> bytes:
    """
    *aead_encrypt* takes *key*, *msg*, *ad* as bytes and returns *mac* and *ct*
    bytes objects.

    XChaCha20 and Poly1305 (RFC 8439)

    >>> from rendez.vous.reunion.__vectors__ import aead_ad, aead_key, aead_pt, aead_ct
    >>> _aead_ct = aead_encrypt(aead_key, aead_pt, aead_ad)
    >>> aead_ct == _aead_ct
    True
    """
    mac: bytes
    ct: bytes
    mac, ct = monocypher.lock(key, DEFAULT_AEAD_NONCE, plaintext, associated_data=ad)
    return mac + ct

def aead_decrypt(key: bytes, ciphertext: bytes, ad: bytes) -> Optional[bytes]:
    """

    *aead_decrypt* takes *key*, *ciphertext*, *ad* as bytes and returns
    *plaintext* as bytes.

    XChaCha20 and Poly1305 (RFC 8439)

    >>> from rendez.vous.reunion.__vectors__ import aead_ad, aead_key, aead_pt, aead_ct
    >>> _aead_pt = aead_decrypt(aead_key, aead_ct, aead_ad)
    >>> aead_pt == _aead_pt
    True
    """
    mac: bytes
    ct: bytes
    mac, ct = ciphertext[:16], ciphertext[16:]
    return cast(Optional[bytes], monocypher.unlock(key, DEFAULT_AEAD_NONCE, mac, ct, associated_data=ad))


def unelligator(hidden: bytes) -> bytes:
    """
    *unelligator* takes *hidden* a bytes object that contains a single x25519
    public key encoded with the elligator map; it reverses the map returning a
    bytes object that represents a normal x25519 public key.

    >>> from rendez.vous.reunion.__vectors__ import esk_a_seed, esk_b_seed
    >>> from rendez.vous.reunion.__vectors__ import epk_a, epk_b
    >>> from rendez.vous.reunion.__vectors__ import pk_a, pk_b
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
    return cast(bytes, monocypher.elligator_map(hidden))

def generate_hidden_key_pair(seed: bytes) -> Tuple[bytes, bytes]:
    """
    *generate_hidden_key_pair* takes a 32 byte object known as *seed* and
    returns a two-tuple consisting of a bytes object containing a x25519 public
    key encoded with the elligator map, and the corresponding bytes object for
    the respective x25519 secret key.

    >>> from rendez.vous.reunion.__vectors__ import hidden_key_pair_seed, hidden_key_pair_pk_a
    >>> from rendez.vous.reunion.__vectors__ import hidden_key_pair_sk_a
    >>> epk_25519_a, sk_25519_a = generate_hidden_key_pair(hidden_key_pair_seed)
    >>> hidden_key_pair_pk_a == epk_25519_a 
    True
    >>> hidden_key_pair_sk_a == sk_25519_a
    True
    """
    return cast(Tuple[bytes, bytes], monocypher.elligator_key_pair(seed))

def generate_ctidh_key_pair(seed: bytes) -> Tuple[object, object]:
    """
    *generate_hidden_key_pair* takes a 32 byte object known as *seed* and
    returns a two-tuple consisting of a bytes object containing a CTIDH public
    key, and the corresponding bytes object for the respective CTIDH secret key.

    FIXME: it would be nice to upstream this function (and the CSPRNG it uses,
    defined later in this file) to the highctidh library.

    >>> from rendez.vous.reunion.__vectors__ import ctidh_key_pair_seed
    >>> from rendez.vous.reunion.__vectors__ import ctidh_key_pair_seed_pk
    >>> from rendez.vous.reunion.__vectors__ import ctidh_key_pair_seed_sk
    >>> pk, sk = generate_ctidh_key_pair(seed=ctidh_key_pair_seed)
    >>> ctidh_key_pair_seed_pk == bytes(pk)
    True
    >>> ctidh_key_pair_seed_sk == bytes(sk)
    True
    """
    rng = highctidh_deterministic_rng(seed)
    sk = ctidh1024.generate_secret_key(rng=rng, context=1)
    pk = ctidh1024.derive_public_key(sk)
    return pk, sk


def prp_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    *prp_encrypt* takes *key* and *plaintext* and returns a bytes encoded
    ciphertext of length 32.  It is explictly not authenticated encryption by
    design and should only be used where authentication of ciphertexts is an
    anti-feature.

    This is intended to be implemented with rijndael with a 256 bit block size.
    Currently we use two 128 bit blocks of AES as rijndael is not in the
    standard library; it should be replaced with rijndael.

    >>> from rendez.vous.reunion.__vectors__ import prp_key, prp_pt, prp_ct
    >>> _prp_ct = prp_encrypt(prp_key, prp_pt)
    >>> prp_ct == _prp_ct
    True
    """
    assert len(key) == 32, len(key)
    assert len(plaintext) == 32, len(plaintext)
    cipher: Cipher[Any] = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    res: bytes = encryptor.update(plaintext) + encryptor.finalize()
    assert len(res) == 32, len(res)
    return res

def prp_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    *prp_decrypt* takes *key* and *ciphertext* and returns a bytes encoded
    plaintext of length 32.  It is explictly not authenticated encryption by
    design and should only be used where authentication of ciphertexts is an
    anti-feature.

    This is intended to be implemented with rijndael with a 256 bit block size.
    Currently we use two 128 bit blocks of AES as rijndael is not in the
    standard library; it should be replaced with rijndael.

    >>> from rendez.vous.reunion.__vectors__ import prp_key, prp_pt, prp_ct
    >>> _prp_ct = prp_encrypt(prp_key, prp_pt)
    >>> prp_ct == _prp_ct
    True
    >>> _prp_pt = prp_decrypt(prp_key, prp_ct)
    >>> prp_pt == _prp_pt
    True
    """
    assert len(ciphertext) == 32, len(ciphertext)
    assert len(key) == 32, len(key)
    cipher: Cipher[Any] = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def highctidh_deterministic_rng(seed: bytes) -> Callable[[memoryview, int], None]:
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

    >>> from rendez.vous.reunion.__vectors__ import highctidh_context, highctidh_drng_seed
    >>> det_rng = highctidh_deterministic_rng(highctidh_drng_seed)
    >>> highctidh_1024_priv_key = ctidh1024.generate_secret_key(rng=det_rng, context=highctidh_context)
    """
    assert len(seed) >= 32, "deterministic seed should be at least 256 bits"
    context_state: dict[int, int] = {}
    def _shake256_csprng(buf: memoryview, context: int) -> None:
        """
        *_shake256_csprng* takes a memoryview *buf* and an integer in *context* and returns
        a function suitable for use with the highctidh determininstic *rng*
        parameter.

        >>> from rendez.vous.reunion.__vectors__ import highctidh_context, highctidh_drng_seed
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
        return None
    return _shake256_csprng
