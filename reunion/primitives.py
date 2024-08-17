import struct
from hashlib import blake2b, shake_256
from hkdf import Hkdf as _Hkdf
from highctidh import ctidh
import monocypher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ctidh1024 = ctidh(1024)

null_nonce = b"\x00" * 32


def Hash(msg: bytes) -> bytes:
    """
    *Hash* takes *msg* and returns 32 bytes of the *blake2b* digest of the
    message as bytes.

    >>> _hash = Hash(b'REUNION is for rendezvous')
    >>> len(_hash) == 32
    True
    >>> type(_hash) == bytes
    True
    """
    return blake2b(msg).digest()[:32]


def argon2i(password: bytes, salt: bytes, _wipe: bool=False):
    return monocypher.argon2i_32(
        nb_blocks=100000,
        nb_iterations=3,
        password=password,
        salt=salt,
        key=None,
        ad=None,
        _wipe=_wipe,
    )

def hkdf(key, salt, hash=blake2b):
    return _Hkdf(salt=salt, input_key_material=key, hash=hash)

def x25519(sk: bytes, pk: bytes) -> bytes:
    return monocypher.key_exchange(sk, pk)


def aead_encrypt(key: bytes, msg: bytes, ad: bytes) -> bytes:
    mac, ct = monocypher.lock(key, null_nonce, msg, associated_data=ad)
    return mac + ct


def aead_decrypt(key: bytes, msg: bytes, ad: bytes) -> bytes:
    mac, ct = msg[:16], msg[16:]
    return monocypher.unlock(key, null_nonce, mac, ct, associated_data=ad)


def unelligator(hidden: bytes) -> bytes:
    return monocypher.elligator_map(hidden)


def generate_hidden_key_pair(seed: bytes) -> bytes:
    return monocypher.elligator_key_pair(seed)


def prp_encrypt(key, msg):
    # 32-byte block cipher rijndael-enc(key, plaintext)
    # note: should actually be rijandael with a 256 bit block size, but here it
    # is two blocks of AES (128 bit block size) for now.
    assert len(key) == 32, len(key)
    assert len(msg) == 32, len(msg)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    res = encryptor.update(msg) + encryptor.finalize()
    assert len(res) == 32, len(res)
    return res


def prp_decrypt(key, ct):
    # 32-byte block cipher rijndael-dec(key, ciphertext),
    # note: should actually be rijandael with a 256 bit block size, but here it
    # is two blocks of AES (128 bit block size) for now.
    assert len(ct) == 32, len(ct)
    assert len(key) == 32, len(key)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def highctidh_deterministic_rng(seed:bytes):
    '''
    This function was copied from a file in the examples directory in a branch
    of the highctidh repo, and is used only to enable known-answer tests.

    ---

    Instantiate a SHAKE-256-based CSPRNG using a seed.
    The seed should be at least 32 bytes (256 bits).

    Returns a function suitable for the optional rng=
    argument to highctidh.ctidh.generate_secret_key.
    This enables deterministic key generation when also passing a deterministic
    context= argument.

    The CSPRNG keeps state internally to be able to provide
    unique entropy to libhighctidh (which calls it many times
    during the process of generating a key).

    It is safe to use the same seed to generate multiple keys if (and only if)
    **distinct** context arguments are passed.

    Usage:
        import secrets
        # These should be saved/restored in consequent runs:
        my_seed = secrets.token_bytes(32)
        my_context = 1
        # Load the library:
        import highctidh
        ct1024 = highctidh.ctidh(1024)
        # Instantiate CSPRNG:
        det_rng = deterministic_rng(seed)
        # (Re-)generate the private key:
        priv_key = ct1024.generate_secret_key(rng=det_rng, context=my_context)
    '''
    assert len(seed) >= 32, "deterministic seed should be at least 256 bits"
    context_state = {}
    def shake256_csprng(buf:memoryview, context:int):
        # context_state[context] is a counter, incremented on each call,
        # packed to little-endian uint64
        context_state[context] = 1 + context_state.get(context, 0)
        portable_state = struct.pack('<Q', context_state[context])
        # the user provided context packed to little-endian uint64:
        portable_context = struct.pack('<Q', context)
        little_endian_out = shake_256(
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
    return shake256_csprng

# def myrng(buf, ctx):
#    """realistic rng for real usage"""
#    buf[:] = secrets.token_bytes(len(buf))

# x = ctidh_f.generate_secret_key(rng=myrng)
