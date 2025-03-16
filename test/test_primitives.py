import os
import unittest

from rendez.vous.reunion.primitives import aead_decrypt, aead_encrypt, argon2i
from rendez.vous.reunion.primitives import generate_hidden_key_pair, Hash
from rendez.vous.reunion.primitives import highctidh_deterministic_rng, hkdf, prp_decrypt
from rendez.vous.reunion.primitives import prp_encrypt, unelligator, x25519

class TestPrimitives(unittest.TestCase):
    def test_aead(self):
        key = os.urandom(32)
        msg = os.urandom(32)
        ad = os.urandom(32)
        self.assertEqual(aead_decrypt(key, aead_encrypt(key, msg, ad), ad), msg)

    def test_elligator(self):
        epk_a, sk_a = generate_hidden_key_pair(os.urandom(32))
        epk_b, sk_b = generate_hidden_key_pair(os.urandom(32))
        ss1 = x25519(sk_a, unelligator(epk_b))
        ss2 = x25519(sk_b, unelligator(epk_a))
        assert ss1 == ss2

    def test_prp(self):
        key = os.urandom(32)
        msg = os.urandom(32)
        ct = prp_encrypt(key, msg)
        msg2 = prp_decrypt(key, ct)
        assert msg == msg2

    def test_argon_hkdf(self):
        salt = b"\x00" * 32
        passphrase = b"passphrase"
        a1 = argon2i(passphrase, salt)
        a2 = argon2i(passphrase, salt)
        assert a1 == a2
        pdk1 = hkdf(argon2i(passphrase, salt), salt).expand(b"", 32)
        pdk2 = hkdf(argon2i(passphrase, salt), salt).expand(b"", 32)
        assert pdk1 == pdk2

    def _test_argon_single_char(self):
        salt = b"\x00" * 32
        passphrase = b"p"
        a1 = argon2i(passphrase, salt)
        a2 = argon2i(passphrase, salt)
        a3 = argon2i(passphrase, salt)
        assert a3 == a2
        assert (
            passphrase == b"\x00"
        )  # this should not pass but does (on first run only!) due to the pymonocypher bug where it is zeroing a (interned, due to being 1 byte) bytes object


        assert a1 == a2 # this should pass, but does not
