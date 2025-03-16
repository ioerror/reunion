import os
import unittest

from rendez.vous.reunion.constants import DEFAULT_AEAD_NONCE, DEFAULT_ARGON_SALT, DEFAULT_HKDF_SALT
from rendez.vous.reunion.primitives import aead_decrypt, aead_encrypt, argon2i
from rendez.vous.reunion.primitives import generate_hidden_key_pair, Hash
from rendez.vous.reunion.primitives import highctidh_deterministic_rng, hkdf, prp_decrypt
from rendez.vous.reunion.primitives import prp_encrypt, unelligator, x25519
from rendez.vous.reunion.__vectors__ import esk_a_seed, esk_b_seed
from rendez.vous.reunion.__vectors__ import epk_a, epk_b
from rendez.vous.reunion.__vectors__ import esk_a, esk_b
from rendez.vous.reunion.__vectors__ import pk_a, pk_b
from rendez.vous.reunion.__vectors__ import aead_key, aead_pt, aead_ad, aead_ct
from rendez.vous.reunion.__vectors__ import prp_key, prp_pt, prp_ct
from rendez.vous.reunion.__vectors__ import a1, a2, pdk1, pdk2, h, h_preimage


class TestPrimitivesStaticVectors(unittest.TestCase):
    def test_hash(self):
        _hash = Hash(h_preimage)
        self.assertEqual(h, _hash)

    def test_aead_encrypt(self):
        _aead_ct = aead_encrypt(aead_key, aead_pt, aead_ad)
        self.assertEqual(aead_ct, _aead_ct)

    def test_aead_decrypt(self):
        _aead_ct = aead_encrypt(aead_key, aead_pt, aead_ad)
        _aead_pt = aead_decrypt(aead_key, aead_ct, aead_ad)
        self.assertEqual(aead_pt, _aead_pt)

    def test_elligator(self):
        # We must copy these because generate_hidden_key_pair will bzero the memory
        esk_a_seed_elligator_copy = bytes(a for a in esk_a_seed)
        esk_b_seed_elligator_copy = bytes(b for b in esk_b_seed)
        _epk_a, _esk_a = generate_hidden_key_pair(esk_a_seed_elligator_copy)
        _epk_b, _esk_b = generate_hidden_key_pair(esk_b_seed_elligator_copy)
        self.assertEqual(epk_a, _epk_a)
        self.assertEqual(esk_a, _esk_a)
        self.assertEqual(epk_b, _epk_b)
        self.assertEqual(esk_b, _esk_b)

    def test_unelligator(self):
        # We must copy these because generate_hidden_key_pair will bzero the memory
        esk_a_unelligator_seed_copy = bytes(a for a in esk_a_seed)
        esk_b_unelligator_seed_copy = bytes(b for b in esk_b_seed)
        _epk_a, _esk_a = generate_hidden_key_pair(esk_a_unelligator_seed_copy)
        _epk_b, _esk_b = generate_hidden_key_pair(esk_b_unelligator_seed_copy)
        self.assertEqual(epk_a, _epk_a)
        self.assertEqual(esk_a, _esk_a)
        self.assertEqual(epk_b, _epk_b)
        self.assertEqual(esk_b, _esk_b)
        self.assertEqual(pk_a, unelligator(_epk_a))
        self.assertEqual(pk_b, unelligator(_epk_b))

    def test_elligator_dh(self):
        # We must copy these because generate_hidden_key_pair will bzero the memory
        esk_a_seed_dh_copy = bytes(e for e in esk_a_seed)
        esk_b_seed_dh_copy = bytes(f for f in esk_b_seed)
        _epk_a, _esk_a = generate_hidden_key_pair(esk_a_seed_dh_copy)
        _epk_b, _esk_b = generate_hidden_key_pair(esk_b_seed_dh_copy)
        ss1 = x25519(esk_a, unelligator(epk_b))
        ss2 = x25519(esk_b, unelligator(epk_a))
        self.assertEqual(ss1, ss2)

    def test_prp(self):
        _ct = prp_encrypt(prp_key, prp_pt)
        self.assertEqual(prp_ct, _ct)
        _msg = prp_decrypt(prp_key, _ct)
        self.assertEqual(prp_pt, _msg)

    def test_argon_hkdf_with_internal_argon2i_bzero(self):
        salt_a1 = DEFAULT_HKDF_SALT
        salt_a2 = b'\x01' * 32
        passphrase_a1 = b'passphrase'
        passphrase_a2 = b'passphrase'
        _a1 = argon2i(passphrase_a1, salt_a1)
        self.assertEqual(a1, _a1)
        _a2 = argon2i(passphrase_a2, salt_a2)
        self.assertEqual(a2, _a2)
        passphrase_a1_copy = bytes(g for g in passphrase_a1)
        passphrase_a2_copy = bytes(h for h in passphrase_a1)
        _pdk1 = hkdf(argon2i(passphrase_a1_copy, salt_a1, _wipe=True), salt_a1).expand(b'', 32)
        _pdk2 = hkdf(argon2i(passphrase_a2_copy, salt_a1, _wipe=True), salt_a2).expand(b'', 32)
        self.assertEqual(passphrase_a1_copy, passphrase_a2_copy)
        self.assertEqual(pdk1, _pdk1)
        self.assertEqual(pdk2, _pdk2)

    def test_argon_hkdf_without_internal_argon2i_bzero(self):
        salt_a1 = DEFAULT_HKDF_SALT
        salt_a2 = b'\x01' * 32
        passphrase_a1 = b'passphrase'
        passphrase_a2 = b'passphrase'
        _a1 = argon2i(passphrase_a1, salt_a1)
        self.assertEqual(a1, _a1)
        _a2 = argon2i(passphrase_a2, salt_a2)
        self.assertEqual(a2, _a2)
        _pdk1 = hkdf(argon2i(passphrase_a1, salt_a1, _wipe=False), salt_a1).expand(b'', 32)
        _pdk2 = hkdf(argon2i(passphrase_a2, salt_a1, _wipe=False), salt_a2).expand(b'', 32)
        self.assertEqual(pdk1, _pdk1)
        self.assertEqual(pdk2, _pdk2)

    def test_argon_single_char_memory_corruption(self):
        passphrase = b'p'
        salt = b'\x00' * 32
        a1 = argon2i(passphrase, salt, _wipe=True)

        salt = b'\x00' * 32
        passphrase = b'p'
        # Here we do not zero memory
        a2 = argon2i(passphrase, salt, _wipe=False)
        self.assertEqual(passphrase, b'p')
        self.assertEqual(salt, b'\x00' * 32)

        # Here we do zero memory
        self.assertEqual(passphrase, b'p')
        a3 = argon2i(passphrase, salt, _wipe=True)
        # The salt value remains 32 bytes
        self.assertEqual(salt, b'\x00' * 32)
        # The password goes from length 32 to length 1
        self.assertEqual(passphrase, b'\x00')

        self.assertEqual(a3, a2)
        self.assertNotEqual(a1, a2)
