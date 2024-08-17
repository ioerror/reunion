import os
import unittest

from reunion.primitives import aead_decrypt, aead_encrypt, argon2i
from reunion.primitives import generate_hidden_key_pair, Hash
from reunion.primitives import highctidh_deterministic_rng, hkdf, prp_decrypt
from reunion.primitives import prp_encrypt, unelligator, x25519

# Static test vectors
esk_a_seed = bytes.fromhex('e60498784e625a21d6285ee7a6144a0464dab10120b11f3794dd00e36da98c27')
esk_a = bytes.fromhex('f988f98f466ff8585598ad12956b385e6090e9fdfdac3ca17c77cad61ac8a430')
epk_a = bytes.fromhex('b92b89f7bea9d4deee61a07a930edc4f50a7e5eb38a6b5667f44dea5032703f5')
pk_a = bytes.fromhex('95fa3b2a70e42f4dc66117a02680ddfe45a55451654e7bd685ba2a4179289104')
esk_b_seed = bytes.fromhex('f50a1248b83f07c6232485508bc889352531a5387b18580d8f6685c352c454d2')
esk_b = bytes.fromhex('8ba80391df517ee3e3901046adf8c4aab8068cb9a569349e98ee8241b7fde770')
epk_b = bytes.fromhex('9c1c114b9f11908e6f046805c97a1ba8261e3a3a34cfca9a72d20f3701c553b1')
pk_b = bytes.fromhex('6d4d5132efddd1ccfdb42178d5cab993617b50a43e24a0b6679e0d6f17ddae1e')
aead_key = bytes.fromhex('2e845d6aa49d50fd388c9c7072aac817ec71e323a4d32532263a757c98404c8a')
aead_msg = bytes.fromhex('5245554e494f4e20697320666f722052656e64657a766f7573')
aead_ad = bytes.fromhex('e7bab55e065f23a4cb74ce9e6c02aed0c31c90cce16b3d6ec7c98a3ed65327cf')
aead_ct = bytes.fromhex('a405c2d42d576140108a84a08a9c8ee140d5c72c5332ec6713cf7c6fb27719a9007606f7834853245b')
prp_key = bytes.fromhex('37620a87ccc74b5e425164371603bd96c794594b7d07e4887bae6c7f08fa9659')
prp_msg = bytes.fromhex('5245554e494f4e20697320666f722052656e64657a766f75732e2e2e20505250')
prp_ct = bytes.fromhex('a74b26c607e56b1f59a84d91ff738e6b55f94ceedc418118347c2b733e5ebe92')
a1 = bytes.fromhex('fbe519150e9cb72815951bb49fee855c1ba3f1b8b6cdcb48013141eeb52203ba')
a2 = bytes.fromhex('991f924198039449b27f61490d3a75ecf2a57795179801a40f61953453b748c9')
pdk1 = bytes.fromhex('2938568958db545bf6a9a9f4b6b0f5567f1b7d45c5357c7221f80bd9dec011f3')
pdk2 = bytes.fromhex('3e237c4afe43755a9a932e02233470ef4f44877341709837ae3acf680c1a301a')

class TestPrimitivesStaticVectors(unittest.TestCase):
    def test_aead_encrypt(self):
        _aead_ct = aead_encrypt(aead_key, aead_msg, aead_ad)
        self.assertEqual(aead_ct, _aead_ct)

    def test_aead_decrypt(self):
        _aead_ct = aead_encrypt(aead_key, aead_msg, aead_ad)
        _aead_pt = aead_decrypt(aead_key, aead_ct, aead_ad)
        self.assertEqual(aead_msg, _aead_pt)

    def test_elligator(self):
        # We must copy these because generate_hidden_key_pair will bzero the memory
        esk_a_seed_copy = bytes(a for a in esk_a_seed)
        esk_b_seed_copy = bytes(b for b in esk_b_seed)
        _epk_a, _esk_a = generate_hidden_key_pair(esk_a_seed_copy)
        _epk_b, _esk_b = generate_hidden_key_pair(esk_b_seed_copy)
        self.assertEqual(epk_a, _epk_a)
        self.assertEqual(esk_a, _esk_a)
        self.assertEqual(epk_b, _epk_b)
        self.assertEqual(esk_b, _esk_b)

    def test_unelligator(self):
        # We must copy these because generate_hidden_key_pair will bzero the memory
        esk_a_seed_copy = bytes(c for c in esk_a_seed)
        esk_b_seed_copy = bytes(d for d in esk_b_seed)
        _epk_a, _sk_a = generate_hidden_key_pair(esk_a_seed_copy)
        _epk_b, _sk_b = generate_hidden_key_pair(esk_b_seed_copy)
        self.assertEqual(epk_a, _epk_a)
        self.assertEqual(epk_b, _epk_b)
        self.assertEqual(pk_a, unelligator(_epk_a))
        self.assertEqual(pk_b, unelligator(_epk_b))

    def test_elligator_dh(self):
        # We must copy these because generate_hidden_key_pair will bzero the memory
        esk_a_seed_copy = bytes(e for e in esk_a_seed)
        esk_b_seed_copy = bytes(f for f in esk_b_seed)
        _epk_a, _esk_a = generate_hidden_key_pair(esk_a_seed_copy)
        _epk_b, _esk_b = generate_hidden_key_pair(esk_b_seed_copy)
        ss1 = x25519(esk_a, unelligator(epk_b))
        ss2 = x25519(esk_b, unelligator(epk_a))
        self.assertEqual(ss1, ss2)

    def test_prp(self):
        _ct = prp_encrypt(prp_key, prp_msg)
        self.assertEqual(prp_ct, _ct)
        _msg = prp_decrypt(prp_key, _ct)
        self.assertEqual(prp_msg, _msg)

    def test_argon_hkdf_with_internal_argon2i_bzero(self):
        salt_a1 = b'\x00' * 32
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
        salt_a1 = b'\x00' * 32
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
