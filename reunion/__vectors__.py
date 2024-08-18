"""
Test vectors for internal use and to assist in cross verification of REUNION
protocol implementations.

>>> len(esk_a_seed) == 32
True
>>> len(esk_a) == 32
True
>>> len(epk_a) == 32
True
>>> len(pk_a) == 32
True
>>> len(esk_b_seed) == 32
True
>>> len(esk_b) == 32
True
>>> len(epk_b) == 32
True
>>> len(pk_b) == 32
True
>>> len(aead_key) == 32
True
>>> len(aead_pt) == 25
True
>>> len(aead_ad) == 32
True
>>> len(aead_ct) == 41
True
>>> len(prp_key) == 32
True
>>> len(prp_msg) == 32
True
>>> len(prp_ct) == 32
True
>>> len(a1) == 32
True
>>> len(a2) == 32
True
>>> len(pdk1) == 32
True
>>> len(pdk2) == 32
True
>>> len(h) == 32
True
"""

from reunion.constants import DEFAULT_HKDF_SALT

hkdf_salt: bytes = DEFAULT_HKDF_SALT

esk_a_seed: bytes = bytes.fromhex('e60498784e625a21d6285ee7a6144a0464dab10120b11f3794dd00e36da98c27')
esk_a: bytes = bytes.fromhex('f988f98f466ff8585598ad12956b385e6090e9fdfdac3ca17c77cad61ac8a430')
epk_a: bytes = bytes.fromhex('b92b89f7bea9d4deee61a07a930edc4f50a7e5eb38a6b5667f44dea5032703f5')
pk_a: bytes = bytes.fromhex('95fa3b2a70e42f4dc66117a02680ddfe45a55451654e7bd685ba2a4179289104')
esk_b_seed: bytes = bytes.fromhex('f50a1248b83f07c6232485508bc889352531a5387b18580d8f6685c352c454d2')
esk_b: bytes = bytes.fromhex('8ba80391df517ee3e3901046adf8c4aab8068cb9a569349e98ee8241b7fde770')
epk_b: bytes = bytes.fromhex('9c1c114b9f11908e6f046805c97a1ba8261e3a3a34cfca9a72d20f3701c553b1')
pk_b: bytes = bytes.fromhex('6d4d5132efddd1ccfdb42178d5cab993617b50a43e24a0b6679e0d6f17ddae1e')
aead_key: bytes = bytes.fromhex('2e845d6aa49d50fd388c9c7072aac817ec71e323a4d32532263a757c98404c8a')
aead_pt: bytes = bytes.fromhex('5245554e494f4e20697320666f722052656e64657a766f7573')
aead_ad: bytes = bytes.fromhex('e7bab55e065f23a4cb74ce9e6c02aed0c31c90cce16b3d6ec7c98a3ed65327cf')
aead_ct: bytes = bytes.fromhex('a405c2d42d576140108a84a08a9c8ee140d5c72c5332ec6713cf7c6fb27719a9007606f7834853245b')
prp_key: bytes = bytes.fromhex('37620a87ccc74b5e425164371603bd96c794594b7d07e4887bae6c7f08fa9659')
prp_msg: bytes = bytes.fromhex('5245554e494f4e20697320666f722052656e64657a766f75732e2e2e20505250')
prp_ct: bytes = bytes.fromhex('a74b26c607e56b1f59a84d91ff738e6b55f94ceedc418118347c2b733e5ebe92')
hkdf_key = bytes.fromhex('513e3c670ab00a436de0d801b07e085149ef205d27807d656253cd9a08a7bdf0')
hkdf_pdk = bytes.fromhex('9a3b6d37987a9ea05709a9ef2b8c8e4e0b0c51088cb6edc93bcacf4ff36fda1c')
a1: bytes = bytes.fromhex('fbe519150e9cb72815951bb49fee855c1ba3f1b8b6cdcb48013141eeb52203ba')
a2: bytes = bytes.fromhex('991f924198039449b27f61490d3a75ecf2a57795179801a40f61953453b748c9')
pdk1: bytes = bytes.fromhex('2938568958db545bf6a9a9f4b6b0f5567f1b7d45c5357c7221f80bd9dec011f3')
pdk2: bytes = bytes.fromhex('3e237c4afe43755a9a932e02233470ef4f44877341709837ae3acf680c1a301a')
h: bytes = bytes.fromhex('1ffb4f05cb3e841d44079afbcc51f62edbd7092294edac59846b8519f48c5a45')
h_preimage: bytes = bytes(b'REUNION is for rendezvous')
