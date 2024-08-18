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
>>> len(prp_pt) == 32
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
>>> len(ReunionSession_A_msg) == 47
True
>>> len(ReunionSession_B_msg) == 439
True
>>> len(ReunionSession_passphrase) == 10
True
>>> len(ReunionSession_four_party_A_msg) == 9
True
>>> len(ReunionSession_four_party_B_msg) == 9
True
>>> len(ReunionSession_four_party_C_msg) == 9
True
>>> len(ReunionSession_four_party_D_msg) == 9
True
"""

from reunion.constants import DEFAULT_ARGON_SALT, DEFAULT_HKDF_SALT

argon2i_salt: bytes = DEFAULT_ARGON_SALT
argon2i_password: bytes = bytes(b'REUNION is for rendezvous')
argon2i_hash: bytes = bytes.fromhex('131f782cae57faa5055277621aec7c3984fbef048c8d183848f3def2697c7acd')

hkdf_salt: bytes = DEFAULT_HKDF_SALT
hkdf_key = bytes.fromhex('513e3c670ab00a436de0d801b07e085149ef205d27807d656253cd9a08a7bdf0')
hkdf_pdk = bytes.fromhex('9a3b6d37987a9ea05709a9ef2b8c8e4e0b0c51088cb6edc93bcacf4ff36fda1c')

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
prp_pt: bytes = bytes.fromhex('5245554e494f4e20697320666f722052656e64657a766f75732e2e2e20505250')
prp_ct: bytes = bytes.fromhex('a74b26c607e56b1f59a84d91ff738e6b55f94ceedc418118347c2b733e5ebe92')
a1: bytes = bytes.fromhex('fbe519150e9cb72815951bb49fee855c1ba3f1b8b6cdcb48013141eeb52203ba')
a2: bytes = bytes.fromhex('991f924198039449b27f61490d3a75ecf2a57795179801a40f61953453b748c9')
pdk1: bytes = bytes.fromhex('2938568958db545bf6a9a9f4b6b0f5567f1b7d45c5357c7221f80bd9dec011f3')
pdk2: bytes = bytes.fromhex('3e237c4afe43755a9a932e02233470ef4f44877341709837ae3acf680c1a301a')
h: bytes = bytes.fromhex('1ffb4f05cb3e841d44079afbcc51f62edbd7092294edac59846b8519f48c5a45')
h_preimage: bytes = bytes(b'REUNION is for rendezvous')

x25519_sk_seed_a: bytes = bytes.fromhex('a0f5f44533e439e9aced82d38eaab109df03c6f26833530343b1fac080fc6287')
x25519_sk_seed_b: bytes = bytes.fromhex('31a09e46971b29b5a9c59706c973d4f7f00361b442fd08b4724103b0b7f3ab24')
highctidh_drng_seed: bytes = bytes.fromhex('163d228fd8182bdb0e259fbf0ed5a776b47126ba4d61d774cce87f6546f8d677')
highctidh_context: int = 1

#  generate_hidden_key_pair
hidden_key_pair_seed: bytes = bytes.fromhex('5aace7eec7f3a5ead537d23cbee29ed1003f3aa73d9a7a97b72d249b9119d409')
hidden_key_pair_pk_a: bytes = bytes.fromhex('dd134b5b287d6698f8db9cd58f7f4ccd2293103010fd2e7a11ed984debe2cde6')
hidden_key_pair_sk_a: bytes = bytes.fromhex('d6b067b9b98e9616dde7e9aa52bd75f13493897ec4908230508b5abb293a5140')

# generate_ctidh_key_pair
ctidh_key_pair_seed: bytes = bytes.fromhex('4141414141414141414141414141414141414141414141414141414141414141')
ctidh_key_pair_seed_pk: bytes = bytes.fromhex('a0e897b81374cc17aa917637cda97a56377c9b7bdbe86a53a6f01ce35a0366684568e7de4e38000214a2600ac6a9d07b2379ccccdf0c7ca94ff1288eeb06347101be8cabd24543315eb1d00596d05ebfcde4f13e076bc30635db8aa249b55c992ecb24f9ba128a90b8b1d93420ca8f6454572d4c3b492027b942fb45d1e5a20e')
ctidh_key_pair_seed_sk: bytes = bytes.fromhex('01fffd00ff000000ff03ff00fd00ff00fe00000000ffff0100ffff01ff0200ff0100ffff01010001fffffe0001020001010000ff03000100ff00ff0000fd0000fe0003010100ff0302000000ff000000fe000002010001ffff00000000fe03000001ff0001fe010000010000ff00ff0100ffff00010101000000000000000100ff00')

t1_empty_id: bytes = bytes.fromhex('786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419')

ReunionSession_A_msg: bytes = "Mr. Watson — Come here — I want to see you.".encode()
ReunionSession_B_msg: bytes = """\
when a man gives his order to produce a definite result and stands by that
order it seems to have the effect of giving him what might be termed a second
sight which enables him to see right through ordinary problems. What this power
is I cannot say; all I know is that it exists and it becomes available only
when a man is in that state of mind in which he knows exactly what he wants and
is fully determined not to quit until he finds it.""".encode()
ReunionSession_passphrase: bytes = b"passphrase"
ReunionSession_passphrase1: bytes = b"passphrase1"
ReunionSession_passphrase2: bytes = b"passphrase2"
ReunionSession_four_party_A_msg: bytes = b"a message"
ReunionSession_four_party_B_msg: bytes = b"b message"
ReunionSession_four_party_C_msg: bytes = b"c message"
ReunionSession_four_party_D_msg: bytes = b"d message"

