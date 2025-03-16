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

from rendez.vous.reunion.constants import DEFAULT_ARGON_SALT, DEFAULT_HKDF_SALT

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

# Deterministic Session vectors
dsession_salt: bytes = DEFAULT_HKDF_SALT
dsession_seed: bytes = bytes.fromhex('0123456789')
dsession_seed_a: bytes = b'alice' + dsession_seed
dsession_seed_b: bytes = b'bob' + dsession_seed
dsession_passphrase: bytes = b'reunion is for rendezvous'
dsession_dh_seed_a: bytes = bytes.fromhex('324d226178bc2e0f625dcb91d83cb7fd8ed710755695559927fc75edff85a96b') # bytes(Hash(dsession_seed_a + b"diffie-hellman")).hex()
dsession_dh_seed_b: bytes = bytes.fromhex('79455c612276de0d2d511744936efc30c4cbb0e9715b737dbaca8d7d4acaf8b0') # bytes(Hash(dsession_seed_b + b"diffie-hellman")).hex()

# To aid developers who do not have a highctidh seed keygen interface we
# include the following vectors and document their generation
# from rendez.vous.reunion.__vectors__ import dsession_seed # bytes.fromhex('0123456789')
# from rendez.vous.reunion.primitives import Hash
# from rendez.vous.reunion.primitives import generate_ctidh_key_pair
# ctidh_seed=bytes(Hash(dsession_seed + b'ctidh'))
# pk, sk = generate_ctidh_key_pair(seed=ctidh_seed)
# pk_bytes = bytes(pk)
# sk_bytes = bytes(sk)
# pk_bytes.hex()
# '4bcac087636d43ba832e08b95fd2a3f39f399baa9b6104f7b77ce224d1542f1480e6129a77e321da2c140da6fc084fcf16c57223a47913be2a3bddba78f09a012cfbe63cd8e7dd1f6253851067a17d725407ce12b8c115e977bdee9035c4981e0eca26df65f6b27cd0dd5bc64b765d890ecf9c486148243851bbf92d1df7e80d'
# sk_bytes.hex()
# '0200020000fffe00fe00ff00010001ff000001ffff0100ff000202ffff0000ff01000101fe000002000200fe0000fffffffd0000ff01000000ff0001fe0100ff000101010100ffff00ff00ff000301010100ffffff010300ff00fe00000201000000010101000000ffffff010001010100010100ffff000001ff00000000ff000100'
dsession_ctidh_seed_a: bytes =  bytes.fromhex('72122f0b686abcbe62a15e2bc819b97e30f66da2baec7c9fb4372ff74e7883e9') # bytes(Hash(dsession_seed_a + b"ctidh")).hex()
dsession_ctidh_seed_b: bytes =  bytes.fromhex('be3e954aa84dc8526dce9774f099175f9bc86e0cca0eb357d5b79484678e21c6') # bytes(Hash(dsession_seed_b + b"ctidh")).hex()

dsession_ctidh_seed_sk_a: bytes = bytes.fromhex('0200fd0000ff01fffe00fe000100fe00000001fefe00010000fd0001000000fd0000fe00ff0200fffdff010000ff000201ff00fe0100ff000000010000ff030000010100020101ff0002ff00ff0001000002000002ff0101ff010000ff01020100000000fe0000ff000100ff00ff000100ff000000ff000001ff02ff010000000100') # _, sk = generate_ctidh_key_pair(seed=dsession_ctidh_seed_a); bytes(sk).hex()
dsession_ctidh_seed_pk_a: bytes = bytes.fromhex('45a65c2972ddf00acf524db29bf9394ce79a17fdb08f1f135dd8b3296d4d83281381b039312a8fbb19a982bea2f55b71e7998c125aeea20eebbbd683b556f35bf250c0b07c7b59251b36610110aa506ddeb8400df688f2560fc9ab8c830786acd47a6e356ae9f9bbece3df3c4b6e083bde2a955fe583e79071c05e8348280104') # pk, _ = generate_ctidh_key_pair(seed=dsession_ctidh_seed_a); bytes(pk).hex()

dsession_ctidh_seed_sk_b: bytes = bytes.fromhex('01ff00fffd0100000004ff040000000002020100ff0002ff000000020001fd0000ff00ff010301000103000000000000fe03ff0000ffffff02010000ff00fd01010002ff00fe010100ff01ffffff00ff0100010100030100000000000100fc00fe00000001fe0000010000ff000200010100000000000200fe01ff00ff0001000000') # _, sk = generate_ctidh_key_pair(seed=dsession_ctidh_seed_b); bytes(sk).hex()
dsession_ctidh_seed_pk_b: bytes = bytes.fromhex('abfea79fc55ef3557b3e39fe01613b2d789e01d26a018d02e2388603a734110e478699d7e90292a393909009975889be1719aff29edbf6a3ec170589689840cf615fff22aa1b37abb9d9ba010953ee154c78f9e0eee28d625a7d2df73b5aa22b502b5040edb7fe8feb48b13541fb647974a3e5d24441e9021da8ad37fefeca05') # pk, _ = generate_ctidh_key_pair(seed=dsession_ctidh_seed_b); bytes(pk).hex()

dsession_gamma_seed_a: bytes = bytes.fromhex('6ba51aada3aca321534d73733860b59ea63a9746dc0bd3b00c09f5eb6feb508a') # bytes(Hash(dsession_seed_a + b"gamma")).hex()
dsession_gamma_seed_b: bytes = bytes.fromhex('75884ac7ad53827bb7bf280bc016191bcdfb6ef80c434e8155ef102e8db258ce') # bytes(Hash(dsession_seed_b + b"gamma")).hex()

dsession_delta_seed_a: bytes = bytes.fromhex('d5d0587357083f14ba559f775432b948f30e8e658ff866e2873b7768b3fa8ba5') # bytes(Hash(dsession_seed_a + b"delta")).hex()
dsession_delta_seed_b: bytes = bytes.fromhex('33f1732459211686a4acf28f0cccaa0b8cb9f57b5398765481cd073297a38449') # bytes(Hash(dsession_seed_b + b"delta")).hex()

dsession_dummy_seed_a: bytes = bytes.fromhex('a99f86fb345e9d833ce5534df39beb076f48c4cb62cdb940e23324df510065ea') # bytes(Hash(dsession_seed_a + b"dummy")).hex()
dsession_dummy_seed_b: bytes = bytes.fromhex('9e7a7f9f95146604a206a1a577f6d34dc9550054ae635d955eef9b33a8a899b9') # bytes(Hash(dsession_seed_b + b"dummy")).hex()

dsession_tweak_a: int = 32 # Hash(dsession_seed_a + b"tweaked")[0]
dsession_tweak_b: int = 243 # Hash(dsession_seed_b + b"tweaked")[0]

dsession_payload_A: bytes = bytes.fromhex('f06b1a5db24a0394fb28a53de02059fc34166424e40e64d7a857efdc38f158f1') # bytes(Hash(b"deterministic session payload A" + dsession_seed_a)).hex()
dsession_payload_B: bytes = bytes.fromhex('03475cb34f16bceabe4945197cf2a0064eb3a28601fc9489e613debe5e282e1d') # bytes(Hash(b"deterministic session payload B" + dsession_seed_b)).hex()
# These outputs are the known values for the generated Protocol messages
dsession_AT1: bytes = bytes.fromhex('e668c52c59cacc162dc6e36dcf42b6ee861a5765b45d8f83c25447c25fb3b49245a65c2972ddf00acf524db29bf9394ce79a17fdb08f1f135dd8b3296d4d83281381b039312a8fbb19a982bea2f55b71e7998c125aeea20eebbbd683b556f35bf250c0b07c7b59251b36610110aa506ddeb8400df688f2560fc9ab8c830786acd47a6e356ae9f9bbece3df3c4b6e083bde2a955fe583e79071c05e834828010496515ab6b675874566529d859a131b50b05bebaa197fe1920b42d1eff6fecc4aac538ab23f58f17b80d131cdb5e112c53c3bd6e4f0cf2df35f1e7d668b2ad1df')
dsession_AT1_alpha: bytes = bytes.fromhex('e668c52c59cacc162dc6e36dcf42b6ee861a5765b45d8f83c25447c25fb3b492')
dsession_AT1_beta: bytes = bytes.fromhex('45a65c2972ddf00acf524db29bf9394ce79a17fdb08f1f135dd8b3296d4d83281381b039312a8fbb19a982bea2f55b71e7998c125aeea20eebbbd683b556f35bf250c0b07c7b59251b36610110aa506ddeb8400df688f2560fc9ab8c830786acd47a6e356ae9f9bbece3df3c4b6e083bde2a955fe583e79071c05e8348280104')
dsession_AT1_gamma: bytes = bytes.fromhex('96515ab6b675874566529d859a131b50')
dsession_AT1_delta: bytes = bytes.fromhex('b05bebaa197fe1920b42d1eff6fecc4aac538ab23f58f17b80d131cdb5e112c53c3bd6e4f0cf2df35f1e7d668b2ad1df')
dsession_AT2: bytes = bytes.fromhex('f1872b8c7d23cc9702b4b118d5bb60bfc25f5c54c177fd7929c4f5af0a68eae5')
dsession_AT3: bytes = bytes.fromhex('74d2fe513e03e8fbe44385164e964f536e0c32c6af07ba2a71596a1fec33a711')
dsession_BT1: bytes = bytes.fromhex('913b88079eab1350bf1bb9f8733dc001f32cf5438448c0adaa79d20537a9964eabfea79fc55ef3557b3e39fe01613b2d789e01d26a018d02e2388603a734110e478699d7e90292a393909009975889be1719aff29edbf6a3ec170589689840cf615fff22aa1b37abb9d9ba010953ee154c78f9e0eee28d625a7d2df73b5aa22b502b5040edb7fe8feb48b13541fb647974a3e5d24441e9021da8ad37fefeca053bfeccc3e28e9e9bc334ea418a31a2bbbd2a144eb045a30f91c3bd6cb39f82c703125f7620e44935f3ed76e540ca839980f208afa40d2773eb60b35ed8ac9a26')
dsession_BT1_alpha: bytes = bytes.fromhex('913b88079eab1350bf1bb9f8733dc001f32cf5438448c0adaa79d20537a9964e')
dsession_BT1_beta: bytes = bytes.fromhex('abfea79fc55ef3557b3e39fe01613b2d789e01d26a018d02e2388603a734110e478699d7e90292a393909009975889be1719aff29edbf6a3ec170589689840cf615fff22aa1b37abb9d9ba010953ee154c78f9e0eee28d625a7d2df73b5aa22b502b5040edb7fe8feb48b13541fb647974a3e5d24441e9021da8ad37fefeca05')
dsession_BT1_gamma: bytes = bytes.fromhex('3bfeccc3e28e9e9bc334ea418a31a2bb')
dsession_BT1_delta: bytes = bytes.fromhex('bd2a144eb045a30f91c3bd6cb39f82c703125f7620e44935f3ed76e540ca839980f208afa40d2773eb60b35ed8ac9a26')
dsession_BT2: bytes = bytes.fromhex('12424018c8a15ca1d88247ef1285b3f8d36fffe33090a5af87b453acb2e7626e')
dsession_BT3: bytes = bytes.fromhex('4e01f3a88fa886b41f786dab1ccf82f94a73082bbb8444c0408b875187355b9a')
