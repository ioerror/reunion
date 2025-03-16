import os
import unittest
from dataclasses import dataclass, asdict
from rendez.vous.reunion.primitives import Hash
from rendez.vous.reunion.session import ReunionSession, DEFAULT_HKDF_SALT
from rendez.vous.reunion.__vectors__ import dsession_salt, dsession_passphrase
from rendez.vous.reunion.__vectors__ import dsession_seed_a, dsession_seed_b
from rendez.vous.reunion.__vectors__ import dsession_payload_A, dsession_payload_B
from rendez.vous.reunion.__vectors__ import dsession_seed_a, dsession_seed_b
from rendez.vous.reunion.__vectors__ import dsession_dh_seed_a, dsession_dh_seed_b
from rendez.vous.reunion.__vectors__ import dsession_ctidh_seed_a, dsession_ctidh_seed_b
from rendez.vous.reunion.__vectors__ import dsession_gamma_seed_a, dsession_gamma_seed_b
from rendez.vous.reunion.__vectors__ import dsession_ctidh_seed_sk_a, dsession_ctidh_seed_pk_a
from rendez.vous.reunion.__vectors__ import dsession_ctidh_seed_sk_b, dsession_ctidh_seed_pk_b
from rendez.vous.reunion.__vectors__ import dsession_delta_seed_a, dsession_delta_seed_b
from rendez.vous.reunion.__vectors__ import dsession_dummy_seed_a, dsession_dummy_seed_b
from rendez.vous.reunion.__vectors__ import dsession_tweak_a, dsession_tweak_b
from rendez.vous.reunion.__vectors__ import dsession_AT1, dsession_AT2, dsession_AT3
from rendez.vous.reunion.__vectors__ import dsession_AT1_alpha, dsession_AT1_beta
from rendez.vous.reunion.__vectors__ import dsession_AT1_gamma, dsession_AT1_delta
from rendez.vous.reunion.__vectors__ import dsession_BT1, dsession_BT2, dsession_BT3
from rendez.vous.reunion.__vectors__ import dsession_BT1_alpha, dsession_BT1_beta
from rendez.vous.reunion.__vectors__ import dsession_BT1_gamma, dsession_BT1_delta

def DeterministicSession(
    passphrase: bytes, payload: bytes, seed: bytes, salt=DEFAULT_HKDF_SALT
):
    # seed = bytes.fromhex('0123456789')
    assert dsession_salt == DEFAULT_HKDF_SALT

    assert dsession_seed_a == seed or dsession_seed_b == seed

    assert dsession_dh_seed_a == bytes(Hash(seed + b"diffie-hellman")) or \
           dsession_dh_seed_b == bytes(Hash(seed + b"diffie-hellman"))

    assert dsession_ctidh_seed_a == bytes(Hash(seed + b"ctidh")) or \
           dsession_ctidh_seed_b == bytes(Hash(seed + b"ctidh"))

    assert dsession_gamma_seed_a == bytes(Hash(seed + b"gamma")) or \
           dsession_gamma_seed_b == bytes(Hash(seed + b"gamma"))

    assert dsession_delta_seed_a == bytes(Hash(seed + b"delta")) or \
           dsession_delta_seed_b == bytes(Hash(seed + b"delta"))

    assert dsession_dummy_seed_a == bytes(Hash(seed + b"dummy")) or \
           dsession_dummy_seed_b == bytes(Hash(seed + b"dummy"))

    assert type(dsession_tweak_a) == type(Hash(seed + b"tweaked")[0]) and \
           type(dsession_tweak_b) == type(Hash(seed + b"tweaked")[0])

    assert dsession_tweak_a == int(Hash(seed + b"tweaked")[0]) or \
           dsession_tweak_b == int(Hash(seed + b"tweaked")[0])

    assert dsession_passphrase == b'reunion is for rendezvous'

    assert dsession_payload_A == bytes(Hash(b"deterministic session payload A" + seed)) or \
           dsession_payload_B == bytes(Hash(b"deterministic session payload B" + seed))

    if seed == dsession_seed_a:
      dh_seed=dsession_dh_seed_a
      ctidh_seed=dsession_ctidh_seed_a
      gamma_seed=dsession_gamma_seed_a
      delta_seed=dsession_delta_seed_a
      dummy_seed=dsession_dummy_seed_a
      tweak=dsession_tweak_a
    if seed == dsession_seed_b:
      dh_seed=dsession_dh_seed_b
      ctidh_seed=dsession_ctidh_seed_b
      gamma_seed=dsession_gamma_seed_b
      delta_seed=dsession_delta_seed_b
      dummy_seed=dsession_dummy_seed_b
      tweak=dsession_tweak_b

    return ReunionSession(
        payload=payload,
        salt=salt,
        passphrase=passphrase,
        dh_seed=dh_seed,
        ctidh_seed=ctidh_seed,
        gamma_seed=gamma_seed,
        delta_seed=delta_seed,
        dummy_seed=dummy_seed,
        tweak=tweak,
    )


@dataclass
class SessionKAT:
    """
    This is a step toward we way that we could have regeneratable data-driven
    known-answer tests.

    Ideally the actual KATs could be read from a data file rather than this
    docstring, and could also include serialized secret keys (rather than just
    their seed as it is here now) so that other implementations could load them
    from the data file and test reunion compatibility without necessarily
    needing to be completely seed-compatible when generating the keys.

    >>> SessionKAT.generate_from_seed(bytes.fromhex('0123456789'))
          seed: 0123456789
    passphrase: 7265756e696f6e20697320666f722072656e64657a766f7573
     payload_A: f06b1a5db24a0394fb28a53de02059fc34166424e40e64d7a857efdc38f158f1
     payload_B: 03475cb34f16bceabe4945197cf2a0064eb3a28601fc9489e613debe5e282e1d
           AT1: e668c52c59cacc162dc6e36dcf42b6ee861a5765b45d8f83c25447c25fb3b49245a65c2972ddf00acf524db29bf9394ce79a17fdb08f1f135dd8b3296d4d83281381b039312a8fbb19a982bea2f55b71e7998c125aeea20eebbbd683b556f35bf250c0b07c7b59251b36610110aa506ddeb8400df688f2560fc9ab8c830786acd47a6e356ae9f9bbece3df3c4b6e083bde2a955fe583e79071c05e834828010496515ab6b675874566529d859a131b50b05bebaa197fe1920b42d1eff6fecc4aac538ab23f58f17b80d131cdb5e112c53c3bd6e4f0cf2df35f1e7d668b2ad1df
     AT1_alpha: e668c52c59cacc162dc6e36dcf42b6ee861a5765b45d8f83c25447c25fb3b492
      AT1_beta: 45a65c2972ddf00acf524db29bf9394ce79a17fdb08f1f135dd8b3296d4d83281381b039312a8fbb19a982bea2f55b71e7998c125aeea20eebbbd683b556f35bf250c0b07c7b59251b36610110aa506ddeb8400df688f2560fc9ab8c830786acd47a6e356ae9f9bbece3df3c4b6e083bde2a955fe583e79071c05e8348280104
     AT1_gamma: 96515ab6b675874566529d859a131b50
     AT1_delta: b05bebaa197fe1920b42d1eff6fecc4aac538ab23f58f17b80d131cdb5e112c53c3bd6e4f0cf2df35f1e7d668b2ad1df
           AT2: f1872b8c7d23cc9702b4b118d5bb60bfc25f5c54c177fd7929c4f5af0a68eae5
           AT3: 74d2fe513e03e8fbe44385164e964f536e0c32c6af07ba2a71596a1fec33a711
           BT1: 913b88079eab1350bf1bb9f8733dc001f32cf5438448c0adaa79d20537a9964eabfea79fc55ef3557b3e39fe01613b2d789e01d26a018d02e2388603a734110e478699d7e90292a393909009975889be1719aff29edbf6a3ec170589689840cf615fff22aa1b37abb9d9ba010953ee154c78f9e0eee28d625a7d2df73b5aa22b502b5040edb7fe8feb48b13541fb647974a3e5d24441e9021da8ad37fefeca053bfeccc3e28e9e9bc334ea418a31a2bbbd2a144eb045a30f91c3bd6cb39f82c703125f7620e44935f3ed76e540ca839980f208afa40d2773eb60b35ed8ac9a26
     BT1_alpha: 913b88079eab1350bf1bb9f8733dc001f32cf5438448c0adaa79d20537a9964e
      BT1_beta: abfea79fc55ef3557b3e39fe01613b2d789e01d26a018d02e2388603a734110e478699d7e90292a393909009975889be1719aff29edbf6a3ec170589689840cf615fff22aa1b37abb9d9ba010953ee154c78f9e0eee28d625a7d2df73b5aa22b502b5040edb7fe8feb48b13541fb647974a3e5d24441e9021da8ad37fefeca05
     BT1_gamma: 3bfeccc3e28e9e9bc334ea418a31a2bb
     BT1_delta: bd2a144eb045a30f91c3bd6cb39f82c703125f7620e44935f3ed76e540ca839980f208afa40d2773eb60b35ed8ac9a26
           BT2: 12424018c8a15ca1d88247ef1285b3f8d36fffe33090a5af87b453acb2e7626e
           BT3: 4e01f3a88fa886b41f786dab1ccf82f94a73082bbb8444c0408b875187355b9a
    """

    seed: bytes = None
    passphrase: bytes = None
    payload_A: bytes = None
    payload_B: bytes = None
    AT1: bytes = None
    AT1_alpha: bytes = None
    AT1_beta: bytes = None
    AT1_gamma: bytes = None
    AT1_delta: bytes = None
    AT2: bytes = None
    AT3: bytes = None
    BT1: bytes = None
    BT1_alpha: bytes = None
    BT1_beta: bytes = None
    BT1_gamma: bytes = None
    BT1_delta: bytes = None
    BT2: bytes = None
    BT3: bytes = None

    @classmethod
    def generate_from_seed(cls, seed):
        self = cls()
        self.seed = seed
        self.passphrase = dsession_passphrase
        self.payload_A = dsession_payload_A
        self.payload_B = dsession_payload_B
        A = DeterministicSession(self.passphrase, self.payload_A, dsession_seed_a)
        B = DeterministicSession(self.passphrase, self.payload_B, dsession_seed_b)
        self.AT1 = A.t1
        self.AT1_alpha = A.t1.alpha
        self.AT1_beta = A.t1.beta
        self.AT1_gamma = A.t1.gamma
        self.AT1_delta = A.t1.delta
        self.BT1 = B.t1
        self.BT1_alpha = B.t1.alpha
        self.BT1_beta = B.t1.beta
        self.BT1_gamma = B.t1.gamma
        self.BT1_delta = B.t1.delta
        self.AT2 = A.process_t1(B.t1)
        self.BT2 = B.process_t1(A.t1)
        self.AT3, a_isdummy = A.process_t2(B.t1.id, self.BT2)
        self.BT3, b_isdummy = B.process_t2(A.t1.id, self.AT2)
        assert not a_isdummy and not b_isdummy
        A.process_t3(B.t1.id, self.BT3)
        B.process_t3(A.t1.id, self.AT3)
        assert A.results[0] == self.payload_B
        assert B.results[0] == self.payload_A
        assert self.passphrase == dsession_passphrase
        assert self.payload_A == dsession_payload_A
        assert self.payload_B == dsession_payload_B
        assert self.AT1.hex() == dsession_AT1.hex()
        assert self.AT1_alpha.hex() == dsession_AT1_alpha.hex()
        assert self.AT1_beta.hex() == dsession_AT1_beta.hex()
        assert self.AT1_gamma.hex() == dsession_AT1_gamma.hex()
        assert self.AT1_delta.hex() == dsession_AT1_delta.hex()
        assert self.AT2.hex() == dsession_AT2.hex()
        assert self.AT3.hex() == dsession_AT3.hex()
        assert self.BT1.hex() == dsession_BT1.hex()
        assert self.BT1_alpha.hex() == dsession_BT1_alpha.hex()
        assert self.BT1_beta.hex() == dsession_BT1_beta.hex()
        assert self.BT1_gamma.hex() == dsession_BT1_gamma.hex()
        assert self.BT1_delta.hex() == dsession_BT1_delta.hex()
        assert self.BT2.hex() == dsession_BT2.hex()
        assert self.BT3.hex() == dsession_BT3.hex()
        return self

    def __repr__(self):
        return "\n".join(f"{k:>10}: {bytes(v).hex()}" for k, v in asdict(self).items())
