import os
import unittest
from dataclasses import dataclass, asdict
from rendez.vous.reunion.primitives import Hash
from rendez.vous.reunion.session import ReunionSession, DEFAULT_HKDF_SALT


def DeterministicSession(
    passphrase: bytes, payload: bytes, seed: bytes, salt=DEFAULT_HKDF_SALT
):
    return ReunionSession(
        payload=payload,
        salt=salt,
        passphrase=passphrase,
        dh_seed=Hash(seed + b"dh"),
        ctidh_seed=Hash(seed + b"ct"),
        gamma_seed=Hash(seed + b"g"),
        delta_seed=Hash(seed + b"d"),
        dummy_seed=Hash(seed + b"d"),
        tweak=Hash(seed + b"t")[0],
    )


@dataclass
class SessionKAT:
    """
    This is a step toward we way that we could have regeneratable data-driven
    known-answer tests.

    Ideally the actual KATs could be read from a data file rather than this
    docstring, and could also include serialized secret keys (rather than just
    their seed as it is here now) so that other implementations could load them
    from the data file and reunion compatibility without necessarily needing to
    be completely seed-compatible when generating the keys.

    >>> SessionKAT.generate_from_seed(bytes.fromhex("1234"))
          seed: 1234
    passphrase: 9b0ac4fbd2e84a047b40695c391664890e570ee302a22c16c7025f52ed0586db
     payload_A: 00b7bf81a81bea5506669e6c00646beead875b9b1c5a8f30ea4a11ccf6ce2a98
     payload_B: 5c0d6c7b18d41aa1bb35dcf72f91bf9da292278c6057c8525df7e76ee4fa0764
           AT1: b7e50c69c1576ac0c38aa770facf18f86e837de3a265ba1b6776a4d64526c546214e6df3a72dad41d7218a65a691198ec1d13c040b100abbd8f72519bcfe597bc5b7012111e8b0e4bd59037650c24c047677ccccbe6f0230730ba7735edb73f03aee4c4115c4f0c9376d4ce59d311e90391fa65061df52d7ac6b4cd09b7e93a530a6fef8ddc407f67323ee079abe15669e9b15d9d4fec0e542ff69994234c609520e55fc3d434366794d59a0d672d7fd3dbad2eed6713de60de1098dc99bc2d24b24d1fdedb856c9104690350d0917d173de3ff6d4d5e6957305cd761eb4bdc2
           AT2: da4cc76fb741b2bb28ca95754290b1e484db06c9698254b7146d9ec36d5ad715
           AT3: f78bbb76c53025c3a0218aa54bbfedb02f3d8e375c737976272b1c0e4d885ec2
           BT1: 54ad5d6ca02c133782ffbbc26027d6d096ffb48c0df8c4bc469ba7b50881ea6bce6f8ba1e460862933a85b9b6a190adc6648cdd61a648e570d1b34b7e5830057c8117e95c57d7c1da083ad9d39ec2c367856b8dbe164f7f964c53da076f690edb1e8f4e276e757e074545eda23a60397227cf5d8d63d4ded364d01042402b9c0135cf19897d79ec764a37c579ebf3aaaee10926238dc06bc4d7b89b3b67cd7046b350f40fbb821fae6ec563366f419de62d3bdef94405a6f39595342fcb9fa6261185db123cd0e1d367097cf80f47f0acb9ba73062f605abc187556b65a9bc23
           BT2: 4eb24741bb5365e0424ce9010a43c06f00e12bfb326fc165efaed029294ba442
           BT3: 377a59cbbc4eeaa4ac25827b279dc115cb3b051449feb8248d5e2bc6f74460b6
    """

    seed: bytes = None
    passphrase: bytes = None
    payload_A: bytes = None
    payload_B: bytes = None
    AT1: bytes = None
    AT2: bytes = None
    AT3: bytes = None
    BT1: bytes = None
    BT2: bytes = None
    BT3: bytes = None

    @classmethod
    def generate_from_seed(cls, seed):
        self = cls()
        self.seed = seed
        self.passphrase = Hash(b"passphrase" + seed)
        self.payload_A = Hash(b"payload A" + seed)
        self.payload_B = Hash(b"payload B" + seed)
        A = DeterministicSession(self.passphrase, self.payload_A, b"a" + seed)
        B = DeterministicSession(self.passphrase, self.payload_B, b"b" + seed)
        self.AT1 = A.t1
        self.BT1 = B.t1
        self.AT2 = A.process_t1(B.t1)
        self.BT2 = B.process_t1(A.t1)
        self.AT3, a_isdummy = A.process_t2(B.t1.id, self.BT2)
        self.BT3, b_isdummy = B.process_t2(A.t1.id, self.AT2)
        assert not a_isdummy and not b_isdummy
        A.process_t3(B.t1.id, self.BT3)
        B.process_t3(A.t1.id, self.AT3)
        assert A.results[0] == self.payload_B
        assert B.results[0] == self.payload_A
        return self

    def __repr__(self):
        return "\n".join(f"{k:>10}: {bytes(v).hex()}" for k, v in asdict(self).items())
