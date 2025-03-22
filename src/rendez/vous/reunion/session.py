"""
This module implements the REUNION cryptographic protocol as described in
Algorithm 1 of the REUNION paper.

>>> assert len(DEFAULT_HKDF_SALT) == 32
"""

import os
from typing import Any, cast, Callable, Dict, List, Optional, Tuple, Union

from .types import HKDF, KeygenDict

# Curve25519 E/F p with Diﬀie-Hellman function DH(private, public), base point
# P ∈ E(F p ), 32-byte EpochID, 32-byte SharedRandom, aead-enc(key, plaintext,
# ad) function, aead-dec(key, ciphertext, ad) function, password hashing
# function argon2id(), key derivation function HKDF(), 32-byte block cipher
# rijndael-enc(key, plaintext)/rijndael-dec(key, ciphertext), random number
# generator function RNG, Elligator encode/decode functions.

from rendez.vous.reunion.primitives import (
    x25519,
    ctidh1024,
    aead_encrypt,
    aead_decrypt,
    argon2i,
    hkdf,
    prp_encrypt,
    prp_decrypt,
    unelligator,
    generate_hidden_key_pair,
    generate_ctidh_key_pair,
    Hash,
)

from rendez.vous.reunion.constants import (
    DEFAULT_HKDF_SALT
)


class T1(bytes):

    """
    This class provides attribute access to the four parts of a T1 message, and
    its id.

    The T1 message consists of four sections; the α, β, γ, and δ:
    – α is an Elligator-encoded Curve25519 public key, encrypted by a PRP using
    a symmetric key derived as described in Step 8. The encryption and
    decryption of α is unauthenticated, i.e. does not provide a validity check.
    The elligator encoding ensures that plaintext is indistinguishable from
    random bytes and every sequence of random bytes maps to a valid public key.
    – β is a CSIDH public key
    – γ is the MAC of an AEAD encryption of an empty string using a random
    key which is revealed by the T2.
    – δ is an AEAD ciphertext containing the message payload which is only de-
    cryptable by a valid T3.


    >>> from rendez.vous.reunion.__vectors__ import ReunionSession_passphrase
    >>> from rendez.vous.reunion.__vectors__ import ReunionSession_A_msg
    >>> ReunionSession_a = ReunionSession.create(ReunionSession_passphrase, ReunionSession_A_msg)
    >>> T1 = ReunionSession_a.t1
    >>> alpha = T1.alpha
    >>> type(alpha) == bytes
    True
    >>> len(alpha) == T1.LEN_ALPHA
    True
    >>> beta = T1.beta
    >>> type(beta) == bytes
    True
    >>> len(beta) == T1.LEN_BETA
    True
    >>> gamma = T1.gamma
    >>> type(beta) == bytes
    True
    >>> len(gamma) == T1.LEN_GAMMA
    True
    """

    LEN_ALPHA: int = 32
    LEN_BETA: int = 128
    LEN_GAMMA: int = 16

    @property
    def alpha(self) -> bytes:
        """
        α is an Elligator-encoded Curve25519 public key, encrypted by a PRP using
        a symmetric key derived as described in Step 8. The encryption and
        decryption of α is unauthenticated, i.e. does not provide a validity check.
        The elligator encoding ensures that plaintext is indistinguishable from
        random bytes and every sequence of random bytes maps to a valid public key.

        Returns *T1.LEN_ALPHA* byte slice of length 32.

        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_passphrase
        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_A_msg
        >>> ReunionSession_a = ReunionSession.create(ReunionSession_passphrase, ReunionSession_A_msg)
        >>> T1 = ReunionSession_a.t1
        >>> alpha = T1.alpha
        >>> type(alpha) == bytes
        True
        >>> len(alpha) == T1.LEN_ALPHA
        True
        """
        return self[: self.LEN_ALPHA]

    @property
    def beta(self) -> bytes:
        """
        β is a CSIDH public key. CSIDH is provided by highctidh and CTIDH1024
        is used.

        Returns *T1.LEN_BETA* byte slice of length 128.

        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_passphrase
        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_A_msg
        >>> ReunionSession_a = ReunionSession.create(ReunionSession_passphrase, ReunionSession_A_msg)
        >>> T1 = ReunionSession_a.t1
        >>> beta = T1.beta
        >>> type(beta) == bytes
        True
        >>> len(beta) == T1.LEN_BETA
        True
        """
        return self[self.LEN_ALPHA : self.LEN_ALPHA + self.LEN_BETA]

    @property
    def gamma(self) -> bytes:
        """
        γ is the MAC of an AEAD encryption of an empty string using a random
        key which is revealed by the T2. AEAD is provided by monocypher
        and XChaCha20Poly1305 is used.

        Returns *T1.LEN_GAMMA* byte slice of length 16.

        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_passphrase
        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_A_msg
        >>> ReunionSession_a = ReunionSession.create(ReunionSession_passphrase, ReunionSession_A_msg)
        >>> T1 = ReunionSession_a.t1
        >>> gamma = T1.gamma
        >>> type(gamma) == bytes
        True
        >>> len(gamma) == T1.LEN_GAMMA
        True
        """
        return self[
            self.LEN_ALPHA
            + self.LEN_BETA : self.LEN_ALPHA
            + self.LEN_BETA
            + self.LEN_GAMMA
        ]

    @property
    def delta(self) -> bytes:
        """
        δ is an AEAD ciphertext containing the message payload which is only de-
        cryptable by a valid T3. AEAD is provided by monocypher and
        XChaCha20Poly1305 is used.

        Returns *T1.LEN_DELTA* byte slice of variable length.

        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_passphrase
        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_A_msg
        >>> ReunionSession_a = ReunionSession.create(ReunionSession_passphrase, ReunionSession_A_msg)
        >>> T1 = ReunionSession_a.t1
        >>> delta = T1.delta
        >>> type(delta) == bytes
        True
        """
        return self[self.LEN_ALPHA + self.LEN_BETA + self.LEN_GAMMA :]

    @property
    def id(self) -> bytes:
        """
        Returns a *Hash* of itself as 32 bytes.

        >>> from rendez.vous.reunion.__vectors__ import t1_empty_id
        >>> t1 = T1()
        >>> t1_id = t1.id
        >>> t1_empty_id.hex() == t1_id.hex()
        True
        >>> len(t1_id) == 32
        True
        """
        return Hash(self)

    def __repr__(self) -> str:
        """
        *__repr__* returns the type and six bytes of the id encoded as hex.

        >>> T1() # doctest: +ELLIPSIS
        <T1:...>
        >>> t1 = T1()
        >>> t1.__repr__() # doctest: +ELLIPSIS
        '<T1:...>'
        """
        return "<%s:%s>" % (
            type(self).__name__,
            self.id[:6].hex(),
        )


class ReunionSession(object):
    """
    Phases 0 and 1 are implemented in this object directly, while 2, 3, and 4
    are implemented in the Peer object which ReunionSession instantiates for
    each new t1.

    >>> from rendez.vous.reunion.__vectors__ import ReunionSession_passphrase
    >>> from rendez.vous.reunion.__vectors__ import ReunionSession_A_msg
    >>> from rendez.vous.reunion.__vectors__ import ReunionSession_B_msg
    >>> ReunionSession_a = ReunionSession.create(ReunionSession_passphrase, ReunionSession_A_msg)
    >>> ReunionSession_b = ReunionSession.create(ReunionSession_passphrase, ReunionSession_B_msg)
    >>> A_t2 = ReunionSession_a.process_t1(ReunionSession_b.t1)
    >>> B_t2 = ReunionSession_b.process_t1(ReunionSession_a.t1)
    >>> A_t3, is_dummy_A = ReunionSession_a.process_t2(ReunionSession_b.t1.id, B_t2)
    >>> B_t3, is_dummy_B = ReunionSession_b.process_t2(ReunionSession_a.t1.id, A_t2)
    >>> is_dummy_A == False
    True
    >>> is_dummy_B == False
    True
    >>> B_msg_A = ReunionSession_a.process_t3(ReunionSession_b.t1.id, B_t3)
    >>> A_msg_B = ReunionSession_b.process_t3(ReunionSession_a.t1.id, A_t3)
    >>> ReunionSession_A_msg == A_msg_B
    True
    >>> ReunionSession_B_msg == B_msg_A
    True
    """

    @classmethod
    def keygen(cls) -> KeygenDict:
        """
        All of the RNG access is consolidated here in a class method, so that
        everything else in the ReunionSession and Peer classes (except "create"
        which calls this) can be sans IO.

        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_passphrase
        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_A_msg
        >>> from rendez.vous.reunion.session import ReunionSession
        >>> ReunionSession_a = ReunionSession.create(ReunionSession_passphrase, ReunionSession_A_msg)
        >>> ReunionSession_a_keys = ReunionSession_a.keygen()
        >>> ReunionSession_a_keys.keys()
        dict_keys(['dh_seed', 'ctidh_seed', 'gamma_seed', 'delta_seed', 'dummy_seed', 'tweak'])
        """
        return dict(
            dh_seed=Hash(os.urandom(32)),
            ctidh_seed=Hash(os.urandom(32)),
            gamma_seed=Hash(os.urandom(32)),
            delta_seed=Hash(os.urandom(32)),
            dummy_seed=Hash(os.urandom(32)),
            tweak=Hash(os.urandom(32))[0],
        )

    @classmethod
    def create(cls, passphrase: bytes, payload: bytes, salt: bytes = DEFAULT_HKDF_SALT) -> Any:
        """
        This is the typical way to instantiate a ReunionSession object.

        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_passphrase
        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_A_msg
        >>> from rendez.vous.reunion.session import ReunionSession
        >>> ReunionSession_a = ReunionSession.create(ReunionSession_passphrase, ReunionSession_A_msg)
        >>> type(ReunionSession_a)
        <class 'rendez.vous.reunion.session.ReunionSession'>
        """
        # XXX The above tests should construct a ReunionSession that sets all
        # seeds and verifies the values of the returned fields on the object.
        return cls(
            payload=payload,
            salt=salt,
            passphrase=passphrase,
            **cls.keygen(),
        )

    def __init__(
        self,
        salt: bytes,
        passphrase: bytes,
        payload: bytes,
        dh_seed: bytes,
        ctidh_seed: bytes,
        gamma_seed: bytes,
        delta_seed: bytes,
        dummy_seed: bytes,
        tweak: int,
    ):
        # dict of Peer objects, keyed by their t1 id
        self.peers: Dict[bytes, Peer] = {}

        # list of payloads decrypted
        self.results: List[bytes] = []

        self.dh_epk: bytes 
        dh_sk_bytes: bytes
        self.dh_epk, dh_sk_bytes = generate_hidden_key_pair(dh_seed)

        # Step2a: esk Aα ∈ Z, public key epk Aα = esk Aα · P ∈ E(Fp).
        self.dh_sk: bytes = dh_sk_bytes

        # Step2b: esk Aβ ∈ Z, public key epk Aβ = esk Aβ · P ∈ E(Fp)
        self.csidh_pk: bytes
        self.csidh_sk: bytes
        self.csidh_pk, self.csidh_sk = cast(Tuple[bytes, bytes], generate_ctidh_key_pair(ctidh_seed))


        # Step 3: salt ← SharedRandom∥EpochID.
        # Setting the salt, or context, is the responsibility of the
        # application using this library. DEFAULT_SALT is 32 null bytes.
        self.salt: bytes
        self.salt = salt

        # Step 4: pdk ← HKDF(salt, argon2id(salt, Q)).
        kdf: HKDF = hkdf(key=argon2i(passphrase, salt), salt=salt)
        self.pdk: bytes = kdf.expand(b"", 32)

        # Step 5a: sk Aγ ← H(pdk, RNG(32), msg A )
        self.sk_gamma: bytes = Hash(self.pdk + gamma_seed + payload)

        # Step 5b: sk Aδ ← H(pdk, RNG(32), msg A )
        self.sk_delta: bytes = Hash(self.pdk + delta_seed + payload)

        # t1 beta is the unencrypted csidh pk
        beta: bytes = self.csidh_pk

        # Step 6: T1Aγ ← aead-enc(sk Aγ ,“”, RS)
        gamma: bytes = aead_encrypt(self.sk_gamma, b"", salt)

        # Step 7: T1Aδ ← aead-enc(sk Aδ , msg a , RS)
        delta: bytes = aead_encrypt(self.sk_delta, payload, salt)

        # Step 8: pdkA ← H(pdk, epkAβ , T1Aγ , T1Bδ )
        self.alpha_key: bytes = Hash(self.pdk + beta + gamma + delta)

        # Step 9: T1Aα ← rijndael-enc(pdkA , epkAα)
        alpha: bytes = prp_encrypt(self.alpha_key, self.dh_epk)

        # Step 10: T1A ← T1 Aα ∥ epkAβ ∥ T1 Aγ ∥ T1 Aδ
        self.t1: T1 = T1(alpha + beta + gamma + delta)

        # deviation from the paper - we generate dummys derministically using this Hkdf.
        self.dummy_hkdf: HKDF = hkdf(key=dummy_seed, salt=salt)
        # FIXME: why dummy_hkdf? doesn't it run out after a small number of values?
        # was this just for testing purposes?

    # steps 11, 12, and 13 happen in the application using this library

    def process_t1(self, t1: T1) -> bytes:
        # Step 14: for each new T1Bi do ▷ Phase 2: Process T1; transmit T2
        # implementation of steps 14 to 22 is in Peer.__init__
        """
        Process T1 message *t1* from respective peers.

        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_passphrase
        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_A_msg
        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_B_msg
        >>> ReunionSession_a = ReunionSession.create(ReunionSession_passphrase, ReunionSession_A_msg)
        >>> ReunionSession_b = ReunionSession.create(ReunionSession_passphrase, ReunionSession_B_msg)
        >>> A_t2 = ReunionSession_a.process_t1(ReunionSession_b.t1)
        >>> B_t2 = ReunionSession_b.process_t1(ReunionSession_a.t1)
        """
        if t1 == self.t1:
            assert (
                False
            ), "we don't actually expect this to happen right now but later might return None here"
            return None

        peer = self.peers.get(t1.id)
        if peer is None:
            peer = Peer(t1, self)
            self.peers[t1.id] = peer

        return peer.t2_tx

    # steps 23 and 24, transmit t1, is in the application

    def process_t2(self, t1_id: bytes, t2: bytes) -> Tuple[bytes, bool]:
        # Step 25: for each new T2Bi do ▷ Phase 3: Process T2, transmit T3
        # implementation of steps 25 to 33 is in Peer.process_t2
        """
        Process T2 message *t2* from respective peers keyed by *t1_id*.

        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_passphrase
        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_A_msg
        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_B_msg
        >>> ReunionSession_a = ReunionSession.create(ReunionSession_passphrase, ReunionSession_A_msg)
        >>> ReunionSession_b = ReunionSession.create(ReunionSession_passphrase, ReunionSession_B_msg)
        >>> A_t2 = ReunionSession_a.process_t1(ReunionSession_b.t1)
        >>> B_t2 = ReunionSession_b.process_t1(ReunionSession_a.t1)
        >>> A_t3, is_dummy_A = ReunionSession_a.process_t2(ReunionSession_b.t1.id, B_t2)
        >>> B_t3, is_dummy_B = ReunionSession_b.process_t2(ReunionSession_a.t1.id, A_t2)
        >>> is_dummy_A == False
        True
        >>> is_dummy_B == False
        True
        """

        if t1_id in self.peers:
            return self.peers[t1_id].process_t2(t2)
        else:
            return self.dummy_hkdf.expand(t1_id + t2, 32), True

    def process_t3(self, t1_id: bytes, t3: bytes) -> Optional[bytes]:
        # Step 36: for each new T3Bi do ▷ Phase 4: Process T3; decrypt δ
        """
        Process T3 message *t3* from respective peers keyed by *t1_id*. For
        successful rendezvous, the respective peer's message is returned as a
        bytes object or *None* is returned.

        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_passphrase
        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_A_msg
        >>> from rendez.vous.reunion.__vectors__ import ReunionSession_B_msg
        >>> ReunionSession_a = ReunionSession.create(ReunionSession_passphrase, ReunionSession_A_msg)
        >>> ReunionSession_b = ReunionSession.create(ReunionSession_passphrase, ReunionSession_B_msg)
        >>> A_t2 = ReunionSession_a.process_t1(ReunionSession_b.t1)
        >>> B_t2 = ReunionSession_b.process_t1(ReunionSession_a.t1)
        >>> A_t3, is_dummy_A = ReunionSession_a.process_t2(ReunionSession_b.t1.id, B_t2)
        >>> B_t3, is_dummy_B = ReunionSession_b.process_t2(ReunionSession_a.t1.id, A_t2)
        >>> is_dummy_A == False
        True
        >>> is_dummy_B == False
        True
        >>> B_msg_A = ReunionSession_a.process_t3(ReunionSession_b.t1.id, B_t3)
        >>> A_msg_B = ReunionSession_b.process_t3(ReunionSession_a.t1.id, A_t3)
        >>> ReunionSession_A_msg == A_msg_B
        True
        >>> ReunionSession_B_msg == B_msg_A
        True
        """
        if t1_id in self.peers:
            return self.peers[t1_id].process_t3(t3)
        else:
            return None


class Peer(object):
    def __init__(peer, t1: T1, session: ReunionSession):
        """
        This method implements the inside of the for loop in Phase 2 of
        Algorithm 1.
        """

        # Step 14: for each new T1Bi do ▷ Phase 2: Process T1; transmit T2

        peer.t1: T1 = t1
        peer.session: ReunionSession = session

        # Step 15: pdkBi ← H(pdk, T1Biβ, T1Biγ, T1Biδ)
        peer.alpha_key: bytes = Hash(session.pdk + t1.beta + t1.gamma + t1.delta)

        # Step 16: epkBiα ← unelligator(rijndael-dec(pdkBi , T1Biα )).
        peer.dh_pk: bytes = unelligator(prp_decrypt(peer.alpha_key, t1.alpha))

        # Step 17: epkBiβ ← T1Biβ
        peer.csidh_pk: bytes = ctidh1024.public_key_from_bytes(t1.beta)

        # Step 18: dh1ssi ← H(DH(eskAα , epkBiα))
        peer.dh_ss: bytes = x25519(session.dh_sk, peer.dh_pk)

        # Step 19: dh2ssi ← H(DH(eskAβ , epkBiβ)).
        peer.csidh_ss: bytes = ctidh1024.dh(
            session.csidh_sk, peer.csidh_pk
        )  # note that this can throw exceptions, see app/reunion-client.py:process_t1(T1(t1))

        # Step 20: T2kitx ← H(pdkA, pdkBi, dh1ssi, dh2ssi)
        peer.t2key_tx: bytes = Hash(
            session.alpha_key + peer.alpha_key + peer.dh_ss + peer.csidh_ss
        )

        # Step 21: T2kirx ← H(pdkBi, pdkA, dh1ssi, dh2ssi)
        peer.t2key_rx: bytes = Hash(
            peer.alpha_key + session.alpha_key + peer.dh_ss + peer.csidh_ss
        )

        # Step 22: T2Ai ← rijndael-enc(T2kitx, skAγ)
        peer.t2_tx: bytes = prp_encrypt(peer.t2key_tx, session.sk_gamma)
        peer.t2_rx: Optional[bytes] = None
        peer.payload: Optional[bytes] = None

        # Step 23 and 24, transmit, is implemented in an application using this library

    def process_t2(peer, t2: bytes) -> Tuple[bytes, bool]:
        """
        This method implements the inside of the for loop in Phase 3 of
        Algorithm 1. It returns a 2-tuple of (t3, is_dummy).
        """

        # Step 25: for each new T2Bi do ▷ Phase 3: Process T2, transmit T3

        # Step 26: skBiγ ← rijndael-dec(T2kirx, T2Bi)
        sk_gamma: bytes = prp_decrypt(peer.t2key_rx, t2)

        # Step 27: if “” = aead-dec(sk B i γ , T 1 B i γ , RS) then
        aead_res: Optional[bytes] = aead_decrypt(sk_gamma, peer.t1.gamma, peer.session.salt)

        if aead_res is not None:
            assert aead_res == b"", aead_res

            peer.t2_rx = t2

            # Step 28: T3kitx ← H(T2kitx, T2Ai , T2Bi).
            t3key_tx: bytes = Hash(peer.t2key_tx + peer.t2_tx + t2)

            # Step 29: T3kirx ← H(T2kirx, T2Bi, T2Ai)
            peer.t3_key_rx: bytes = Hash(peer.t2key_rx + peer.t2_rx + peer.t2_tx)

            # Step 30: T3Ai ← rijndael-enc(T3kitx, skAδ)
            return prp_encrypt(t3key_tx, peer.session.sk_delta), False

        # Step 31: else
        else:
            # Step 32: T3Ai ← H(RNG(32))
            return peer.session.dummy_hkdf.expand(peer.t1.id + t2, 32), True

    def process_t3(peer, t3: bytes) -> Optional[bytes]:
        """
        This method implements the inside of the for loop in Phase 4 of
        Algorithm 1.
        """

        # Step 36: for each new T3Bi do ▷ Phase 4: Process T3; decrypt δ

        if peer.t2_rx is None:
            # we didn't receive a valid t2 from this peer, so, we can't decrypt
            # their t3.
            # At the cost of a more complicated API, we could implement support
            # for out-of-order delivery by storing t3s here and attempting to
            # process them again when we receive a t2 from the corresponding
            # t1. As it is now, if we receive their t3 before their t2 we will
            # never decrypt the t1 delta payload.
            return None
        else:
            # Step 37: skBiδ ← rijndael-dec(T3kirx, T3Bi).
            sk_delta: bytes = prp_decrypt(peer.t3_key_rx, t3)

            # Step 38: if msgBi ← aead-dec(skBiδ, T1Biδ, RS) then
            peer.payload = aead_decrypt(sk_delta, peer.t1.delta, peer.session.salt)
            if peer.payload is not None:
                # Step 39: add to results
                peer.session.results.append(peer.payload)
            return peer.payload

if '__main__' == __name__:
    import doctest
    doctest.testmod(verbose=True)
