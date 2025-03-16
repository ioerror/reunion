import os
import unittest

from rendez.vous.reunion.session import ReunionSession
from rendez.vous.reunion.util import get_pairs

from rendez.vous.reunion.__vectors__ import ReunionSession_passphrase
from rendez.vous.reunion.__vectors__ import ReunionSession_passphrase1
from rendez.vous.reunion.__vectors__ import ReunionSession_passphrase2
from rendez.vous.reunion.__vectors__ import ReunionSession_A_msg
from rendez.vous.reunion.__vectors__ import ReunionSession_B_msg
from rendez.vous.reunion.__vectors__ import ReunionSession_four_party_A_msg
from rendez.vous.reunion.__vectors__ import ReunionSession_four_party_B_msg
from rendez.vous.reunion.__vectors__ import ReunionSession_four_party_C_msg
from rendez.vous.reunion.__vectors__ import ReunionSession_four_party_D_msg

class TestReunionSession(unittest.TestCase):
    def setUp(self):
        pass

    def test_internals(self):
        A = ReunionSession.create(ReunionSession_passphrase, ReunionSession_A_msg)
        B = ReunionSession.create(ReunionSession_passphrase, ReunionSession_B_msg)

        A_t2 = A.process_t1(B.t1)
        B_t2 = B.process_t1(A.t1)

        A_t3, is_dummy_A = A.process_t2(B.t1.id, B_t2)
        B_t3, is_dummy_B = B.process_t2(A.t1.id, A_t2)

        assert is_dummy_A == False
        assert is_dummy_B == False

        A.process_t3(B.t1.id, B_t3)
        B.process_t3(A.t1.id, A_t3)

        A_peer = list(A.peers.values())[0]
        B_peer = list(B.peers.values())[0]
        assert A_peer.csidh_ss == B_peer.csidh_ss
        assert A_peer.dh_ss == B_peer.dh_ss
        assert B_peer.alpha_key == A.alpha_key
        assert B.salt == A.salt
        assert B.pdk == A.pdk

        A_msg_B = B.results[0]
        B_msg_A = A.results[0]

        self.assertEqual(ReunionSession_A_msg, A_msg_B)
        self.assertEqual(ReunionSession_B_msg, B_msg_A)

    def test_2party(self):
        """
        This test is disabled because the test_4party tests a superset of its
        functionality. It remains here as a demonstration of the simplest
        pairwise instantiation of the protocol.
        """
        A = ReunionSession.create(ReunionSession_passphrase, ReunionSession_A_msg)
        B = ReunionSession.create(ReunionSession_passphrase, ReunionSession_B_msg)

        A_t2 = A.process_t1(B.t1)
        B_t2 = B.process_t1(A.t1)

        A_t3, is_dummy_A = A.process_t2(B.t1.id, B_t2)
        B_t3, is_dummy_B = B.process_t2(A.t1.id, A_t2)

        A.process_t3(B.t1.id, B_t3)
        B.process_t3(A.t1.id, A_t3)

        A_msg_B = B.results[0]
        B_msg_A = A.results[0]

        self.assertEqual(ReunionSession_A_msg, A_msg_B)
        self.assertEqual(ReunionSession_B_msg, B_msg_A)

    def test_4party_interleaved(self):
        """
        4 parties means 16 CSIDH operations (N**2, or, N key generations plus
        N*(N-1) rendezvouses with others) so this test takes a little while.

        this test is often disabled as it is very similar to test_4party.

        in this variant, each pair of peers runs the protocol to completion
        before the next pair begins (but with each peer still reusing a single
        session).
        """

        A = ReunionSession.create(ReunionSession_passphrase1, ReunionSession_four_party_A_msg)
        B = ReunionSession.create(ReunionSession_passphrase1, ReunionSession_four_party_B_msg)
        C = ReunionSession.create(ReunionSession_passphrase2, ReunionSession_four_party_C_msg)
        D = ReunionSession.create(ReunionSession_passphrase2, ReunionSession_four_party_D_msg)

        sessions = (A, B, C, D)

        for a, b in get_pairs(sessions):
            a_t2 = a.process_t1(b.t1)
            b_t2 = b.process_t1(a.t1)

            a_t3, is_dummy_a = a.process_t2(b.t1.id, b_t2)
            b_t3, is_dummy_b = b.process_t2(a.t1.id, a_t2)

            a.process_t3(b.t1.id, b_t3)
            b.process_t3(a.t1.id, a_t3)

        A_msg_B = B.results[0]
        B_msg_A = A.results[0]
        C_msg_D = D.results[0]
        D_msg_C = C.results[0]

        self.assertEqual(ReunionSession_four_party_A_msg, A_msg_B)
        self.assertEqual(ReunionSession_four_party_B_msg, B_msg_A)
        self.assertEqual(ReunionSession_four_party_C_msg, C_msg_D)
        self.assertEqual(ReunionSession_four_party_D_msg, D_msg_C)
        self.assertTrue(all(len(r.results) == 1 for r in sessions))

    def test_4party(self):
        """
        4 parties means 16 CSIDH operations (N**2, or, N key generations plus
        N*(N-1) rendezvouses with others) so this test takes a little while.

        in this variant of the 4party test, we effectively operate in distinct
        phases: everyone transmits their t1 before anyone transmits their t2,
        etc.

        """

        # Phase 0: setup
        A = ReunionSession.create(ReunionSession_passphrase1, ReunionSession_four_party_A_msg)
        B = ReunionSession.create(ReunionSession_passphrase1, ReunionSession_four_party_B_msg)
        C = ReunionSession.create(ReunionSession_passphrase2, ReunionSession_four_party_C_msg)
        D = ReunionSession.create(ReunionSession_passphrase2, ReunionSession_four_party_D_msg)

        Rs = (A, B, C, D)

        # Phase 1: Transmit 𝑇1
        t1s = [r.t1 for r in Rs]

        # Phase 2: Process 𝑇1; transmit 𝑇2
        t2s = [
            (r.t1.id, t1.id, r.process_t1(t1)) for r in Rs for t1 in t1s if r.t1 != t1
        ]

        # Phase 3: Process 𝑇2, transmit 𝑇3
        t3s = [
            (r.t1.id, from_, r.process_t2(from_, t2)[0])
            for r in Rs
            for from_, to, t2 in t2s
            if r.t1.id == to
        ]

        # Phase 4: Process 𝑇3; decrypt payload
        [r.process_t3(from_, t3) for r in Rs for from_, to, t3 in t3s if r.t1.id == to]

        A_msg_B = B.results[0]
        B_msg_A = A.results[0]
        C_msg_D = D.results[0]
        D_msg_C = C.results[0]

        self.assertEqual(ReunionSession_four_party_A_msg, A_msg_B)
        self.assertEqual(ReunionSession_four_party_B_msg, B_msg_A)
        self.assertEqual(ReunionSession_four_party_C_msg, C_msg_D)
        self.assertEqual(ReunionSession_four_party_D_msg, D_msg_C)
        self.assertTrue(all(len(r.results) == 1 for r in Rs))


if __name__ == "__main__":
    unittest.main()
