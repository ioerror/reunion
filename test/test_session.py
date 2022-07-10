import os
import unittest

from reunion.session import ReunionSession, Hash, unelligator, generate_hidden_key_pair
from monocypher.public import PrivateKey


def get_pairs(items):
    """
    Helper function to get all unique pairs from a list of items.

    >>> list(get_pairs("ABCD"))
    [('A', 'B'), ('A', 'C'), ('A', 'D'), ('B', 'C'), ('B', 'D'), ('C', 'D')]
    """
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            yield items[i], items[j]


class TestReunionSession(unittest.TestCase):
    def setUp(self):
        pass

    def _test_2party(self):

        """
        This test is disabled because the test_4party tests a superset of its
        functionality. It remains here as a demonstration of the simplest
        pairwise instantiation of the protocol.
        """

        A_msg = "Mr. Watson — Come here — I want to see you.".encode()
        B_msg = """\
when a man gives his order to produce a definite result and stands by that
order it seems to have the effect of giving him what might be termed a second
sight which enables him to see right through ordinary problems. What this power
is I cannot say; all I know is that it exists and it becomes available only
when a man is in that state of mind in which he knows exactly what he wants and
is fully determined not to quit until he finds it.""".encode()

        passphrase = b"passphrase"

        A = ReunionSession.create(passphrase, A_msg)
        B = ReunionSession.create(passphrase, B_msg)

        A_t2 = A.process_t1(B.t1)
        B_t2 = B.process_t1(A.t1)

        A_t3, is_dummy_A = A.process_t2(Hash(B.t1), B_t2)
        B_t3, is_dummy_B = B.process_t2(Hash(A.t1), A_t2)

        A.process_t3(Hash(B.t1), B_t3)
        B.process_t3(Hash(A.t1), A_t3)

        A_msg_B = B.results[0]
        B_msg_A = A.results[0]

        self.assertEqual(A_msg, A_msg_B)
        self.assertEqual(B_msg, B_msg_A)

    def _4party_interleaved(self):

        """
        4 parties means 16 CSIDH operations (N**2, or, N key generations plus
        N*(N-1) rendezvouses with others) so this test takes a little while.

        this test is often disabled as it is very similar to test_4party.

        in this variant, each pair of peers runs the protocol to completion
        before the next pair begins (but with each peer still reusing a single
        session).
        """

        A_msg = b"a message"
        B_msg = b"b message"
        C_msg = b"c message"
        D_msg = b"d message"

        passphrase1 = b"passphrase1"
        passphrase2 = b"passphrase2"

        A = ReunionSession.create(passphrase1, A_msg)
        B = ReunionSession.create(passphrase1, B_msg)
        C = ReunionSession.create(passphrase2, C_msg)
        D = ReunionSession.create(passphrase2, D_msg)

        sessions = (A, B, C, D)

        for a, b in get_pairs(sessions):
            a_t2 = a.process_t1(b.t1)
            b_t2 = b.process_t1(a.t1)

            a_t3, is_dummy_a = a.process_t2(Hash(b.t1), b_t2)
            b_t3, is_dummy_b = b.process_t2(Hash(a.t1), a_t2)

            a.process_t3(Hash(b.t1), b_t3)
            b.process_t3(Hash(a.t1), a_t3)

        A_msg_B = B.results[0]
        B_msg_A = A.results[0]
        C_msg_D = D.results[0]
        D_msg_C = C.results[0]

        self.assertEqual(A_msg, A_msg_B)
        self.assertEqual(B_msg, B_msg_A)
        self.assertEqual(C_msg, C_msg_D)
        self.assertEqual(D_msg, D_msg_C)
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

        A_msg = b"a message"
        B_msg = b"b message"
        C_msg = b"c message"
        D_msg = b"d message"

        passphrase1 = b"passphrase1"
        passphrase2 = b"passphrase2"

        A = ReunionSession.create(passphrase1, A_msg)
        B = ReunionSession.create(passphrase1, B_msg)
        C = ReunionSession.create(passphrase2, C_msg)
        D = ReunionSession.create(passphrase2, D_msg)

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

        self.assertEqual(A_msg, A_msg_B)
        self.assertEqual(B_msg, B_msg_A)
        self.assertEqual(C_msg, C_msg_D)
        self.assertEqual(D_msg, D_msg_C)
        self.assertTrue(all(len(r.results) == 1 for r in Rs))


if __name__ == "__main__":
    unittest.main()
    # import doctest
    # doctest.testmod(verbose=True)
