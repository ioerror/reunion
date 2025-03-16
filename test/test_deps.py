import os
import unittest

class TestDependencies(unittest.TestCase):
  def test_imports(self):
    import monocypher
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from flask import Flask, stream_with_context, request, Response
    from hashlib import blake2b, shake_256
    from highctidh import ctidh
    from hkdf import Hkdf
    from stem.control import Controller
    from typing import Dict, List
    from typing import Set
    import asyncio
    import click
    import datetime
    import highctidh
    import ifaddr
    import json
    import logging
    import monocypher
    import os
    import random
    import requests
    import secrets
    import socket
    import socks
    import struct
    import time

  def test_exports(self):
    from rendez.vous.reunion.primitives import aead_decrypt, aead_encrypt, argon2i
    from rendez.vous.reunion.primitives import generate_hidden_key_pair, Hash
    from rendez.vous.reunion.primitives import highctidh_deterministic_rng, hkdf, prp_decrypt
    from rendez.vous.reunion.primitives import prp_encrypt, unelligator, x25519

