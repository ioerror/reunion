"""
Constants used in the REUNION protocol

>>> len(DEFAULT_AEAD_NONCE) == 24
True
>>> len(DEFAULT_ARGON_SALT) == 32
True
>>> len(DEFAULT_HKDF_SALT) == 32
True
>>> DEFAULT_CTIDH_SIZE == 1024
True
"""

DEFAULT_AEAD_NONCE: bytes = b"\x00" * 24
DEFAULT_ARGON_SALT: bytes = b"\x00" * 32
DEFAULT_HKDF_SALT: bytes = b"\x00" * 32

DEFAULT_CTIDH_SIZE: int = 1024 
