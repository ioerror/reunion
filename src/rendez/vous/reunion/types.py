from typing import Protocol, TypedDict

class HKDF(Protocol):
    def expand(self, info: bytes, length: int) -> bytes:
        pass

class KeygenDict(TypedDict):
    dh_seed: bytes
    ctidh_seed: bytes
    gamma_seed: bytes
    delta_seed: bytes
    dummy_seed: bytes
    tweak: int
