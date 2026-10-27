import hashlib
import itertools

class BasePoWSolver:
    def has_leading_zero_bits(self, digest: bytes, difficulty: int) -> bool:
        full_bytes, remaining_bits = divmod(difficulty, 8)
        if digest[:full_bytes] != b"\x00" * full_bytes:
            return False
        if remaining_bits > 0:
            return (digest[full_bytes] >> (8 - remaining_bits)) == 0
        return True

class ScryptSolver(BasePoWSolver):
    def __init__(self):
        self.memory_cost = 128
        self.block_size = 8
        self.parallelization = 1
        self.derived_key_length = 16

    def solve(self, challenge_type: str, challenge_input: str, difficulty: int) -> str:
        base = challenge_type + challenge_input
        salt = challenge_input.encode()
        
        for nonce in itertools.count():
            digest = hashlib.scrypt(
                f"{base}{nonce}".encode(),
                salt=salt,
                n=self.memory_cost,
                r=self.block_size,
                p=self.parallelization,
                dklen=self.derived_key_length,
            )
            if self.has_leading_zero_bits(digest, difficulty):
                return str(nonce)
                
        raise RuntimeError("Exhausted nonce space without finding a solution.")