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

class Sha256Solver(BasePoWSolver):
    def solve(self, challenge_type: str, challenge_input: str, difficulty: int) -> str:
        base = (challenge_type + challenge_input).encode()
        
        for nonce in itertools.count():
            digest = hashlib.sha256(base + str(nonce).encode()).digest()
            if self.has_leading_zero_bits(digest, difficulty):
                return str(nonce)
                
        raise RuntimeError("Exhausted nonce space without finding a solution.")