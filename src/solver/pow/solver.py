from src.solver.pow.types.sha256 import Sha256Solver
from src.solver.pow.types.scrypt import ScryptSolver
from src.solver.pow.types.bandwidth import BandwidthSolver

class ChallengeSolverRouter:
    def __init__(self):
        self.sha256_challenge = bytes([
            0x7b, 0x0c, 0x47, 0x0f, 0x0c, 0xfe, 0x3a, 0x80,
            0xa9, 0xe2, 0x65, 0x26, 0xad, 0x18, 0x5f, 0x48,
            0x4f, 0x68, 0x17, 0xd0, 0x83, 0x27, 0x12, 0xa4,
            0xa3, 0x7a, 0x90, 0x87, 0x86, 0xa6, 0xa6, 0x7f
        ])

        self.scrypt_challenge = bytes([
            0x72, 0xf9, 0x57, 0xdf, 0x65, 0x6e, 0x80, 0xba,
            0x55, 0xf5, 0xd8, 0xce, 0x2e, 0x8c, 0x7c, 0xcb,
            0x59, 0x68, 0x7d, 0xba, 0x3b, 0xfb, 0x27, 0x3d,
            0x54, 0xb0, 0x8a, 0x26, 0x1b, 0x2f, 0x30, 0x02
        ])

        self.bandwidth_challenge = bytes([
            0xa9, 0xfa, 0xaf, 0xfd, 0x31, 0xb4, 0xd5, 0xed,
            0xe2, 0xa2, 0xe1, 0x9d, 0x2d, 0x7f, 0xd5, 0x25,
            0xf6, 0x6f, 0xee, 0x61, 0x91, 0x15, 0x11, 0x96,
            0x0d, 0xcb, 0xb5, 0x2d, 0x3c, 0x48, 0xce, 0x25
        ])

        self.solvers = {
            "h" + self.sha256_challenge.hex(): Sha256Solver(),
            "h" + self.scrypt_challenge.hex(): ScryptSolver(),
            "h" + self.bandwidth_challenge.hex(): BandwidthSolver(),
        }

    def solve_payload(self, payload: dict) -> str:
        challenge_type = payload.get("challenge_type")
        difficulty = payload.get("difficulty")
        challenge_input = payload.get("challenge", {}).get("input", "")

        if not challenge_type or difficulty is None:
            raise ValueError("Payload missing required fields: 'challenge_type' or 'difficulty'.")

        solver = self.solvers.get(challenge_type)
        if not solver:
            raise ValueError(f"Unknown challenge_type provided: {challenge_type}")

     
        return solver.solve(challenge_type, challenge_input, difficulty)


