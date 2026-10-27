import base64

class BandwidthSolver:
    def __init__(self):
        self.sizes = {
            1: 0x400,
            2: 0x2800,
            3: 0x19000,
            4: 0x100000,
            5: 0xA00000,
        }

    def solve(self, challenge_type: str, challenge_input: str, difficulty: int) -> str:
        size = self.sizes.get(difficulty)
        if size is None:
            raise ValueError(f"Invalid difficulty size: {difficulty}. Allowed: {list(self.sizes.keys())}")
            
        return base64.b64encode(b"\x00" * size).decode()