"""
Quick helper for testing: brute-forces a nonce that satisfies the proof-of-work
rule (SHA-256(indicatorValue + nonce) starts with N leading zero hex chars).

This is basically a tiny preview of what Member 3's real Python client will do
before submitting a threat. Run:

    python find_nonce.py "198.51.100.42" 4

and paste the printed nonce into your POST /api/threats test request.
"""
import hashlib
import sys


def find_nonce(indicator_value: str, difficulty: int = 4) -> int:
    target_prefix = "0" * difficulty
    nonce = 0
    while True:
        candidate = f"{indicator_value}{nonce}".encode("utf-8")
        digest = hashlib.sha256(candidate).hexdigest()
        if digest.startswith(target_prefix):
            return nonce
        nonce += 1


if __name__ == "__main__":
    value = sys.argv[1] if len(sys.argv) > 1 else "198.51.100.42"
    diff = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    found = find_nonce(value, diff)
    print(f"indicatorValue: {value}")
    print(f"difficulty:     {diff}")
    print(f"valid nonce:    {found}")
