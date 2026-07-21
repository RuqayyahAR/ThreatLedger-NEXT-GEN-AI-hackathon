import hashlib
import sys

def mine(indicator_value: str, difficulty: int = 4) -> int:
    """Brute-forces a cryptographic nonce to satisfy backend proof-of-work checks.
    Backend verifies: SHA-256(indicatorValue + nonce) starts with difficulty leading zeros."""
    prefix = "0" * difficulty
    nonce = 0
    while True:
        candidate = f"{indicator_value}{nonce}"
        digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
        if digest.startswith(prefix):
            return nonce
        nonce += 1

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 mine_nonce.py <indicatorValue> [difficulty]")
        sys.exit(1)

    indicator_value = sys.argv[1]
    difficulty = int(sys.argv[2]) if len(sys.argv) > 2 else 4

    print(f"[*] Mining cryptographic nonce for {indicator_value}...")
    found_nonce = mine(indicator_value, difficulty)
    print(f"[+] Valid Nonce Found: {found_nonce}")
    print(f"Use this in your POST body as \"proofOfWorkNonce\": {found_nonce}")
