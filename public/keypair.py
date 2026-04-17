"""
Public / Private Key Demo — Python
Blockchain 101 context: secp256k1 + ECDSA + SHA-256

Install:  pip install ecdsa cryptography
Run:      python keypair.py
"""

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
from ecdsa.util import sigencode_string, sigdecode_string


# ─── 1. Key Generation ────────────────────────────────────────────────────────

def generate_key_pair() -> dict:
    """Generate a secp256k1 ECDSA key pair."""
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    return {
        "private_key": sk.to_string().hex(),
        "public_key":  "04" + vk.to_string().hex(),  # uncompressed format
        "_sk": sk,
        "_vk": vk
    }


def key_pair_from_private(private_key_hex: str) -> dict:
    """Restore a key pair from a private key hex string."""
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    vk = sk.get_verifying_key()
    return {
        "private_key": private_key_hex,
        "public_key":  "04" + vk.to_string().hex(),
        "_sk": sk,
        "_vk": vk
    }


# ─── 2. Hash ──────────────────────────────────────────────────────────────────

def hash_message(message: str) -> bytes:
    """Return SHA-256 digest of a UTF-8 message."""
    return hashlib.sha256(message.encode("utf-8")).digest()


def hash_hex(message: str) -> str:
    """Return SHA-256 digest as hex string."""
    return hash_message(message).hex()


# ─── 3. Sign ──────────────────────────────────────────────────────────────────

def sign_message(sk: SigningKey, message: str) -> str:
    """Sign a message and return the signature as hex."""
    digest = hash_message(message)
    sig    = sk.sign_digest(digest, sigencode=sigencode_string)
    return sig.hex()


def sign_to_rs(sk: SigningKey, message: str) -> dict:
    """Sign and return {r, s} components separately."""
    sig_hex = sign_message(sk, message)
    sig_bytes = bytes.fromhex(sig_hex)
    r = sig_bytes[:32].hex()
    s = sig_bytes[32:].hex()
    return {"r": r, "s": s, "hex": sig_hex}


# ─── 4. Verify ────────────────────────────────────────────────────────────────

def verify_signature(vk: VerifyingKey, message: str, sig_hex: str) -> bool:
    """Return True if the signature is valid for the given message and key."""
    try:
        digest = hash_message(message)
        vk.verify_digest(bytes.fromhex(sig_hex), digest, sigdecode=sigdecode_string)
        return True
    except BadSignatureError:
        return False


def verify_from_public_hex(public_key_hex: str, message: str, sig_hex: str) -> bool:
    """Verify using a raw public key hex string (04 prefix stripped internally)."""
    raw = bytes.fromhex(public_key_hex.lstrip("04")[:128])  # 64 bytes = x + y
    vk  = VerifyingKey.from_string(raw, curve=SECP256k1)
    return verify_signature(vk, message, sig_hex)


# ─── 5. Key Database (JSON-backed) ────────────────────────────────────────────

class KeyDatabase:
    """
    A simple JSON-backed key database.
    Each record stores a key pair along with metadata.

    ⚠ Warning: stores private keys in plaintext.
       In production, encrypt private keys before persisting
       (e.g. AES-256-GCM with a password-derived key).
    """

    def __init__(self, path: str = "keys.json"):
        self.path    = path
        self.records: list[dict] = self._load()

    def _load(self) -> list:
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("keys", [])
        return []

    def _save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "keys": self.records}, f, indent=2)

    def add(self, label: str, kp: dict, tags: Optional[list] = None) -> dict:
        """Save a key pair and return the stored record."""
        record = {
            "id":          str(uuid.uuid4()),
            "label":       label,
            "public_key":  kp["public_key"],
            "private_key": kp["private_key"],
            "curve":       "secp256k1",
            "created_at":  datetime.now(timezone.utc).isoformat(),
            "tags":        tags or []
        }
        self.records.append(record)
        self._save()
        return record

    def find_by_id(self, key_id: str) -> Optional[dict]:
        return next((r for r in self.records if r["id"] == key_id), None)

    def find_by_label(self, label: str) -> list[dict]:
        return [r for r in self.records if r["label"] == label]

    def all_public_keys(self) -> list[str]:
        return [r["public_key"] for r in self.records]

    def count(self) -> int:
        return len(self.records)

    def __repr__(self):
        return f"<KeyDatabase path={self.path!r} records={self.count()}>"


# ─── 6. Signed Transaction ────────────────────────────────────────────────────

def create_signed_transaction(sk: SigningKey, public_key_hex: str, tx_data: dict) -> dict:
    """Create and sign a transaction record."""
    payload   = json.dumps(tx_data, separators=(",", ":"), sort_keys=True)
    msg_hash  = hash_hex(payload)
    sig       = sign_to_rs(sk, payload)
    verified  = verify_from_public_hex(public_key_hex, payload, sig["hex"])

    return {
        "transaction": tx_data,
        "hash":        msg_hash,
        "signature": {
            "algorithm": "ECDSA-secp256k1",
            "r":         sig["r"],
            "s":         sig["s"]
        },
        "public_key": public_key_hex,
        "verified":   verified
    }


# ─── Demo ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Public/Private Key Demo (Python) ===\n")

    # 1. Generate
    kp = generate_key_pair()
    print(f"Private key : {kp['private_key']}")
    print(f"Public key  : {kp['public_key'][:42]}...\n")

    # 2. Sign
    message = "Send 1 BTC to Alice"
    sig     = sign_to_rs(kp["_sk"], message)
    print(f"Message     : {message}")
    print(f"Hash        : {hash_hex(message)}")
    print(f"r           : {sig['r']}")
    print(f"s           : {sig['s']}\n")

    # 3. Verify original
    valid = verify_signature(kp["_vk"], message, sig["hex"])
    print(f"Verify original : {'VALID ✓' if valid else 'INVALID ✗'}")

    # 4. Verify tampered
    tampered = verify_signature(kp["_vk"], message + "!", sig["hex"])
    print(f"Verify tampered : {'VALID' if tampered else 'INVALID ✗'}\n")

    # 5. Key database
    db = KeyDatabase("demo_keys.json")
    rec = db.add("Alice main wallet", kp, tags=["bitcoin", "hot"])
    print(f"Saved to DB: {rec['id']}")
    print(f"DB count   : {db.count()}\n")

    # 6. Signed transaction
    tx = create_signed_transaction(
        kp["_sk"],
        kp["public_key"],
        {
            "from":      kp["public_key"][:16] + "...",
            "to":        "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf",
            "amount":    1.0,
            "currency":  "BTC",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )
    print("Signed transaction:")
    print(json.dumps({k: v for k, v in tx.items() if k != "signature"}, indent=2))
    print(f"\nVerified: {tx['verified']}")

    # Cleanup demo file
    if os.path.exists("demo_keys.json"):
        os.remove("demo_keys.json")