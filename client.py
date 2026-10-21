"""Audit Log Tamper-Evident Hash Chain and Merkle Tree.
100% Python Standard Library.
"""

import hashlib
import json
import time
from typing import List, Dict, Any, Optional


class AuditLogChain:
    """Tamper-evident audit ledger that links sequential event entries into a cryptographic
    SHA-256 hash chain and computes Merkle root proofs for compliance verification."""

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self):
        self.chain: List[Dict[str, Any]] = []

    def append_event(
        self,
        actor: str,
        action: str,
        target: str,
        metadata: Optional[Dict[str, Any]] = None,
        timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Appends a new event entry cryptographically bound to the preceding block hash."""
        idx = len(self.chain)
        prev_hash = self.chain[-1]["current_hash"] if idx > 0 else self.GENESIS_HASH
        ts = timestamp if timestamp is not None else time.time()

        payload = {
            "index": idx,
            "timestamp": ts,
            "actor": actor,
            "action": action,
            "target": target,
            "metadata": metadata or {},
            "prev_hash": prev_hash,
        }

        # Canonical deterministic JSON string for hashing
        canonical_str = json.dumps(payload, sort_keys=True)
        current_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        entry = {**payload, "current_hash": current_hash}
        self.chain.append(entry)
        return entry

    def verify_chain_integrity(self) -> Dict[str, Any]:
        """Validates the entire chronological chain. Returns True if zero tampering detected."""
        for i, block in enumerate(self.chain):
            expected_prev = self.chain[i - 1]["current_hash"] if i > 0 else self.GENESIS_HASH
            if block["prev_hash"] != expected_prev:
                return {
                    "is_valid": False,
                    "corrupted_index": i,
                    "reason": f"Hash pointer broken at block #{i}. Expected prev_hash {expected_prev}, got {block['prev_hash']}",
                }

            # Recompute hash
            recalc_payload = {
                "index": block["index"],
                "timestamp": block["timestamp"],
                "actor": block["actor"],
                "action": block["action"],
                "target": block["target"],
                "metadata": block["metadata"],
                "prev_hash": block["prev_hash"],
            }
            canonical_str = json.dumps(recalc_payload, sort_keys=True)
            recalc_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

            if recalc_hash != block["current_hash"]:
                return {
                    "is_valid": False,
                    "corrupted_index": i,
                    "reason": f"Payload altered at block #{i}. Expected current_hash {recalc_hash}, recorded {block['current_hash']}",
                }

        return {
            "is_valid": True,
            "total_blocks_verified": len(self.chain),
            "latest_hash": self.chain[-1]["current_hash"] if self.chain else self.GENESIS_HASH,
        }

    def compute_merkle_root(self) -> str:
        """Constructs a binary Merkle tree over all block hashes and returns the root hash."""
        if not self.chain:
            return self.GENESIS_HASH

        hashes = [b["current_hash"] for b in self.chain]

        while len(hashes) > 1:
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])  # Duplicate last leaf if odd

            new_level = []
            for i in range(0, len(hashes), 2):
                combined = (hashes[i] + hashes[i + 1]).encode("utf-8")
                parent_hash = hashlib.sha256(combined).hexdigest()
                new_level.append(parent_hash)
            hashes = new_level

        return hashes[0]

    def export_ledger_manifest(self) -> Dict[str, Any]:
        """Exports high-level cryptographic summary of the compliance log."""
        verification = self.verify_chain_integrity()
        return {
            "total_events": len(self.chain),
            "merkle_root": self.compute_merkle_root(),
            "chain_valid": verification["is_valid"],
            "genesis_hash": self.GENESIS_HASH,
            "latest_block_hash": verification.get("latest_hash"),
        }
