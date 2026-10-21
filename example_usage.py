"""Example usage for Audit Log Tamper-Evident Hash Chain and Merkle Tree."""
from client import AuditLogChain


def main():
    ledger = AuditLogChain()

    print("=== 1. Recording Audit Events ===")
    b0 = ledger.append_event(
        actor="system_admin",
        action="CREATE_TENANT",
        target="org_globex_corp",
        metadata={"plan": "enterprise", "seats": 50},
    )
    print(f"Block #0 Hash: {b0['current_hash'][:16]}... (prev: {b0['prev_hash'][:8]}...)")

    b1 = ledger.append_event(
        actor="user_alice",
        action="UPDATE_SECURITY_POLICY",
        target="mfa_settings",
        metadata={"enforce_totp": True},
    )
    print(f"Block #1 Hash: {b1['current_hash'][:16]}... (prev: {b1['prev_hash'][:8]}...)")

    b2 = ledger.append_event(
        actor="bot_rotator",
        action="ROTATE_KMS_KEY",
        target="key_kms_prod_01",
        metadata={"algorithm": "AES-256-GCM"},
    )
    print(f"Block #2 Hash: {b2['current_hash'][:16]}... (prev: {b2['prev_hash'][:8]}...)")

    print("\n=== 2. Verifying Untampered Chain Integrity ===")
    v_clean = ledger.verify_chain_integrity()
    print("Clean Verification:", v_clean)
    assert v_clean["is_valid"] is True

    print("\n=== 3. Computing Cryptographic Merkle Root ===")
    merkle_root = ledger.compute_merkle_root()
    print("Merkle Root:", merkle_root)

    print("\n=== 4. Tampering Simulation & Instant Detection ===")
    # Malicious actor tampers with block 1 payload
    ledger.chain[1]["action"] = "DISABLE_SECURITY_POLICY"
    v_tampered = ledger.verify_chain_integrity()
    print("Tampered Verification:", v_tampered)
    assert v_tampered["is_valid"] is False
    print("Detected corruption successfully at block:", v_tampered["corrupted_index"])


if __name__ == "__main__":
    main()
