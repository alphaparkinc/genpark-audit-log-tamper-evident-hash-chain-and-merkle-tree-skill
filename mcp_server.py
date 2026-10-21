"""MCP server for Audit Log Tamper-Evident Hash Chain and Merkle Tree."""
import sys
import json
from client import AuditLogChain

_audit_ledger = AuditLogChain()


def handle_request(req):
    method = req.get("method")
    if method == "tools/list":
        return {
            "tools": [
                {
                    "name": "append_audit_event",
                    "description": "Appends an immutable audit event cryptographically linked to the preceding block hash",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "actor": {"type": "string"},
                            "action": {"type": "string"},
                            "target": {"type": "string"},
                            "metadata": {"type": "object"},
                        },
                        "required": ["actor", "action", "target"],
                    },
                },
                {
                    "name": "verify_chain_integrity",
                    "description": "Verifies chronological SHA-256 hash pointers across all blocks to detect any record tampering",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                    },
                },
                {
                    "name": "compute_merkle_root",
                    "description": "Generates binary Merkle tree root hash across all recorded event hashes",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                    },
                },
                {
                    "name": "export_ledger_manifest",
                    "description": "Exports compliance manifest summary with Merkle root and cryptographic validity status",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                    },
                },
            ]
        }
    elif method == "tools/call":
        params = req.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})
        if tool_name == "append_audit_event":
            res = _audit_ledger.append_event(
                actor=args.get("actor"),
                action=args.get("action"),
                target=args.get("target"),
                metadata=args.get("metadata"),
            )
            return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
        elif tool_name == "verify_chain_integrity":
            res = _audit_ledger.verify_chain_integrity()
            return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
        elif tool_name == "compute_merkle_root":
            res = _audit_ledger.compute_merkle_root()
            return {"content": [{"type": "text", "text": res}]}
        elif tool_name == "export_ledger_manifest":
            res = _audit_ledger.export_ledger_manifest()
            return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
    return {"error": "Method not found"}


if __name__ == "__main__":
    for line in sys.stdin:
        if line.strip():
            print(json.dumps(handle_request(json.loads(line))))
            sys.stdout.flush()
