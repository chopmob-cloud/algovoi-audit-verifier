#!/usr/bin/env python3
"""
Demo bundle generator — builds a small synthetic signed AlgoVoi audit
bundle for testing scripts/verify_audit_bundle.py against.

Use this to:
  * Confirm your Python + rfc8785 install is working before verifying a
    real bundle from AlgoVoi compliance.
  * Inspect the bundle JSON shape end-to-end (matches the production
    format exactly, including HMAC signing).
  * Run integration smoke tests in CI.

The generator produces a 3-row audit_log bundle with a known signing
key. Running the verifier against the output should always print
PASS for the four single-bundle checks (the off-VM anchor is null
because nothing has been "shipped" — that check skips).

Usage:
    python scripts/demo_audit_bundle.py [PATH] [--key KEY]

If PATH is omitted, writes to ./demo_bundle.json in the current dir.
If --key is omitted, uses a fixed deterministic key so the bundle
hash is reproducible across runs.

Standalone — only depends on stdlib + rfc8785 (PyPI). No imports from
the AlgoVoi codebase. Safe to run on an auditor's air-gapped machine.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# Genesis prev_hash for the start of any AlgoVoi chain.
GENESIS_PREV_HASH = "0" * 64

# Deterministic demo key — change with --key for a different bundle hash.
DEFAULT_KEY = "demo-key-not-for-production-use"


def _canonicalise(payload: dict[str, Any]) -> bytes:
    """RFC 8785 canonical JSON — same canonicalisation the gateway uses."""
    import rfc8785
    return rfc8785.dumps(payload)


def _audit_log_row(*, chain_position: int, prev_hash: str) -> dict[str, Any]:
    """Build one audit_log row. Field set mirrors
    shared/utils/audit_chain.py::audit_log_canonical_fields."""
    canonical = {
        "trace_id":       f"00000000-0000-0000-0000-{chain_position:012d}",
        "actor":          "demo-admin@example.com",
        "action":         "tenant.create",
        "target_type":    "tenant",
        "target_id":      f"tnt-{chain_position}",
        "tenant_id":      None,
        "before_state":   None,
        "after_state":    {"created": True, "seq": chain_position},
        "ip_address":     "203.0.113.7",
        "user_agent":     "demo-agent/1.0",
        "created_at":     f"2026-05-06T20:00:{chain_position:02d}+00:00",
        "chain_position": chain_position,
        "prev_hash":      prev_hash,
    }
    content_hash = hashlib.sha256(_canonicalise(canonical)).hexdigest()
    return {"id": chain_position * 100, "content_hash": content_hash, **canonical}


def _screening_hit_row(*, chain_position: int, prev_hash: str) -> dict[str, Any]:
    """Build one screening_hits row. Field set mirrors
    shared/utils/audit_chain.py::screening_hit_canonical_fields."""
    canonical = {
        "screened_at":        f"2026-05-06T20:00:{chain_position:02d}+00:00",
        "subject_type":       "payer",
        "wallet_address":     f"0xdemo{chain_position:0>36}",
        "tenant_id":          None,
        "payment_ledger_id":  None,
        "sanctions_entry_id": chain_position,
        "action_taken":       "flagged",
        "screening_context":  "realtime",
        "chain_position":     chain_position,
        "prev_hash":          prev_hash,
    }
    content_hash = hashlib.sha256(_canonicalise(canonical)).hexdigest()
    return {"id": chain_position * 100, "content_hash": content_hash, **canonical}


def _compliance_event_row(*, chain_position: int, prev_hash: str) -> dict[str, Any]:
    """Build one compliance_events row. Field set mirrors
    shared/utils/audit_chain.py::compliance_event_payload_for_hash. Note:
    `id` IS in the hash payload for this chain (UUID generated app-side
    pre-INSERT, unlike the BIGSERIAL ids of the other chains)."""
    fixed_uuid = f"11111111-1111-1111-1111-{chain_position:012d}"
    tenant_uuid = f"22222222-2222-2222-2222-{chain_position:012d}"
    rule_uuid   = f"33333333-3333-3333-3333-{chain_position:012d}"
    canonical = {
        "id":                     fixed_uuid,
        "tenant_id":              tenant_uuid,
        "rule_id":                rule_uuid,
        "payment_ledger_id":      None,
        "payer_address_snapshot": None,
        "review_of_event_id":     None,
        "event_type":             "alert",
        "metric_value":           "100.0000",
        "threshold_value":        "50.0000",
        "created_at":             f"2026-05-06T20:00:{chain_position:02d}+00:00",
        "chain_position":         chain_position,
        "prev_hash":              prev_hash,
    }
    content_hash = hashlib.sha256(_canonicalise(canonical)).hexdigest()
    # ComplianceEvent renders id as a string (UUID), not int. The verifier's
    # _id_for_bundle helper does the same on the gateway side.
    out = {**canonical, "content_hash": content_hash}
    return out


def _negotiation_trace_row(*, chain_position: int, prev_hash: str) -> dict[str, Any]:
    """Build one negotiation_trace_events row. Field set mirrors
    shared/utils/audit_chain.py::negotiation_trace_canonical_fields."""
    canonical = {
        "trace_id":          "44444444-4444-4444-4444-444444444444",
        "session_id":        None,
        "tenant_id":         None,
        "counterparty_a":    "did:example:demo_agent_a",
        "counterparty_b":    "did:example:demo_agent_b",
        "protocol":          "x402",
        "message_seq":       chain_position,
        "message_role":      "offer" if chain_position == 1 else "counter",
        "message_payload":   {"step": chain_position, "amount": "10000", "asset": "USDC"},
        "payment_ledger_id": None,
        "created_at":        f"2026-05-06T20:00:{chain_position:02d}+00:00",
        "chain_position":    chain_position,
        "prev_hash":         prev_hash,
    }
    content_hash = hashlib.sha256(_canonicalise(canonical)).hexdigest()
    # NegotiationTraceEvent.id is UUID — verifier's _id_for_bundle stringifies.
    fixed_uuid = f"55555555-5555-5555-5555-{chain_position:012d}"
    return {"id": fixed_uuid, "content_hash": content_hash, **canonical}


# Per-chain row builder registry. Adding a 5th chain in the future = add
# a builder above and a row here.
_CHAIN_BUILDERS: dict[str, Any] = {
    "audit_log":                _audit_log_row,
    "screening_hits":           _screening_hit_row,
    "compliance_events":        _compliance_event_row,
    "negotiation_trace_events": _negotiation_trace_row,
}


# Per-chain selection_criteria scaffolds (mirrors what the gateway's
# build_*_bundle shims emit when no filters are supplied).
_CHAIN_EMPTY_CRITERIA: dict[str, dict[str, Any]] = {
    "audit_log": {
        "actor":       None, "action":     None, "target_type": None,
        "tenant_id":   None, "trace_id":   None, "since":       None,
        "until":       None,
    },
    "screening_hits": {
        "subject_type":      None, "action_taken":   None, "screening_context": None,
        "tenant_id":         None, "wallet_address": None,
        "since":             None, "until":          None,
    },
    "compliance_events": {
        "tenant_id":         None, "rule_id":           None, "event_type": None,
        "payment_ledger_id": None, "since":             None, "until":      None,
    },
    "negotiation_trace_events": {
        "trace_id":          None, "tenant_id":     None, "protocol":     None,
        "counterparty":      None, "message_role":  None,
        "payment_ledger_id": None, "since":         None, "until":        None,
    },
}


def build_demo_bundle(
    *,
    chain_name: str = "audit_log",
    row_count: int = 3,
    signing_key: str = DEFAULT_KEY,
    key_id: str = "demo-v1",
) -> dict[str, Any]:
    """Build a complete signed demo bundle for any of the four chains.
    Returns the dict; caller writes it to disk if desired."""
    if row_count < 1:
        raise ValueError("row_count must be >= 1")
    if chain_name not in _CHAIN_BUILDERS:
        raise ValueError(
            f"chain_name '{chain_name}' is not recognised. "
            f"Expected one of: {sorted(_CHAIN_BUILDERS)}"
        )

    builder = _CHAIN_BUILDERS[chain_name]
    rows: list[dict[str, Any]] = []
    prev = GENESIS_PREV_HASH
    for pos in range(1, row_count + 1):
        row = builder(chain_position=pos, prev_hash=prev)
        rows.append(row)
        prev = row["content_hash"]

    head = rows[-1]
    bundle: dict[str, Any] = {
        "chain_format_version": 1,
        "chain_name":           chain_name,
        "bundle_emitted_at":    datetime.now(timezone.utc).isoformat(),
        "selection_criteria":   _CHAIN_EMPTY_CRITERIA[chain_name],
        "selection": {
            "row_count":          len(rows),
            "min_chain_position": rows[0]["chain_position"],
            "max_chain_position": rows[-1]["chain_position"],
            "truncated":          False,
            "max_rows_cap":       10000,
        },
        "rows":          rows,
        "bridging_rows": [],
        "bridging":      {"included": True, "row_count": 0, "truncated": False},
        "chain_anchor": {
            "chain_name":             chain_name,
            "genesis_chain_position": 1,
            "genesis_prev_hash":      GENESIS_PREV_HASH,
            "current_head": {
                "chain_position": head["chain_position"],
                "content_hash":   head["content_hash"],
            },
        },
        "off_vm_anchor": None,    # nothing has been "shipped" in this demo
        "verification_instructions": (
            f"Demo bundle for chain '{chain_name}'. Run "
            f"scripts/verify_audit_bundle.py against this file with "
            f"--signing-key '{signing_key}' to verify."
        ),
    }

    # Sign — HMAC-SHA256 over RFC 8785 canonical JSON of bundle minus signature.
    inner = {k: v for k, v in bundle.items() if k != "bundle_signature"}
    digest = hmac.new(
        signing_key.encode("utf-8"),
        _canonicalise(inner),
        hashlib.sha256,
    ).hexdigest()
    bundle["bundle_signature"] = {
        "algorithm":        "HMAC-SHA256",
        "canonicalisation": "RFC 8785",
        "key_id":           key_id,
        "hex":              digest,
    }
    return bundle


def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic signed AlgoVoi audit bundle for "
                    "testing scripts/verify_audit_bundle.py.",
    )
    parser.add_argument(
        "path", type=Path, nargs="?", default=Path("demo_bundle.json"),
        help="Output path for the demo bundle JSON (default: ./demo_bundle.json).",
    )
    parser.add_argument(
        "--key", default=DEFAULT_KEY,
        help=f"HMAC signing key. Default: {DEFAULT_KEY!r}.",
    )
    parser.add_argument(
        "--key-id", default="demo-v1",
        help="Key id label (default: 'demo-v1').",
    )
    parser.add_argument(
        "--rows", type=int, default=3,
        help="Number of chain rows in the bundle (default: 3).",
    )
    parser.add_argument(
        "--chain", default="audit_log",
        choices=sorted(_CHAIN_BUILDERS.keys()),
        help="Which chain to generate a demo bundle for (default: audit_log).",
    )
    args = parser.parse_args()

    bundle = build_demo_bundle(
        chain_name=args.chain,
        row_count=args.rows,
        signing_key=args.key,
        key_id=args.key_id,
    )
    args.path.parent.mkdir(parents=True, exist_ok=True)
    args.path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")

    print(f"Wrote demo bundle: {args.path}")
    print(f"Chain: {args.chain}, rows: {args.rows}, signing key id: {args.key_id!r}")
    print()
    print("Verify it with:")
    print(f"  python scripts/verify_audit_bundle.py {args.path} --signing-key {args.key!r}")
    print()
    print("Expected verdict: PASS (off_vm_anchor will skip; "
          "bridging not needed because rows are contiguous).")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
