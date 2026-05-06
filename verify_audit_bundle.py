#!/usr/bin/env python3
"""
Reference verifier for AlgoVoi selective-disclosure audit bundles.

Designed to run STANDALONE on an auditor's machine — no imports from the
AlgoVoi codebase. Only stdlib + the `rfc8785` PyPI package (which is
listed as a dependency in the bundle's `verification_instructions`).

What this verifies (mirroring the recipe in
gateway/app/routers/compliance_gate.py::selective_disclosure_bundles):

  1. Per-row content_hash — SHA-256 over the RFC 8785 canonical JSON of
     each row's canonical-fields payload, confirmed against the stored
     content_hash. Tamper-evidence per row.

  2. Continuity walk — across `rows + bridging_rows` ordered by
     chain_position, every prev_hash must equal the previous entry's
     content_hash. No fabricated gap or reorder.

  3. Bundle signature (optional) — when `bundle_signature` is non-null
     and `--signing-key` is provided: HMAC-SHA256 over the RFC 8785
     canonical JSON of `{bundle minus bundle_signature}` must equal
     `bundle_signature.hex`. Proves AlgoVoi emission.

What this does NOT verify (out of scope for the local CLI):

  * Anchor cross-check against the off-VM Object-Locked manifest. That
    requires fetching the s3 object at
    `s3://{off_vm_anchor.bucket_name}/{off_vm_anchor.object_key}` and
    confirming it's still under Object Lock retention. Doable with
    `aws s3api head-object`; this CLI emits the recommended command in
    the report rather than running it (no aws creds required).

Usage:
    python verify_audit_bundle.py BUNDLE.json
    python verify_audit_bundle.py BUNDLE.json --signing-key 'shared-secret'
    python verify_audit_bundle.py BUNDLE.json --signing-key-env AUDIT_BUNDLE_KEY
    python verify_audit_bundle.py BUNDLE.json --json   # machine-readable

Exit codes:
    0 — all checks passed (or skipped optional ones)
    1 — at least one check failed
    2 — bundle is malformed or unparseable
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Per-chain canonical-field extractors
#
# The audit_log / screening_hits / compliance_events / negotiation_trace_events
# chains each commit a different set of fields to their content_hash. The
# functions below MUST match what the gateway computes at insert time —
# any drift here will cause every row to fail verification on the auditor
# side. See shared/utils/audit_chain.py for the source of truth on the
# server.
# ---------------------------------------------------------------------------


def _audit_log_canonical_fields(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "trace_id":       row.get("trace_id"),
        "actor":          row.get("actor"),
        "action":         row.get("action"),
        "target_type":    row.get("target_type"),
        "target_id":      row.get("target_id"),
        "tenant_id":      row.get("tenant_id"),
        "before_state":   row.get("before_state"),
        "after_state":    row.get("after_state"),
        "ip_address":     row.get("ip_address"),
        "user_agent":     row.get("user_agent"),
        "created_at":     row.get("created_at"),
        "chain_position": row.get("chain_position"),
        "prev_hash":      row.get("prev_hash"),
    }


def _screening_hit_canonical_fields(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "screened_at":        row.get("screened_at"),
        "subject_type":       row.get("subject_type"),
        "wallet_address":     row.get("wallet_address"),
        "tenant_id":          row.get("tenant_id"),
        "payment_ledger_id":  row.get("payment_ledger_id"),
        "sanctions_entry_id": row.get("sanctions_entry_id"),
        "action_taken":       row.get("action_taken"),
        "screening_context":  row.get("screening_context"),
        "chain_position":     row.get("chain_position"),
        "prev_hash":          row.get("prev_hash"),
    }


def _compliance_event_canonical_fields(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id":                     row.get("id"),
        "tenant_id":              row.get("tenant_id"),
        "rule_id":                row.get("rule_id"),
        "payment_ledger_id":      row.get("payment_ledger_id"),
        "payer_address_snapshot": row.get("payer_address_snapshot"),
        "review_of_event_id":     row.get("review_of_event_id"),
        "event_type":             row.get("event_type"),
        "metric_value":           row.get("metric_value"),
        "threshold_value":        row.get("threshold_value"),
        "created_at":             row.get("created_at"),
        "chain_position":         row.get("chain_position"),
        "prev_hash":              row.get("prev_hash"),
    }


def _negotiation_trace_canonical_fields(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "trace_id":          row.get("trace_id"),
        "session_id":        row.get("session_id"),
        "tenant_id":         row.get("tenant_id"),
        "counterparty_a":    row.get("counterparty_a"),
        "counterparty_b":    row.get("counterparty_b"),
        "protocol":          row.get("protocol"),
        "message_seq":       row.get("message_seq"),
        "message_role":      row.get("message_role"),
        "message_payload":   row.get("message_payload"),
        "payment_ledger_id": row.get("payment_ledger_id"),
        "created_at":        row.get("created_at"),
        "chain_position":    row.get("chain_position"),
        "prev_hash":         row.get("prev_hash"),
    }


_FIELD_EXTRACTORS = {
    "audit_log":                _audit_log_canonical_fields,
    "screening_hits":           _screening_hit_canonical_fields,
    "compliance_events":        _compliance_event_canonical_fields,
    "negotiation_trace_events": _negotiation_trace_canonical_fields,
}


# Bundle envelope versions this verifier knows how to interpret. Bumping
# the gateway's CHAIN_FORMAT_VERSION (control_plane/app/services/audit.py)
# means a breaking change to either the bundle envelope or the per-chain
# canonical-fields layout — verifiers built against an older version
# CANNOT correctly verify a newer bundle, so we fail fatally rather than
# return false-PASS. Auditors should pull a fresh verifier.
_SUPPORTED_CHAIN_FORMAT_VERSIONS = frozenset({1})


# Per-chain map: selection_criteria key -> row field name (exact-match).
# Used by check_selection_criteria_match. Only fields with a meaningful
# exact-match equivalent are listed here; range filters (since/until) and
# disjunctive filters (negotiation_trace's `counterparty` matches a OR b)
# are handled separately below.
_CRITERIA_EXACT_MATCH: dict[str, dict[str, str]] = {
    "audit_log": {
        "actor":       "actor",
        "action":      "action",
        "target_type": "target_type",
        "tenant_id":   "tenant_id",
        "trace_id":    "trace_id",
    },
    "screening_hits": {
        "subject_type":      "subject_type",
        "action_taken":      "action_taken",
        "screening_context": "screening_context",
        "tenant_id":         "tenant_id",
        "wallet_address":    "wallet_address",
    },
    "compliance_events": {
        "tenant_id":         "tenant_id",
        "rule_id":           "rule_id",
        "event_type":        "event_type",
        "payment_ledger_id": "payment_ledger_id",
    },
    "negotiation_trace_events": {
        "trace_id":          "trace_id",
        "tenant_id":         "tenant_id",
        "protocol":          "protocol",
        "message_role":      "message_role",
        "payment_ledger_id": "payment_ledger_id",
        # `counterparty` is intentionally absent — it's a disjunctive filter
        # (matches counterparty_a OR counterparty_b) handled in
        # _check_disjunctive_counterparty below.
    },
}


# ---------------------------------------------------------------------------
# Result aggregation
# ---------------------------------------------------------------------------


class CheckReport:
    """Aggregates check results into a single PASS/FAIL summary."""

    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []
        self.fatal: list[str] = []

    def add(self, name: str, passed: bool, detail: str = "") -> None:
        self.checks.append({"name": name, "passed": passed, "detail": detail})

    def add_skip(self, name: str, reason: str) -> None:
        self.checks.append({"name": name, "passed": None, "detail": f"skipped: {reason}"})

    def add_fatal(self, msg: str) -> None:
        self.fatal.append(msg)

    @property
    def all_passed(self) -> bool:
        if self.fatal:
            return False
        return all(c["passed"] is not False for c in self.checks)

    @property
    def has_fatal(self) -> bool:
        return bool(self.fatal)

    def to_dict(self) -> dict[str, Any]:
        return {
            "all_passed": self.all_passed,
            "fatal":      self.fatal,
            "checks":     self.checks,
        }

    def render(self) -> str:
        lines: list[str] = []
        if self.fatal:
            lines.append("FATAL:")
            for f in self.fatal:
                lines.append(f"  ! {f}")
            return "\n".join(lines)
        for c in self.checks:
            mark = "ok" if c["passed"] is True else ("FAIL" if c["passed"] is False else "skip")
            line = f"  [{mark:>4}] {c['name']}"
            if c.get("detail"):
                line += f" -- {c['detail']}"
            lines.append(line)
        verdict = "PASS" if self.all_passed else "FAIL"
        lines.append(f"\nVerdict: {verdict}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def _canonicalise(payload: dict[str, Any]) -> bytes:
    """Wrapper for rfc8785.dumps — the canonical JSON spec the gateway uses
    when computing every hash. Imported lazily so the script's --help works
    even if rfc8785 isn't installed yet."""
    import rfc8785
    return rfc8785.dumps(payload)


def check_per_row_content_hash(bundle: dict[str, Any], report: CheckReport) -> None:
    """Re-compute SHA-256 over the canonical JSON of each selected row's
    canonical-fields payload, confirm equals row.content_hash."""
    chain_name = bundle.get("chain_name")
    extractor = _FIELD_EXTRACTORS.get(chain_name) if chain_name else None
    if extractor is None:
        report.add(
            "per_row_content_hash",
            False,
            f"unknown chain_name '{chain_name}' (expected one of {sorted(_FIELD_EXTRACTORS)})",
        )
        return

    rows = bundle.get("rows", [])
    if not rows:
        report.add_skip("per_row_content_hash", "selection is empty (zero rows)")
        return

    failures: list[str] = []
    for r in rows:
        expected = r.get("content_hash")
        if not expected or len(expected) != 64:
            failures.append(f"chain_position={r.get('chain_position')!r}: stored content_hash missing or wrong length")
            continue
        canonical = extractor(r)
        actual = hashlib.sha256(_canonicalise(canonical)).hexdigest()
        if actual != expected:
            failures.append(
                f"chain_position={r.get('chain_position')!r}: "
                f"recomputed {actual[:16]}... != stored {expected[:16]}..."
            )

    if failures:
        detail = f"{len(failures)} of {len(rows)} rows failed: " + "; ".join(failures[:3])
        if len(failures) > 3:
            detail += f"; (+{len(failures) - 3} more)"
        report.add("per_row_content_hash", False, detail)
    else:
        report.add("per_row_content_hash", True, f"{len(rows)} rows verified")


def check_continuity(bundle: dict[str, Any], report: CheckReport) -> None:
    """Walk rows + bridging_rows ordered by chain_position. Every entry's
    prev_hash must equal the previous entry's content_hash."""
    rows = bundle.get("rows", [])
    bridging = bundle.get("bridging_rows", [])
    bridging_meta = bundle.get("bridging", {})

    if not rows:
        report.add_skip("continuity", "selection is empty")
        return

    union: list[dict[str, Any]] = []
    for r in rows:
        union.append({
            "chain_position": r.get("chain_position"),
            "content_hash":   r.get("content_hash"),
            "prev_hash":      r.get("prev_hash"),
            "kind":           "selected",
        })
    for b in bridging:
        union.append({
            "chain_position": b.get("chain_position"),
            "content_hash":   b.get("content_hash"),
            "prev_hash":      b.get("prev_hash"),
            "kind":           "bridging",
        })
    union.sort(key=lambda x: (x["chain_position"] is None, x["chain_position"]))

    # Detect gaps in the merged set. If gaps exist AND bridging wasn't
    # included, we can't verify continuity locally — that's a known limit.
    if len(union) > 1:
        positions = [u["chain_position"] for u in union]
        gaps = []
        for i in range(1, len(positions)):
            if positions[i] is None or positions[i - 1] is None:
                continue
            if positions[i] - positions[i - 1] > 1:
                gaps.append((positions[i - 1], positions[i]))
        if gaps and not bridging_meta.get("included"):
            report.add_skip(
                "continuity",
                f"gaps between selected positions {gaps[:2]} but bridging_rows not included; "
                "request the bundle with include_bridging_rows=true to enable this check",
            )
            return
        if gaps:
            # Bridging WAS requested but still has gaps → the bundle itself
            # claims more bridging rows existed but were truncated, OR there
            # are real gaps in the chain (a tamper).
            report.add(
                "continuity",
                False,
                f"gaps remain after bridging at positions {gaps[:3]} — chain has missing rows",
            )
            return

    # Walk
    failures: list[str] = []
    for i in range(1, len(union)):
        prev = union[i - 1]
        curr = union[i]
        if curr["prev_hash"] != prev["content_hash"]:
            failures.append(
                f"position {curr['chain_position']} ({curr['kind']}): "
                f"prev_hash {curr['prev_hash'][:12]}... != "
                f"content_hash of position {prev['chain_position']} ({prev['kind']}) "
                f"{prev['content_hash'][:12]}..."
            )

    if failures:
        detail = f"{len(failures)} broken link(s): " + "; ".join(failures[:2])
        report.add("continuity", False, detail)
    else:
        report.add(
            "continuity",
            True,
            f"{len(union)} entries (selected={len(rows)}, bridging={len(bridging)}) chain forward correctly",
        )


def check_bundle_signature(
    bundle: dict[str, Any],
    signing_key: str | None,
    report: CheckReport,
) -> None:
    """If the bundle has a non-null bundle_signature AND signing_key was
    supplied, recompute HMAC-SHA256 over rfc8785(bundle minus signature)
    and confirm equals signature.hex."""
    sig = bundle.get("bundle_signature")
    if sig is None:
        report.add_skip("bundle_signature", "bundle has bundle_signature: null (signing not configured server-side)")
        return
    if not isinstance(sig, dict) or "hex" not in sig:
        report.add("bundle_signature", False, f"bundle_signature is not a valid signature object: {sig!r}")
        return
    if not signing_key:
        report.add_skip(
            "bundle_signature",
            f"bundle is signed with key_id='{sig.get('key_id')}', algorithm='{sig.get('algorithm')}' — "
            "pass --signing-key or --signing-key-env to verify",
        )
        return
    if sig.get("algorithm") != "HMAC-SHA256" or sig.get("canonicalisation") != "RFC 8785":
        report.add(
            "bundle_signature",
            False,
            f"unsupported signature algorithm/canonicalisation: {sig.get('algorithm')}/{sig.get('canonicalisation')}",
        )
        return

    inner = {k: v for k, v in bundle.items() if k != "bundle_signature"}
    canonical = _canonicalise(inner)
    expected = hmac.new(
        signing_key.encode("utf-8"),
        canonical,
        hashlib.sha256,
    ).hexdigest()
    if expected == sig["hex"]:
        report.add(
            "bundle_signature",
            True,
            f"HMAC-SHA256 verified against key_id='{sig.get('key_id')}'",
        )
    else:
        report.add(
            "bundle_signature",
            False,
            f"recomputed {expected[:16]}... != stored {sig['hex'][:16]}... — wrong key, or bundle tampered",
        )


def _parse_object_key_sha_prefix(object_key: str) -> str | None:
    """Extract the 16-hex-char sha256 prefix encoded in the object_key.

    Format (per shared/utils/audit_chain_shipper.py::build_object_key):
      '{chain_name}/{from:09d}-{to:09d}-{sha256[:16]}.ndjson'
    e.g. 'audit_log/000000001-000000100-abc123def456ab78.ndjson'
    """
    if not object_key:
        return None
    basename = object_key.rsplit("/", 1)[-1]
    if not basename.endswith(".ndjson"):
        return None
    stem = basename[: -len(".ndjson")]
    parts = stem.rsplit("-", 1)
    if len(parts) != 2:
        return None
    sha_prefix = parts[1]
    if len(sha_prefix) != 16 or not all(c in "0123456789abcdef" for c in sha_prefix):
        return None
    return sha_prefix


def check_off_vm_anchor(
    bundle: dict[str, Any],
    manifest_dir: Path | None,
    report: CheckReport,
) -> None:
    """Verify the off-VM Object-Locked manifest locally if --manifest-dir was
    provided, otherwise emit the recommended `aws s3api head-object` command.

    When `manifest_dir` is set, the verifier:
      1. Locates the manifest file within manifest_dir matching
         off_vm_anchor.object_key (or just its basename — both supported).
      2. Computes the full SHA-256 of the file bytes.
      3. Confirms the first 16 hex chars match the sha256 prefix encoded
         in object_key (this is what the gateway hashed at ship time and
         encoded into the object_key per audit_chain_shipper.build_object_key).
      4. Parses the LAST NDJSON line and confirms its `chain_position` +
         `content_hash` match `bundle.chain_anchor.current_head`.

    All four sub-checks must pass for the manifest cross-check to succeed.
    On any miss the result is FAIL — a manifest-vs-anchor mismatch is the
    strongest tamper signal available locally without bucket-read creds.
    """
    anchor = bundle.get("off_vm_anchor")
    if not anchor:
        report.add_skip(
            "off_vm_anchor",
            "no off_vm_anchor in bundle (chain has not been shipped yet, "
            "or bundle is from before shipping started)",
        )
        return

    bucket = anchor.get("bucket_name")
    key = anchor.get("object_key") or ""
    lock_until = anchor.get("object_lock_until")

    if manifest_dir is None:
        cmd = (
            f"aws s3api head-object --bucket {bucket} --key {key!s}  "
            "  # confirm ObjectLockMode=COMPLIANCE and ObjectLockRetainUntilDate "
            f"matches '{lock_until}'"
        )
        report.add_skip(
            "off_vm_anchor",
            f"pass --manifest-dir DIR to verify a downloaded manifest locally, "
            f"or run separately: {cmd}",
        )
        return

    expected_sha_prefix = _parse_object_key_sha_prefix(key)
    if expected_sha_prefix is None:
        report.add(
            "off_vm_anchor",
            False,
            f"could not parse sha256 prefix from object_key '{key}' "
            "(expected '{chain_name}/{from:09d}-{to:09d}-{sha256[:16]}.ndjson')",
        )
        return

    # Try a few path layouts: full key under manifest_dir, basename only.
    basename = key.rsplit("/", 1)[-1]
    candidates = [
        manifest_dir / key,        # e.g. manifests/audit_log/000000001-000000100-abc.ndjson
        manifest_dir / basename,   # e.g. manifests/000000001-000000100-abc.ndjson
    ]
    manifest_path = next((p for p in candidates if p.exists()), None)
    if manifest_path is None:
        report.add(
            "off_vm_anchor",
            False,
            f"manifest file not found in {manifest_dir} "
            f"(looked for {key!s} and {basename!s})",
        )
        return

    manifest_bytes = manifest_path.read_bytes()
    actual_sha_full = hashlib.sha256(manifest_bytes).hexdigest()
    if actual_sha_full[:16] != expected_sha_prefix:
        report.add(
            "off_vm_anchor",
            False,
            f"manifest sha256 prefix {actual_sha_full[:16]} != "
            f"object_key prefix {expected_sha_prefix} — manifest tampered or wrong file",
        )
        return

    # Parse last NDJSON line.
    lines = [ln for ln in manifest_bytes.split(b"\n") if ln.strip()]
    if not lines:
        report.add("off_vm_anchor", False, f"manifest at {manifest_path} is empty")
        return
    try:
        last_row = json.loads(lines[-1].decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        report.add("off_vm_anchor", False, f"last NDJSON line is malformed: {exc}")
        return

    head = (bundle.get("chain_anchor") or {}).get("current_head") or {}
    head_pos = head.get("chain_position")
    head_hash = head.get("content_hash")
    last_pos = last_row.get("chain_position")
    last_hash = last_row.get("content_hash")
    last_shipped = anchor.get("last_shipped_position")

    # The bundle's chain_anchor.current_head reflects the LATEST in-DB chain
    # position, which may exceed last_shipped (newer rows queued but not
    # yet shipped). The manifest's last entry should match
    # off_vm_anchor.last_shipped_position, NOT necessarily current_head.
    if last_pos != last_shipped:
        report.add(
            "off_vm_anchor",
            False,
            f"manifest last entry chain_position={last_pos} != "
            f"off_vm_anchor.last_shipped_position={last_shipped}",
        )
        return

    # If the in-DB head hasn't advanced beyond last_shipped, head_hash must
    # also match. If it HAS advanced, head_hash differs and that's expected.
    if head_pos == last_shipped and last_hash != head_hash:
        report.add(
            "off_vm_anchor",
            False,
            f"manifest last entry content_hash {last_hash[:16] if last_hash else None}... "
            f"!= chain_anchor.current_head.content_hash {head_hash[:16] if head_hash else None}...",
        )
        return

    detail = (
        f"manifest sha256 matches object_key prefix; last entry chain_position="
        f"{last_pos} content_hash={last_hash[:16] if last_hash else None}... "
        f"matches off_vm_anchor.last_shipped_position"
    )
    if head_pos == last_shipped:
        detail += " (and current_head)"
    else:
        detail += f" (current_head is ahead at {head_pos} — newer rows not yet shipped)"
    report.add("off_vm_anchor", True, detail)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def check_selection_criteria_match(bundle: dict[str, Any], report: CheckReport) -> None:
    """
    Per-row consistency between `selection_criteria` and `rows`.

    Closes a real attack vector: a malicious operator could return chain
    rows that hash-verify correctly but DON'T match the filter the
    auditor's request specified. The bundle would technically pass
    per_row_content_hash + continuity (because the rows ARE genuine
    chain rows) but be substantively misleading — the auditor asked
    for actor=X and got rows for actor=Y.

    Implementation: for every non-null exact-match filter in
    selection_criteria, every row in `rows` must have the corresponding
    field equal to the filter value. Range filters (since/until) and
    the disjunctive `counterparty` filter (negotiation_trace) are
    handled separately. If `rows` is empty, this is vacuously true and
    we report SKIP.
    """
    chain_name = bundle.get("chain_name")
    rows = bundle.get("rows") or []
    crit = bundle.get("selection_criteria") or {}

    if not rows:
        report.add_skip(
            "selection_criteria_match",
            "selection is empty (zero rows); criteria match is vacuously true",
        )
        return

    exact_map = _CRITERIA_EXACT_MATCH.get(chain_name, {})

    # Collect every (criteria_key, expected_value) pair that's actually set
    active_filters: list[tuple[str, Any, str]] = []   # (criteria_key, expected, row_field)
    for crit_key, row_field in exact_map.items():
        expected = crit.get(crit_key)
        if expected is not None:
            active_filters.append((crit_key, expected, row_field))

    # Disjunctive: negotiation_trace_events.counterparty matches a OR b
    counterparty: str | None = None
    if chain_name == "negotiation_trace_events":
        counterparty = crit.get("counterparty")

    if not active_filters and counterparty is None:
        # No filters were set — everything matches by definition.
        report.add_skip(
            "selection_criteria_match",
            "no exact-match filters set in selection_criteria",
        )
        return

    failures: list[str] = []
    for r in rows:
        for crit_key, expected, row_field in active_filters:
            actual = r.get(row_field)
            if actual != expected:
                failures.append(
                    f"chain_position={r.get('chain_position')}: "
                    f"row.{row_field}={actual!r} does not match "
                    f"selection_criteria.{crit_key}={expected!r}"
                )
        if counterparty is not None:
            a = r.get("counterparty_a")
            b = r.get("counterparty_b")
            if a != counterparty and b != counterparty:
                failures.append(
                    f"chain_position={r.get('chain_position')}: "
                    f"neither counterparty_a={a!r} nor counterparty_b={b!r} "
                    f"matches selection_criteria.counterparty={counterparty!r}"
                )

    if failures:
        sample = failures[:3]
        detail = (
            f"{len(failures)} row(s) violate selection_criteria. "
            "First: " + sample[0]
        )
        if len(failures) > 1:
            detail += f"  (+{len(failures) - 1} more)"
        report.add("selection_criteria_match", False, detail)
    else:
        applied = ", ".join(f"{k}={v!r}" for k, _v, _r in [(k, e, r) for k, e, r in active_filters] for v in [_v])
        if counterparty is not None:
            applied = (applied + ", " if applied else "") + f"counterparty={counterparty!r}"
        report.add(
            "selection_criteria_match",
            True,
            f"all {len(rows)} row(s) match the {len(active_filters) + (1 if counterparty else 0)} active filter(s): {applied}",
        )


def check_aggregate(bundles: list[dict[str, Any]], report: CheckReport) -> None:
    """
    Cross-bundle integrity check. Run when an auditor receives multiple
    bundles for the same chain (e.g. one per quarter over a year of
    activity) and wants to confirm they're internally consistent — i.e.
    AlgoVoi can't have shown a different version of history to different
    audiences.

    Three sub-checks:

      1. SAME CHAIN — every bundle.chain_name must match. Cross-chain
         comparison is meaningless and probably indicates a bundle was
         dropped into the wrong directory.

      2. OVERLAP CONSISTENCY — for any chain_position that appears in
         more than one bundle (across `rows` ∪ `bridging_rows`), the
         (content_hash, prev_hash) tuple must be identical in every
         bundle. A disagreement is a strong tamper signal: AlgoVoi
         cannot legitimately produce two valid bundles that disclose
         different facts about the same chain row.

      3. MONOTONIC HEAD — sort bundles by bundle_emitted_at ascending;
         chain_anchor.current_head.chain_position must be monotonically
         non-decreasing. A newer bundle claiming a smaller head than an
         older bundle would mean the chain regressed — never legitimate
         for a write-once chain.

    Pass-through behaviour: if only ONE bundle is given, this is a no-op
    skip (single-bundle mode handled by the standard four checks).
    """
    if len(bundles) < 2:
        return  # caller doesn't run this for single-bundle mode anyway

    # 1. Same chain
    chain_names = {b.get("chain_name") for b in bundles}
    if len(chain_names) != 1:
        report.add(
            "aggregate.same_chain",
            False,
            f"bundles span multiple chains: {sorted(chain_names)} — "
            "aggregation requires all bundles to be from one chain",
        )
        return  # other aggregate checks are meaningless across mixed chains
    report.add(
        "aggregate.same_chain",
        True,
        f"all {len(bundles)} bundles are from chain '{chain_names.pop()}'",
    )

    # 2. Overlap consistency — collect (chain_position) -> {(content_hash, prev_hash)}
    #    across rows + bridging_rows, flag any chain_position with more than
    #    one distinct (content_hash, prev_hash) tuple.
    by_position: dict[int, set[tuple[str, str]]] = {}
    sources: dict[int, list[str]] = {}   # position -> list of bundle indices
    for idx, b in enumerate(bundles):
        for r in (b.get("rows") or []):
            cp = r.get("chain_position")
            if cp is None:
                continue
            tup = (r.get("content_hash"), r.get("prev_hash"))
            by_position.setdefault(cp, set()).add(tup)
            sources.setdefault(cp, []).append(f"bundle[{idx}].rows")
        for r in (b.get("bridging_rows") or []):
            cp = r.get("chain_position")
            if cp is None:
                continue
            tup = (r.get("content_hash"), r.get("prev_hash"))
            by_position.setdefault(cp, set()).add(tup)
            sources.setdefault(cp, []).append(f"bundle[{idx}].bridging_rows")

    contradictions = [
        (cp, tuples) for cp, tuples in by_position.items() if len(tuples) > 1
    ]
    if contradictions:
        sample = contradictions[:2]
        detail = (
            f"{len(contradictions)} chain_position(s) have contradicting "
            f"(content_hash, prev_hash) values across bundles. "
            f"First: position {sample[0][0]} appears in {sources.get(sample[0][0], [])} "
            f"with {len(sample[0][1])} distinct hash tuples"
        )
        report.add("aggregate.overlap_consistency", False, detail)
    else:
        overlap_positions = sum(1 for cp, srcs in sources.items() if len(srcs) > 1)
        report.add(
            "aggregate.overlap_consistency",
            True,
            f"{overlap_positions} chain_position(s) appeared in multiple bundles; "
            "all overlap rows agree on (content_hash, prev_hash)",
        )

    # 3. Monotonic head (sorted by bundle_emitted_at)
    head_pairs = [
        (
            b.get("bundle_emitted_at") or "",
            ((b.get("chain_anchor") or {}).get("current_head") or {}).get("chain_position"),
            idx,
        )
        for idx, b in enumerate(bundles)
    ]
    head_pairs.sort(key=lambda x: x[0])
    decreasing: list[tuple[str, int | None, str, int | None]] = []
    for i in range(1, len(head_pairs)):
        prev_emitted, prev_head, prev_idx = head_pairs[i - 1]
        curr_emitted, curr_head, curr_idx = head_pairs[i]
        if prev_head is None or curr_head is None:
            continue   # can't compare; treat as ok
        if curr_head < prev_head:
            decreasing.append((prev_emitted, prev_head, curr_emitted, curr_head))
    if decreasing:
        d = decreasing[0]
        report.add(
            "aggregate.monotonic_head",
            False,
            f"chain head regressed: bundle emitted {d[0]} claimed head "
            f"chain_position={d[1]}, but bundle emitted {d[2]} (later) claimed "
            f"head chain_position={d[3]} — chain cannot legitimately go backwards",
        )
    else:
        heads = [str(h[1]) for h in head_pairs if h[1] is not None]
        report.add(
            "aggregate.monotonic_head",
            True,
            f"chain heads non-decreasing across emission order: [{', '.join(heads)}]",
        )


def verify_bundle(
    bundle: dict[str, Any],
    signing_key: str | None = None,
    manifest_dir: Path | None = None,
) -> CheckReport:
    """Run all checks against a parsed bundle dict. Returns the CheckReport."""
    report = CheckReport()

    # Version check first — if this verifier doesn't know the envelope
    # format, every other check is unreliable. Fail fatally with a clear
    # "go pull a newer verifier" message rather than risk a false PASS.
    version = bundle.get("chain_format_version")
    if version is None:
        report.add_fatal(
            "bundle is missing required field 'chain_format_version' "
            "— bundle is malformed or was not emitted by AlgoVoi"
        )
        return report
    if version not in _SUPPORTED_CHAIN_FORMAT_VERSIONS:
        report.add_fatal(
            f"bundle.chain_format_version={version!r} is not supported by "
            f"this verifier (supported: {sorted(_SUPPORTED_CHAIN_FORMAT_VERSIONS)}). "
            "Pull a fresh verifier from https://github.com/chopmob-cloud/algovoi-audit-verifier "
            "— running an older verifier against a newer bundle risks a false PASS."
        )
        return report

    chain_name = bundle.get("chain_name")
    if chain_name not in _FIELD_EXTRACTORS:
        report.add_fatal(
            f"bundle.chain_name='{chain_name}' is not recognised "
            f"(expected one of: {sorted(_FIELD_EXTRACTORS)})"
        )
        return report

    if "rows" not in bundle:
        report.add_fatal("bundle is missing required field 'rows'")
        return report

    check_per_row_content_hash(bundle, report)
    check_continuity(bundle, report)
    check_selection_criteria_match(bundle, report)
    check_bundle_signature(bundle, signing_key, report)
    check_off_vm_anchor(bundle, manifest_dir, report)
    return report


def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify an AlgoVoi selective-disclosure audit bundle locally.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "bundles", type=Path, nargs="+",
        help=(
            "Path(s) to bundle JSON file(s). With one file, runs the standard "
            "four-check verification. With two or more, also runs cross-bundle "
            "aggregate checks (same chain, no contradicting overlap-row hashes, "
            "monotonic chain head over time)."
        ),
    )
    parser.add_argument(
        "--signing-key", default=None,
        help="HMAC signing key (string). Required to verify bundle_signature.",
    )
    parser.add_argument(
        "--signing-key-env", default=None, metavar="VAR",
        help="Read the signing key from this environment variable.",
    )
    parser.add_argument(
        "--manifest-dir", type=Path, default=None, metavar="DIR",
        help=(
            "Directory containing locally-downloaded off-VM Object-Locked NDJSON "
            "manifest files. When provided, the verifier confirms that the "
            "manifest matching off_vm_anchor.object_key has the right sha256 "
            "and that its last entry matches the bundle's anchor. Without this "
            "flag, off_vm_anchor verification is skipped (recommended `aws s3api "
            "head-object` command is emitted instead)."
        ),
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit the report as JSON to stdout (machine-readable).",
    )
    args = parser.parse_args()

    if args.signing_key and args.signing_key_env:
        print("error: pass at most one of --signing-key or --signing-key-env", file=sys.stderr)
        return 2

    signing_key = args.signing_key
    if args.signing_key_env:
        signing_key = os.environ.get(args.signing_key_env)
        if not signing_key:
            print(f"error: env var {args.signing_key_env} is not set", file=sys.stderr)
            return 2

    if args.manifest_dir is not None and not args.manifest_dir.is_dir():
        print(f"error: --manifest-dir is not a directory: {args.manifest_dir}", file=sys.stderr)
        return 2

    # Load every requested bundle. A missing/malformed file is a hard error
    # (we don't want to silently skip a bundle the auditor explicitly asked
    # to verify).
    bundles: list[dict[str, Any]] = []
    for path in args.bundles:
        if not path.exists():
            print(f"error: bundle file not found: {path}", file=sys.stderr)
            return 2
        try:
            bundles.append(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError as exc:
            print(f"error: bundle {path} is not valid JSON: {exc}", file=sys.stderr)
            return 2

    # Per-bundle verification first.
    per_bundle_reports: list[tuple[Path, CheckReport]] = []
    overall_pass = True
    overall_fatal = False
    for path, bundle in zip(args.bundles, bundles):
        rpt = verify_bundle(
            bundle,
            signing_key=signing_key,
            manifest_dir=args.manifest_dir,
        )
        per_bundle_reports.append((path, rpt))
        if rpt.has_fatal:
            overall_fatal = True
        if not rpt.all_passed:
            overall_pass = False

    # Cross-bundle aggregate (only when 2+ bundles were given).
    aggregate_report: CheckReport | None = None
    if len(bundles) >= 2 and not overall_fatal:
        aggregate_report = CheckReport()
        check_aggregate(bundles, aggregate_report)
        if not aggregate_report.all_passed:
            overall_pass = False

    # Output.
    if args.json:
        out = {
            "bundles": [
                {"path": str(p), "report": rpt.to_dict()}
                for p, rpt in per_bundle_reports
            ],
        }
        if aggregate_report is not None:
            out["aggregate"] = aggregate_report.to_dict()
        out["all_passed"] = overall_pass and not overall_fatal
        print(json.dumps(out, indent=2))
    else:
        for path, rpt in per_bundle_reports:
            print(f"\n=== {path} ===")
            print(rpt.render())
        if aggregate_report is not None:
            print(f"\n=== aggregate ({len(bundles)} bundles) ===")
            print(aggregate_report.render())
        verdict = "PASS" if (overall_pass and not overall_fatal) else "FAIL"
        print(f"\nOverall: {verdict}")

    if overall_fatal:
        return 2
    return 0 if overall_pass else 1


if __name__ == "__main__":
    sys.exit(_main())
