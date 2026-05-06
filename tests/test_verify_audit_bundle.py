"""
Unit tests for the standalone bundle verifier CLI
(scripts/verify_audit_bundle.py).

Approach: build small synthetic bundles in-memory using the same hashing
machinery the gateway uses, then run the verifier's `verify_bundle()`
function against them. The verifier is decoupled from the gateway code
— it only depends on stdlib + rfc8785.

Covered:
  T1  PASS — small valid audit_log bundle (1 row, no bridging needed)
  T2  PASS — 3 contiguous rows + correct content_hash + correct chain links
  T3  FAIL — tampered actor field on a row → per_row_content_hash fails
  T4  FAIL — broken prev_hash on row 2 → continuity check fails
  T5  PASS — sparse selection (positions 1, 4) WITH bridging rows
  T6  SKIP — sparse selection (positions 1, 4) WITHOUT bridging rows
  T7  PASS — signed bundle + correct key supplied
  T8  FAIL — signed bundle + wrong key supplied
  T9  SKIP — signed bundle, no key supplied → continuity-only verdict still PASS
  T10 FATAL — bundle has unknown chain_name
  T11 FATAL — bundle missing 'rows' field
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path

import pytest
import rfc8785

# The CLI lives in scripts/, not on sys.path by default. Import it directly.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verify_audit_bundle as v  # noqa: E402


GENESIS_PREV = "0" * 64


def _hash_audit_log(payload: dict) -> str:
    return hashlib.sha256(rfc8785.dumps(payload)).hexdigest()


def _build_audit_log_row(
    *,
    chain_position: int,
    prev_hash: str,
    actor: str = "admin@example.com",
    action: str = "tenant.create",
) -> dict:
    """Build a fully-hashed row whose content_hash matches its canonical form."""
    canonical = {
        "trace_id":       f"00000000-0000-0000-0000-{chain_position:012d}",
        "actor":          actor,
        "action":         action,
        "target_type":    "tenant",
        "target_id":      f"tnt-{chain_position}",
        "tenant_id":      None,
        "before_state":   None,
        "after_state":    None,
        "ip_address":     None,
        "user_agent":     None,
        "created_at":     f"2026-05-06T20:00:{chain_position:02d}+00:00",
        "chain_position": chain_position,
        "prev_hash":      prev_hash,
    }
    return {
        "id":           chain_position * 100,
        "content_hash": _hash_audit_log(canonical),
        **canonical,
    }


def _empty_bundle_envelope(rows: list, bridging: list, *, include_bridging: bool = True) -> dict:
    return {
        "chain_format_version": 1,
        "chain_name":           "audit_log",
        "bundle_emitted_at":    "2026-05-06T22:00:00+00:00",
        "selection_criteria":   {},
        "selection": {
            "row_count":          len(rows),
            "min_chain_position": rows[0]["chain_position"] if rows else None,
            "max_chain_position": rows[-1]["chain_position"] if rows else None,
            "truncated":          False,
            "max_rows_cap":       10000,
        },
        "rows":          rows,
        "bridging_rows": bridging if include_bridging else [],
        "bridging": {
            "included":   include_bridging,
            "row_count":  len(bridging) if include_bridging else 0,
            "truncated":  False,
        },
        "chain_anchor": {
            "chain_name":             "audit_log",
            "genesis_chain_position": 1,
            "genesis_prev_hash":      GENESIS_PREV,
            "current_head": {
                "chain_position": rows[-1]["chain_position"] if rows else None,
                "content_hash":   rows[-1]["content_hash"]   if rows else None,
            },
        },
        "off_vm_anchor":             None,
        "verification_instructions": "...",
        "bundle_signature":          None,
    }


# ---------------------------------------------------------------------------
# T1 — single row
# ---------------------------------------------------------------------------


def test_t1_single_row_valid_bundle_passes():
    row = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    bundle = _empty_bundle_envelope([row], [])
    report = v.verify_bundle(bundle)
    assert report.all_passed is True


# ---------------------------------------------------------------------------
# T2 — 3 contiguous rows
# ---------------------------------------------------------------------------


def test_t2_three_contiguous_rows_passes():
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    r2 = _build_audit_log_row(chain_position=2, prev_hash=r1["content_hash"])
    r3 = _build_audit_log_row(chain_position=3, prev_hash=r2["content_hash"])
    bundle = _empty_bundle_envelope([r1, r2, r3], [])
    report = v.verify_bundle(bundle)
    assert report.all_passed is True
    # All checks ran; per_row + continuity both passed
    names = {c["name"]: c["passed"] for c in report.checks}
    assert names["per_row_content_hash"] is True
    assert names["continuity"]           is True


# ---------------------------------------------------------------------------
# T3 — tamper detection
# ---------------------------------------------------------------------------


def test_t3_tampered_actor_field_fails_per_row_hash():
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    # Tamper: change actor without re-computing content_hash
    r1["actor"] = "evil@attacker.example"
    bundle = _empty_bundle_envelope([r1], [])
    report = v.verify_bundle(bundle)
    assert report.all_passed is False
    fail = next(c for c in report.checks if c["name"] == "per_row_content_hash")
    assert fail["passed"] is False
    assert "recomputed" in fail["detail"]


# ---------------------------------------------------------------------------
# T4 — broken prev_hash (continuity)
# ---------------------------------------------------------------------------


def test_t4_broken_prev_hash_fails_continuity():
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    # r2's prev_hash points to the wrong predecessor — its OWN canonical form
    # still hashes correctly, but the link breaks.
    r2 = _build_audit_log_row(chain_position=2, prev_hash="f" * 64)
    bundle = _empty_bundle_envelope([r1, r2], [])
    report = v.verify_bundle(bundle)
    assert report.all_passed is False
    cont = next(c for c in report.checks if c["name"] == "continuity")
    assert cont["passed"] is False
    assert "prev_hash" in cont["detail"]


# ---------------------------------------------------------------------------
# T5 — sparse selection WITH bridging
# ---------------------------------------------------------------------------


def test_t5_sparse_selection_with_bridging_passes():
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    r2 = _build_audit_log_row(chain_position=2, prev_hash=r1["content_hash"])
    r3 = _build_audit_log_row(chain_position=3, prev_hash=r2["content_hash"])
    r4 = _build_audit_log_row(chain_position=4, prev_hash=r3["content_hash"])
    # Selected: r1 + r4. Bridging: r2 + r3 (hash-only).
    bridging = [
        {"chain_position": 2, "content_hash": r2["content_hash"], "prev_hash": r2["prev_hash"]},
        {"chain_position": 3, "content_hash": r3["content_hash"], "prev_hash": r3["prev_hash"]},
    ]
    bundle = _empty_bundle_envelope([r1, r4], bridging, include_bridging=True)
    report = v.verify_bundle(bundle)
    assert report.all_passed is True


# ---------------------------------------------------------------------------
# T6 — sparse selection WITHOUT bridging → continuity skipped (not failed)
# ---------------------------------------------------------------------------


def test_t6_sparse_selection_without_bridging_skips_continuity():
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    r4 = _build_audit_log_row(chain_position=4, prev_hash="b" * 64)
    bundle = _empty_bundle_envelope([r1, r4], [], include_bridging=False)
    report = v.verify_bundle(bundle)
    cont = next(c for c in report.checks if c["name"] == "continuity")
    # Skipped (passed is None), not failed — this is a configuration choice
    # by the operator, not a tamper signal.
    assert cont["passed"] is None
    assert "include_bridging_rows=true" in cont["detail"]
    # Per-row hashes still pass → all_passed is True (skipped checks don't fail)
    assert report.all_passed is True


# ---------------------------------------------------------------------------
# T7 — signed bundle, correct key
# ---------------------------------------------------------------------------


def _attach_signature(bundle: dict, key: str, key_id: str = "v1") -> None:
    inner = {k: val for k, val in bundle.items() if k != "bundle_signature"}
    canonical = rfc8785.dumps(inner)
    digest = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    bundle["bundle_signature"] = {
        "algorithm":        "HMAC-SHA256",
        "canonicalisation": "RFC 8785",
        "key_id":           key_id,
        "hex":              digest,
    }


def test_t7_signed_bundle_correct_key_passes():
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    bundle = _empty_bundle_envelope([r1], [])
    _attach_signature(bundle, "shared-secret-key")
    report = v.verify_bundle(bundle, signing_key="shared-secret-key")
    sig = next(c for c in report.checks if c["name"] == "bundle_signature")
    assert sig["passed"] is True
    assert "verified" in sig["detail"].lower()
    assert report.all_passed is True


# ---------------------------------------------------------------------------
# T8 — signed bundle, wrong key
# ---------------------------------------------------------------------------


def test_t8_signed_bundle_wrong_key_fails():
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    bundle = _empty_bundle_envelope([r1], [])
    _attach_signature(bundle, "shared-secret-key")
    report = v.verify_bundle(bundle, signing_key="WRONG-KEY")
    sig = next(c for c in report.checks if c["name"] == "bundle_signature")
    assert sig["passed"] is False
    assert "wrong key" in sig["detail"].lower() or "tampered" in sig["detail"].lower()
    assert report.all_passed is False


# ---------------------------------------------------------------------------
# T9 — signed bundle, no key supplied → signature check skipped, others pass
# ---------------------------------------------------------------------------


def test_t9_signed_bundle_no_key_skips_signature():
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    bundle = _empty_bundle_envelope([r1], [])
    _attach_signature(bundle, "shared-secret-key", key_id="prod-v1")
    report = v.verify_bundle(bundle, signing_key=None)
    sig = next(c for c in report.checks if c["name"] == "bundle_signature")
    assert sig["passed"] is None
    assert "prod-v1" in sig["detail"]
    # The non-signature checks all passed → bundle is verifiable as far as
    # the auditor's local capability goes.
    assert report.all_passed is True


# ---------------------------------------------------------------------------
# T10 — unknown chain_name
# ---------------------------------------------------------------------------


def test_t10_unknown_chain_name_is_fatal():
    bundle = _empty_bundle_envelope([], [])
    bundle["chain_name"] = "made_up_chain"
    report = v.verify_bundle(bundle)
    assert report.has_fatal is True
    assert report.all_passed is False
    assert any("made_up_chain" in f for f in report.fatal)


# ---------------------------------------------------------------------------
# T11 — missing 'rows' field
# ---------------------------------------------------------------------------


def test_t11_missing_rows_field_is_fatal():
    bundle = _empty_bundle_envelope([], [])
    del bundle["rows"]
    report = v.verify_bundle(bundle)
    assert report.has_fatal is True
    assert report.all_passed is False
    assert any("rows" in f for f in report.fatal)


# ---------------------------------------------------------------------------
# T11b — chain_format_version handling (forward-compatibility safety net)
# ---------------------------------------------------------------------------


def test_t11b_missing_chain_format_version_is_fatal():
    """Bundle without chain_format_version is malformed — verifier MUST
    fail fatally rather than guess at the format."""
    bundle = _empty_bundle_envelope([], [])
    del bundle["chain_format_version"]
    report = v.verify_bundle(bundle)
    assert report.has_fatal is True
    assert report.all_passed is False
    assert any("chain_format_version" in f for f in report.fatal)


def test_t11c_future_chain_format_version_is_fatal():
    """A bundle with a chain_format_version this verifier doesn't know
    must fail fatally with a clear 'pull a fresh verifier' message,
    NOT silently per-row-hash-fail (which would look like a tamper)."""
    bundle = _empty_bundle_envelope([], [])
    bundle["chain_format_version"] = 99   # imaginary future version
    report = v.verify_bundle(bundle)
    assert report.has_fatal is True
    assert report.all_passed is False
    fatal_msg = " ".join(report.fatal)
    # The version number itself appears in the message
    assert "99" in fatal_msg
    # And the operator is told to pull a fresh verifier (case-insensitive)
    msg_lower = fatal_msg.lower()
    assert "pull a fresh verifier" in msg_lower or "fresh verifier" in msg_lower


def test_t11d_supported_version_set_pins_v1_only():
    """The supported-versions set is the contract: v1 is in, anything
    else is out. Pinning this with a test guards against accidental
    additions before the verifier has actually been updated to handle
    a new envelope format."""
    assert v._SUPPORTED_CHAIN_FORMAT_VERSIONS == frozenset({1})


def test_t11e_zero_version_is_fatal():
    """Edge case: chain_format_version=0 (or any unknown value) is also
    treated as unsupported, not silently truthy."""
    bundle = _empty_bundle_envelope([], [])
    bundle["chain_format_version"] = 0
    report = v.verify_bundle(bundle)
    assert report.has_fatal is True
    assert report.all_passed is False


# ---------------------------------------------------------------------------
# T24-T29 — selection_criteria_match (the misrepresentation-attack net)
# ---------------------------------------------------------------------------


def test_t24_no_filters_set_skips_check():
    """When selection_criteria has no exact-match filters set, the check
    is vacuously satisfied. SKIP, not FAIL or PASS."""
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    bundle = _empty_bundle_envelope([r1], [])
    # All criteria are None by default in _empty_bundle_envelope
    rpt = v.CheckReport()
    v.check_selection_criteria_match(bundle, rpt)
    crit = next(c for c in rpt.checks if c["name"] == "selection_criteria_match")
    assert crit["passed"] is None  # skipped


def test_t25_actor_filter_matches_passes():
    """When selection_criteria.actor is set and every row has matching
    actor, the check passes."""
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV, actor="auditor@example.com")
    r2 = _build_audit_log_row(chain_position=2, prev_hash=r1["content_hash"], actor="auditor@example.com")
    bundle = _empty_bundle_envelope([r1, r2], [])
    bundle["selection_criteria"]["actor"] = "auditor@example.com"
    rpt = v.CheckReport()
    v.check_selection_criteria_match(bundle, rpt)
    crit = next(c for c in rpt.checks if c["name"] == "selection_criteria_match")
    assert crit["passed"] is True
    assert "2 row(s) match" in crit["detail"]


def test_t26_actor_filter_mismatch_fails():
    """The misrepresentation-attack scenario: criteria says actor=X,
    rows are for actor=Y. Hashes can still verify (they're real chain
    rows), but the bundle is substantively misleading. This check
    catches it."""
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV, actor="auditor@example.com")
    r2 = _build_audit_log_row(chain_position=2, prev_hash=r1["content_hash"], actor="someone_else@example.com")
    bundle = _empty_bundle_envelope([r1, r2], [])
    bundle["selection_criteria"]["actor"] = "auditor@example.com"
    rpt = v.CheckReport()
    v.check_selection_criteria_match(bundle, rpt)
    crit = next(c for c in rpt.checks if c["name"] == "selection_criteria_match")
    assert crit["passed"] is False
    assert "row.actor='someone_else@example.com'" in crit["detail"]
    assert "selection_criteria.actor='auditor@example.com'" in crit["detail"]


def test_t27_empty_rows_skips():
    """Empty selection — vacuously true, skip not fail."""
    bundle = _empty_bundle_envelope([], [])
    bundle["selection_criteria"]["actor"] = "any-value"
    rpt = v.CheckReport()
    v.check_selection_criteria_match(bundle, rpt)
    crit = next(c for c in rpt.checks if c["name"] == "selection_criteria_match")
    assert crit["passed"] is None  # skipped (vacuously true)


def test_t28_multiple_filters_all_must_match():
    """Two filters set; if either mismatches on any row, the check fails."""
    r1 = _build_audit_log_row(
        chain_position=1, prev_hash=GENESIS_PREV,
        actor="auditor@example.com", action="tenant.create",
    )
    r2 = _build_audit_log_row(
        chain_position=2, prev_hash=r1["content_hash"],
        actor="auditor@example.com", action="tenant.update",   # different action
    )
    bundle = _empty_bundle_envelope([r1, r2], [])
    bundle["selection_criteria"]["actor"]  = "auditor@example.com"
    bundle["selection_criteria"]["action"] = "tenant.create"   # only r1 matches
    rpt = v.CheckReport()
    v.check_selection_criteria_match(bundle, rpt)
    crit = next(c for c in rpt.checks if c["name"] == "selection_criteria_match")
    assert crit["passed"] is False
    assert "row.action='tenant.update'" in crit["detail"]


def test_t29_full_verify_bundle_includes_criteria_check():
    """End-to-end: verify_bundle() runs all checks. Confirm
    selection_criteria_match is one of them."""
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    bundle = _empty_bundle_envelope([r1], [])
    bundle["selection_criteria"]["actor"] = "admin@example.com"   # matches what _build_audit_log_row sets
    report = v.verify_bundle(bundle)
    names = {c["name"] for c in report.checks}
    assert "selection_criteria_match" in names
    crit = next(c for c in report.checks if c["name"] == "selection_criteria_match")
    assert crit["passed"] is True
    assert report.all_passed is True


# ---------------------------------------------------------------------------
# T12-T16 — off-VM manifest cross-check (--manifest-dir)
# ---------------------------------------------------------------------------


def _manifest_ndjson(rows: list[dict]) -> bytes:
    """Reproduce shared/utils/audit_chain_shipper.serialise_batch_to_ndjson:
       sort_keys=True, separators=(',', ':'), trailing newline."""
    lines = []
    for row in rows:
        lines.append(json.dumps(row, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return b"\n".join(lines) + b"\n"


def _bundle_with_anchor(
    *,
    rows: list[dict],
    last_shipped_position: int,
    object_key: str,
) -> dict:
    """Build a bundle whose off_vm_anchor points at the given object_key.
    `rows` is the bundle's selected rows (already valid, hash-chained)."""
    b = _empty_bundle_envelope(rows, [])
    b["off_vm_anchor"] = {
        "chain_name":            "audit_log",
        "last_shipped_position": last_shipped_position,
        "shipped_at":            "2026-05-06T18:00:00+00:00",
        "bucket_name":           "algovoiretention",
        "object_key":            object_key,
        "object_etag":           "etag-placeholder",
        "object_lock_until":     "2033-05-06T18:00:00+00:00",
        "shipper_version":       "avs-v1",
    }
    return b


def test_t12_manifest_match_passes(tmp_path):
    """Happy path: manifest in --manifest-dir has matching sha256 prefix
    AND last-line chain_position+content_hash match the bundle anchor."""
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    # Manifest content == the row, NDJSON-serialised the same way the
    # shipper would.
    manifest_bytes = _manifest_ndjson([r1])
    sha = hashlib.sha256(manifest_bytes).hexdigest()
    object_key = f"audit_log/000000001-000000001-{sha[:16]}.ndjson"

    manifest_path = tmp_path / object_key
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(manifest_bytes)

    bundle = _bundle_with_anchor(
        rows=[r1],
        last_shipped_position=1,
        object_key=object_key,
    )
    report = v.verify_bundle(bundle, manifest_dir=tmp_path)

    anchor = next(c for c in report.checks if c["name"] == "off_vm_anchor")
    assert anchor["passed"] is True
    assert "manifest sha256 matches" in anchor["detail"]
    assert report.all_passed is True


def test_t13_manifest_sha_mismatch_fails(tmp_path):
    """Manifest body modified — sha256 prefix in object_key no longer
    matches the file's actual hash."""
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    manifest_bytes = _manifest_ndjson([r1])
    real_sha = hashlib.sha256(manifest_bytes).hexdigest()
    # object_key claims a DIFFERENT sha (16 hex of all 'a')
    fake_prefix = "a" * 16
    object_key = f"audit_log/000000001-000000001-{fake_prefix}.ndjson"

    manifest_path = tmp_path / object_key
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(manifest_bytes)

    bundle = _bundle_with_anchor(
        rows=[r1],
        last_shipped_position=1,
        object_key=object_key,
    )
    report = v.verify_bundle(bundle, manifest_dir=tmp_path)

    anchor = next(c for c in report.checks if c["name"] == "off_vm_anchor")
    assert anchor["passed"] is False
    assert "tampered or wrong file" in anchor["detail"]
    # And it must NOT match the real sha
    assert real_sha[:16] != fake_prefix
    assert report.all_passed is False


def test_t14_manifest_missing_fails(tmp_path):
    """--manifest-dir provided but the file referenced by object_key isn't
    actually in the directory."""
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    object_key = f"audit_log/000000001-000000001-{('b'*16)}.ndjson"
    bundle = _bundle_with_anchor(
        rows=[r1],
        last_shipped_position=1,
        object_key=object_key,
    )
    # No file written under tmp_path — verifier should report missing.
    report = v.verify_bundle(bundle, manifest_dir=tmp_path)
    anchor = next(c for c in report.checks if c["name"] == "off_vm_anchor")
    assert anchor["passed"] is False
    assert "not found" in anchor["detail"]


def test_t15_manifest_last_entry_mismatches_anchor_fails(tmp_path):
    """Manifest's last NDJSON line's chain_position doesn't match
    off_vm_anchor.last_shipped_position — should fail."""
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    r2 = _build_audit_log_row(chain_position=2, prev_hash=r1["content_hash"])
    # Manifest contains rows 1 + 2, file's last entry is at position 2
    manifest_bytes = _manifest_ndjson([r1, r2])
    sha = hashlib.sha256(manifest_bytes).hexdigest()
    # But the bundle's anchor claims last_shipped_position=99 — mismatch
    object_key = f"audit_log/000000001-000000002-{sha[:16]}.ndjson"
    manifest_path = tmp_path / object_key
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(manifest_bytes)

    bundle = _bundle_with_anchor(
        rows=[r1, r2],
        last_shipped_position=99,   # WRONG — manifest's last is at position 2
        object_key=object_key,
    )
    report = v.verify_bundle(bundle, manifest_dir=tmp_path)
    anchor = next(c for c in report.checks if c["name"] == "off_vm_anchor")
    assert anchor["passed"] is False
    assert "manifest last entry chain_position=2" in anchor["detail"]
    assert "last_shipped_position=99" in anchor["detail"]


def test_t16_no_off_vm_anchor_with_flag_skips(tmp_path):
    """Bundle has no off_vm_anchor — even with --manifest-dir set, the
    check should skip rather than fail (chain hasn't been shipped yet)."""
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    bundle = _empty_bundle_envelope([r1], [])
    bundle["off_vm_anchor"] = None
    report = v.verify_bundle(bundle, manifest_dir=tmp_path)
    anchor = next(c for c in report.checks if c["name"] == "off_vm_anchor")
    assert anchor["passed"] is None
    assert "not been shipped" in anchor["detail"]
    assert report.all_passed is True   # skip doesn't fail


def test_t17_manifest_basename_lookup(tmp_path):
    """As a convenience, the manifest can also be placed at the top level
    of --manifest-dir (just the basename, not the full bucket-relative path)."""
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    manifest_bytes = _manifest_ndjson([r1])
    sha = hashlib.sha256(manifest_bytes).hexdigest()
    object_key = f"audit_log/000000001-000000001-{sha[:16]}.ndjson"
    basename = object_key.rsplit("/", 1)[-1]

    # Write at tmp_path / basename (NOT tmp_path / object_key)
    (tmp_path / basename).write_bytes(manifest_bytes)

    bundle = _bundle_with_anchor(
        rows=[r1],
        last_shipped_position=1,
        object_key=object_key,
    )
    report = v.verify_bundle(bundle, manifest_dir=tmp_path)
    anchor = next(c for c in report.checks if c["name"] == "off_vm_anchor")
    assert anchor["passed"] is True


# ---------------------------------------------------------------------------
# T19-T23 — multi-bundle aggregate checks (check_aggregate)
# ---------------------------------------------------------------------------


def _signed_chain_bundle(
    *,
    rows_payload: list[tuple[int, str]],   # list of (chain_position, prev_hash) — content is auto-built
    head_position: int,
    head_hash: str,
    chain_name: str = "audit_log",
    bundle_emitted_at: str = "2026-05-06T22:00:00+00:00",
) -> dict:
    """Build a bundle from a list of (chain_position, prev_hash) tuples,
    auto-computing each row's content_hash from canonical fields."""
    rows = []
    for pos, prev in rows_payload:
        row = _build_audit_log_row(chain_position=pos, prev_hash=prev)
        rows.append(row)
    bundle = {
        "chain_format_version": 1,
        "chain_name":           chain_name,
        "bundle_emitted_at":    bundle_emitted_at,
        "selection_criteria":   {},
        "selection": {
            "row_count":          len(rows),
            "min_chain_position": rows[0]["chain_position"] if rows else None,
            "max_chain_position": rows[-1]["chain_position"] if rows else None,
            "truncated":          False,
            "max_rows_cap":       10000,
        },
        "rows":          rows,
        "bridging_rows": [],
        "bridging":      {"included": True, "row_count": 0, "truncated": False},
        "chain_anchor": {
            "chain_name":             chain_name,
            "genesis_chain_position": 1,
            "genesis_prev_hash":      GENESIS_PREV,
            "current_head": {"chain_position": head_position, "content_hash": head_hash},
        },
        "off_vm_anchor":             None,
        "verification_instructions": "...",
        "bundle_signature":          None,
    }
    return bundle


def test_t19_aggregate_two_bundles_same_chain_consistent_passes():
    """Two bundles, same chain, non-overlapping ranges, head monotonic →
    aggregate PASS."""
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    r2 = _build_audit_log_row(chain_position=2, prev_hash=r1["content_hash"])
    r3 = _build_audit_log_row(chain_position=3, prev_hash=r2["content_hash"])

    b1 = _empty_bundle_envelope([r1, r2], [])
    b1["bundle_emitted_at"] = "2026-04-01T12:00:00+00:00"
    b1["chain_anchor"]["current_head"] = {
        "chain_position": 2, "content_hash": r2["content_hash"],
    }

    b2 = _empty_bundle_envelope([r3], [])
    b2["bundle_emitted_at"] = "2026-05-01T12:00:00+00:00"
    b2["chain_anchor"]["current_head"] = {
        "chain_position": 3, "content_hash": r3["content_hash"],
    }

    rpt = v.CheckReport()
    v.check_aggregate([b1, b2], rpt)
    assert rpt.all_passed is True
    names = {c["name"]: c["passed"] for c in rpt.checks}
    assert names["aggregate.same_chain"]            is True
    assert names["aggregate.overlap_consistency"]   is True
    assert names["aggregate.monotonic_head"]        is True


def test_t20_aggregate_mixed_chain_names_fails():
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)

    b_audit = _empty_bundle_envelope([r1], [])
    b_audit["chain_name"] = "audit_log"

    b_screen = _empty_bundle_envelope([r1], [])
    b_screen["chain_name"] = "screening_hits"

    rpt = v.CheckReport()
    v.check_aggregate([b_audit, b_screen], rpt)
    same = next(c for c in rpt.checks if c["name"] == "aggregate.same_chain")
    assert same["passed"] is False
    assert "multiple chains" in same["detail"]


def test_t21_aggregate_overlap_disagreement_fails():
    """Same chain_position appears in two bundles but with DIFFERENT
    content_hash — strongest tamper signal aggregation can detect."""
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)

    b1 = _empty_bundle_envelope([r1], [])

    # Build a second bundle with chain_position=1 but a tampered content_hash.
    r1_tamper = dict(r1)
    r1_tamper["content_hash"] = "f" * 64   # different
    b2 = _empty_bundle_envelope([r1_tamper], [])

    rpt = v.CheckReport()
    v.check_aggregate([b1, b2], rpt)
    overlap = next(c for c in rpt.checks if c["name"] == "aggregate.overlap_consistency")
    assert overlap["passed"] is False
    assert "contradicting" in overlap["detail"]


def test_t22_aggregate_non_monotonic_head_fails():
    """Bundle emitted later claims a SMALLER chain head than an earlier
    bundle — the chain regressed. Always a tamper signal for write-once."""
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    r2 = _build_audit_log_row(chain_position=2, prev_hash=r1["content_hash"])

    # April bundle: head at position 5 (claim)
    b_old = _empty_bundle_envelope([r1, r2], [])
    b_old["bundle_emitted_at"] = "2026-04-01T12:00:00+00:00"
    b_old["chain_anchor"]["current_head"] = {
        "chain_position": 5, "content_hash": "x" * 64,
    }

    # May bundle (newer): head at position 3 — IMPOSSIBLE for write-once chain
    b_new = _empty_bundle_envelope([r1], [])
    b_new["bundle_emitted_at"] = "2026-05-01T12:00:00+00:00"
    b_new["chain_anchor"]["current_head"] = {
        "chain_position": 3, "content_hash": "y" * 64,
    }

    rpt = v.CheckReport()
    v.check_aggregate([b_old, b_new], rpt)
    mono = next(c for c in rpt.checks if c["name"] == "aggregate.monotonic_head")
    assert mono["passed"] is False
    assert "regressed" in mono["detail"]


def test_t23_aggregate_overlap_with_matching_hashes_passes():
    """When two bundles overlap on the same chain_position AND agree on
    content_hash + prev_hash, that's fine — both legitimate disclosures
    of the same row."""
    r1 = _build_audit_log_row(chain_position=1, prev_hash=GENESIS_PREV)
    r2 = _build_audit_log_row(chain_position=2, prev_hash=r1["content_hash"])

    # Both bundles contain row 2 (overlap), with identical hashes
    b1 = _empty_bundle_envelope([r1, r2], [])
    b1["bundle_emitted_at"] = "2026-04-01T12:00:00+00:00"
    b1["chain_anchor"]["current_head"] = {
        "chain_position": 2, "content_hash": r2["content_hash"],
    }
    b2 = _empty_bundle_envelope([r2], [])  # just row 2 in this one
    b2["bundle_emitted_at"] = "2026-05-01T12:00:00+00:00"
    b2["chain_anchor"]["current_head"] = {
        "chain_position": 2, "content_hash": r2["content_hash"],
    }

    rpt = v.CheckReport()
    v.check_aggregate([b1, b2], rpt)
    overlap = next(c for c in rpt.checks if c["name"] == "aggregate.overlap_consistency")
    assert overlap["passed"] is True
    assert "1 chain_position" in overlap["detail"]   # exactly 1 overlap position


# ---------------------------------------------------------------------------


def test_t18_object_key_sha_prefix_parser():
    """Direct unit test of _parse_object_key_sha_prefix — must accept the
    standard format and reject malformed inputs without raising."""
    assert v._parse_object_key_sha_prefix(
        "audit_log/000000001-000000100-abcdef0123456789.ndjson"
    ) == "abcdef0123456789"
    # Multi-segment chain name — only the LAST '-' separates the sha
    assert v._parse_object_key_sha_prefix(
        "negotiation_trace_events/000000001-000000001-1234567890abcdef.ndjson"
    ) == "1234567890abcdef"
    # Bad cases — return None, never raise
    assert v._parse_object_key_sha_prefix("") is None
    assert v._parse_object_key_sha_prefix("not_a_path") is None
    assert v._parse_object_key_sha_prefix("audit_log/no-sha-here.ndjson") is None  # 8 chars not 16
    assert v._parse_object_key_sha_prefix("audit_log/foo-bar.txt") is None         # wrong extension
    # Non-hex
    assert v._parse_object_key_sha_prefix(
        "audit_log/000000001-000000001-zzzzzzzzzzzzzzzz.ndjson"
    ) is None
