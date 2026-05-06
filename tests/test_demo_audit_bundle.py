"""
Unit tests for scripts/demo_audit_bundle.py.

The demo generator's job is to produce a bundle that the production
verifier (scripts/verify_audit_bundle.py) accepts as PASS. So the
strongest test is to feed its output straight into the verifier.

Covered:
  T1  build_demo_bundle returns a dict with the canonical envelope shape
  T2  Default 3-row bundle has chain_position 1..3 with valid prev_hash links
  T3  Bundle is correctly signed (verifier PASSes signature with the same key)
  T4  Verifier returns all_passed=True on demo bundle (end-to-end)
  T5  Verifier FAILs signature when given the wrong key
  T6  Custom row count (e.g. 5 rows) produces a longer valid chain
  T7  Custom signing key produces a different signature hex
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Both scripts/ scripts on sys.path so we can import them as modules.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import demo_audit_bundle as d  # noqa: E402
import verify_audit_bundle as v  # noqa: E402


# ---------------------------------------------------------------------------
# T1 — envelope shape
# ---------------------------------------------------------------------------


def test_t1_demo_bundle_has_canonical_envelope():
    bundle = d.build_demo_bundle()
    # All top-level keys the verifier expects
    expected_top_level_keys = {
        "chain_format_version", "chain_name", "bundle_emitted_at",
        "selection_criteria", "selection", "rows", "bridging_rows",
        "bridging", "chain_anchor", "off_vm_anchor",
        "verification_instructions", "bundle_signature",
    }
    assert expected_top_level_keys <= set(bundle.keys())
    assert bundle["chain_format_version"] == 1
    assert bundle["chain_name"] == "audit_log"


# ---------------------------------------------------------------------------
# T2 — default 3 rows + valid chain links
# ---------------------------------------------------------------------------


def test_t2_default_three_rows_chain_correctly():
    bundle = d.build_demo_bundle()
    rows = bundle["rows"]
    assert len(rows) == 3
    assert [r["chain_position"] for r in rows] == [1, 2, 3]
    # Genesis: row 1's prev_hash is GENESIS
    assert rows[0]["prev_hash"] == d.GENESIS_PREV_HASH
    # Each subsequent row's prev_hash equals the previous row's content_hash
    assert rows[1]["prev_hash"] == rows[0]["content_hash"]
    assert rows[2]["prev_hash"] == rows[1]["content_hash"]
    # Chain anchor's current_head matches the last row
    head = bundle["chain_anchor"]["current_head"]
    assert head["chain_position"] == 3
    assert head["content_hash"]   == rows[2]["content_hash"]


# ---------------------------------------------------------------------------
# T3 — bundle is correctly signed (verifier accepts the demo key)
# ---------------------------------------------------------------------------


def test_t3_bundle_signature_recomputable():
    """Round-trip: hand the demo bundle to verify_bundle with the demo key
    and confirm the bundle_signature check passes."""
    bundle = d.build_demo_bundle()
    report = v.verify_bundle(bundle, signing_key=d.DEFAULT_KEY)
    sig = next(c for c in report.checks if c["name"] == "bundle_signature")
    assert sig["passed"] is True


# ---------------------------------------------------------------------------
# T4 — verifier all_passed
# ---------------------------------------------------------------------------


def test_t4_verifier_passes_default_demo_bundle():
    """End-to-end: a freshly generated demo bundle must produce an
    all-pass verdict from the verifier (off_vm_anchor will skip — that
    skip doesn't count as a fail per the verifier's contract)."""
    bundle = d.build_demo_bundle()
    report = v.verify_bundle(bundle, signing_key=d.DEFAULT_KEY)
    assert report.all_passed is True


# ---------------------------------------------------------------------------
# T5 — wrong key fails signature
# ---------------------------------------------------------------------------


def test_t5_wrong_key_fails_signature():
    bundle = d.build_demo_bundle()
    report = v.verify_bundle(bundle, signing_key="completely-wrong-key")
    sig = next(c for c in report.checks if c["name"] == "bundle_signature")
    assert sig["passed"] is False
    # Other checks should still pass — only the signature check fails
    per_row = next(c for c in report.checks if c["name"] == "per_row_content_hash")
    assert per_row["passed"] is True
    cont = next(c for c in report.checks if c["name"] == "continuity")
    assert cont["passed"] is True
    assert report.all_passed is False


# ---------------------------------------------------------------------------
# T6 — longer chain
# ---------------------------------------------------------------------------


def test_t6_five_row_bundle_chains_correctly():
    bundle = d.build_demo_bundle(row_count=5)
    assert len(bundle["rows"]) == 5
    assert [r["chain_position"] for r in bundle["rows"]] == [1, 2, 3, 4, 5]
    report = v.verify_bundle(bundle, signing_key=d.DEFAULT_KEY)
    assert report.all_passed is True


# ---------------------------------------------------------------------------
# T7 — custom signing key changes the signature
# ---------------------------------------------------------------------------


def test_t7_custom_key_differs_from_default():
    a = d.build_demo_bundle(signing_key="key-A")
    b = d.build_demo_bundle(signing_key="key-B")
    # Different keys → different signature hex
    assert a["bundle_signature"]["hex"] != b["bundle_signature"]["hex"]
    # Each bundle still verifies under its own key
    assert v.verify_bundle(a, signing_key="key-A").all_passed is True
    assert v.verify_bundle(b, signing_key="key-B").all_passed is True


# ---------------------------------------------------------------------------
# T8 — row_count < 1 raises
# ---------------------------------------------------------------------------


def test_t8_zero_rows_raises():
    with pytest.raises(ValueError):
        d.build_demo_bundle(row_count=0)


# ---------------------------------------------------------------------------
# T9 — unknown chain name raises
# ---------------------------------------------------------------------------


def test_t9_unknown_chain_raises():
    with pytest.raises(ValueError, match="not recognised"):
        d.build_demo_bundle(chain_name="made_up_chain")


# ---------------------------------------------------------------------------
# T10-T13 — every supported chain produces a verifier-PASS bundle
#           (this is the strongest end-to-end integration test of the
#           full per-chain canonical-fields layout)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("chain_name", [
    "audit_log",
    "screening_hits",
    "compliance_events",
    "negotiation_trace_events",
])
def test_t10_each_chain_passes_verifier(chain_name: str):
    """For each chain, build a 3-row demo bundle and confirm the
    production verifier accepts it as PASS. This is the strongest
    coupling test between demo_audit_bundle.py's row builders and
    verify_audit_bundle.py's _FIELD_EXTRACTORS — any divergence (e.g.
    one side adds a field the other doesn't) trips this test before it
    reaches a real auditor."""
    bundle = d.build_demo_bundle(chain_name=chain_name)
    assert bundle["chain_name"] == chain_name
    report = v.verify_bundle(bundle, signing_key=d.DEFAULT_KEY)
    assert report.all_passed is True, (
        f"chain {chain_name!r} demo bundle did not all-pass: "
        f"{[c for c in report.checks if c['passed'] is False]}"
    )


@pytest.mark.parametrize("chain_name", [
    "audit_log",
    "screening_hits",
    "compliance_events",
    "negotiation_trace_events",
])
def test_t11_each_chain_continuity_walks(chain_name: str):
    """For each chain, a 5-row demo bundle's prev_hash links must form a
    valid forward chain — verified independently of the verifier by
    walking the rows manually."""
    bundle = d.build_demo_bundle(chain_name=chain_name, row_count=5)
    rows = bundle["rows"]
    assert rows[0]["prev_hash"] == d.GENESIS_PREV_HASH
    for i in range(1, len(rows)):
        assert rows[i]["prev_hash"] == rows[i - 1]["content_hash"], (
            f"chain {chain_name!r} broke continuity between rows {i-1} and {i}"
        )


# ---------------------------------------------------------------------------
# T12 — JSON Schema validation across all 4 chains
#
# This is the third independent attestation that demo+verifier+schema all
# agree on the bundle envelope. If the schema and the canonical-fields
# layout drift (someone adds a field server-side without updating the
# schema, or vice versa), this test trips immediately.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("chain_name", [
    "audit_log",
    "screening_hits",
    "compliance_events",
    "negotiation_trace_events",
])
def test_t12_demo_bundles_validate_against_json_schema(chain_name: str):
    """For each chain, the demo bundle output must validate against the
    formal JSON Schema at docs/audit-bundle.schema.json. This is what
    auditors use as a structural pre-flight check before running the
    hash-based verification — if a real bundle from AlgoVoi fails this
    schema validation, it's malformed and verification will fail anyway.

    Skip gracefully if jsonschema isn't installed (it's an optional dep
    for auditors, not a test-suite requirement).
    """
    pytest.importorskip("jsonschema")
    import json
    import jsonschema

    schema_path = Path(__file__).resolve().parents[1] / "audit-bundle.schema.json"
    if not schema_path.exists():
        pytest.skip(f"schema file not present at {schema_path}")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    bundle = d.build_demo_bundle(chain_name=chain_name)
    # raises ValidationError on failure — pytest reports it cleanly
    jsonschema.validate(instance=bundle, schema=schema)


def test_t13_schema_rejects_invalid_chain_name():
    """A bundle with an unsupported chain_name should fail schema
    validation. Smoke test that the schema's enum constraint actually
    bites."""
    pytest.importorskip("jsonschema")
    import json
    import jsonschema

    schema_path = Path(__file__).resolve().parents[1] / "audit-bundle.schema.json"
    if not schema_path.exists():
        pytest.skip(f"schema file not present at {schema_path}")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    bundle = d.build_demo_bundle(chain_name="audit_log")
    bundle["chain_name"] = "made_up_chain"
    with pytest.raises(jsonschema.exceptions.ValidationError):
        jsonschema.validate(instance=bundle, schema=schema)


def test_t14_schema_rejects_short_content_hash():
    """A bundle with a content_hash that isn't 64 hex chars should fail
    schema validation via the Sha256Hex pattern constraint."""
    pytest.importorskip("jsonschema")
    import json
    import jsonschema

    schema_path = Path(__file__).resolve().parents[1] / "audit-bundle.schema.json"
    if not schema_path.exists():
        pytest.skip(f"schema file not present at {schema_path}")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    bundle = d.build_demo_bundle(chain_name="audit_log")
    bundle["rows"][0]["content_hash"] = "abc"   # way too short
    with pytest.raises(jsonschema.exceptions.ValidationError):
        jsonschema.validate(instance=bundle, schema=schema)
