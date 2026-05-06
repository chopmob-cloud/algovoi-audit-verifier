# Audit-Bundle Verifier — Auditor Runbook

**Audience:** external auditors, regulators, MLROs, compliance reviewers handed a selective-disclosure audit bundle by AlgoVoi.

**When to read:** when you need to confirm that the rows in the bundle you've received are tamper-evidently part of AlgoVoi's immutable hash chain — without trusting AlgoVoi's infrastructure, the transport, or any single attestation surface.

**Companion script:** [`verify_audit_bundle.py`](verify_audit_bundle.py).

---

## What this verifier proves (and what it doesn't)

**Proves, when all checks pass:**

- Every selected row's `content_hash` was computed honestly from the row's stored fields (no tampered actor, action, payload, etc.)
- The selected rows are part of a continuous chain — no gap, reorder, or deletion possible without breaking the prev_hash links
- The bundle was emitted by AlgoVoi (when signed and you have the published signing key)
- The chain head you see matches what's in the off-VM Object-Locked manifest (when you have access to the manifest file)
- Across multiple bundles received over time, AlgoVoi has not disclosed contradicting facts about the same chain row, and the chain has not regressed

**Does not prove:**

- That the rows you see are the *only* rows in the chain. Selective disclosure means you only see what AlgoVoi was authorised to release. Bridging rows expose hash links for unselected rows so you can verify continuity, but never their content.
- That the underlying row content (actor, action, payload) is *true*. Hash verification confirms the data has not been altered since insert; it does not certify that what was inserted reflects reality. The compliance regime + KYB process around AlgoVoi is the trust source for content veracity.
- That the off-VM Object Lock retention is *current*. The verifier accepts the `object_lock_until` value from the bundle. If you want to confirm it's still locked, run `aws s3api head-object` against the bucket directly.

---

## Quickstart

You need Python 3.10+ and one PyPI package:

```bash
pip install rfc8785
```

### Try it yourself in 30 seconds (no real bundle needed)

To confirm your toolchain works before your real bundle arrives, generate a synthetic demo bundle and verify it:

```bash
$ python demo_audit_bundle.py
Wrote demo bundle: demo_bundle.json
Chain: audit_log, rows: 3, signing key id: 'demo-v1'

Verify it with:
  python verify_audit_bundle.py demo_bundle.json --signing-key 'demo-key-not-for-production-use'

$ python verify_audit_bundle.py demo_bundle.json \
    --signing-key 'demo-key-not-for-production-use'
  [  ok] per_row_content_hash -- 3 rows verified
  [  ok] continuity -- 3 entries chain forward correctly
  [  ok] bundle_signature -- HMAC-SHA256 verified against key_id='demo-v1'
  [skip] off_vm_anchor -- skipped: no off_vm_anchor in bundle
                          (chain has not been shipped yet, ...)

Verdict: PASS
```

If you don't get `Verdict: PASS`, your `rfc8785` install is wrong or you're on a Python version older than 3.10. Fix that before trusting any verdict on a real bundle.

The demo generator supports all four chains:

```bash
python demo_audit_bundle.py --chain audit_log
python demo_audit_bundle.py --chain screening_hits
python demo_audit_bundle.py --chain compliance_events
python demo_audit_bundle.py --chain negotiation_trace_events
```

Each produces a different canonical-fields payload — useful when AlgoVoi has handed you a bundle from a chain other than `audit_log` and you want to double-check your verifier handles it before running on the real bundle.

The demo generator and verifier are both standalone — only stdlib + `rfc8785`. No imports from the AlgoVoi codebase. Both safe to run on an air-gapped machine.

### Optional: structural pre-flight via JSON Schema

Before running the hash-based verifier, you can validate the bundle's structure against the formal JSON Schema at [`audit-bundle.schema.json`](audit-bundle.schema.json). This is a separate, lighter-weight check — it tells you "this is a well-formed bundle in a known shape" without hashing anything. Useful as a CI gate, or to sanity-check a bundle before committing to full verification.

```bash
pip install jsonschema   # one-off

python - <<'EOF'
import json, jsonschema
bundle = json.load(open("bundle.json"))
schema = json.load(open("audit-bundle.schema.json"))
jsonschema.validate(instance=bundle, schema=schema)
print("Schema OK — bundle is structurally valid")
EOF
```

The schema covers all 4 chain row shapes via conditional `allOf` rules — `chain_name="audit_log"` enforces the audit_log row keys, `chain_name="screening_hits"` enforces those, etc. Auditors writing reference verifiers in other languages (Go, TypeScript, Rust) can use this schema as the source of truth for the bundle envelope without reading Python.

### Verifying a real bundle

Single bundle:

```bash
python verify_audit_bundle.py bundle.json
```

Bundle + signature key + locally-downloaded manifest:

```bash
python verify_audit_bundle.py bundle.json \
    --signing-key 'shared-with-auditor' \
    --manifest-dir ./manifests
```

Multiple bundles (cross-bundle aggregate checks):

```bash
python verify_audit_bundle.py q1.json q2.json q3.json q4.json \
    --signing-key 'shared-with-auditor'
```

Machine-readable output for CI / scripting:

```bash
python verify_audit_bundle.py bundle.json --json
```

Exit codes:

- `0` — all checks passed (or skipped optional ones)
- `1` — at least one check failed
- `2` — bundle file missing, malformed, or unrecognised chain_name

---

## The seven checks

| # | Check | What it detects | Always runs? |
|---|---|---|---|
| 1 | `per_row_content_hash` | Per-row tamper of any disclosed field | Yes |
| 2 | `continuity` | Fabricated gap, reorder, or row deletion within the bundle's window | When the bundle has 2+ rows |
| 3 | `selection_criteria_match` | Returned rows don't match the operator's filter — substantively misleading bundle | When at least one exact-match filter is set |
| 4 | `bundle_signature` | Forged or modified bundle (HMAC-SHA256 over canonical JSON) | When bundle is signed AND you supply the key |
| 5 | `off_vm_anchor` | Mismatch between the bundle's claim and the Object-Locked manifest in the bucket | When you supply `--manifest-dir` |
| 6 | `aggregate.same_chain` | Cross-chain mixing | When 2+ bundles |
| 7 | `aggregate.overlap_consistency` | Same chain row disclosed with different content to different audiences | When 2+ bundles overlap |
| 8 | `aggregate.monotonic_head` | Chain regressed (newer bundle claims smaller head) | When 2+ bundles |

A `[skip]` result is not a failure — it means the input you supplied did not exercise that check. A `[FAIL]` is conclusive.

---

## Verification recipes

### 1. Per-row content hash

For every row in `bundle.rows`:

1. Build a payload dict from the row's canonical fields. The exact field set depends on `bundle.chain_name`:
   - `audit_log` — `trace_id, actor, action, target_type, target_id, tenant_id, before_state, after_state, ip_address, user_agent, created_at, chain_position, prev_hash`
   - `screening_hits` — `screened_at, subject_type, wallet_address, tenant_id, payment_ledger_id, sanctions_entry_id, action_taken, screening_context, chain_position, prev_hash`
   - `compliance_events` — `id, tenant_id, rule_id, payment_ledger_id, payer_address_snapshot, review_of_event_id, event_type, metric_value, threshold_value, created_at, chain_position, prev_hash`
   - `negotiation_trace_events` — `trace_id, session_id, tenant_id, counterparty_a, counterparty_b, protocol, message_seq, message_role, message_payload, payment_ledger_id, created_at, chain_position, prev_hash`
2. Canonicalise the payload via [RFC 8785 JSON Canonicalization Scheme](https://datatracker.ietf.org/doc/html/rfc8785).
3. Compute SHA-256 of the canonical bytes.
4. Confirm the hex digest equals `row.content_hash`.

The verifier's per-chain field extractors live at `_FIELD_EXTRACTORS` in the script. Note `id` is excluded from the canonical payload for `audit_log`, `screening_hits`, and `negotiation_trace_events` (server-generated, not knowable pre-INSERT); included for `compliance_events` (UUID, generated by application code pre-INSERT).

### 2. Continuity

Build a list `union = bundle.rows + bundle.bridging_rows`, sorted by `chain_position` ascending. For every consecutive pair `(prev, curr)` in `union`, confirm `curr.prev_hash == prev.content_hash`.

If `bundle.rows` has gaps in `chain_position` AND `bridging_rows` is empty, the verifier reports `[skip]` rather than failing — request the bundle again with `include_bridging_rows=true` to enable the check.

If gaps remain even WITH bridging rows present (because bridging was truncated at the 50 000 row cap), the verifier reports `[FAIL]` — there's a real chain-integrity issue or AlgoVoi truncated the bundle in a way that breaks verification.

### 3. selection_criteria match

For every non-null exact-match filter in `bundle.selection_criteria`, every row in `bundle.rows` must have the corresponding field equal to the filter value. Per-chain mappings (criteria key ↔ row field):

- **audit_log** — `actor`, `action`, `target_type`, `tenant_id`, `trace_id` (range filters `since` / `until` apply to `created_at` and aren't checked locally yet)
- **screening_hits** — `subject_type`, `action_taken`, `screening_context`, `tenant_id`, `wallet_address`
- **compliance_events** — `tenant_id`, `rule_id`, `event_type`, `payment_ledger_id`
- **negotiation_trace_events** — `trace_id`, `tenant_id`, `protocol`, `message_role`, `payment_ledger_id`. The `counterparty` filter is disjunctive: a row matches if either `counterparty_a == counterparty` OR `counterparty_b == counterparty`.

This is the misrepresentation-attack net. Hash-based checks confirm the rows in the bundle ARE genuine chain rows, but they don't confirm the rows are the ones the operator's filter would have selected. Without this check, a malicious operator could return real chain rows with `actor=Y` in response to a request for `actor=X` — the bundle would pass per-row hash + continuity, but the auditor would never see the actor=X events that actually exist. The criteria-match check catches that by re-applying the filter locally and confirming every returned row qualifies.

If `bundle.rows` is empty, the check is vacuously satisfied and SKIPs. If no exact-match filters are set in `selection_criteria`, the check also SKIPs (everything matches by definition).

### 4. Bundle signature

If `bundle.bundle_signature` is non-null AND you supply `--signing-key K`:

1. Remove `bundle_signature` from the bundle dict.
2. Canonicalise the rest via RFC 8785.
3. Compute `HMAC-SHA256(K, canonical_bytes).hexdigest()`.
4. Confirm equals `bundle_signature.hex`.

Verify the `bundle_signature.algorithm` is `"HMAC-SHA256"` and `bundle_signature.canonicalisation` is `"RFC 8785"`. Verify `bundle_signature.key_id` matches the key version you were given.

### 5. Off-VM anchor

If you supply `--manifest-dir DIR`:

1. Find the manifest file in `DIR` matching `bundle.off_vm_anchor.object_key` (full path or basename both accepted).
2. Compute SHA-256 of the file's bytes. Confirm the first 16 hex chars match the sha prefix encoded in the object_key (the gateway computes this prefix at ship time and embeds it in the key).
3. Parse the LAST NDJSON line of the file. Confirm its `chain_position` equals `off_vm_anchor.last_shipped_position`.
4. If `bundle.chain_anchor.current_head.chain_position == last_shipped_position`, confirm the manifest's last-line `content_hash` also equals `current_head.content_hash`. If `current_head` is ahead, the difference is expected (newer rows queued in the DB, not yet shipped).

If you don't have the manifest file, you can still run `aws s3api head-object` against the bucket using your bucket-read credentials to confirm `ObjectLockMode=COMPLIANCE` and `ObjectLockRetainUntilDate` matches `off_vm_anchor.object_lock_until`. The verifier emits the recommended command when `--manifest-dir` is not supplied.

### 6–8. Cross-bundle aggregate

When you pass 2+ bundles:

- **`same_chain`** — `bundle.chain_name` must match across all bundles. Cross-chain comparison is meaningless.
- **`overlap_consistency`** — for any `chain_position` that appears in more than one bundle (across `rows + bridging_rows`), the `(content_hash, prev_hash)` tuple must be identical in every bundle. **A disagreement is a strong tamper signal**: AlgoVoi cannot legitimately produce two valid bundles disclosing different facts about the same chain row.
- **`monotonic_head`** — sort bundles by `bundle_emitted_at` ascending; `chain_anchor.current_head.chain_position` must be non-decreasing. **A newer bundle claiming a smaller head than an older bundle would mean the write-once chain regressed** — never legitimate.

---

## Bundle format reference

Every bundle has this top-level shape:

```jsonc
{
  "chain_format_version": 1,
  "chain_name": "audit_log",                          // or screening_hits / compliance_events / negotiation_trace_events
  "bundle_emitted_at": "2026-05-06T22:00:00+00:00",
  "selection_criteria": { /* echo of the operator's filter params */ },
  "selection": {
    "row_count": N,
    "min_chain_position": M,
    "max_chain_position": K,
    "truncated": false,                               // true when the operator's filter would have returned more than max_rows_cap
    "max_rows_cap": 10000
  },
  "rows": [
    {
      "id": ...,                                      // AuditLog.id (int) | ComplianceEvent.id (UUID string)
      "content_hash": "<64 hex chars>",
      "chain_position": M,
      "prev_hash": "<64 hex chars>",
      // ... per-chain canonical fields ...
    },
    ...
  ],
  "bridging_rows": [
    // Hash-only entries between min_chain_position and max_chain_position
    // that are NOT in the selected set. Content of unselected events is
    // never disclosed.
    {
      "chain_position": ...,
      "content_hash":   "<64 hex chars>",
      "prev_hash":      "<64 hex chars>"
    },
    ...
  ],
  "bridging": {
    "included": true,
    "row_count": ...,
    "truncated": false                                // true when bridging hit the 50 000 row cap
  },
  "chain_anchor": {
    "chain_name": "audit_log",
    "genesis_chain_position": 1,
    "genesis_prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "current_head": {
      "chain_position": ...,
      "content_hash":   "..."
    }
  },
  "off_vm_anchor": {
    "chain_name": "audit_log",
    "last_shipped_position": ...,
    "shipped_at": "...",
    "bucket_name": "algovoiretention",
    "object_key": "audit_log/000000001-000000100-abc123def456ab78.ndjson",
    "object_etag": "...",
    "object_lock_until": "2033-05-06T18:00:00+00:00",
    "shipper_version": "avs-v1"
  } | null,                                           // null when chain has not been shipped yet
  "verification_instructions": "...",                 // human + machine readable recipe text
  "bundle_signature": {
    "algorithm":        "HMAC-SHA256",
    "canonicalisation": "RFC 8785",
    "key_id":           "v1",
    "hex":              "<64 hex chars>"
  } | null                                            // null when AUDIT_BUNDLE_SIGNING_KEY is not configured server-side
}
```

---

## Worked example — single bundle

```bash
$ python verify_audit_bundle.py q4-2025.json --signing-key "$AUDITOR_KEY"
  [  ok] per_row_content_hash -- 142 rows verified
  [  ok] continuity -- 142 entries (selected=142, bridging=0) chain forward correctly
  [  ok] bundle_signature -- HMAC-SHA256 verified against key_id='prod-v1'
  [skip] off_vm_anchor -- pass --manifest-dir DIR to verify a downloaded manifest locally,
                          or run separately: aws s3api head-object --bucket algovoiretention
                          --key audit_log/000000001-000000142-abcd1234ef567890.ndjson
                          # confirm ObjectLockMode=COMPLIANCE and ObjectLockRetainUntilDate
                          # matches '2033-05-06T18:00:00+00:00'

Verdict: PASS
```

PASS verdict means: every disclosed row's hash recomputes correctly, the chain links forward without break, and the bundle was emitted by the holder of `prod-v1` (which AlgoVoi published as the current signing key id on `/compliance/attestation`). The off-VM anchor was skipped only because no manifest file was provided locally — run the suggested `aws s3api head-object` separately if you also want that surface confirmed.

## Worked example — multi-bundle aggregate

```bash
$ python verify_audit_bundle.py q1.json q2.json q3.json q4.json \
    --signing-key "$AUDITOR_KEY" \
    --manifest-dir ./manifests/

=== q1.json ===
  [  ok] per_row_content_hash -- 87 rows verified
  [  ok] continuity -- 87 entries chain forward correctly
  [  ok] bundle_signature -- HMAC-SHA256 verified against key_id='prod-v1'
  [  ok] off_vm_anchor -- manifest sha256 matches object_key prefix; ...
Verdict: PASS

=== q2.json ===  ... Verdict: PASS
=== q3.json ===  ... Verdict: PASS
=== q4.json ===  ... Verdict: PASS

=== aggregate (4 bundles) ===
  [  ok] aggregate.same_chain -- all 4 bundles are from chain 'audit_log'
  [  ok] aggregate.overlap_consistency -- 12 chain_position(s) appeared in multiple bundles;
                                          all overlap rows agree on (content_hash, prev_hash)
  [  ok] aggregate.monotonic_head -- chain heads non-decreasing across emission order:
                                     [142, 318, 547, 891]

Overall: PASS
```

PASS verdict at the `Overall:` line means: every individual bundle is internally consistent AND the four bundles are mutually consistent across the year of activity they cover.

---

## Failure modes — what each FAIL means

| Check failure | Most likely cause |
|---|---|
| `per_row_content_hash` FAIL | A row in `bundle.rows` has been tampered with after insert. |
| `continuity` FAIL | A row that should be in the chain is missing (deletion attempt) OR rows have been re-ordered OR a fabricated row was inserted between known links. |
| `selection_criteria_match` FAIL | **Strongest substantive-misrepresentation signal.** AlgoVoi returned chain rows that don't match the operator's filter — bundle is technically valid but answers a different question than the auditor asked. |
| `bundle_signature` FAIL | The bundle has been modified after AlgoVoi signed it, OR you're using the wrong signing key (check `bundle_signature.key_id` against AlgoVoi's published key versions). |
| `off_vm_anchor` FAIL — sha mismatch | The manifest file you downloaded does not match the manifest the gateway uploaded at ship time — local file corruption OR a malicious overlay against your bucket. |
| `off_vm_anchor` FAIL — chain_position mismatch | Either the bundle's anchor block has been tampered, or you have the wrong manifest file for this anchor. |
| `aggregate.same_chain` FAIL | Bundles from different chains were grouped together — operator error, not a tamper signal. |
| `aggregate.overlap_consistency` FAIL | **Strongest tamper signal available.** AlgoVoi disclosed conflicting facts about the same chain row to different audiences. |
| `aggregate.monotonic_head` FAIL | A bundle emitted later claims a smaller chain head than an earlier bundle — the write-once chain has been rolled back, which is never legitimate. |

Any FAIL warrants formal escalation to AlgoVoi's compliance officer and possibly to the regulator that commissioned the audit.

---

## Source-of-truth references

- The verifier script (this repo): [`verify_audit_bundle.py`](verify_audit_bundle.py)
- The bundle envelope JSON Schema (this repo): [`audit-bundle.schema.json`](audit-bundle.schema.json)
- The compliance attestation surface (public, advertises the available chains, current signing key id, and the verification recipe): [`https://api.algovoi.co.uk/compliance/attestation`](https://api.algovoi.co.uk/compliance/attestation) — the `audit_chain.selective_disclosure_bundles` block.

The verifier mirrors several server-side helpers from AlgoVoi's private monorepo by hand (canonical-fields layouts at `shared/utils/audit_chain.py`, NDJSON shipper format at `audit_chain_shipper.py`, HMAC signing at `control_plane/app/services/audit.py::_sign_bundle`). The helper names are listed here for diligence purposes. **You do not need access to AlgoVoi's private code** — the verifier is fully self-contained and exercised end-to-end by the test suite in this repo (`pytest tests/`).

---

## Bundle format versioning

Every bundle carries a `chain_format_version` integer at the top level. The current version is **1**.

The verifier explicitly checks this field FIRST. If the version is unknown (older verifier, newer bundle), the verifier fails fatally with:

```
FATAL:
  ! bundle.chain_format_version=2 is not supported by this verifier
    (supported: [1]). Pull a fresh verifier from
    https://github.com/chopmob-cloud/algovoi-audit-verifier —
    running an older verifier against a newer bundle risks a false PASS.
```

Why this matters: a newer envelope might add fields to the canonical-fields hash payload, change the canonicalisation algorithm, or restructure the chain anchor. An older verifier walking a newer bundle would silently miss the new fields and report bogus per-row-hash failures (which look like tamper). The fatal-on-unknown-version contract avoids that — auditors who hit it know to pull a fresh verifier rather than question the bundle itself.

If you receive a bundle with an unknown version: pull the latest `verify_audit_bundle.py` from `https://github.com/chopmob-cloud/algovoi-audit-verifier`, re-run, and only escalate to AlgoVoi compliance if the fresh verifier still fails. Conversely, if you're running the verifier in CI against a fixed version pin, bump the pin when AlgoVoi announces a format version change.

The supported-versions set lives at `_SUPPORTED_CHAIN_FORMAT_VERSIONS` in the verifier source. AlgoVoi commits to documenting any future version bump and providing migration guidance before the bump rolls out in production.

---

## Trust model

The verifier deliberately depends on:

- Python stdlib (audit-able)
- `rfc8785` PyPI package (audit-able — JSON canonicalisation per IETF spec)

It deliberately does NOT depend on:

- Any AlgoVoi codebase imports
- Network access
- AlgoVoi infrastructure being available
- AWS credentials (off-VM anchor cross-check works against locally-downloaded manifests)

You can run the verifier offline on an air-gapped machine and obtain the same verdict. The whole verification recipe is reproducible in any language; this script is one reference implementation. Ports to Go / TypeScript / Rust are available on request.
