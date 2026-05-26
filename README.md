# algovoi-audit-verifier

[![test](https://github.com/chopmob-cloud/algovoi-audit-verifier/actions/workflows/test.yml/badge.svg)](https://github.com/chopmob-cloud/algovoi-audit-verifier/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://github.com/chopmob-cloud/algovoi-audit-verifier/actions/workflows/test.yml)

Standalone reference verifier for AlgoVoi selective-disclosure audit bundles. Designed to run on an external auditor's machine without trusting AlgoVoi's infrastructure, transport, or any single attestation surface.

---

## Two ways to verify

### 1. Hosted endpoint (zero install)

Live at [`verify.algovoi.co.uk`](https://verify.algovoi.co.uk). POST your bundle, get back a structured verification report. Stateless, no bundle is retained.

```bash
curl -X POST -H 'Content-Type: application/json' \
    --data-binary @your-bundle.json \
    https://verify.algovoi.co.uk/verify
```

Optional signature verification: pass the shared signing key in the `X-Audit-Bundle-Key` header.

Response is JSON with `all_passed: bool`, `fatal: [...]`, and a `checks: [...]` array.
HTTP 200 = all checks passed or optional-skipped; 422 = one or more checks failed; 400/413 = malformed or too-large request.

OpenAPI docs at [`verify.algovoi.co.uk/docs`](https://verify.algovoi.co.uk/docs).

### 2. Offline (auditor's machine, no network round-trip)

```bash
pip install algovoi-audit-verifier

# Generate a synthetic signed bundle (no real bundle needed)
algovoi-verify-demo > demo_bundle.json   # or: python demo_audit_bundle.py

# Verify it
algovoi-verify demo_bundle.json \
    --signing-key 'demo-key-not-for-production-use'
```

Or run the HTTP server locally (same code path as `verify.algovoi.co.uk`):

```bash
pip install 'algovoi-audit-verifier[server]'
algovoi-verify-server
# POST bundles to http://localhost:8000/verify
```

Expected output ends with `Verdict: PASS`. If you don't see that, your `rfc8785` install is wrong or you're on Python < 3.10 — fix that before trusting any verdict on a real bundle from AlgoVoi.

---

## What this is for

When AlgoVoi compliance hands you a JSON bundle in response to a selective-disclosure request, this script lets you confirm — locally and offline — that the bundle's claims are tamper-evident, internally consistent, and were genuinely emitted by AlgoVoi.

Eight independent attestation surfaces:

| # | Check | What it detects |
|---|---|---|
| 1 | per_row_content_hash | Per-row tamper of any disclosed field |
| 2 | continuity | Fabricated gap, reorder, or row deletion |
| 3 | selection_criteria_match | Substantive misrepresentation (returned rows don't match the filter) |
| 4 | bundle_signature | Bundle modified after signing, OR wrong signing key |
| 5 | off_vm_anchor | Mismatch between bundle's claim and Object-Locked manifest |
| 6 | aggregate.same_chain | Multiple bundles span different chains (operator error) |
| 7 | aggregate.overlap_consistency | Same chain row disclosed differently to different audiences |
| 8 | aggregate.monotonic_head | Write-once chain regressed (never legitimate) |

See [`AUDITOR-RUNBOOK.md`](AUDITOR-RUNBOOK.md) for the full verification recipe, examples, and failure-mode guide.

---

## Repository layout

```
.
├── verify_audit_bundle.py      Reference verifier CLI
├── demo_audit_bundle.py         Synthetic bundle generator (toolchain smoke test)
├── audit-bundle.schema.json     Formal JSON Schema 2020-12 for the bundle envelope
├── AUDITOR-RUNBOOK.md          Full auditor-facing runbook
├── tests/                       pytest suite (56 cases, exercises all 4 chains end-to-end)
└── README.md                    This file
```

---

## Install + run from source

```bash
git clone https://github.com/chopmob-cloud/algovoi-audit-verifier
cd algovoi-audit-verifier
pip install rfc8785

# Optional: also install jsonschema for structural pre-flight
pip install jsonschema

# Optional: install pytest if you want to run the test suite
pip install pytest pytest-asyncio
pytest tests/   # 56 tests, ~1 second
```

The verifier itself is pure Python stdlib + [rfc8785](https://pypi.org/project/rfc8785/) (RFC 8785 JSON Canonicalization). Nothing else is required.

---

## Trust model

The verifier deliberately does NOT depend on:

- Network access (works air-gapped)
- AlgoVoi infrastructure (no API calls)
- AWS credentials (the off-VM anchor cross-check works against locally-downloaded manifest files; the script also emits the recommended `aws s3api head-object` command for you to run separately if you have bucket-read access)
- Any AlgoVoi codebase imports

This means: if you can `pip install rfc8785` and run a Python script, you can verify a bundle without contacting AlgoVoi at all. The whole verification recipe is reproducible in any language; this script is one reference implementation. Ports to Go / TypeScript / Rust are welcome — the [`audit-bundle.schema.json`](audit-bundle.schema.json) is the machine-readable source of truth for the envelope format.

---

## Supported bundle versions

| `chain_format_version` | Status | Verifier handles |
|---|---|---|
| 1 | current | yes |
| 2+ | reserved for future breaking changes | no — verifier fails fatally with "pull a fresh verifier" |

If you encounter a bundle whose version this verifier doesn't recognise, pull the latest from this repo. If the latest still fails, escalate to AlgoVoi compliance.

---

## Conformance to the canonicalisation discipline

This verifier consumes receipts pinned to `canon_version: jcs-rfc8785-v1` (or `jcs-rfc8785-v2` under the strictly-additive PQC-aware discipline). The pin selects which canonicalisation rule the verifier applies at receipt-bytes verification time. A receipt without a recognised `canon_version` pin is treated as opaque; the verifier fails closed rather than guessing the rule.

The substrate discipline is defined at [docs.algovoi.co.uk/canonicalisation-substrate](https://docs.algovoi.co.uk/canonicalisation-substrate) (v1) and [docs.algovoi.co.uk/canonicalisation-substrate-v2](https://docs.algovoi.co.uk/canonicalisation-substrate-v2) (v2, PQC-aware additive successor).

## Substrate adopters

AlgoVoi is recorded in the [Substrate Adopters Registry](https://docs.algovoi.co.uk/adopters) as the substrate author. Parties anchoring their own services or specifications to `canon_version: jcs-rfc8785-v1` (or v2) are recorded in the registry via the [submission process](https://docs.algovoi.co.uk/adopters#how-to-submit-an-adoption-entry). AlgoVoi validates submissions against the artefact's canonical bytes and adds qualifying entries.

---

## License

MIT — see [`LICENSE`](LICENSE).

---

## Reporting issues

Open an issue on this repo for verifier bugs, schema clarifications, or auditor-facing documentation gaps. For questions about specific bundles you've received, contact AlgoVoi compliance directly.
