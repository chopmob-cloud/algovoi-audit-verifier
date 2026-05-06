# algovoi-audit-verifier

Standalone reference verifier for AlgoVoi selective-disclosure audit bundles. Designed to run on an external auditor's machine without trusting AlgoVoi's infrastructure, transport, or any single attestation surface.

> **For AlgoVoi internal teams:** the canonical source for the verifier lives in the private `AlgoVoi-Hand` monorepo at `scripts/verify_audit_bundle.py`. This public repo is the auditor-facing distribution copy.

---

## Quickstart (30 seconds)

```bash
pip install rfc8785

# Generate a synthetic signed bundle (no real bundle needed)
python demo_audit_bundle.py

# Verify it
python verify_audit_bundle.py demo_bundle.json \
    --signing-key 'demo-key-not-for-production-use'
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

## License

MIT — see [`LICENSE`](LICENSE).

---

## Reporting issues

Open an issue on this repo for verifier bugs, schema clarifications, or auditor-facing documentation gaps. For questions about specific bundles you've received, contact AlgoVoi compliance directly.
