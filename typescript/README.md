# @algovoi/audit-verifier (TypeScript)

TypeScript reference verifier for AlgoVoi selective-disclosure audit bundles.
Byte-for-byte parity with the Python sibling
[`algovoi-audit-verifier`](https://pypi.org/project/algovoi-audit-verifier/)
on PyPI.

Standalone — auditor-runnable on any Node.js 18+ machine with no AlgoVoi
infrastructure trust required.

## Install

```bash
npm install @algovoi/substrate canonicalize        # peer deps
npm install @algovoi/audit-verifier
```

Or just install the package directly (canonicalize is a dependency, pulled
automatically):

```bash
npm install @algovoi/audit-verifier
```

## Three ways to verify

### 1. Hosted endpoint (zero install)

POST your bundle to `https://verify.algovoi.co.uk/verify` and get a
structured verification report. Same code path as this package.

### 2. Programmatic use

```ts
import { verifyBundle } from '@algovoi/audit-verifier';

const bundle = JSON.parse(fs.readFileSync('audit-bundle.json', 'utf-8'));
const report = await verifyBundle(bundle, {
  signingKey: process.env.AUDIT_BUNDLE_KEY,  // optional
});

console.log(report.render());                 // human-readable PASS/FAIL
console.log(report.toJSON());                 // machine-readable
if (!report.allPassed) process.exit(1);
```

### 3. Demo + smoke test

```ts
import { buildDemoBundle, verifyBundle } from '@algovoi/audit-verifier';

const bundle = buildDemoBundle({ chainName: 'audit_log', rowCount: 3 });
const report = await verifyBundle(bundle, {
  signingKey: 'demo-key-not-for-production-use',
});
console.log(report.allPassed);   // true
```

## What this verifier checks

| # | Check | What it proves |
|---|---|---|
| 1 | `per_row_content_hash` | Each row's stored `content_hash` matches `SHA-256(JCS(canonical-fields))` — per-row tamper-evidence |
| 2 | `continuity` | `prev_hash` walks unbroken across `rows + bridging_rows` ordered by `chain_position` — no fabricated gap or reorder |
| 3 | `bundle_signature` | HMAC-SHA256 over `JCS(bundle - signature)` matches `bundle_signature.hex` — proves AlgoVoi emission (when signing key supplied) |
| 4 | `selection_criteria_match` | Selected rows actually match the filter declared in `selection_criteria` (when exact-match filters are set) |
| 5 | `off_vm_anchor` | Off-VM Object-Lock manifest tail entry matches `chain_anchor.current_head` (when `manifestDir` supplied) |

A bundle that passes all five checks (or has them skipped for legitimate
reasons — no signing key supplied, no manifest available, etc.) has its
`all_passed` set to `true`.

## Cross-implementation parity

This TypeScript verifier is **byte-for-byte equivalent** to the Python
sibling on PyPI:

| Implementation | Package |
|---|---|
| Python | [`algovoi-audit-verifier`](https://pypi.org/project/algovoi-audit-verifier/) |
| TypeScript | `@algovoi/audit-verifier` (this package) |

Both verifiers produce identical:
- JCS canonical bytes for the same input object (RFC 8785)
- SHA-256 hash for the same canonical preimage
- HMAC-SHA256 signature for the same `(bundle - signature, key)` pair
- Per-row `content_hash` for the same row content
- Check report shape (`all_passed`, `fatal[]`, `checks[]`)

The parity is exercised by 9 cross-impl tests in this repo's
`test/parity.test.ts`, which generate bundles in Python and verify them in
TypeScript (and vice versa).

## Substrate

This verifier composes against the AlgoVoi canonicalisation substrate:

- Spec: `specs/canonicalisation.md` ([PR #2436](https://github.com/x402-foundation/x402/pull/2436)) — three-voice coalition co-signed
- Pin: `urn:x402:canonicalisation:jcs-rfc8785-v1`
- Substrate SDK: [`@algovoi/substrate`](https://www.npmjs.com/package/@algovoi/substrate)
- 53-vector conformance corpus: [`chopmob-cloud/algovoi-jcs-conformance-vectors`](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors)

## Hosted equivalent

The same code path runs at <https://verify.algovoi.co.uk> behind nginx + Cloudflare on a dedicated VM. POST any audit bundle to `/verify` and get back the same `CheckReportJSON` shape this package returns programmatically.

## Licence

MIT. See `LICENSE`.

## Author

AlgoVoi (Christopher Hopley, GitHub [`chopmob-cloud`](https://github.com/chopmob-cloud)).
