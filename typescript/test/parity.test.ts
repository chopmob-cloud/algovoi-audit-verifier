/**
 * Cross-impl parity tests: Python algovoi-audit-verifier ↔ TypeScript
 * @algovoi/audit-verifier produce byte-for-byte identical canonical
 * preimages and SHA-256 results on the same demo bundle inputs.
 *
 * The Python demo bundles used as fixtures are generated at test setup
 * time via the algovoi-audit-verifier PyPI package. We assert that:
 *   1. The Python-generated bundle verifies cleanly under TypeScript.
 *   2. The TypeScript-built bundle (with bundleEmittedAt pinned to the
 *      same value as the Python one) produces the SAME bundle_signature
 *      hex -- proving canonicalisation parity.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execSync } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalize, buildDemoBundle, verifyBundle, sha256JcsHex } from '../src/index.js';

interface PythonBundle {
  bundle_emitted_at: string;
  bundle_signature?: { hex: string; key_id?: string };
  [k: string]: unknown;
}

const TMPDIR = mkdtempSync(join(tmpdir(), 'algovoi-parity-'));

function runPythonDemo(chainName: string, rowCount: number, signingKey: string, keyId: string): PythonBundle {
  const scriptPath = join(TMPDIR, `gen-${chainName}-${rowCount}.py`);
  const script = `import sys, json
sys.path.insert(0, r'C:\\tmp\\algovoi-audit-verifier')
import demo_audit_bundle as d
b = d.build_demo_bundle(chain_name=${JSON.stringify(chainName)}, row_count=${rowCount}, signing_key=${JSON.stringify(signingKey)}, key_id=${JSON.stringify(keyId)})
print(json.dumps(b))
`;
  writeFileSync(scriptPath, script, 'utf-8');
  const stdout = execSync(`python "${scriptPath}"`, { encoding: 'utf-8' });
  return JSON.parse(stdout) as PythonBundle;
}

function runPythonExpr(expr: string): string {
  const scriptPath = join(TMPDIR, `expr-${Date.now()}.py`);
  writeFileSync(scriptPath, expr, 'utf-8');
  return execSync(`python "${scriptPath}"`, { encoding: 'utf-8' }).trim();
}

describe('cross-impl parity with Python', () => {
  let pyBundle: PythonBundle;

  beforeAll(() => {
    pyBundle = runPythonDemo('audit_log', 3, 'demo-key-not-for-production-use', 'demo-v1');
  });

  it('Python-generated bundle verifies under TypeScript verifier', async () => {
    const report = await verifyBundle(pyBundle, { signingKey: 'demo-key-not-for-production-use' });
    expect(report.allPassed).toBe(true);
    // Signature must verify -- proves HMAC parity, JCS canonicalisation parity, hex-encoding parity.
    const sigCheck = report.checks.find((c) => c.name === 'bundle_signature');
    expect(sigCheck?.passed).toBe(true);
  });

  it('TypeScript bundle with pinned timestamp produces identical signature to Python', () => {
    // Re-build in TS with the SAME bundle_emitted_at + same signing key + same chain + rowCount.
    const tsBundle = buildDemoBundle({
      chainName: 'audit_log',
      rowCount: 3,
      signingKey: 'demo-key-not-for-production-use',
      keyId: 'demo-v1',
      bundleEmittedAt: pyBundle.bundle_emitted_at,
    });

    const tsSig = tsBundle.bundle_signature?.hex;
    const pySig = pyBundle.bundle_signature?.hex;
    expect(tsSig).toBe(pySig);
  });

  it('TypeScript bundle canonicalises identically to Python (per-row content_hashes match)', () => {
    const tsBundle = buildDemoBundle({
      chainName: 'audit_log',
      rowCount: 3,
      signingKey: 'demo-key-not-for-production-use',
      keyId: 'demo-v1',
      bundleEmittedAt: pyBundle.bundle_emitted_at,
    });

    const tsRows = tsBundle.rows ?? [];
    const pyRows = (pyBundle.rows ?? []) as Array<Record<string, unknown>>;
    expect(tsRows.length).toBe(pyRows.length);
    for (let i = 0; i < tsRows.length; i++) {
      expect(tsRows[i]!['content_hash']).toBe(pyRows[i]!['content_hash']);
    }
  });

  it.each(['audit_log', 'screening_hits', 'compliance_events', 'negotiation_trace_events'])(
    'chain %s: TS bundle byte-identical signature to Python',
    (chainName) => {
      const py = runPythonDemo(chainName, 3, 'demo-key-not-for-production-use', 'demo-v1');
      const ts = buildDemoBundle({
        chainName,
        rowCount: 3,
        signingKey: 'demo-key-not-for-production-use',
        keyId: 'demo-v1',
        bundleEmittedAt: py.bundle_emitted_at,
      });
      expect(ts.bundle_signature?.hex).toBe(py.bundle_signature?.hex);
    },
  );

  it('JCS canonical bytes match Python on a fixed object', () => {
    // Spot-check that our canonicalize wraps the same RFC 8785 behaviour as Python's rfc8785.
    const obj = { b: 1, a: { c: 'utf-8 a o u', d: [3, 2, 1] } };
    const pyCanon = runPythonExpr(
      `import rfc8785\nprint(rfc8785.dumps({'b':1,'a':{'c':'utf-8 a o u','d':[3,2,1]}}).decode('utf-8'))`,
    );
    expect(canonicalize(obj)).toBe(pyCanon);
  });

  it('SHA-256(JCS()) matches Python for a fixed object', () => {
    const obj = { foo: 'bar', baz: 42 };
    const pyHash = runPythonExpr(
      `import hashlib, rfc8785\nprint(hashlib.sha256(rfc8785.dumps({'foo':'bar','baz':42})).hexdigest())`,
    );
    expect(sha256JcsHex(obj)).toBe(pyHash);
  });
});
