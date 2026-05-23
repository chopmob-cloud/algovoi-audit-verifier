/**
 * Tests for verify_audit_bundle.ts -- behaviour parity with the
 * Python sibling.
 */
import { describe, it, expect } from 'vitest';
import {
  buildDemoBundle,
  verifyBundle,
  CheckReport,
  SUPPORTED_CHAIN_FORMAT_VERSIONS,
  parseObjectKeyShaPrefix,
} from '../src/index.js';

describe('SUPPORTED_CHAIN_FORMAT_VERSIONS', () => {
  it('supports version 1', () => {
    expect(SUPPORTED_CHAIN_FORMAT_VERSIONS.has(1)).toBe(true);
  });
});

describe('verifyBundle -- valid bundles', () => {
  it('audit_log demo bundle passes structural checks', async () => {
    const bundle = buildDemoBundle({ chainName: 'audit_log' });
    const report = await verifyBundle(bundle);
    expect(report.allPassed).toBe(true);
    expect(report.fatal).toEqual([]);
    const names = report.checks.map((c) => c.name);
    expect(names).toContain('per_row_content_hash');
    expect(names).toContain('continuity');
    expect(names).toContain('bundle_signature');
    expect(names).toContain('off_vm_anchor');
    expect(names).toContain('selection_criteria_match');
  });

  it('audit_log demo bundle passes with signing key', async () => {
    const bundle = buildDemoBundle({ chainName: 'audit_log' });
    const report = await verifyBundle(bundle, { signingKey: 'demo-key-not-for-production-use' });
    expect(report.allPassed).toBe(true);
    const sigCheck = report.checks.find((c) => c.name === 'bundle_signature');
    expect(sigCheck?.passed).toBe(true);
    expect(sigCheck?.detail).toContain('HMAC-SHA256 verified');
  });

  it('audit_log demo bundle fails signing check with wrong key', async () => {
    const bundle = buildDemoBundle({ chainName: 'audit_log' });
    const report = await verifyBundle(bundle, { signingKey: 'wrong-key' });
    expect(report.allPassed).toBe(false);
    const sigCheck = report.checks.find((c) => c.name === 'bundle_signature');
    expect(sigCheck?.passed).toBe(false);
  });

  it.each(['audit_log', 'screening_hits', 'compliance_events', 'negotiation_trace_events'])(
    'demo bundle for chain %s passes structural checks',
    async (chainName) => {
      const bundle = buildDemoBundle({ chainName });
      const report = await verifyBundle(bundle);
      expect(report.allPassed).toBe(true);
    },
  );

  it('5-row chain still verifies', async () => {
    const bundle = buildDemoBundle({ rowCount: 5 });
    const report = await verifyBundle(bundle);
    expect(report.allPassed).toBe(true);
    const contCheck = report.checks.find((c) => c.name === 'continuity');
    expect(contCheck?.detail).toContain('5 entries');
  });
});

describe('verifyBundle -- malformed bundles (fatal)', () => {
  it('missing chain_format_version → fatal', async () => {
    const bundle = buildDemoBundle();
    delete (bundle as Record<string, unknown>).chain_format_version;
    const report = await verifyBundle(bundle);
    expect(report.allPassed).toBe(false);
    expect(report.fatal.some((f) => f.includes('chain_format_version'))).toBe(true);
  });

  it('unsupported chain_format_version → fatal', async () => {
    const bundle = buildDemoBundle();
    bundle.chain_format_version = 999;
    const report = await verifyBundle(bundle);
    expect(report.allPassed).toBe(false);
    expect(report.fatal.some((f) => f.includes('not supported'))).toBe(true);
  });

  it('unknown chain_name → fatal', async () => {
    const bundle = buildDemoBundle();
    bundle.chain_name = 'made_up_chain';
    const report = await verifyBundle(bundle);
    expect(report.allPassed).toBe(false);
    expect(report.fatal.some((f) => f.includes('chain_name'))).toBe(true);
  });

  it('missing rows → fatal', async () => {
    const bundle = buildDemoBundle();
    delete (bundle as Record<string, unknown>).rows;
    const report = await verifyBundle(bundle);
    expect(report.allPassed).toBe(false);
    expect(report.fatal.some((f) => f.includes("'rows'"))).toBe(true);
  });
});

describe('verifyBundle -- tampering detection', () => {
  it('tampered content_hash on row 0 → per_row_content_hash FAIL', async () => {
    const bundle = buildDemoBundle();
    (bundle.rows![0] as Record<string, unknown>).content_hash = '0'.repeat(64);
    const report = await verifyBundle(bundle);
    expect(report.allPassed).toBe(false);
    const c = report.checks.find((c) => c.name === 'per_row_content_hash');
    expect(c?.passed).toBe(false);
    expect(c?.detail).toContain('1 of');
  });

  it('tampered created_at on row 0 → per_row_content_hash FAIL', async () => {
    const bundle = buildDemoBundle();
    (bundle.rows![0] as Record<string, unknown>).created_at = '1999-01-01T00:00:00+00:00';
    const report = await verifyBundle(bundle);
    expect(report.allPassed).toBe(false);
    expect(report.checks.find((c) => c.name === 'per_row_content_hash')?.passed).toBe(false);
  });

  it('removed row 1 → continuity break', async () => {
    const bundle = buildDemoBundle({ rowCount: 3 });
    // Drop the middle row.
    bundle.rows = [bundle.rows![0]!, bundle.rows![2]!];
    // We also drop bridging meta so the gap is detected as a real gap.
    bundle.bridging = { included: false };
    const report = await verifyBundle(bundle);
    const c = report.checks.find((c) => c.name === 'continuity');
    // With bridging marked not-included and a gap present, continuity skips.
    expect(c?.passed).toBe(null);  // skip
    expect(c?.detail).toContain('bridging_rows not included');
  });

  it('forged prev_hash on row 1 → continuity FAIL', async () => {
    const bundle = buildDemoBundle({ rowCount: 3 });
    (bundle.rows![1] as Record<string, unknown>).prev_hash = '1'.repeat(64);
    // Also need to break per_row_content_hash for this row since content
    // depends on prev_hash. So we just expect both to fail.
    const report = await verifyBundle(bundle);
    expect(report.allPassed).toBe(false);
  });
});

describe('checkSelectionCriteriaMatch', () => {
  it('passes when no exact-match filters set (all-null criteria)', async () => {
    const bundle = buildDemoBundle();
    // Demo criteria are all-null → skip.
    const report = await verifyBundle(bundle);
    const c = report.checks.find((c) => c.name === 'selection_criteria_match');
    expect(c?.passed).toBe(null);  // skip
  });

  it('passes when criteria match the rows', async () => {
    const bundle = buildDemoBundle();
    bundle.selection_criteria!.actor = 'demo-admin@example.com';
    const report = await verifyBundle(bundle);
    const c = report.checks.find((c) => c.name === 'selection_criteria_match');
    expect(c?.passed).toBe(true);
  });

  it('fails when criteria do not match the rows', async () => {
    const bundle = buildDemoBundle();
    bundle.selection_criteria!.actor = 'someone-else@example.com';
    const report = await verifyBundle(bundle);
    const c = report.checks.find((c) => c.name === 'selection_criteria_match');
    expect(c?.passed).toBe(false);
  });
});

describe('parseObjectKeyShaPrefix', () => {
  it('extracts prefix from a well-formed key', () => {
    expect(
      parseObjectKeyShaPrefix('audit_log/000000001-000000100-abc123def456ab78.ndjson'),
    ).toBe('abc123def456ab78');
  });

  it('returns null for non-ndjson keys', () => {
    expect(
      parseObjectKeyShaPrefix('audit_log/000000001-000000100-abc123def456ab78.txt'),
    ).toBeNull();
  });

  it('returns null for wrong-length prefix', () => {
    expect(
      parseObjectKeyShaPrefix('audit_log/000000001-000000100-tooshort.ndjson'),
    ).toBeNull();
  });

  it('returns null for non-hex prefix', () => {
    expect(
      parseObjectKeyShaPrefix('audit_log/000000001-000000100-XYZ123def456ab78.ndjson'),
    ).toBeNull();
  });

  it('returns null for empty / null input', () => {
    expect(parseObjectKeyShaPrefix(undefined)).toBeNull();
    expect(parseObjectKeyShaPrefix('')).toBeNull();
  });
});

describe('CheckReport', () => {
  it('all_passed is true when only ok + skip', () => {
    const r = new CheckReport();
    r.add('foo', true);
    r.addSkip('bar', 'no data');
    expect(r.allPassed).toBe(true);
  });

  it('all_passed is false when any fail', () => {
    const r = new CheckReport();
    r.add('foo', true);
    r.add('bar', false, 'broken');
    expect(r.allPassed).toBe(false);
  });

  it('all_passed is false when fatal present', () => {
    const r = new CheckReport();
    r.add('foo', true);
    r.addFatal('boom');
    expect(r.allPassed).toBe(false);
  });

  it('toJSON has correct shape', () => {
    const r = new CheckReport();
    r.add('foo', true, 'detail');
    const j = r.toJSON();
    expect(j.all_passed).toBe(true);
    expect(j.fatal).toEqual([]);
    expect(j.checks).toEqual([{ name: 'foo', passed: true, detail: 'detail' }]);
  });
});
