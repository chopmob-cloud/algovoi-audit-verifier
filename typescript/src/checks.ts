/**
 * The five verifier checks ported byte-for-byte from verify_audit_bundle.py:
 *
 *   1. checkPerRowContentHash  -- SHA-256(JCS(canonical-fields)) per row
 *   2. checkContinuity         -- prev_hash walks unbroken across rows + bridging
 *   3. checkBundleSignature    -- HMAC-SHA256 over RFC 8785 canonical bundle
 *   4. checkSelectionCriteria  -- selected rows actually match the filter
 *   5. checkOffVmAnchor        -- off-VM Object-Lock manifest cross-check
 *                                (when manifestDir provided)
 */
import { createHash, createHmac } from 'node:crypto';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';

import { canonicalize, canonicaliseToBytes, sha256Hex } from './canonicalize.js';
import type { CheckReport } from './check-report.js';
import { FIELD_EXTRACTORS, KNOWN_CHAIN_NAMES } from './extractors.js';
import type {
  AuditBundle,
  AuditRow,
  BundleSignature,
} from './types.js';

// ---------------------------------------------------------------------------
// 1. Per-row content_hash
// ---------------------------------------------------------------------------

export function checkPerRowContentHash(bundle: AuditBundle, report: CheckReport): void {
  const chainName = bundle.chain_name;
  const extractor = chainName ? FIELD_EXTRACTORS[chainName] : undefined;
  if (!extractor) {
    report.add(
      'per_row_content_hash',
      false,
      `unknown chain_name '${chainName}' (expected one of ${JSON.stringify(KNOWN_CHAIN_NAMES)})`,
    );
    return;
  }
  const rows = bundle.rows ?? [];
  if (rows.length === 0) {
    report.addSkip('per_row_content_hash', 'selection is empty (zero rows)');
    return;
  }
  const failures: string[] = [];
  for (const r of rows) {
    const expected = r['content_hash'];
    if (typeof expected !== 'string' || expected.length !== 64) {
      failures.push(`chain_position=${JSON.stringify(r['chain_position'])}: stored content_hash missing or wrong length`);
      continue;
    }
    const canonical = extractor(r);
    const actual = sha256Hex(canonicaliseToBytes(canonical));
    if (actual !== expected) {
      failures.push(
        `chain_position=${JSON.stringify(r['chain_position'])}: ` +
        `recomputed ${actual.slice(0, 16)}... != stored ${expected.slice(0, 16)}...`,
      );
    }
  }
  if (failures.length > 0) {
    let detail = `${failures.length} of ${rows.length} rows failed: ${failures.slice(0, 3).join('; ')}`;
    if (failures.length > 3) detail += `; (+${failures.length - 3} more)`;
    report.add('per_row_content_hash', false, detail);
  } else {
    report.add('per_row_content_hash', true, `${rows.length} rows verified`);
  }
}

// ---------------------------------------------------------------------------
// 2. Continuity walk
// ---------------------------------------------------------------------------

interface UnionEntry {
  chain_position: number | null;
  content_hash:   string | undefined;
  prev_hash:      string | undefined;
  kind:           'selected' | 'bridging';
}

export function checkContinuity(bundle: AuditBundle, report: CheckReport): void {
  const rows = bundle.rows ?? [];
  const bridging = bundle.bridging_rows ?? [];
  const bridgingMeta = bundle.bridging ?? {};

  if (rows.length === 0) {
    report.addSkip('continuity', 'selection is empty');
    return;
  }

  const union: UnionEntry[] = [];
  for (const r of rows) {
    union.push({
      chain_position: (r['chain_position'] as number | null | undefined) ?? null,
      content_hash:   r['content_hash'] as string | undefined,
      prev_hash:      r['prev_hash']    as string | undefined,
      kind:           'selected',
    });
  }
  for (const b of bridging) {
    union.push({
      chain_position: (b['chain_position'] as number | null | undefined) ?? null,
      content_hash:   b['content_hash'] as string | undefined,
      prev_hash:      b['prev_hash']    as string | undefined,
      kind:           'bridging',
    });
  }
  // Sort by chain_position, nulls last (Python uses (None, position) tuple).
  union.sort((a, b) => {
    if (a.chain_position === null && b.chain_position === null) return 0;
    if (a.chain_position === null) return 1;
    if (b.chain_position === null) return -1;
    return a.chain_position - b.chain_position;
  });

  // Detect gaps in the merged set.
  if (union.length > 1) {
    const gaps: Array<[number, number]> = [];
    for (let i = 1; i < union.length; i++) {
      const p0 = union[i - 1]!.chain_position;
      const p1 = union[i]!.chain_position;
      if (p0 === null || p1 === null) continue;
      if (p1 - p0 > 1) gaps.push([p0, p1]);
    }
    if (gaps.length > 0 && !bridgingMeta.included) {
      report.addSkip(
        'continuity',
        `gaps between selected positions ${JSON.stringify(gaps.slice(0, 2))} but bridging_rows not included; ` +
        'request the bundle with include_bridging_rows=true to enable this check',
      );
      return;
    }
    if (gaps.length > 0) {
      report.add(
        'continuity',
        false,
        `gaps remain after bridging at positions ${JSON.stringify(gaps.slice(0, 3))} -- chain has missing rows`,
      );
      return;
    }
  }

  // Walk
  const failures: string[] = [];
  for (let i = 1; i < union.length; i++) {
    const prev = union[i - 1]!;
    const curr = union[i]!;
    if (curr.prev_hash !== prev.content_hash) {
      failures.push(
        `position ${curr.chain_position} (${curr.kind}): ` +
        `prev_hash ${(curr.prev_hash ?? '').slice(0, 12)}... != ` +
        `content_hash of position ${prev.chain_position} (${prev.kind}) ` +
        `${(prev.content_hash ?? '').slice(0, 12)}...`,
      );
    }
  }
  if (failures.length > 0) {
    const detail = `${failures.length} broken link(s): ${failures.slice(0, 2).join('; ')}`;
    report.add('continuity', false, detail);
  } else {
    report.add(
      'continuity',
      true,
      `${union.length} entries (selected=${rows.length}, bridging=${bridging.length}) chain forward correctly`,
    );
  }
}

// ---------------------------------------------------------------------------
// 3. Bundle signature
// ---------------------------------------------------------------------------

export function checkBundleSignature(
  bundle: AuditBundle,
  signingKey: string | null | undefined,
  report: CheckReport,
): void {
  const sig = bundle.bundle_signature;
  if (sig === null || sig === undefined) {
    report.addSkip(
      'bundle_signature',
      'bundle has bundle_signature: null (signing not configured server-side)',
    );
    return;
  }
  if (typeof sig !== 'object' || Array.isArray(sig) || !('hex' in sig)) {
    report.add('bundle_signature', false, `bundle_signature is not a valid signature object: ${JSON.stringify(sig)}`);
    return;
  }
  const s = sig as BundleSignature;
  if (!signingKey) {
    report.addSkip(
      'bundle_signature',
      `bundle is signed with key_id='${s.key_id}', algorithm='${s.algorithm}' -- ` +
      'pass --signing-key or --signing-key-env to verify',
    );
    return;
  }
  if (s.algorithm !== 'HMAC-SHA256' || s.canonicalisation !== 'RFC 8785') {
    report.add(
      'bundle_signature',
      false,
      `unsupported signature algorithm/canonicalisation: ${s.algorithm}/${s.canonicalisation}`,
    );
    return;
  }

  // Build inner = bundle minus bundle_signature
  const inner: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(bundle)) {
    if (k !== 'bundle_signature') inner[k] = v;
  }
  const canonical = canonicaliseToBytes(inner);
  const expected = createHmac('sha256', signingKey).update(canonical).digest('hex');
  if (expected === s.hex) {
    report.add(
      'bundle_signature',
      true,
      `HMAC-SHA256 verified against key_id='${s.key_id}'`,
    );
  } else {
    report.add(
      'bundle_signature',
      false,
      `recomputed ${expected.slice(0, 16)}... != stored ${s.hex.slice(0, 16)}... -- wrong key, or bundle tampered`,
    );
  }
}

// ---------------------------------------------------------------------------
// 4. Selection criteria match
// ---------------------------------------------------------------------------

const CRITERIA_EXACT_MATCH: Record<string, Record<string, string>> = {
  audit_log: {
    actor:       'actor',
    action:      'action',
    target_type: 'target_type',
    tenant_id:   'tenant_id',
    trace_id:    'trace_id',
  },
  screening_hits: {
    subject_type:      'subject_type',
    action_taken:      'action_taken',
    screening_context: 'screening_context',
    tenant_id:         'tenant_id',
    wallet_address:    'wallet_address',
  },
  compliance_events: {
    tenant_id:         'tenant_id',
    rule_id:           'rule_id',
    event_type:        'event_type',
    payment_ledger_id: 'payment_ledger_id',
  },
  negotiation_trace_events: {
    tenant_id:         'tenant_id',
    session_id:        'session_id',
    protocol:          'protocol',
    payment_ledger_id: 'payment_ledger_id',
  },
};

export function checkSelectionCriteriaMatch(bundle: AuditBundle, report: CheckReport): void {
  const rows = bundle.rows ?? [];
  const criteria = bundle.selection_criteria ?? {};
  const chainName = bundle.chain_name ?? '';
  const exactMap = CRITERIA_EXACT_MATCH[chainName] ?? {};

  // Find which exact-match filters were set
  const activeFilters: Array<[string, unknown]> = [];
  for (const [criterionKey, rowField] of Object.entries(exactMap)) {
    if (criterionKey in criteria && criteria[criterionKey] !== null && criteria[criterionKey] !== undefined) {
      activeFilters.push([rowField, criteria[criterionKey]]);
    }
  }
  if (activeFilters.length === 0) {
    report.addSkip('selection_criteria_match', 'no exact-match filters set in selection_criteria');
    return;
  }
  if (rows.length === 0) {
    report.addSkip('selection_criteria_match', 'no rows to check');
    return;
  }

  const violations: string[] = [];
  for (const r of rows) {
    for (const [field, expected] of activeFilters) {
      // Negotiation_trace counterparty is a disjunctive filter handled separately;
      // exactMap above does not include it.
      const actual = r[field];
      if (actual !== expected) {
        violations.push(
          `chain_position=${JSON.stringify(r['chain_position'])}: ` +
          `row.${field}=${JSON.stringify(actual)} != criteria.${field}=${JSON.stringify(expected)}`,
        );
        break;  // one violation per row is enough
      }
    }
  }
  if (violations.length > 0) {
    let detail = `${violations.length} of ${rows.length} rows do not match selection_criteria: ${violations.slice(0, 3).join('; ')}`;
    if (violations.length > 3) detail += `; (+${violations.length - 3} more)`;
    report.add('selection_criteria_match', false, detail);
  } else {
    report.add(
      'selection_criteria_match',
      true,
      `${rows.length} rows match ${activeFilters.length} exact-match filter(s)`,
    );
  }
}

// ---------------------------------------------------------------------------
// 5. Off-VM anchor
// ---------------------------------------------------------------------------

export function parseObjectKeyShaPrefix(objectKey: string | undefined): string | null {
  if (!objectKey) return null;
  const basename = objectKey.includes('/') ? objectKey.slice(objectKey.lastIndexOf('/') + 1) : objectKey;
  if (!basename.endsWith('.ndjson')) return null;
  const stem = basename.slice(0, -'.ndjson'.length);
  const dashIdx = stem.lastIndexOf('-');
  if (dashIdx < 0) return null;
  const shaPrefix = stem.slice(dashIdx + 1);
  if (shaPrefix.length !== 16) return null;
  if (!/^[0-9a-f]+$/.test(shaPrefix)) return null;
  return shaPrefix;
}

export async function checkOffVmAnchor(
  bundle: AuditBundle,
  manifestDir: string | null | undefined,
  report: CheckReport,
): Promise<void> {
  const anchor = bundle.off_vm_anchor;
  if (!anchor || !anchor.object_key) {
    report.addSkip(
      'off_vm_anchor',
      'no off_vm_anchor in bundle (chain has not been shipped yet, or bundle is from before shipping started)',
    );
    return;
  }
  if (!manifestDir) {
    report.addSkip(
      'off_vm_anchor',
      `manifestDir not provided -- run \`aws s3api head-object --bucket ${anchor.bucket_name} --key ${anchor.object_key}\` and confirm ObjectLockMode=COMPLIANCE`,
    );
    return;
  }

  const expectedShaPrefix = parseObjectKeyShaPrefix(anchor.object_key);
  if (!expectedShaPrefix) {
    report.add('off_vm_anchor', false, `object_key has no parseable sha256 prefix: ${anchor.object_key}`);
    return;
  }

  // Try to locate the manifest file: by full key path, by basename.
  const candidates = [
    path.join(manifestDir, anchor.object_key),
    path.join(manifestDir, path.basename(anchor.object_key)),
  ];
  let manifestPath: string | null = null;
  for (const c of candidates) {
    try {
      await fs.access(c);
      manifestPath = c;
      break;
    } catch {
      // continue
    }
  }
  if (!manifestPath) {
    report.add(
      'off_vm_anchor',
      false,
      `manifest file not found in ${manifestDir} for object_key=${anchor.object_key}`,
    );
    return;
  }

  // Compute SHA-256 of the file bytes.
  const buf = await fs.readFile(manifestPath);
  const fullSha = createHash('sha256').update(buf).digest('hex');
  if (fullSha.slice(0, 16) !== expectedShaPrefix) {
    report.add(
      'off_vm_anchor',
      false,
      `manifest sha prefix ${fullSha.slice(0, 16)} != object_key prefix ${expectedShaPrefix}`,
    );
    return;
  }

  // Parse last NDJSON line and confirm chain_position + content_hash match bundle.chain_anchor.current_head.
  const text = buf.toString('utf-8');
  const lines = text.split('\n').filter((l) => l.trim().length > 0);
  if (lines.length === 0) {
    report.add('off_vm_anchor', false, 'manifest file is empty');
    return;
  }
  let lastEntry: Record<string, unknown>;
  try {
    lastEntry = JSON.parse(lines[lines.length - 1]!);
  } catch (e) {
    report.add('off_vm_anchor', false, `last NDJSON line is not valid JSON: ${(e as Error).message}`);
    return;
  }
  const head = bundle.chain_anchor?.current_head;
  if (!head) {
    report.add('off_vm_anchor', false, 'bundle.chain_anchor.current_head missing -- cannot cross-check manifest tail');
    return;
  }
  const headPos = head.chain_position;
  const headHash = head.content_hash;
  if (lastEntry['chain_position'] !== headPos) {
    report.add(
      'off_vm_anchor',
      false,
      `manifest tail chain_position=${lastEntry['chain_position']} != bundle chain_anchor.current_head.chain_position=${headPos}`,
    );
    return;
  }
  if (lastEntry['content_hash'] !== headHash) {
    report.add(
      'off_vm_anchor',
      false,
      `manifest tail content_hash=${String(lastEntry['content_hash']).slice(0, 16)}... != bundle chain_anchor.current_head.content_hash=${String(headHash).slice(0, 16)}...`,
    );
    return;
  }

  report.add(
    'off_vm_anchor',
    true,
    `manifest sha verified + tail entry at chain_position=${headPos} matches chain_anchor.current_head`,
  );
}
