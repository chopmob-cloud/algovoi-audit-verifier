/**
 * Demo bundle generator -- builds a small synthetic signed AlgoVoi audit
 * bundle for testing the verifier.
 *
 * Byte-for-byte equivalent to the Python sibling demo_audit_bundle.py
 * when called with bundle_emitted_at fixed (the Python default uses
 * datetime.now() so timestamps will differ; passing a fixed emittedAt
 * makes the two implementations produce identical bytes for the same
 * row_count + chain_name + signing_key + key_id).
 */
import { createHash, createHmac } from 'node:crypto';
import { canonicaliseToBytes } from './canonicalize.js';
import type { AuditBundle, AuditRow } from './types.js';

export const GENESIS_PREV_HASH = '0'.repeat(64);
export const DEFAULT_KEY = 'demo-key-not-for-production-use';

function pad(n: number, width: number): string {
  return String(n).padStart(width, '0');
}

function sha256OfJcs(obj: unknown): string {
  return createHash('sha256').update(canonicaliseToBytes(obj)).digest('hex');
}

function auditLogRow(chainPosition: number, prevHash: string): AuditRow {
  const canonical: Record<string, unknown> = {
    trace_id:       `00000000-0000-0000-0000-${pad(chainPosition, 12)}`,
    actor:          'demo-admin@example.com',
    action:         'tenant.create',
    target_type:    'tenant',
    target_id:      `tnt-${chainPosition}`,
    tenant_id:      null,
    before_state:   null,
    after_state:    { created: true, seq: chainPosition },
    ip_address:     '203.0.113.7',
    user_agent:     'demo-agent/1.0',
    created_at:     `2026-05-06T20:00:${pad(chainPosition, 2)}+00:00`,
    chain_position: chainPosition,
    prev_hash:      prevHash,
  };
  const contentHash = sha256OfJcs(canonical);
  return { id: chainPosition * 100, content_hash: contentHash, ...canonical };
}

function screeningHitRow(chainPosition: number, prevHash: string): AuditRow {
  const canonical: Record<string, unknown> = {
    screened_at:        `2026-05-06T20:00:${pad(chainPosition, 2)}+00:00`,
    subject_type:       'payer',
    wallet_address:     `0xdemo${String(chainPosition).padStart(36, '0')}`,
    tenant_id:          null,
    payment_ledger_id:  null,
    sanctions_entry_id: chainPosition,
    action_taken:       'flagged',
    screening_context:  'realtime',
    chain_position:     chainPosition,
    prev_hash:          prevHash,
  };
  const contentHash = sha256OfJcs(canonical);
  return { id: chainPosition * 100, content_hash: contentHash, ...canonical };
}

function complianceEventRow(chainPosition: number, prevHash: string): AuditRow {
  const fixedUuid = `11111111-1111-1111-1111-${pad(chainPosition, 12)}`;
  const tenantUuid = `22222222-2222-2222-2222-${pad(chainPosition, 12)}`;
  const ruleUuid = `33333333-3333-3333-3333-${pad(chainPosition, 12)}`;
  const canonical: Record<string, unknown> = {
    id:                     fixedUuid,
    tenant_id:              tenantUuid,
    rule_id:                ruleUuid,
    payment_ledger_id:      null,
    payer_address_snapshot: null,
    review_of_event_id:     null,
    event_type:             'alert',
    metric_value:           '100.0000',
    threshold_value:        '50.0000',
    created_at:             `2026-05-06T20:00:${pad(chainPosition, 2)}+00:00`,
    chain_position:         chainPosition,
    prev_hash:              prevHash,
  };
  const contentHash = sha256OfJcs(canonical);
  return { ...canonical, content_hash: contentHash };
}

function negotiationTraceRow(chainPosition: number, prevHash: string): AuditRow {
  const canonical: Record<string, unknown> = {
    trace_id:          '44444444-4444-4444-4444-444444444444',
    session_id:        null,
    tenant_id:         null,
    counterparty_a:    'did:example:demo_agent_a',
    counterparty_b:    'did:example:demo_agent_b',
    protocol:          'x402',
    message_seq:       chainPosition,
    message_role:      chainPosition === 1 ? 'offer' : 'counter',
    message_payload:   { step: chainPosition, amount: '10000', asset: 'USDC' },
    payment_ledger_id: null,
    created_at:        `2026-05-06T20:00:${pad(chainPosition, 2)}+00:00`,
    chain_position:    chainPosition,
    prev_hash:         prevHash,
  };
  const contentHash = sha256OfJcs(canonical);
  const fixedUuid = `55555555-5555-5555-5555-${pad(chainPosition, 12)}`;
  return { id: fixedUuid, content_hash: contentHash, ...canonical };
}

type ChainBuilder = (chainPosition: number, prevHash: string) => AuditRow;

const CHAIN_BUILDERS: Record<string, ChainBuilder> = {
  audit_log:                auditLogRow,
  screening_hits:           screeningHitRow,
  compliance_events:        complianceEventRow,
  negotiation_trace_events: negotiationTraceRow,
};

const CHAIN_EMPTY_CRITERIA: Record<string, Record<string, unknown>> = {
  audit_log: {
    actor: null, action: null, target_type: null,
    tenant_id: null, trace_id: null, since: null, until: null,
  },
  screening_hits: {
    subject_type: null, action_taken: null, screening_context: null,
    tenant_id: null, wallet_address: null,
    since: null, until: null,
  },
  compliance_events: {
    tenant_id: null, rule_id: null, event_type: null,
    payment_ledger_id: null, since: null, until: null,
  },
  negotiation_trace_events: {
    trace_id: null, tenant_id: null, protocol: null,
    counterparty: null, message_role: null,
    payment_ledger_id: null, since: null, until: null,
  },
};

export interface BuildDemoBundleOptions {
  chainName?: string;
  rowCount?: number;
  signingKey?: string;
  keyId?: string;
  /**
   * Override the bundle_emitted_at timestamp; defaults to current time.
   * Pass a fixed ISO string when you need byte-for-byte determinism (e.g.
   * cross-impl tests against the Python sibling).
   */
  bundleEmittedAt?: string;
}

export function buildDemoBundle(options: BuildDemoBundleOptions = {}): AuditBundle {
  const chainName = options.chainName ?? 'audit_log';
  const rowCount = options.rowCount ?? 3;
  const signingKey = options.signingKey ?? DEFAULT_KEY;
  const keyId = options.keyId ?? 'demo-v1';

  if (rowCount < 1) throw new Error('row_count must be >= 1');
  const builder = CHAIN_BUILDERS[chainName];
  if (!builder) {
    const known = Object.keys(CHAIN_BUILDERS).sort();
    throw new Error(`chain_name '${chainName}' is not recognised. Expected one of: ${JSON.stringify(known)}`);
  }

  const rows: AuditRow[] = [];
  let prev = GENESIS_PREV_HASH;
  for (let pos = 1; pos <= rowCount; pos++) {
    const row = builder(pos, prev);
    rows.push(row);
    prev = row['content_hash'] as string;
  }

  const head = rows[rows.length - 1]!;
  const bundle: AuditBundle = {
    chain_format_version: 1,
    chain_name:           chainName,
    bundle_emitted_at:    options.bundleEmittedAt ?? new Date().toISOString(),
    selection_criteria:   CHAIN_EMPTY_CRITERIA[chainName]!,
    selection: {
      row_count:          rows.length,
      min_chain_position: rows[0]!['chain_position'],
      max_chain_position: head['chain_position'],
      truncated:          false,
      max_rows_cap:       10000,
    },
    rows:          rows,
    bridging_rows: [],
    bridging:      { included: true, row_count: 0, truncated: false } as unknown as AuditBundle['bridging'],
    chain_anchor: {
      chain_name:             chainName,
      genesis_chain_position: 1,
      genesis_prev_hash:      GENESIS_PREV_HASH,
      current_head: {
        chain_position: head['chain_position'] as number,
        content_hash:   head['content_hash']   as string,
      },
    } as unknown as AuditBundle['chain_anchor'],
    off_vm_anchor: null as unknown as AuditBundle['off_vm_anchor'],
    verification_instructions:
      `Demo bundle for chain '${chainName}'. Run the AlgoVoi audit ` +
      `verifier against this file with --signing-key '${signingKey}' to verify.`,
  };

  // Sign: HMAC-SHA256 over JCS canonical of bundle minus signature.
  const inner: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(bundle)) {
    if (k !== 'bundle_signature') inner[k] = v;
  }
  const digest = createHmac('sha256', signingKey).update(canonicaliseToBytes(inner)).digest('hex');
  bundle.bundle_signature = {
    algorithm:        'HMAC-SHA256',
    canonicalisation: 'RFC 8785',
    key_id:           keyId,
    hex:              digest,
  };
  return bundle;
}
