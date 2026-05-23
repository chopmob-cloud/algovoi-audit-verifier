/**
 * Public type surface for the audit-verifier.
 */

export type AuditRow = Record<string, unknown>;

export type FieldExtractor = (row: AuditRow) => Record<string, unknown>;

export interface BundleSignature {
  hex: string;
  algorithm?: string;
  canonicalisation?: string;
  key_id?: string;
}

export interface OffVmAnchor {
  bucket_name?: string;
  object_key?: string;
  region?: string;
  object_lock_until?: string;
}

export interface ChainAnchor {
  current_head?: {
    chain_position?: number;
    content_hash?: string;
  };
}

export interface SelectionCriteria {
  [key: string]: unknown;
  since?: string;
  until?: string;
}

export interface BridgingMeta {
  included?: boolean;
}

export interface AuditBundle {
  chain_format_version?: number;
  chain_name?: string;
  rows?: AuditRow[];
  bridging_rows?: AuditRow[];
  bridging?: BridgingMeta;
  bundle_signature?: BundleSignature | null;
  off_vm_anchor?: OffVmAnchor;
  chain_anchor?: ChainAnchor;
  selection_criteria?: SelectionCriteria;
  [key: string]: unknown;
}

export type CheckResult = 'ok' | 'fail' | 'skip';

export interface CheckEntry {
  name: string;
  passed: boolean | null;  // true=ok, false=fail, null=skip
  detail: string;
}

export interface VerifyBundleOptions {
  signingKey?: string | null;
  manifestDir?: string | null;
}

export interface CheckReportJSON {
  all_passed: boolean;
  fatal: string[];
  checks: CheckEntry[];
}
