/**
 * Per-chain canonical-field extractors.
 *
 * Each chain (audit_log / screening_hits / compliance_events /
 * negotiation_trace_events) commits a different set of fields to its
 * content_hash. These functions MUST byte-for-byte match the Python
 * sibling (verify_audit_bundle.py) and the emitter side, otherwise every
 * row will fail verification on the auditor side.
 */
import type { AuditRow, FieldExtractor } from './types.js';

function auditLogCanonicalFields(row: AuditRow): Record<string, unknown> {
  return {
    trace_id:       row.trace_id ?? null,
    actor:          row.actor ?? null,
    action:         row.action ?? null,
    target_type:    row.target_type ?? null,
    target_id:      row.target_id ?? null,
    tenant_id:      row.tenant_id ?? null,
    before_state:   row.before_state ?? null,
    after_state:    row.after_state ?? null,
    ip_address:     row.ip_address ?? null,
    user_agent:     row.user_agent ?? null,
    created_at:     row.created_at ?? null,
    chain_position: row.chain_position ?? null,
    prev_hash:      row.prev_hash ?? null,
  };
}

function screeningHitCanonicalFields(row: AuditRow): Record<string, unknown> {
  return {
    screened_at:        row.screened_at ?? null,
    subject_type:       row.subject_type ?? null,
    wallet_address:     row.wallet_address ?? null,
    tenant_id:          row.tenant_id ?? null,
    payment_ledger_id:  row.payment_ledger_id ?? null,
    sanctions_entry_id: row.sanctions_entry_id ?? null,
    action_taken:       row.action_taken ?? null,
    screening_context:  row.screening_context ?? null,
    chain_position:     row.chain_position ?? null,
    prev_hash:          row.prev_hash ?? null,
  };
}

function complianceEventCanonicalFields(row: AuditRow): Record<string, unknown> {
  return {
    id:                     row.id ?? null,
    tenant_id:              row.tenant_id ?? null,
    rule_id:                row.rule_id ?? null,
    payment_ledger_id:      row.payment_ledger_id ?? null,
    payer_address_snapshot: row.payer_address_snapshot ?? null,
    review_of_event_id:     row.review_of_event_id ?? null,
    event_type:             row.event_type ?? null,
    metric_value:           row.metric_value ?? null,
    threshold_value:        row.threshold_value ?? null,
    created_at:             row.created_at ?? null,
    chain_position:         row.chain_position ?? null,
    prev_hash:              row.prev_hash ?? null,
  };
}

function negotiationTraceCanonicalFields(row: AuditRow): Record<string, unknown> {
  return {
    trace_id:          row.trace_id ?? null,
    session_id:        row.session_id ?? null,
    tenant_id:         row.tenant_id ?? null,
    counterparty_a:    row.counterparty_a ?? null,
    counterparty_b:    row.counterparty_b ?? null,
    protocol:          row.protocol ?? null,
    message_seq:       row.message_seq ?? null,
    message_role:      row.message_role ?? null,
    message_payload:   row.message_payload ?? null,
    payment_ledger_id: row.payment_ledger_id ?? null,
    created_at:        row.created_at ?? null,
    chain_position:    row.chain_position ?? null,
    prev_hash:         row.prev_hash ?? null,
  };
}

export const FIELD_EXTRACTORS: Record<string, FieldExtractor> = {
  audit_log:                auditLogCanonicalFields,
  screening_hits:           screeningHitCanonicalFields,
  compliance_events:        complianceEventCanonicalFields,
  negotiation_trace_events: negotiationTraceCanonicalFields,
};

export const KNOWN_CHAIN_NAMES = Object.keys(FIELD_EXTRACTORS).sort();
