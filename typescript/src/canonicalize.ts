/**
 * Canonicalisation wrapper for the audit verifier.
 *
 * Uses RFC 8785 JCS via the `canonicalize` npm package, byte-for-byte
 * equivalent to the Python `rfc8785` package used by the sibling
 * algovoi-audit-verifier (Python).
 */
import canonicalizeLib from 'canonicalize';
import { createHash } from 'node:crypto';

export function canonicalize(obj: unknown): string {
  const out = canonicalizeLib(obj);
  if (out === undefined) {
    throw new Error('canonicalize returned undefined (input not JCS-canonicalisable)');
  }
  return out;
}

export function canonicaliseToBytes(obj: unknown): Buffer {
  return Buffer.from(canonicalize(obj), 'utf-8');
}

export function sha256Hex(bytes: Buffer | string): string {
  return createHash('sha256').update(bytes).digest('hex');
}

export function sha256JcsHex(obj: unknown): string {
  return sha256Hex(canonicaliseToBytes(obj));
}
