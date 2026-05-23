/**
 * @algovoi/audit-verifier
 *
 * TypeScript reference verifier for AlgoVoi selective-disclosure audit
 * bundles. Byte-for-byte parity with the Python sibling
 * algovoi-audit-verifier (PyPI).
 *
 * The hosted version is at https://verify.algovoi.co.uk; the offline /
 * embedded version is this package.
 */

export {
  canonicalize,
  canonicaliseToBytes,
  sha256Hex,
  sha256JcsHex,
} from './canonicalize.js';

export { FIELD_EXTRACTORS, KNOWN_CHAIN_NAMES } from './extractors.js';
export { CheckReport } from './check-report.js';
export {
  checkPerRowContentHash,
  checkContinuity,
  checkBundleSignature,
  checkSelectionCriteriaMatch,
  checkOffVmAnchor,
  parseObjectKeyShaPrefix,
} from './checks.js';
export { verifyBundle, SUPPORTED_CHAIN_FORMAT_VERSIONS } from './verify.js';
export { buildDemoBundle } from './demo.js';

export type {
  AuditBundle,
  AuditRow,
  BundleSignature,
  ChainAnchor,
  CheckEntry,
  CheckReportJSON,
  CheckResult,
  FieldExtractor,
  OffVmAnchor,
  SelectionCriteria,
  VerifyBundleOptions,
} from './types.js';
