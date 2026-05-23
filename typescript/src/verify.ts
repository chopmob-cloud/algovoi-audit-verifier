/**
 * verifyBundle -- run all checks against a parsed bundle, return CheckReport.
 *
 * Behaviour byte-for-byte parity with the Python sibling verify_bundle().
 */
import { CheckReport } from './check-report.js';
import {
  checkPerRowContentHash,
  checkContinuity,
  checkBundleSignature,
  checkSelectionCriteriaMatch,
  checkOffVmAnchor,
} from './checks.js';
import { KNOWN_CHAIN_NAMES } from './extractors.js';
import type { AuditBundle, VerifyBundleOptions } from './types.js';

export const SUPPORTED_CHAIN_FORMAT_VERSIONS = new Set<number>([1]);

export async function verifyBundle(
  bundle: AuditBundle,
  options: VerifyBundleOptions = {},
): Promise<CheckReport> {
  const report = new CheckReport();

  // Version check first.
  const version = bundle.chain_format_version;
  if (version === undefined || version === null) {
    report.addFatal(
      "bundle is missing required field 'chain_format_version' " +
      '-- bundle is malformed or was not emitted by AlgoVoi',
    );
    return report;
  }
  if (!SUPPORTED_CHAIN_FORMAT_VERSIONS.has(version)) {
    const supported = Array.from(SUPPORTED_CHAIN_FORMAT_VERSIONS).sort();
    report.addFatal(
      `bundle.chain_format_version=${JSON.stringify(version)} is not supported by ` +
      `this verifier (supported: ${JSON.stringify(supported)}). ` +
      'Pull a fresh verifier from https://github.com/chopmob-cloud/algovoi-audit-verifier ' +
      '-- running an older verifier against a newer bundle risks a false PASS.',
    );
    return report;
  }

  const chainName = bundle.chain_name;
  if (!chainName || !KNOWN_CHAIN_NAMES.includes(chainName)) {
    report.addFatal(
      `bundle.chain_name='${chainName}' is not recognised ` +
      `(expected one of: ${JSON.stringify(KNOWN_CHAIN_NAMES)})`,
    );
    return report;
  }

  if (!('rows' in bundle)) {
    report.addFatal("bundle is missing required field 'rows'");
    return report;
  }

  checkPerRowContentHash(bundle, report);
  checkContinuity(bundle, report);
  checkSelectionCriteriaMatch(bundle, report);
  checkBundleSignature(bundle, options.signingKey ?? null, report);
  await checkOffVmAnchor(bundle, options.manifestDir ?? null, report);

  return report;
}
