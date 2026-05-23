/**
 * CheckReport — aggregates individual check results into a single
 * PASS / FAIL summary. Byte-for-byte equivalent to the Python sibling's
 * CheckReport class.
 */
import type { CheckEntry, CheckReportJSON } from './types.js';

export class CheckReport {
  readonly checks: CheckEntry[] = [];
  readonly fatal: string[] = [];

  add(name: string, passed: boolean, detail = ''): void {
    this.checks.push({ name, passed, detail });
  }

  addSkip(name: string, reason: string): void {
    this.checks.push({ name, passed: null, detail: `skipped: ${reason}` });
  }

  addFatal(msg: string): void {
    this.fatal.push(msg);
  }

  get allPassed(): boolean {
    if (this.fatal.length > 0) return false;
    return this.checks.every((c) => c.passed !== false);
  }

  get hasFatal(): boolean {
    return this.fatal.length > 0;
  }

  toJSON(): CheckReportJSON {
    return {
      all_passed: this.allPassed,
      fatal:      this.fatal.slice(),
      checks:     this.checks.map((c) => ({ ...c })),
    };
  }

  render(): string {
    const lines: string[] = [];
    if (this.fatal.length > 0) {
      lines.push('FATAL:');
      for (const f of this.fatal) lines.push(`  ! ${f}`);
      return lines.join('\n');
    }
    for (const c of this.checks) {
      const mark = c.passed === true ? '  ok' : c.passed === false ? 'FAIL' : 'skip';
      let line = `  [${mark}] ${c.name}`;
      if (c.detail) line += ` -- ${c.detail}`;
      lines.push(line);
    }
    const verdict = this.allPassed ? 'PASS' : 'FAIL';
    lines.push(`\nVerdict: ${verdict}`);
    return lines.join('\n');
  }
}
