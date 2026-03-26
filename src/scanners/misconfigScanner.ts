import { Finding } from '../types/finding';
import { IScanner, ScanContext } from '../types/scanner';
import { runRules } from '../engine/ruleEngine';
import { misconfigRules } from '../rules/misconfigRules';

/**
 * Pattern to detect version-related context on the same line as a match.
 * Matches variable names, keys, or comments containing version-related words.
 */
const VERSION_CONTEXT_PATTERN = /(?:version|versie|versienummer|version_?number)\b|(?:^|[\s(,=:])v\d/i;

export class MisconfigScanner implements IScanner {
  readonly name = 'MisconfigScanner';

  scan(context: ScanContext): Finding[] {
    const findings = runRules(misconfigRules, context);

    // Post-filter MISC-007 (Hardcoded IP) to exclude version numbers
    return findings.filter(f => {
      if (f.id !== 'MISC-007') {
        return true;
      }
      return !this.isVersionContext(context.content, f.location.startLine);
    });
  }

  /**
   * Check if the line containing the match has version-related context,
   * indicating the matched "IP" is actually a version number.
   */
  private isVersionContext(content: string, lineNumber: number): boolean {
    const lines = content.split('\n');
    if (lineNumber < 0 || lineNumber >= lines.length) {
      return false;
    }
    return VERSION_CONTEXT_PATTERN.test(lines[lineNumber]);
  }
}
