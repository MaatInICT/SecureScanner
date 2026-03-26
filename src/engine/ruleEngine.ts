import { Finding, FindingLocation } from '../types/finding';
import { IScannerRule, ScanContext } from '../types/scanner';

/**
 * Build a line offset index for fast offset-to-line/column conversion.
 * Returns an array where index i is the character offset where line i starts.
 */
function buildLineOffsets(content: string): number[] {
  const offsets: number[] = [0];
  for (let i = 0; i < content.length; i++) {
    if (content[i] === '\n') {
      offsets.push(i + 1);
    }
  }
  return offsets;
}

/**
 * Convert a character offset to a line and column number (0-based).
 */
function offsetToPosition(offset: number, lineOffsets: number[]): { line: number; column: number } {
  let low = 0;
  let high = lineOffsets.length - 1;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if (lineOffsets[mid] <= offset) {
      low = mid;
    } else {
      high = mid - 1;
    }
  }
  return { line: low, column: offset - lineOffsets[low] };
}

/**
 * Execute a single rule against file content with a timeout guard.
 */
function executeRule(
  rule: IScannerRule,
  context: ScanContext,
  lineOffsets: number[]
): Finding[] {
  const findings: Finding[] = [];

  // Check language filter
  if (rule.languages && rule.languages.length > 0) {
    if (!rule.languages.includes(context.languageId)) {
      return findings;
    }
  }

  // Check file pattern filter
  if (rule.filePatterns && rule.filePatterns.length > 0) {
    const fileName = context.filePath.split(/[/\\]/).pop() || '';
    const matches = rule.filePatterns.some(pattern => {
      if (pattern.includes('*')) {
        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
        return regex.test(fileName);
      }
      return fileName === pattern;
    });
    if (!matches) {
      return findings;
    }
  }

  // Ensure global flag is set for iteration
  const flags = rule.pattern.flags.includes('g')
    ? rule.pattern.flags
    : rule.pattern.flags + 'g';
  const regex = new RegExp(rule.pattern.source, flags);

  const startTime = Date.now();
  const TIMEOUT_MS = 200;

  let match: RegExpExecArray | null;
  while ((match = regex.exec(context.content)) !== null) {
    // Timeout guard against catastrophic backtracking
    if (Date.now() - startTime > TIMEOUT_MS) {
      break;
    }

    const start = offsetToPosition(match.index, lineOffsets);
    const end = offsetToPosition(match.index + match[0].length, lineOffsets);

    const location: FindingLocation = {
      filePath: context.filePath,
      startLine: start.line,
      startColumn: start.column,
      endLine: end.line,
      endColumn: end.column,
    };

    // Redact matched text for credential findings
    let matchedText = match[0];
    if (rule.category === 'credential' && matchedText.length > 8) {
      matchedText = matchedText.substring(0, 4) + '****' + matchedText.substring(matchedText.length - 4);
    }

    findings.push({
      id: rule.id,
      category: rule.category,
      severity: rule.severity,
      title: rule.title,
      description: rule.description,
      location,
      matchedText,
      cweId: rule.cweId,
      owaspId: rule.owaspId,
    });

    // Prevent infinite loops on zero-length matches
    if (match[0].length === 0) {
      regex.lastIndex++;
    }
  }

  return findings;
}

/**
 * Run all provided rules against a scan context and return findings.
 */
export function runRules(rules: IScannerRule[], context: ScanContext): Finding[] {
  const lineOffsets = buildLineOffsets(context.content);
  const findings: Finding[] = [];

  for (const rule of rules) {
    try {
      const ruleFindings = executeRule(rule, context, lineOffsets);
      findings.push(...ruleFindings);
    } catch {
      // Skip rules that error (e.g., invalid regex)
      console.warn(`SecureScanner: Rule ${rule.id} failed on ${context.filePath}`);
    }
  }

  return findings;
}
