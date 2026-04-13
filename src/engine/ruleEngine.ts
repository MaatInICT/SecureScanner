import { Finding, FindingLocation, Severity } from '../types/finding';
import { IScannerRule, ScanContext } from '../types/scanner';

interface CommentRange {
  start: number;
  end: number;
}

/**
 * Return the single-line comment markers for a given language.
 */
function getCommentMarkers(languageId: string): string[] {
  switch (languageId) {
    case 'python':
    case 'ruby':
    case 'shellscript':
    case 'yaml':
    case 'dockerfile':
    case 'perl':
    case 'r':
    case 'powershell':
      return ['#'];
    case 'javascript':
    case 'typescript':
    case 'javascriptreact':
    case 'typescriptreact':
    case 'java':
    case 'c':
    case 'cpp':
    case 'csharp':
    case 'go':
    case 'rust':
    case 'swift':
    case 'kotlin':
    case 'php':
    case 'scss':
    case 'less':
      return ['//'];
    default:
      return ['//', '#'];
  }
}

/**
 * Build a sorted list of character ranges that fall inside comments.
 * Handles single-line (//, #) and multi-line comments.
 */
function buildCommentRanges(content: string, languageId: string, lineOffsets: number[]): CommentRange[] {
  const ranges: CommentRange[] = [];
  const markers = getCommentMarkers(languageId);

  // Single-line comments: for each line, find the first unquoted marker
  for (let i = 0; i < lineOffsets.length; i++) {
    const lineStart = lineOffsets[i];
    const lineEnd = i + 1 < lineOffsets.length ? lineOffsets[i + 1] - 1 : content.length;
    const line = content.substring(lineStart, lineEnd);

    for (const marker of markers) {
      const idx = findUnquotedMarker(line, marker);
      if (idx !== -1) {
        ranges.push({ start: lineStart + idx, end: lineEnd });
        break;
      }
    }
  }

  // Multi-line comments: /* ... */
  let mlMatch: RegExpExecArray | null;
  const mlRegex = /\/\*[\s\S]*?\*\//g;
  while ((mlMatch = mlRegex.exec(content)) !== null) {
    ranges.push({ start: mlMatch.index, end: mlMatch.index + mlMatch[0].length });
  }

  // HTML comments: <!-- ... -->
  const htmlRegex = /<!--[\s\S]*?-->/g;
  while ((mlMatch = htmlRegex.exec(content)) !== null) {
    ranges.push({ start: mlMatch.index, end: mlMatch.index + mlMatch[0].length });
  }

  return ranges;
}

/**
 * Find the first occurrence of a comment marker that is not inside a string literal.
 * Returns -1 if no unquoted marker is found.
 */
function findUnquotedMarker(line: string, marker: string): number {
  let inSingle = false;
  let inDouble = false;
  let inBacktick = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    const prev = i > 0 ? line[i - 1] : '';

    if (prev === '\\') { continue; }

    if (ch === "'" && !inDouble && !inBacktick) { inSingle = !inSingle; continue; }
    if (ch === '"' && !inSingle && !inBacktick) { inDouble = !inDouble; continue; }
    if (ch === '`' && !inSingle && !inDouble) { inBacktick = !inBacktick; continue; }

    if (!inSingle && !inDouble && !inBacktick) {
      if (line.substring(i, i + marker.length) === marker) {
        return i;
      }
    }
  }
  return -1;
}

/**
 * Check whether a character offset falls inside any comment range.
 */
function isInComment(offset: number, commentRanges: CommentRange[]): boolean {
  return commentRanges.some(r => offset >= r.start && offset < r.end);
}

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
  lineOffsets: number[],
  commentRanges: CommentRange[]
): Finding[] {
  const findings: Finding[] = [];

  // Skip rules marked as safe in test environments
  if (context.isTestEnvironment && rule.testEnvironmentSafe) {
    return findings;
  }

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

    // Downgrade severity for matches found inside comments
    const inComment = isInComment(match.index, commentRanges);
    const severity = inComment ? Severity.Info : rule.severity;
    const title = inComment ? `${rule.title} (in comment)` : rule.title;

    findings.push({
      id: rule.id,
      category: rule.category,
      severity,
      title,
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
  const commentRanges = buildCommentRanges(context.content, context.languageId, lineOffsets);
  const findings: Finding[] = [];

  for (const rule of rules) {
    try {
      const ruleFindings = executeRule(rule, context, lineOffsets, commentRanges);
      findings.push(...ruleFindings);
    } catch {
      // Skip rules that error (e.g., invalid regex)
      console.warn(`SecureScanner: Rule ${rule.id} failed on ${context.filePath}`);
    }
  }

  return findings;
}
