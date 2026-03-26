import { Finding, FindingLocation, Severity } from '../types/finding';
import { IScannerRule, ScanContext } from '../types/scanner';

/**
 * Identifies all comment and docstring ranges in a file based on the language.
 * Returns an array of [start, end] character offset pairs.
 */
function buildCommentRanges(content: string, languageId: string): [number, number][] {
  const ranges: [number, number][] = [];

  // Single-line comment tokens per language family
  const singleLineTokens = getSingleLineCommentTokens(languageId);
  // Multi-line comment delimiters per language family
  const multiLineDelimiters = getMultiLineCommentDelimiters(languageId);
  // Docstring delimiters (Python)
  const docstringDelimiters = getDocstringDelimiters(languageId);

  let i = 0;
  while (i < content.length) {
    // Check for string literals first (skip them to avoid false positives)
    if (content[i] === '"' && content[i + 1] !== '"' || content[i] === "'" && content[i + 1] !== "'") {
      // Check it's not a docstring delimiter before skipping as string
      let isDocstring = false;
      for (const delim of docstringDelimiters) {
        if (content.substring(i, i + delim.length) === delim) {
          isDocstring = true;
          break;
        }
      }
      if (!isDocstring) {
        const quote = content[i];
        i++;
        while (i < content.length && content[i] !== quote) {
          if (content[i] === '\\') { i++; } // skip escaped char
          i++;
        }
        i++; // skip closing quote
        continue;
      }
    }

    // Check docstring delimiters (""" or ''') — must check before single-line
    let matchedDocstring = false;
    for (const delim of docstringDelimiters) {
      if (content.substring(i, i + delim.length) === delim) {
        const start = i;
        i += delim.length;
        const endIdx = content.indexOf(delim, i);
        if (endIdx !== -1) {
          i = endIdx + delim.length;
        } else {
          i = content.length;
        }
        ranges.push([start, i]);
        matchedDocstring = true;
        break;
      }
    }
    if (matchedDocstring) { continue; }

    // Check multi-line comment delimiters (/* */, <!-- -->, --[[ ]])
    let matchedMulti = false;
    for (const [open, close] of multiLineDelimiters) {
      if (content.substring(i, i + open.length) === open) {
        const start = i;
        i += open.length;
        const endIdx = content.indexOf(close, i);
        if (endIdx !== -1) {
          i = endIdx + close.length;
        } else {
          i = content.length;
        }
        ranges.push([start, i]);
        matchedMulti = true;
        break;
      }
    }
    if (matchedMulti) { continue; }

    // Check single-line comment tokens (//, #, --, %, ;, ')
    let matchedSingle = false;
    for (const token of singleLineTokens) {
      if (content.substring(i, i + token.length) === token) {
        const start = i;
        const newlineIdx = content.indexOf('\n', i);
        i = newlineIdx !== -1 ? newlineIdx + 1 : content.length;
        ranges.push([start, i]);
        matchedSingle = true;
        break;
      }
    }
    if (matchedSingle) { continue; }

    i++;
  }

  return ranges;
}

function getSingleLineCommentTokens(languageId: string): string[] {
  switch (languageId) {
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
    case 'scala':
    case 'dart':
    case 'groovy':
    case 'php':
      return ['//'];
    case 'python':
    case 'ruby':
    case 'shellscript':
    case 'bash':
    case 'zsh':
    case 'sh':
    case 'perl':
    case 'r':
    case 'yaml':
    case 'yml':
    case 'dockerfile':
    case 'makefile':
    case 'coffeescript':
    case 'powershell':
    case 'robot':
    case 'robotframework':
      return ['#'];
    case 'sql':
    case 'plsql':
    case 'hql':
      return ['--'];
    case 'lua':
      return ['--'];
    case 'matlab':
    case 'latex':
    case 'tex':
    case 'erlang':
      return ['%'];
    case 'vb':
    case 'vba':
    case 'vbscript':
      return ["'"];
    case 'clojure':
    case 'lisp':
    case 'scheme':
    case 'ini':
    case 'properties':
      return [';'];
    default:
      // Support the most common tokens as fallback
      return ['//', '#', '--'];
  }
}

function getMultiLineCommentDelimiters(languageId: string): [string, string][] {
  switch (languageId) {
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
    case 'scala':
    case 'dart':
    case 'groovy':
    case 'php':
    case 'css':
    case 'scss':
    case 'less':
      return [['/*', '*/']];
    case 'sql':
    case 'plsql':
    case 'hql':
      return [['/*', '*/']];
    case 'html':
    case 'xml':
    case 'svg':
    case 'xhtml':
    case 'vue':
    case 'svelte':
      return [['<!--', '-->']];
    case 'lua':
      return [['--[[', ']]']];
    case 'haskell':
      return [['{-', '-}']];
    case 'robot':
    case 'robotframework':
      return [['***Comments***', '***'], ['*** Comments ***', '***']];
    default:
      return [['/*', '*/'], ['<!--', '-->']];
  }
}

function getDocstringDelimiters(languageId: string): string[] {
  switch (languageId) {
    case 'python':
      return ['"""', "'''"];
    default:
      return [];
  }
}

/**
 * Check if a file is a documentation file based on its extension or name.
 */
const DOCUMENTATION_EXTENSIONS = ['.md', '.rst', '.txt', '.adoc', '.asciidoc', '.rdoc', '.wiki', '.tex', '.rtf'];
const DOCUMENTATION_NAMES = ['readme', 'changelog', 'contributing', 'license', 'authors', 'history', 'news', 'todo', 'faq'];

function isDocumentationFile(filePath: string): boolean {
  const fileName = filePath.split(/[/\\]/).pop()?.toLowerCase() || '';
  const ext = fileName.substring(fileName.lastIndexOf('.'));

  if (DOCUMENTATION_EXTENSIONS.includes(ext)) {
    return true;
  }

  // Check common documentation filenames without extension (e.g. README, LICENSE)
  const baseName = fileName.replace(/\.[^.]+$/, '');
  return DOCUMENTATION_NAMES.includes(baseName);
}

/**
 * Check if a character offset falls within any of the comment/docstring ranges.
 */
function isInComment(offset: number, commentRanges: [number, number][]): boolean {
  for (const [start, end] of commentRanges) {
    if (offset >= start && offset < end) {
      return true;
    }
    if (start > offset) {
      break; // ranges are ordered, no need to check further
    }
  }
  return false;
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
  commentRanges: [number, number][]
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

    // Lower severity for matches in documentation files, comments, or docstrings
    const inDocFile = isDocumentationFile(context.filePath);
    const inComment = !inDocFile && isInComment(match.index, commentRanges);
    let severity = rule.severity;
    let title = rule.title;
    let description = rule.description;

    if (inDocFile) {
      severity = Severity.Info;
      title = `${rule.title} (in documentation)`;
      description = `${rule.description} Note: this match was found in a documentation file, not in executable code.`;
    } else if (inComment) {
      severity = Severity.Low;
      title = `${rule.title} (in comment/docstring)`;
      description = `${rule.description} Note: this match was found in a comment or docstring, not in executable code.`;
    }

    findings.push({
      id: rule.id,
      category: rule.category,
      severity,
      title,
      description,
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
  const commentRanges = buildCommentRanges(context.content, context.languageId);
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
