import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { Finding, FindingCategory, Severity } from '../types/finding';
import { IScanner, ScanContext } from '../types/scanner';
import {
  gitignoreRequiredPatterns,
  aiignoreRequiredPatterns,
  sensitiveFilePatterns,
} from '../rules/fileHygieneRules';

export class FileHygieneScanner implements IScanner {
  readonly name = 'FileHygieneScanner';

  scan(context: ScanContext): Finding[] {
    const fileName = context.filePath.split(/[/\\]/).pop() || '';

    if (fileName === '.gitignore') {
      return this.scanGitignore(context);
    }
    if (fileName === '.aiignore') {
      return this.scanAiignore(context);
    }

    return [];
  }

  /**
   * Scan the workspace for file hygiene issues that can't be detected
   * from file content alone (missing files, unignored sensitive files).
   * Called separately from the normal per-file scan.
   */
  async scanWorkspace(workspaceRoot: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check if .gitignore exists
    const gitignorePath = path.join(workspaceRoot, '.gitignore');
    if (!fs.existsSync(gitignorePath)) {
      findings.push({
        id: 'FH-100',
        category: FindingCategory.FileHygiene,
        severity: Severity.High,
        title: 'Missing .gitignore file',
        description: 'No .gitignore file found in the workspace root. Without a .gitignore, sensitive files like .env, private keys, and credentials may be accidentally committed to version control.',
        location: {
          filePath: workspaceRoot,
          startLine: 0,
          startColumn: 0,
          endLine: 0,
          endColumn: 0,
        },
        cweId: 'CWE-540',
      });
    }

    // Check if .aiignore exists
    const aiignorePath = path.join(workspaceRoot, '.aiignore');
    if (!fs.existsSync(aiignorePath)) {
      findings.push({
        id: 'FH-101',
        category: FindingCategory.FileHygiene,
        severity: Severity.Medium,
        title: 'Missing .aiignore file',
        description: 'No .aiignore file found in the workspace root. Without an .aiignore, AI tools (Copilot, Claude, etc.) may read sensitive files like .env and private keys. Create an .aiignore to control what AI tools can access.',
        location: {
          filePath: workspaceRoot,
          startLine: 0,
          startColumn: 0,
          endLine: 0,
          endColumn: 0,
        },
        cweId: 'CWE-540',
      });
    }

    // Check for sensitive files that exist but are not gitignored
    const gitignoreContent = fs.existsSync(gitignorePath)
      ? fs.readFileSync(gitignorePath, 'utf8')
      : '';

    for (const sensitiveFile of sensitiveFilePatterns) {
      // Check if the sensitive pattern is covered by .gitignore
      if (this.isPatternCovered(sensitiveFile.glob, gitignoreContent)) {
        continue;
      }

      // Search for matching files in the workspace
      try {
        const files = await vscode.workspace.findFiles(
          sensitiveFile.glob,
          '**/node_modules/**',
          5
        );

        for (const file of files) {
          findings.push({
            id: sensitiveFile.ruleId,
            category: FindingCategory.FileHygiene,
            severity: sensitiveFile.severity,
            title: sensitiveFile.title,
            description: sensitiveFile.description,
            location: {
              filePath: file.fsPath,
              startLine: 0,
              startColumn: 0,
              endLine: 0,
              endColumn: 0,
            },
            cweId: sensitiveFile.cweId,
          });
        }
      } catch {
        // Skip if file search fails
      }
    }

    return findings;
  }

  private scanGitignore(context: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const content = context.content;

    for (const rule of gitignoreRequiredPatterns) {
      if (!this.isPatternCovered(rule.pattern, content)) {
        // Find the best line to report on (end of file or after last entry)
        const lines = content.split('\n');
        const lastNonEmptyLine = this.findLastNonEmptyLine(lines);

        findings.push({
          id: rule.id,
          category: FindingCategory.FileHygiene,
          severity: rule.severity,
          title: rule.title,
          description: rule.description,
          location: {
            filePath: context.filePath,
            startLine: lastNonEmptyLine,
            startColumn: 0,
            endLine: lastNonEmptyLine,
            endColumn: lines[lastNonEmptyLine]?.length || 0,
          },
          cweId: rule.cweId,
        });
      }
    }

    return findings;
  }

  private scanAiignore(context: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const content = context.content;

    for (const rule of aiignoreRequiredPatterns) {
      if (!this.isPatternCovered(rule.pattern, content)) {
        const lines = content.split('\n');
        const lastNonEmptyLine = this.findLastNonEmptyLine(lines);

        findings.push({
          id: rule.id,
          category: FindingCategory.FileHygiene,
          severity: rule.severity,
          title: rule.title,
          description: rule.description,
          location: {
            filePath: context.filePath,
            startLine: lastNonEmptyLine,
            startColumn: 0,
            endLine: lastNonEmptyLine,
            endColumn: lines[lastNonEmptyLine]?.length || 0,
          },
          cweId: rule.cweId,
        });
      }
    }

    return findings;
  }

  /**
   * Check if a sensitive pattern is covered by the ignore file content.
   * Handles common gitignore syntaxes:
   * - Exact match: .env
   * - Wildcard: *.pem
   * - Directory patterns: .env.*
   * - Negation awareness: !.env.example should not count as coverage
   */
  private isPatternCovered(pattern: string, ignoreContent: string): boolean {
    const lines = ignoreContent
      .split('\n')
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#'));

    // Normalize pattern for matching
    const normalizedPattern = pattern
      .replace(/\*\*\//g, '')  // Remove glob prefixes
      .replace(/^\.\//, '');   // Remove relative prefix

    for (const line of lines) {
      // Skip negation lines
      if (line.startsWith('!')) {
        continue;
      }

      const normalizedLine = line.replace(/^\//, '');

      // Direct match
      if (normalizedLine === normalizedPattern) {
        return true;
      }

      // Pattern covers the target via wildcard
      // e.g., "*.pem" covers "*.pem" and ".pem" files
      if (normalizedLine === normalizedPattern) {
        return true;
      }

      // .env pattern: check if .env or .env* or .env.* is present
      if (normalizedPattern === '.env') {
        if (normalizedLine === '.env' || normalizedLine === '.env*' || normalizedLine === '.env.*') {
          return true;
        }
      }

      // .env.* pattern: check if .env.* or .env* covers it
      if (normalizedPattern === '.env.*') {
        if (normalizedLine === '.env.*' || normalizedLine === '.env*') {
          return true;
        }
      }

      // Wildcard extension patterns (*.pem, *.key, etc.)
      if (normalizedPattern.startsWith('*.')) {
        const ext = normalizedPattern.substring(1); // .pem, .key, etc.
        if (normalizedLine === normalizedPattern || normalizedLine === '*' + ext) {
          return true;
        }
      }

      // Check for broader coverage
      // e.g., if gitignore has "*.key", it covers "id_rsa" only if the file ends with .key
      // But "id_rsa" needs an exact match or "id_rsa*" wildcard
      if (normalizedPattern === 'id_rsa') {
        if (normalizedLine === 'id_rsa' || normalizedLine === 'id_rsa*' || normalizedLine === '**/id_rsa') {
          return true;
        }
      }

      // credentials.json and serviceAccountKey.json
      if (normalizedPattern === 'credentials.json' || normalizedPattern === 'serviceAccountKey.json') {
        if (normalizedLine === normalizedPattern || normalizedLine === '**/'+normalizedPattern) {
          return true;
        }
      }

      // .htpasswd
      if (normalizedPattern === '.htpasswd') {
        if (normalizedLine === '.htpasswd' || normalizedLine === '**/.htpasswd') {
          return true;
        }
      }

      // *.keystore covers *.jks too? No, check exact match
      if (normalizedPattern === '*.keystore') {
        if (normalizedLine === '*.keystore' || normalizedLine === '*.jks') {
          return true;
        }
      }

      // *.sqlite covers *.db
      if (normalizedPattern === '*.sqlite') {
        if (normalizedLine === '*.sqlite' || normalizedLine === '*.db') {
          return true;
        }
      }
    }

    return false;
  }

  private findLastNonEmptyLine(lines: string[]): number {
    for (let i = lines.length - 1; i >= 0; i--) {
      if (lines[i].trim().length > 0) {
        return i;
      }
    }
    return 0;
  }
}
