import * as vscode from 'vscode';
import * as fs from 'fs';
import { Finding, FindingCategory, Severity } from '../types/finding';
import { ScanContext } from '../types/scanner';
import { SecureScannerConfig } from '../types/config';
import { ScannerRegistry } from './scannerRegistry';
import { CredentialScanner } from '../scanners/credentialScanner';
import { OwaspScanner } from '../scanners/owaspScanner';
import { DependencyScanner } from '../scanners/dependencyScanner';
import { MisconfigScanner } from '../scanners/misconfigScanner';
import { FileHygieneScanner } from '../scanners/fileHygieneScanner';

export class ScannerEngine {
  private registry: ScannerRegistry;
  private _onFindingsChanged = new vscode.EventEmitter<Map<string, Finding[]>>();
  public readonly onFindingsChanged = this._onFindingsChanged.event;
  private findingsMap: Map<string, Finding[]> = new Map();

  private dependencyScanner: DependencyScanner;
  private fileHygieneScanner: FileHygieneScanner;

  constructor() {
    this.registry = new ScannerRegistry();
    this.registry.register(new CredentialScanner());
    this.registry.register(new OwaspScanner());
    this.dependencyScanner = new DependencyScanner();
    this.registry.register(this.dependencyScanner);
    this.registry.register(new MisconfigScanner());
    this.fileHygieneScanner = new FileHygieneScanner();
    this.registry.register(this.fileHygieneScanner);
  }

  loadExternalVulnDb(vulnDbPath: string): void {
    try {
      const data = fs.readFileSync(vulnDbPath, 'utf8');
      const db = JSON.parse(data);
      if (db.npmVulnerabilities && db.pipVulnerabilities) {
        this.dependencyScanner.updateVulnerabilities(
          db.npmVulnerabilities,
          db.pipVulnerabilities
        );
      }
    } catch {
      console.warn('SecureScanner: Could not load external vulnerability database');
    }
  }

  getConfig(): SecureScannerConfig {
    const config = vscode.workspace.getConfiguration('secureScanner');
    const thresholdStr = config.get<string>('severityThreshold', 'Low');
    const severityMap: Record<string, Severity> = {
      'Critical': Severity.Critical,
      'High': Severity.High,
      'Medium': Severity.Medium,
      'Low': Severity.Low,
      'Info': Severity.Info,
    };

    return {
      enableOnSave: config.get<boolean>('enableOnSave', true),
      enableOnOpen: config.get<boolean>('enableOnOpen', true),
      severityThreshold: severityMap[thresholdStr] ?? Severity.Low,
      ignorePaths: config.get<string[]>('ignorePaths', [
        '**/node_modules/**', '**/dist/**', '**/.git/**',
      ]),
      enabledCategories: config.get<FindingCategory[]>('enabledCategories', [
        FindingCategory.Credential,
        FindingCategory.OWASP,
        FindingCategory.Dependency,
        FindingCategory.Misconfiguration,
        FindingCategory.FileHygiene,
      ]),
      maxFileSizeKB: config.get<number>('maxFileSizeKB', 512),
    };
  }

  async scanDocument(document: vscode.TextDocument): Promise<Finding[]> {
    const config = this.getConfig();
    const filePath = document.uri.fsPath;

    // Check file size
    const content = document.getText();
    if (content.length > config.maxFileSizeKB * 1024) {
      return [];
    }

    // Check ignore paths
    for (const pattern of config.ignorePaths) {
      const globPattern = pattern.replace(/\*\*/g, '.*').replace(/\*/g, '[^/\\\\]*');
      if (new RegExp(globPattern).test(filePath.replace(/\\/g, '/'))) {
        return [];
      }
    }

    const context: ScanContext = {
      filePath,
      content,
      languageId: document.languageId,
    };

    const findings: Finding[] = [];
    const scanners = this.registry.getAll();

    for (const scanner of scanners) {
      // Check if category is enabled
      const scannerFindings = await scanner.scan(context);
      const filtered = scannerFindings.filter(f => {
        if (!config.enabledCategories.includes(f.category)) {
          return false;
        }
        if (f.severity > config.severityThreshold) {
          return false;
        }
        return true;
      });
      findings.push(...filtered);
    }

    this.findingsMap.set(filePath, findings);
    this._onFindingsChanged.fire(this.findingsMap);
    return findings;
  }

  async scanWorkspace(): Promise<Finding[]> {
    const allFindings: Finding[] = [];
    const config = this.getConfig();

    const ignorePattern = config.ignorePaths.length > 0
      ? '{' + config.ignorePaths.join(',') + '}'
      : undefined;

    const files = await vscode.workspace.findFiles(
      '**/*',
      ignorePattern,
      5000 // max files
    );

    for (const file of files) {
      try {
        const document = await vscode.workspace.openTextDocument(file);
        const findings = await this.scanDocument(document);
        allFindings.push(...findings);
      } catch {
        // Skip files that can't be opened (binary, etc.)
      }
    }

    // Run workspace-level file hygiene checks (missing files, unignored sensitive files)
    if (config.enabledCategories.includes(FindingCategory.FileHygiene)) {
      const workspaceFolders = vscode.workspace.workspaceFolders;
      if (workspaceFolders) {
        for (const folder of workspaceFolders) {
          const hygieneFindings = await this.fileHygieneScanner.scanWorkspace(folder.uri.fsPath);
          const filtered = hygieneFindings.filter(f => f.severity <= config.severityThreshold);
          allFindings.push(...filtered);

          // Store workspace-level findings under the workspace root path
          const existing = this.findingsMap.get(folder.uri.fsPath) || [];
          this.findingsMap.set(folder.uri.fsPath, [...existing, ...filtered]);
        }
        this._onFindingsChanged.fire(this.findingsMap);
      }
    }

    return allFindings;
  }

  getAllFindings(): Map<string, Finding[]> {
    return new Map(this.findingsMap);
  }

  clearFindings(): void {
    this.findingsMap.clear();
    this._onFindingsChanged.fire(this.findingsMap);
  }

  dispose(): void {
    this._onFindingsChanged.dispose();
  }
}
