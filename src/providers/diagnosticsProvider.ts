import * as vscode from 'vscode';
import { Finding } from '../types/finding';
import { ScannerEngine } from '../engine/scannerEngine';
import { severityToVscode } from '../utils/configManager';

export class DiagnosticsProvider implements vscode.Disposable {
  private diagnosticCollection: vscode.DiagnosticCollection;
  private disposables: vscode.Disposable[] = [];

  constructor(engine: ScannerEngine) {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('securescanner');

    this.disposables.push(
      engine.onFindingsChanged(findingsMap => {
        this.updateDiagnostics(findingsMap);
      })
    );
  }

  private updateDiagnostics(findingsMap: Map<string, Finding[]>): void {
    this.diagnosticCollection.clear();

    for (const [filePath, findings] of findingsMap) {
      const uri = vscode.Uri.file(filePath);
      const diagnostics = findings.map(finding => this.findingToDiagnostic(finding));
      this.diagnosticCollection.set(uri, diagnostics);
    }
  }

  private findingToDiagnostic(finding: Finding): vscode.Diagnostic {
    const range = new vscode.Range(
      finding.location.startLine,
      finding.location.startColumn,
      finding.location.endLine,
      finding.location.endColumn
    );

    const diagnostic = new vscode.Diagnostic(
      range,
      `${finding.title}: ${finding.description}`,
      severityToVscode(finding.severity)
    );

    diagnostic.source = 'SecureScanner';
    diagnostic.code = finding.id;

    if (finding.cweId) {
      diagnostic.code = {
        value: `${finding.id} (${finding.cweId})`,
        target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${finding.cweId.replace('CWE-', '')}.html`),
      };
    }

    return diagnostic;
  }

  clear(): void {
    this.diagnosticCollection.clear();
  }

  dispose(): void {
    this.diagnosticCollection.dispose();
    this.disposables.forEach(d => d.dispose());
  }
}
