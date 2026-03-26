import * as vscode from 'vscode';
import { Severity } from '../types/finding';

export function severityToVscode(severity: Severity): vscode.DiagnosticSeverity {
  switch (severity) {
    case Severity.Critical:
    case Severity.High:
      return vscode.DiagnosticSeverity.Error;
    case Severity.Medium:
      return vscode.DiagnosticSeverity.Warning;
    case Severity.Low:
      return vscode.DiagnosticSeverity.Information;
    case Severity.Info:
      return vscode.DiagnosticSeverity.Hint;
  }
}

export function severityToLabel(severity: Severity): string {
  switch (severity) {
    case Severity.Critical: return 'Critical';
    case Severity.High: return 'High';
    case Severity.Medium: return 'Medium';
    case Severity.Low: return 'Low';
    case Severity.Info: return 'Info';
  }
}

export function severityToIcon(severity: Severity): string {
  switch (severity) {
    case Severity.Critical: return '🔴';
    case Severity.High: return '🟠';
    case Severity.Medium: return '🟡';
    case Severity.Low: return '🔵';
    case Severity.Info: return 'ℹ️';
  }
}
