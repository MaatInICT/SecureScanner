import * as vscode from 'vscode';
import * as path from 'path';
import { Finding, FindingCategory, Severity } from '../types/finding';
import { ScannerEngine } from '../engine/scannerEngine';
import { severityToLabel } from '../utils/configManager';

type TreeItem = CategoryNode | FindingNode;

class CategoryNode extends vscode.TreeItem {
  constructor(
    public readonly category: FindingCategory,
    public readonly count: number
  ) {
    super(
      `${categoryLabel(category)} (${count})`,
      vscode.TreeItemCollapsibleState.Expanded
    );
    this.contextValue = 'category';
    this.iconPath = categoryIcon(category);
  }
}

class FindingNode extends vscode.TreeItem {
  constructor(public readonly finding: Finding) {
    super(
      `[${severityToLabel(finding.severity)}] ${finding.title}`,
      vscode.TreeItemCollapsibleState.None
    );

    this.description = `${path.basename(finding.location.filePath)}:${finding.location.startLine + 1}`;
    this.tooltip = finding.description;
    this.contextValue = 'finding';

    this.command = {
      command: 'vscode.open',
      title: 'Go to Finding',
      arguments: [
        vscode.Uri.file(finding.location.filePath),
        {
          selection: new vscode.Range(
            finding.location.startLine,
            finding.location.startColumn,
            finding.location.endLine,
            finding.location.endColumn
          ),
        },
      ],
    };

    this.iconPath = severityIcon(finding.severity);
  }
}

function categoryLabel(category: FindingCategory): string {
  switch (category) {
    case FindingCategory.Credential: return 'Credentials & Secrets';
    case FindingCategory.OWASP: return 'OWASP Top 10';
    case FindingCategory.Dependency: return 'Vulnerable Dependencies';
    case FindingCategory.Misconfiguration: return 'Misconfigurations';
    case FindingCategory.FileHygiene: return 'File Hygiene (.gitignore/.aiignore)';
  }
}

function categoryIcon(category: FindingCategory): vscode.ThemeIcon {
  switch (category) {
    case FindingCategory.Credential: return new vscode.ThemeIcon('key');
    case FindingCategory.OWASP: return new vscode.ThemeIcon('bug');
    case FindingCategory.Dependency: return new vscode.ThemeIcon('package');
    case FindingCategory.Misconfiguration: return new vscode.ThemeIcon('gear');
    case FindingCategory.FileHygiene: return new vscode.ThemeIcon('eye');
  }
}

function severityIcon(severity: Severity): vscode.ThemeIcon {
  switch (severity) {
    case Severity.Critical: return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
    case Severity.High: return new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
    case Severity.Medium: return new vscode.ThemeIcon('warning');
    case Severity.Low: return new vscode.ThemeIcon('info');
    case Severity.Info: return new vscode.ThemeIcon('lightbulb');
  }
}

export class FindingsTreeViewProvider implements vscode.TreeDataProvider<TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<TreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  private disposables: vscode.Disposable[] = [];

  constructor(private engine: ScannerEngine) {
    this.disposables.push(
      engine.onFindingsChanged(() => {
        this._onDidChangeTreeData.fire(undefined);
      })
    );
  }

  getTreeItem(element: TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: TreeItem): TreeItem[] {
    if (!element) {
      // Root level: show categories
      return this.getCategoryNodes();
    }

    if (element instanceof CategoryNode) {
      return this.getFindingsForCategory(element.category);
    }

    return [];
  }

  private getCategoryNodes(): CategoryNode[] {
    const findingsMap = this.engine.getAllFindings();
    const categoryCounts = new Map<FindingCategory, number>();

    for (const findings of findingsMap.values()) {
      for (const finding of findings) {
        const count = categoryCounts.get(finding.category) || 0;
        categoryCounts.set(finding.category, count + 1);
      }
    }

    const nodes: CategoryNode[] = [];
    for (const category of Object.values(FindingCategory)) {
      const count = categoryCounts.get(category) || 0;
      if (count > 0) {
        nodes.push(new CategoryNode(category, count));
      }
    }

    return nodes;
  }

  private getFindingsForCategory(category: FindingCategory): FindingNode[] {
    const findingsMap = this.engine.getAllFindings();
    const nodes: FindingNode[] = [];

    for (const findings of findingsMap.values()) {
      for (const finding of findings) {
        if (finding.category === category) {
          nodes.push(new FindingNode(finding));
        }
      }
    }

    // Sort by severity (most severe first)
    nodes.sort((a, b) => a.finding.severity - b.finding.severity);
    return nodes;
  }

  dispose(): void {
    this._onDidChangeTreeData.dispose();
    this.disposables.forEach(d => d.dispose());
  }
}
