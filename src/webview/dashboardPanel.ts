import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { Finding } from '../types/finding';
import { ScannerEngine } from '../engine/scannerEngine';
import { fetchVulnerabilityUpdates } from '../engine/vulnDbUpdater';

export class DashboardPanel {
  public static currentPanel: DashboardPanel | undefined;
  private readonly panel: vscode.WebviewPanel;
  private disposables: vscode.Disposable[] = [];

  private constructor(
    panel: vscode.WebviewPanel,
    private engine: ScannerEngine,
    private extensionUri: vscode.Uri,
    private globalStorageUri: vscode.Uri
  ) {
    this.panel = panel;
    this.panel.webview.html = this.getHtmlContent(extensionUri);

    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);

    this.panel.webview.onDidReceiveMessage(
      message => {
        switch (message.command) {
          case 'navigateToFinding':
            this.navigateToFinding(message.finding);
            break;
          case 'refresh':
            this.refresh();
            break;
          case 'scanWorkspace':
            this.scanWorkspace();
            break;
          case 'scanFile':
            this.scanCurrentFile();
            break;
          case 'exportReport':
            this.exportReport();
            break;
          case 'updateVulnDb':
            this.updateVulnDb();
            break;
        }
      },
      null,
      this.disposables
    );

    this.disposables.push(
      engine.onFindingsChanged(() => this.refresh())
    );

    this.refresh();
  }

  static createOrShow(engine: ScannerEngine, extensionUri: vscode.Uri, globalStorageUri: vscode.Uri): void {
    const column = vscode.window.activeTextEditor
      ? vscode.window.activeTextEditor.viewColumn
      : undefined;

    if (DashboardPanel.currentPanel) {
      DashboardPanel.currentPanel.panel.reveal(column);
      DashboardPanel.currentPanel.refresh();
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      'secureScanner.dashboard',
      'Security Dashboard',
      column || vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      }
    );

    DashboardPanel.currentPanel = new DashboardPanel(panel, engine, extensionUri, globalStorageUri);
  }

  private refresh(): void {
    const findingsMap = this.engine.getAllFindings();
    const allFindings: Finding[] = [];
    for (const findings of findingsMap.values()) {
      allFindings.push(...findings);
    }
    this.panel.webview.postMessage({
      type: 'findings',
      data: allFindings,
    });
  }

  private navigateToFinding(finding: Finding): void {
    const uri = vscode.Uri.file(finding.location.filePath);
    const range = new vscode.Range(
      finding.location.startLine,
      finding.location.startColumn,
      finding.location.endLine,
      finding.location.endColumn
    );
    vscode.window.showTextDocument(uri, { selection: range });
  }

  private async scanWorkspace(): Promise<void> {
    this.panel.webview.postMessage({ type: 'scanStatus', status: 'scanning' });
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: 'SecureScanner: Scanning workspace...',
        cancellable: false,
      },
      async () => {
        const findings = await this.engine.scanWorkspace();
        this.panel.webview.postMessage({ type: 'scanStatus', status: 'done', count: findings.length });
        this.refresh();
      }
    );
  }

  private scanCurrentFile(): void {
    const editor = vscode.window.activeTextEditor;
    if (editor) {
      const findings = this.engine.scanDocument(editor.document);
      this.panel.webview.postMessage({ type: 'scanStatus', status: 'done', count: findings.length });
      this.refresh();
    } else {
      vscode.window.showWarningMessage('SecureScanner: No active file to scan.');
    }
  }

  private async updateVulnDb(): Promise<void> {
    this.panel.webview.postMessage({ type: 'vulnDbStatus', status: 'updating' });

    try {
      const result = await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: 'SecureScanner: Updating vulnerability database...',
          cancellable: false,
        },
        async (progress) => {
          return await fetchVulnerabilityUpdates(progress);
        }
      );

      // Save updated rules to global storage (persists across updates)
      const globalStoragePath = this.globalStorageUri.fsPath;
      const vulnDbPath = path.join(globalStoragePath, 'vulnDb.json');

      const vulnDbData = {
        updatedAt: new Date().toISOString(),
        npmVulnerabilities: result.npm,
        pipVulnerabilities: result.pip,
      };

      // Ensure directory exists
      try { fs.mkdirSync(globalStoragePath, { recursive: true }); } catch { /* exists */ }
      fs.writeFileSync(vulnDbPath, JSON.stringify(vulnDbData, null, 2), 'utf8');

      // Reload the scanner engine with updated data
      this.engine.loadExternalVulnDb(vulnDbPath);

      this.panel.webview.postMessage({
        type: 'vulnDbStatus',
        status: 'done',
        npmCount: result.npm.length,
        pipCount: result.pip.length,
      });

      vscode.window.showInformationMessage(
        `SecureScanner: Vulnerability database updated! Found ${result.npm.length} npm + ${result.pip.length} pip vulnerabilities.`
      );

      // Re-scan workspace with updated rules
      const rescan = await vscode.window.showInformationMessage(
        'Re-scan workspace with updated database?',
        'Yes', 'No'
      );
      if (rescan === 'Yes') {
        this.scanWorkspace();
      }
    } catch (err) {
      this.panel.webview.postMessage({ type: 'vulnDbStatus', status: 'error' });
      vscode.window.showErrorMessage(
        `SecureScanner: Failed to update vulnerability database. ${err instanceof Error ? err.message : 'Check your internet connection.'}`
      );
    }
  }

  private async exportReport(): Promise<void> {
    const findingsMap = this.engine.getAllFindings();
    const allFindings: Finding[] = [];
    for (const findings of findingsMap.values()) {
      allFindings.push(...findings);
    }

    const report = {
      generatedAt: new Date().toISOString(),
      totalFindings: allFindings.length,
      findings: allFindings,
    };

    const uri = await vscode.window.showSaveDialog({
      filters: { 'JSON': ['json'] },
      defaultUri: vscode.Uri.file('security-report.json'),
    });

    if (uri) {
      const content = Buffer.from(JSON.stringify(report, null, 2), 'utf8');
      await vscode.workspace.fs.writeFile(uri, content);
      vscode.window.showInformationMessage(`Report exported to ${uri.fsPath}`);
    }
  }

  private getHtmlContent(extensionUri: vscode.Uri): string {
    const nonce = getNonce();
    const logoUri = this.panel.webview.asWebviewUri(
      vscode.Uri.joinPath(extensionUri, 'media', 'logo.svg')
    );

    return /*html*/ `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${this.panel.webview.cspSource}; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; connect-src https://api.osv.dev;">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Dashboard</title>
  <style nonce="${nonce}">
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: var(--vscode-font-family);
      color: var(--vscode-foreground);
      background: var(--vscode-editor-background);
      padding: 20px;
    }
    .branding-header {
      display: flex;
      align-items: center;
      gap: 16px;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--vscode-panel-border);
    }
    .branding-header img {
      height: 52px;
      width: auto;
    }
    .branding-header .branding-text {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    .branding-header .branding-title {
      font-size: 1.6em;
      font-weight: bold;
    }
    .branding-header .branding-sub {
      font-size: 0.8em;
      opacity: 0.6;
    }
    .disclaimer {
      margin-top: 32px;
      padding: 16px;
      border: 1px solid var(--vscode-panel-border);
      border-radius: 6px;
      background: var(--vscode-editorGroupHeader-tabsBackground);
      font-size: 0.78em;
      line-height: 1.5;
      opacity: 0.75;
    }
    .disclaimer strong { opacity: 1; }
    h1 { font-size: 1.6em; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }
    .summary-cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }
    .card {
      padding: 16px;
      border-radius: 8px;
      text-align: center;
      border: 1px solid var(--vscode-panel-border);
    }
    .card .count { font-size: 2em; font-weight: bold; }
    .card .label { font-size: 0.85em; opacity: 0.8; margin-top: 4px; }
    .card.critical { border-left: 4px solid #f44336; }
    .card.high { border-left: 4px solid #ff9800; }
    .card.medium { border-left: 4px solid #ffc107; }
    .card.low { border-left: 4px solid #2196f3; }
    .card.info { border-left: 4px solid #9e9e9e; }
    .card.total { border-left: 4px solid var(--vscode-focusBorder); }
    .toolbar {
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
      flex-wrap: wrap;
      align-items: center;
    }
    .toolbar select, .toolbar input, .toolbar button {
      padding: 6px 10px;
      background: var(--vscode-input-background);
      color: var(--vscode-input-foreground);
      border: 1px solid var(--vscode-input-border);
      border-radius: 4px;
      font-size: 0.9em;
    }
    .toolbar button {
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
      border: none;
      cursor: pointer;
      font-weight: 500;
    }
    .toolbar button:hover { background: var(--vscode-button-secondaryHoverBackground); }
    .toolbar button.primary-btn {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      font-weight: bold;
      padding: 8px 16px;
      font-size: 0.95em;
    }
    .toolbar button.primary-btn:hover { background: var(--vscode-button-hoverBackground); }
    .toolbar button:disabled { opacity: 0.5; cursor: not-allowed; }
    .scanning-indicator {
      display: none;
      align-items: center;
      gap: 8px;
      color: var(--vscode-descriptionForeground);
      font-style: italic;
    }
    .scanning-indicator.active { display: flex; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9em;
    }
    th {
      text-align: left;
      padding: 8px 12px;
      background: var(--vscode-editorGroupHeader-tabsBackground);
      border-bottom: 2px solid var(--vscode-panel-border);
      cursor: pointer;
      user-select: none;
    }
    th:hover { background: var(--vscode-list-hoverBackground); }
    td {
      padding: 8px 12px;
      border-bottom: 1px solid var(--vscode-panel-border);
    }
    tr:hover { background: var(--vscode-list-hoverBackground); }
    tr.clickable { cursor: pointer; }
    .severity-badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.8em;
      font-weight: bold;
    }
    .severity-badge.critical { background: #f44336; color: white; }
    .severity-badge.high { background: #ff9800; color: white; }
    .severity-badge.medium { background: #ffc107; color: #333; }
    .severity-badge.low { background: #2196f3; color: white; }
    .severity-badge.info { background: #9e9e9e; color: white; }
    .update-btn {
      background: #388e3c !important;
      color: white !important;
      font-weight: bold;
    }
    .update-btn:hover { background: #2e7d32 !important; }
    .update-btn:disabled { background: #666 !important; opacity: 0.6; }
    .empty-state {
      text-align: center;
      padding: 60px 20px;
      opacity: 0.6;
    }
    .empty-state h2 { margin-bottom: 8px; }
  </style>
</head>
<body>
  <div class="branding-header">
    <img src="${logoUri}" alt="MaatInICT" />
    <div class="branding-text">
      <span class="branding-title">&#128737; SecureScanner</span>
      <span class="branding-sub">Powered by MaatInICT &mdash; Quality Engineering &amp; Identity Expertise</span>
    </div>
  </div>
  <h1>Security Dashboard</h1>
  <div class="summary-cards" id="summaryCards"></div>
  <div class="toolbar">
    <select id="filterSeverity">
      <option value="all">All Severities</option>
      <option value="0">Critical</option>
      <option value="1">High</option>
      <option value="2">Medium</option>
      <option value="3">Low</option>
      <option value="4">Info</option>
    </select>
    <select id="filterCategory">
      <option value="all">All Categories</option>
      <option value="credential">Credentials</option>
      <option value="owasp">OWASP</option>
      <option value="dependency">Dependencies</option>
      <option value="misconfiguration">Misconfigurations</option>
      <option value="filehygiene">File Hygiene</option>
    </select>
    <input type="text" id="searchInput" placeholder="Search findings...">
    <button id="scanWorkspaceBtn" class="primary-btn">&#128269; Scan Workspace</button>
    <button id="scanFileBtn">&#128196; Scan Current File</button>
    <button id="refreshBtn">&#8635; Refresh</button>
    <button id="exportBtn">&#128190; Export Report</button>
  </div>
  <div class="toolbar" style="margin-top: -8px; margin-bottom: 16px; border-top: 1px solid var(--vscode-panel-border); padding-top: 8px;">
    <span style="font-size: 0.85em; opacity: 0.7;">Vulnerability Database:</span>
    <span id="vulnDbInfo" style="font-size: 0.85em; opacity: 0.7;">Built-in rules loaded</span>
    <button id="updateVulnDbBtn" class="update-btn">&#127760; Update CVE Database</button>
    <span id="vulnDbStatusText" style="font-size: 0.85em; display: none;"></span>
  </div>
  <div id="content"></div>

  <div class="disclaimer">
    <strong>Disclaimer</strong><br>
    SecureScanner is a free tool provided by <strong>MaatInICT</strong> on an "as is" basis, without warranties or guarantees of any kind, either express or implied.
    This tool is intended to assist in identifying potential security issues in your codebase, but it does not guarantee the detection of all vulnerabilities nor the absence of false positives.
    By using SecureScanner, you acknowledge and agree that:<br><br>
    &bull; You use this tool entirely at your own risk and responsibility.<br>
    &bull; MaatInICT shall not be held liable for any damages, losses, security breaches, or other consequences arising from the use of, or reliance on, this tool.<br>
    &bull; This tool does not replace professional security audits, penetration testing, or expert review.<br>
    &bull; Scan results should be validated and verified by qualified personnel before taking action.<br><br>
    &copy; MaatInICT &mdash; Quality Engineering &amp; Identity Expertise
  </div>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    let allFindings = [];

    const severityNames = ['Critical', 'High', 'Medium', 'Low', 'Info'];
    const severityClasses = ['critical', 'high', 'medium', 'low', 'info'];

    function renderSummary(findings) {
      const cards = document.getElementById('summaryCards');
      const counts = [0, 0, 0, 0, 0];
      findings.forEach(f => counts[f.severity]++);

      let html = '<div class="card total"><div class="count">' + findings.length + '</div><div class="label">Total</div></div>';
      severityNames.forEach((name, i) => {
        html += '<div class="card ' + severityClasses[i] + '"><div class="count">' + counts[i] + '</div><div class="label">' + name + '</div></div>';
      });
      cards.innerHTML = html;
    }

    function renderFindings(findings) {
      const content = document.getElementById('content');

      if (findings.length === 0) {
        content.innerHTML = '<div class="empty-state"><h2>No security issues found</h2><p>Click <strong>"Scan Workspace"</strong> above to scan all files in your project.</p></div>';
        return;
      }

      let html = '<table><thead><tr>';
      html += '<th>Severity</th><th>ID</th><th>Title</th><th>Category</th><th>File</th><th>Line</th>';
      html += '</tr></thead><tbody>';

      findings.forEach((f, idx) => {
        const fileName = f.location.filePath.split(/[\\/\\\\]/).pop();
        html += '<tr class="clickable" data-index="' + idx + '">';
        html += '<td><span class="severity-badge ' + severityClasses[f.severity] + '">' + severityNames[f.severity] + '</span></td>';
        html += '<td>' + f.id + '</td>';
        html += '<td>' + f.title + '</td>';
        html += '<td>' + f.category + '</td>';
        html += '<td>' + fileName + '</td>';
        html += '<td>' + (f.location.startLine + 1) + '</td>';
        html += '</tr>';
      });

      html += '</tbody></table>';
      content.innerHTML = html;

      document.querySelectorAll('tr.clickable').forEach(row => {
        row.addEventListener('click', () => {
          const idx = parseInt(row.getAttribute('data-index'));
          vscode.postMessage({ command: 'navigateToFinding', finding: findings[idx] });
        });
      });
    }

    function applyFilters() {
      const severity = document.getElementById('filterSeverity').value;
      const category = document.getElementById('filterCategory').value;
      const search = document.getElementById('searchInput').value.toLowerCase();

      let filtered = allFindings;
      if (severity !== 'all') {
        filtered = filtered.filter(f => f.severity === parseInt(severity));
      }
      if (category !== 'all') {
        filtered = filtered.filter(f => f.category === category);
      }
      if (search) {
        filtered = filtered.filter(f =>
          f.title.toLowerCase().includes(search) ||
          f.description.toLowerCase().includes(search) ||
          f.id.toLowerCase().includes(search)
        );
      }

      renderFindings(filtered);
    }

    document.getElementById('filterSeverity').addEventListener('change', applyFilters);
    document.getElementById('filterCategory').addEventListener('change', applyFilters);
    document.getElementById('searchInput').addEventListener('input', applyFilters);
    document.getElementById('scanWorkspaceBtn').addEventListener('click', () => {
      document.getElementById('scanWorkspaceBtn').disabled = true;
      document.getElementById('scanWorkspaceBtn').textContent = 'Scanning...';
      vscode.postMessage({ command: 'scanWorkspace' });
    });
    document.getElementById('scanFileBtn').addEventListener('click', () => {
      vscode.postMessage({ command: 'scanFile' });
    });
    document.getElementById('refreshBtn').addEventListener('click', () => {
      vscode.postMessage({ command: 'refresh' });
    });
    document.getElementById('exportBtn').addEventListener('click', () => {
      vscode.postMessage({ command: 'exportReport' });
    });
    document.getElementById('updateVulnDbBtn').addEventListener('click', () => {
      const btn = document.getElementById('updateVulnDbBtn');
      const statusText = document.getElementById('vulnDbStatusText');
      btn.disabled = true;
      btn.textContent = 'Updating...';
      statusText.style.display = 'inline';
      statusText.textContent = 'Fetching latest CVE data from OSV.dev...';
      statusText.style.color = 'var(--vscode-descriptionForeground)';
      vscode.postMessage({ command: 'updateVulnDb' });
    });

    window.addEventListener('message', event => {
      const message = event.data;
      if (message.type === 'findings') {
        allFindings = message.data;
        renderSummary(allFindings);
        applyFilters();
      }
      if (message.type === 'scanStatus') {
        const btn = document.getElementById('scanWorkspaceBtn');
        if (message.status === 'done') {
          btn.disabled = false;
          btn.innerHTML = '&#128269; Scan Workspace';
        }
      }
      if (message.type === 'vulnDbStatus') {
        const btn = document.getElementById('updateVulnDbBtn');
        const statusText = document.getElementById('vulnDbStatusText');
        const infoText = document.getElementById('vulnDbInfo');
        if (message.status === 'done') {
          btn.disabled = false;
          btn.innerHTML = '&#127760; Update CVE Database';
          statusText.style.display = 'inline';
          statusText.textContent = 'Updated successfully!';
          statusText.style.color = '#4caf50';
          infoText.textContent = message.npmCount + ' npm + ' + message.pipCount + ' pip vulnerabilities loaded';
          setTimeout(() => { statusText.style.display = 'none'; }, 5000);
        }
        if (message.status === 'error') {
          btn.disabled = false;
          btn.innerHTML = '&#127760; Update CVE Database';
          statusText.style.display = 'inline';
          statusText.textContent = 'Update failed - check internet connection';
          statusText.style.color = '#f44336';
        }
      }
    });
  </script>
</body>
</html>`;
  }

  private dispose(): void {
    DashboardPanel.currentPanel = undefined;
    this.panel.dispose();
    this.disposables.forEach(d => d.dispose());
  }
}

function getNonce(): string {
  let text = '';
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 32; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}
