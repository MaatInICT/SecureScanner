import * as vscode from 'vscode';
import * as https from 'https';
import * as http from 'http';
import * as semver from 'semver';
import { execFile } from 'child_process';

export interface PipPackageStatus {
  name: string;
  currentVersion: string;
  latestVersion: string;
  updateAvailable: boolean;
  source: 'installed' | 'requirements.txt';
}

/**
 * Fetch the latest version of a pip package from a PyPI-compatible index.
 */
function fetchLatestVersion(packageName: string, indexUrl: string): Promise<string | null> {
  const url = `${indexUrl.replace(/\/+$/, '')}/${encodeURIComponent(packageName)}/json`;

  return new Promise((resolve) => {
    const client = url.startsWith('https') ? https : http;

    const req = client.get(url, (res) => {
      // Follow redirects
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        fetchLatestVersion(packageName, res.headers.location.replace(`/${packageName}/json`, ''))
          .then(resolve);
        return;
      }

      if (res.statusCode !== 200) {
        resolve(null);
        res.resume();
        return;
      }

      let body = '';
      res.on('data', (chunk: string) => body += chunk);
      res.on('end', () => {
        try {
          const data = JSON.parse(body);
          resolve(data.info?.version || null);
        } catch {
          resolve(null);
        }
      });
    });

    req.on('error', () => resolve(null));
    req.setTimeout(10000, () => {
      req.destroy();
      resolve(null);
    });
  });
}

/**
 * Parse requirements.txt content into package name + version pairs.
 */
function parseRequirementsTxt(content: string): Array<{ name: string; version: string }> {
  const packages: Array<{ name: string; version: string }> = [];
  const lines = content.split('\n');

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) { continue; }

    const match = line.match(/^([a-zA-Z0-9_.-]+)\s*(?:==|>=|~=)\s*([0-9][0-9a-zA-Z.*]*)/);
    if (match) {
      packages.push({ name: match[1], version: match[2] });
    }
  }

  return packages;
}

/**
 * Try to get installed packages via `pip list --format=json`.
 * Tries pip, pip3, python -m pip, python3 -m pip in order.
 */
function getInstalledPackages(): Promise<Array<{ name: string; version: string }>> {
  const commands: Array<{ cmd: string; args: string[] }> = [
    { cmd: 'pip', args: ['list', '--format=json'] },
    { cmd: 'pip3', args: ['list', '--format=json'] },
    { cmd: 'python', args: ['-m', 'pip', 'list', '--format=json'] },
    { cmd: 'python3', args: ['-m', 'pip', 'list', '--format=json'] },
  ];

  return tryCommands(commands, 0);
}

function tryCommands(
  commands: Array<{ cmd: string; args: string[] }>,
  index: number
): Promise<Array<{ name: string; version: string }>> {
  if (index >= commands.length) {
    return Promise.resolve([]);
  }

  const { cmd, args } = commands[index];

  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: 30000 }, (error, stdout) => {
      if (error || !stdout) {
        // Try next command
        tryCommands(commands, index + 1).then(resolve);
        return;
      }

      try {
        const parsed = JSON.parse(stdout);
        if (Array.isArray(parsed)) {
          resolve(parsed.map((p: { name: string; version: string }) => ({
            name: p.name,
            version: p.version,
          })));
          return;
        }
      } catch {
        // Parse failed, try next
      }
      tryCommands(commands, index + 1).then(resolve);
    });
  });
}

/**
 * Check all pip packages in the workspace for available updates.
 * Combines packages from pip list (installed) and requirements.txt files.
 */
export async function checkPipUpdates(
  indexUrl: string,
  progress?: vscode.Progress<{ message?: string; increment?: number }>
): Promise<PipPackageStatus[]> {
  const results: PipPackageStatus[] = [];

  // Map of lowercase package name -> { version, source }
  const allPackages = new Map<string, { version: string; source: 'installed' | 'requirements.txt' }>();

  // 1. Try pip list for installed packages
  progress?.report({ message: 'Reading installed packages (pip list)...' });
  const installed = await getInstalledPackages();
  for (const pkg of installed) {
    allPackages.set(pkg.name.toLowerCase(), { version: pkg.version, source: 'installed' });
  }

  // 2. Read requirements.txt files in workspace
  progress?.report({ message: 'Reading requirements.txt files...' });
  const files = await vscode.workspace.findFiles('**/requirements*.txt', '**/node_modules/**', 50);

  for (const file of files) {
    try {
      const doc = await vscode.workspace.openTextDocument(file);
      const parsed = parseRequirementsTxt(doc.getText());
      for (const pkg of parsed) {
        const key = pkg.name.toLowerCase();
        // requirements.txt overrides pip list (more specific to project)
        if (!allPackages.has(key)) {
          allPackages.set(key, { version: pkg.version, source: 'requirements.txt' });
        }
      }
    } catch {
      // Skip files that can't be read
    }
  }

  if (allPackages.size === 0) {
    return results;
  }

  const total = allPackages.size;
  let processed = 0;

  for (const [name, { version: currentVersion, source }] of allPackages) {
    progress?.report({
      message: `Checking ${name}... (${processed + 1}/${total})`,
      increment: (1 / total) * 100,
    });

    const latestVersion = await fetchLatestVersion(name, indexUrl);

    if (latestVersion) {
      const current = semver.coerce(currentVersion);
      const latest = semver.coerce(latestVersion);
      const updateAvailable = current && latest ? semver.lt(current, latest) : false;

      if (updateAvailable) {
        results.push({
          name,
          currentVersion,
          latestVersion,
          updateAvailable: true,
          source,
        });
      }
    }

    processed++;
  }

  // Sort by package name
  results.sort((a, b) => a.name.localeCompare(b.name));

  return results;
}
