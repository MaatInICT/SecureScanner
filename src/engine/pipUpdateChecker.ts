import * as vscode from 'vscode';
import * as https from 'https';
import * as http from 'http';
import * as semver from 'semver';

export interface PipPackageStatus {
  name: string;
  currentVersion: string;
  latestVersion: string;
  updateAvailable: boolean;
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
      res.on('data', (chunk) => body += chunk);
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
 * Check all pip packages in the workspace for available updates.
 */
export async function checkPipUpdates(
  indexUrl: string,
  progress?: vscode.Progress<{ message?: string; increment?: number }>
): Promise<PipPackageStatus[]> {
  const results: PipPackageStatus[] = [];

  // Find all requirements.txt files in the workspace
  const files = await vscode.workspace.findFiles('**/requirements*.txt', '**/node_modules/**', 50);

  const allPackages = new Map<string, string>();

  for (const file of files) {
    try {
      const doc = await vscode.workspace.openTextDocument(file);
      const parsed = parseRequirementsTxt(doc.getText());
      for (const pkg of parsed) {
        // Keep the first version found (or could take the highest)
        if (!allPackages.has(pkg.name.toLowerCase())) {
          allPackages.set(pkg.name.toLowerCase(), pkg.version);
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

  for (const [name, currentVersion] of allPackages) {
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
        });
      }
    }

    processed++;
  }

  // Sort by package name
  results.sort((a, b) => a.name.localeCompare(b.name));

  return results;
}
