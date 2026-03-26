import * as semver from 'semver';
import { Finding, FindingCategory, Severity } from '../types/finding';
import { IScanner, ScanContext } from '../types/scanner';
import { npmVulnerabilities, pipVulnerabilities, VulnerableDependency } from '../rules/dependencyRules';

export class DependencyScanner implements IScanner {
  readonly name = 'DependencyScanner';
  private currentNpmVulns: VulnerableDependency[] = npmVulnerabilities;
  private currentPipVulns: VulnerableDependency[] = pipVulnerabilities;

  updateVulnerabilities(npm: VulnerableDependency[], pip: VulnerableDependency[]): void {
    this.currentNpmVulns = npm;
    this.currentPipVulns = pip;
  }

  getVulnCounts(): { npm: number; pip: number } {
    return { npm: this.currentNpmVulns.length, pip: this.currentPipVulns.length };
  }

  scan(context: ScanContext): Finding[] {
    const fileName = context.filePath.split(/[/\\]/).pop() || '';

    if (fileName === 'package.json') {
      return this.scanPackageJson(context);
    }
    if (fileName === 'requirements.txt') {
      return this.scanRequirementsTxt(context);
    }

    return [];
  }

  private scanPackageJson(context: ScanContext): Finding[] {
    const findings: Finding[] = [];

    try {
      const pkg = JSON.parse(context.content);
      const allDeps: Record<string, string> = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
      };

      for (const [name, versionRange] of Object.entries(allDeps)) {
        const vuln = this.currentNpmVulns.find(v => v.package === name);
        if (!vuln) {continue;}

        // Try to parse the version; handle ranges like ^1.2.3, ~1.2.3, etc.
        const cleanVersion = semver.minVersion(versionRange);
        if (!cleanVersion) {continue;}

        if (semver.satisfies(cleanVersion, vuln.vulnerableRange)) {
          const location = this.findDependencyLocation(context.content, name);
          findings.push({
            id: `DEP-${vuln.cve}`,
            category: FindingCategory.Dependency,
            severity: this.mapSeverity(vuln.severity),
            title: `Vulnerable dependency: ${name}`,
            description: `${vuln.description} (${vuln.cve}). Update to ${vuln.fixedVersion} or later.`,
            location: {
              filePath: context.filePath,
              ...location,
            },
            cweId: 'CWE-1035',
          });
        }
      }
    } catch {
      // Invalid JSON, skip
    }

    return findings;
  }

  private scanRequirementsTxt(context: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const lines = context.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('#')) {continue;}

      // Parse package==version or package>=version
      const match = line.match(/^([a-zA-Z0-9_-]+)\s*(?:==|>=|<=|~=|!=)\s*([0-9.]+)/);
      if (!match) {continue;}

      const [, pkgName, version] = match;
      const vuln = this.currentPipVulns.find(
        v => v.package.toLowerCase() === pkgName.toLowerCase()
      );
      if (!vuln) {continue;}

      // Simple version comparison for Python packages
      const cleanVersion = semver.coerce(version);
      const vulnRange = semver.coerce(vuln.fixedVersion);

      if (cleanVersion && vulnRange && semver.lt(cleanVersion, vulnRange)) {
        findings.push({
          id: `DEP-${vuln.cve}`,
          category: FindingCategory.Dependency,
          severity: this.mapSeverity(vuln.severity),
          title: `Vulnerable dependency: ${pkgName}`,
          description: `${vuln.description} (${vuln.cve}). Update to ${vuln.fixedVersion} or later.`,
          location: {
            filePath: context.filePath,
            startLine: i,
            startColumn: 0,
            endLine: i,
            endColumn: line.length,
          },
          cweId: 'CWE-1035',
        });
      }
    }

    return findings;
  }

  private findDependencyLocation(
    content: string,
    packageName: string
  ): { startLine: number; startColumn: number; endLine: number; endColumn: number } {
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(`"${packageName}"`)) {
        return {
          startLine: i,
          startColumn: 0,
          endLine: i,
          endColumn: lines[i].length,
        };
      }
    }
    return { startLine: 0, startColumn: 0, endLine: 0, endColumn: 0 };
  }

  private mapSeverity(severity: string): Severity {
    switch (severity) {
      case 'critical': return Severity.Critical;
      case 'high': return Severity.High;
      case 'medium': return Severity.Medium;
      case 'low': return Severity.Low;
      default: return Severity.Info;
    }
  }
}
