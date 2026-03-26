import * as vscode from 'vscode';
import * as https from 'https';
import { VulnerableDependency } from '../rules/dependencyRules';

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { name: string; ecosystem: string };
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
  }>;
  database_specific?: { severity?: string };
}

interface OsvQueryResponse {
  vulns?: OsvVulnerability[];
  next_page_token?: string;
}

const POPULAR_NPM_PACKAGES = [
  'lodash', 'express', 'axios', 'react', 'webpack', 'minimist',
  'node-fetch', 'jsonwebtoken', 'tar', 'shell-quote', 'moment',
  'qs', 'debug', 'semver', 'glob', 'chalk', 'commander',
  'yargs', 'underscore', 'async', 'request', 'body-parser',
  'cookie-parser', 'cors', 'dotenv', 'mongoose', 'sequelize',
  'passport', 'bcrypt', 'helmet', 'morgan', 'multer', 'nodemailer',
  'socket.io', 'uuid', 'validator', 'xml2js', 'cheerio',
  'handlebars', 'pug', 'ejs', 'marked', 'highlight.js',
  'jquery', 'bootstrap', 'angular', 'vue', 'next', 'nuxt',
  'gatsby', 'electron', 'puppeteer', 'sharp', 'jimp',
];

const POPULAR_PIP_PACKAGES = [
  'django', 'flask', 'requests', 'pyyaml', 'pillow', 'cryptography',
  'numpy', 'pandas', 'scipy', 'matplotlib', 'tensorflow', 'torch',
  'jinja2', 'sqlalchemy', 'celery', 'redis', 'boto3', 'paramiko',
  'urllib3', 'certifi', 'setuptools', 'pip', 'wheel', 'aiohttp',
  'fastapi', 'uvicorn', 'gunicorn', 'werkzeug', 'lxml', 'beautifulsoup4',
];

function httpsPost(url: string, data: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
      },
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => body += chunk);
      res.on('end', () => {
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
          resolve(body);
        } else {
          reject(new Error(`HTTP ${res.statusCode}: ${body}`));
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(10000, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
    req.write(data);
    req.end();
  });
}

function mapOsvSeverity(vuln: OsvVulnerability): 'critical' | 'high' | 'medium' | 'low' {
  // Check CVSS score first
  if (vuln.severity) {
    for (const s of vuln.severity) {
      const score = parseFloat(s.score);
      if (!isNaN(score)) {
        if (score >= 9.0) { return 'critical'; }
        if (score >= 7.0) { return 'high'; }
        if (score >= 4.0) { return 'medium'; }
        return 'low';
      }
    }
  }
  // Fallback to database_specific severity
  const dbSeverity = vuln.database_specific?.severity?.toLowerCase();
  if (dbSeverity === 'critical') { return 'critical'; }
  if (dbSeverity === 'high') { return 'high'; }
  if (dbSeverity === 'moderate' || dbSeverity === 'medium') { return 'medium'; }
  if (dbSeverity === 'low') { return 'low'; }
  return 'medium';
}

function parseOsvVulns(vulns: OsvVulnerability[], ecosystem: string): VulnerableDependency[] {
  const results: VulnerableDependency[] = [];

  for (const vuln of vulns) {
    if (!vuln.affected) { continue; }

    for (const affected of vuln.affected) {
      if (!affected.package || affected.package.ecosystem.toLowerCase() !== ecosystem.toLowerCase()) {
        continue;
      }

      let fixedVersion = '';
      let introducedVersion = '0';

      if (affected.ranges) {
        for (const range of affected.ranges) {
          for (const event of range.events) {
            if (event.fixed) { fixedVersion = event.fixed; }
            if (event.introduced) { introducedVersion = event.introduced; }
          }
        }
      }

      if (!fixedVersion) { continue; }

      results.push({
        package: affected.package.name,
        vulnerableRange: `<${fixedVersion}`,
        fixedVersion,
        cve: vuln.id,
        severity: mapOsvSeverity(vuln),
        description: vuln.summary || vuln.details?.substring(0, 200) || 'Security vulnerability',
      });
    }
  }

  return results;
}

async function queryOsv(packageName: string, ecosystem: string): Promise<OsvVulnerability[]> {
  const data = JSON.stringify({
    package: { name: packageName, ecosystem },
  });

  try {
    const response = await httpsPost('https://api.osv.dev/v1/query', data);
    const parsed: OsvQueryResponse = JSON.parse(response);
    return parsed.vulns || [];
  } catch {
    return [];
  }
}

export interface UpdateResult {
  npmCount: number;
  pipCount: number;
  totalVulns: number;
  errors: string[];
}

export async function fetchVulnerabilityUpdates(
  progress?: vscode.Progress<{ message?: string; increment?: number }>
): Promise<{ npm: VulnerableDependency[]; pip: VulnerableDependency[] }> {
  const npmVulns: VulnerableDependency[] = [];
  const pipVulns: VulnerableDependency[] = [];
  const totalPackages = POPULAR_NPM_PACKAGES.length + POPULAR_PIP_PACKAGES.length;
  let processed = 0;

  // Query npm packages
  for (const pkg of POPULAR_NPM_PACKAGES) {
    progress?.report({
      message: `Checking npm: ${pkg}...`,
      increment: (1 / totalPackages) * 100,
    });

    const vulns = await queryOsv(pkg, 'npm');
    npmVulns.push(...parseOsvVulns(vulns, 'npm'));
    processed++;
  }

  // Query pip packages
  for (const pkg of POPULAR_PIP_PACKAGES) {
    progress?.report({
      message: `Checking PyPI: ${pkg}...`,
      increment: (1 / totalPackages) * 100,
    });

    const vulns = await queryOsv(pkg, 'PyPI');
    pipVulns.push(...parseOsvVulns(vulns, 'PyPI'));
    processed++;
  }

  // Deduplicate by package+cve
  const dedup = (arr: VulnerableDependency[]) => {
    const seen = new Set<string>();
    return arr.filter(v => {
      const key = `${v.package}:${v.cve}`;
      if (seen.has(key)) { return false; }
      seen.add(key);
      return true;
    });
  };

  return {
    npm: dedup(npmVulns),
    pip: dedup(pipVulns),
  };
}

export function generateRulesFileContent(
  npm: VulnerableDependency[],
  pip: VulnerableDependency[]
): string {
  const escapeStr = (s: string) => s.replace(/\\/g, '\\\\').replace(/'/g, "\\'");

  let content = `export interface VulnerableDependency {\n`;
  content += `  package: string;\n`;
  content += `  vulnerableRange: string;\n`;
  content += `  fixedVersion: string;\n`;
  content += `  cve: string;\n`;
  content += `  severity: 'critical' | 'high' | 'medium' | 'low';\n`;
  content += `  description: string;\n`;
  content += `}\n\n`;

  content += `// Auto-updated from OSV.dev on ${new Date().toISOString()}\n`;
  content += `// npm vulnerabilities: ${npm.length}\n`;
  content += `// pip vulnerabilities: ${pip.length}\n\n`;

  content += `export const npmVulnerabilities: VulnerableDependency[] = [\n`;
  for (const v of npm) {
    content += `  {\n`;
    content += `    package: '${escapeStr(v.package)}',\n`;
    content += `    vulnerableRange: '${escapeStr(v.vulnerableRange)}',\n`;
    content += `    fixedVersion: '${escapeStr(v.fixedVersion)}',\n`;
    content += `    cve: '${escapeStr(v.cve)}',\n`;
    content += `    severity: '${v.severity}',\n`;
    content += `    description: '${escapeStr(v.description)}',\n`;
    content += `  },\n`;
  }
  content += `];\n\n`;

  content += `export const pipVulnerabilities: VulnerableDependency[] = [\n`;
  for (const v of pip) {
    content += `  {\n`;
    content += `    package: '${escapeStr(v.package)}',\n`;
    content += `    vulnerableRange: '${escapeStr(v.vulnerableRange)}',\n`;
    content += `    fixedVersion: '${escapeStr(v.fixedVersion)}',\n`;
    content += `    cve: '${escapeStr(v.cve)}',\n`;
    content += `    severity: '${v.severity}',\n`;
    content += `    description: '${escapeStr(v.description)}',\n`;
    content += `  },\n`;
  }
  content += `];\n`;

  return content;
}
