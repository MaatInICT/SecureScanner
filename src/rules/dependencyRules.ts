export interface VulnerableDependency {
  package: string;
  vulnerableRange: string; // semver range that is vulnerable
  fixedVersion: string;
  cve: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
}

export const npmVulnerabilities: VulnerableDependency[] = [
  {
    package: 'lodash',
    vulnerableRange: '<4.17.21',
    fixedVersion: '4.17.21',
    cve: 'CVE-2021-23337',
    severity: 'high',
    description: 'Command injection via template function.',
  },
  {
    package: 'minimist',
    vulnerableRange: '<1.2.6',
    fixedVersion: '1.2.6',
    cve: 'CVE-2021-44906',
    severity: 'critical',
    description: 'Prototype pollution vulnerability.',
  },
  {
    package: 'node-fetch',
    vulnerableRange: '<2.6.7',
    fixedVersion: '2.6.7',
    cve: 'CVE-2022-0235',
    severity: 'high',
    description: 'Exposure of sensitive information to unauthorized actor.',
  },
  {
    package: 'axios',
    vulnerableRange: '<1.6.0',
    fixedVersion: '1.6.0',
    cve: 'CVE-2023-45857',
    severity: 'medium',
    description: 'Cross-Site Request Forgery (CSRF) via cookie exposure.',
  },
  {
    package: 'express',
    vulnerableRange: '<4.19.2',
    fixedVersion: '4.19.2',
    cve: 'CVE-2024-29041',
    severity: 'medium',
    description: 'Open redirect vulnerability.',
  },
  {
    package: 'jsonwebtoken',
    vulnerableRange: '<9.0.0',
    fixedVersion: '9.0.0',
    cve: 'CVE-2022-23529',
    severity: 'high',
    description: 'Insecure implementation of key retrieval function.',
  },
  {
    package: 'tar',
    vulnerableRange: '<6.1.9',
    fixedVersion: '6.1.9',
    cve: 'CVE-2021-37712',
    severity: 'high',
    description: 'Arbitrary file creation/overwrite via insufficient symlink protection.',
  },
  {
    package: 'shell-quote',
    vulnerableRange: '<1.7.3',
    fixedVersion: '1.7.3',
    cve: 'CVE-2021-42740',
    severity: 'critical',
    description: 'Command injection via specially crafted arguments.',
  },
  {
    package: 'moment',
    vulnerableRange: '<2.29.4',
    fixedVersion: '2.29.4',
    cve: 'CVE-2022-31129',
    severity: 'high',
    description: 'Path traversal vulnerability in locale file loading.',
  },
  {
    package: 'qs',
    vulnerableRange: '<6.10.3',
    fixedVersion: '6.10.3',
    cve: 'CVE-2022-24999',
    severity: 'high',
    description: 'Prototype pollution via crafted query strings.',
  },
];

export const pipVulnerabilities: VulnerableDependency[] = [
  {
    package: 'django',
    vulnerableRange: '<4.2.8',
    fixedVersion: '4.2.8',
    cve: 'CVE-2023-46695',
    severity: 'medium',
    description: 'Denial of service via large file upload handling.',
  },
  {
    package: 'flask',
    vulnerableRange: '<2.3.2',
    fixedVersion: '2.3.2',
    cve: 'CVE-2023-30861',
    severity: 'high',
    description: 'Session cookie exposure on shared hosts.',
  },
  {
    package: 'requests',
    vulnerableRange: '<2.31.0',
    fixedVersion: '2.31.0',
    cve: 'CVE-2023-32681',
    severity: 'medium',
    description: 'Unintended leak of Proxy-Authorization header.',
  },
  {
    package: 'pyyaml',
    vulnerableRange: '<6.0.1',
    fixedVersion: '6.0.1',
    cve: 'CVE-2020-14343',
    severity: 'critical',
    description: 'Arbitrary code execution via full_load/load function.',
  },
  {
    package: 'pillow',
    vulnerableRange: '<10.0.1',
    fixedVersion: '10.0.1',
    cve: 'CVE-2023-44271',
    severity: 'high',
    description: 'Denial of service via uncontrolled resource consumption.',
  },
  {
    package: 'cryptography',
    vulnerableRange: '<41.0.6',
    fixedVersion: '41.0.6',
    cve: 'CVE-2023-49083',
    severity: 'high',
    description: 'NULL pointer dereference when loading PKCS7 certificates.',
  },
];
