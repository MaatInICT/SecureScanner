import { Severity, FindingCategory } from '../types/finding';

export interface IgnorePatternRule {
  id: string;
  pattern: string;
  title: string;
  description: string;
  severity: Severity;
  cweId: string;
  /** Glob pattern(s) to check whether matching files exist in the workspace. */
  fileGlobs?: string[];
}

/**
 * Patterns that MUST be present in .gitignore to prevent accidental commits
 * of sensitive files. Each rule checks for a specific pattern or family of patterns.
 */
export const gitignoreRequiredPatterns: IgnorePatternRule[] = [
  {
    id: 'FH-001',
    pattern: '.env',
    title: 'Missing .env in .gitignore',
    description: 'Environment files (.env) often contain secrets, API keys, and database credentials. Add .env and .env.* to .gitignore to prevent accidental commits.',
    severity: Severity.Critical,
    cweId: 'CWE-540',
  },
  {
    id: 'FH-002',
    pattern: '*.pem',
    title: 'Missing *.pem in .gitignore',
    description: 'PEM certificate/key files may contain private keys. Add *.pem to .gitignore.',
    severity: Severity.High,
    cweId: 'CWE-321',
  },
  {
    id: 'FH-003',
    pattern: '*.key',
    title: 'Missing *.key in .gitignore',
    description: 'Key files may contain private cryptographic keys. Add *.key to .gitignore.',
    severity: Severity.High,
    cweId: 'CWE-321',
  },
  {
    id: 'FH-004',
    pattern: '*.p12',
    title: 'Missing *.p12 in .gitignore',
    description: 'PKCS#12 files contain certificates and private keys. Add *.p12 to .gitignore.',
    severity: Severity.High,
    cweId: 'CWE-321',
  },
  {
    id: 'FH-005',
    pattern: '*.pfx',
    title: 'Missing *.pfx in .gitignore',
    description: 'PFX files contain certificates and private keys. Add *.pfx to .gitignore.',
    severity: Severity.High,
    cweId: 'CWE-321',
  },
  {
    id: 'FH-006',
    pattern: '*.sqlite',
    title: 'Missing database files in .gitignore',
    description: 'SQLite database files may contain sensitive data. Add *.sqlite and *.db to .gitignore.',
    severity: Severity.Medium,
    cweId: 'CWE-540',
  },
  {
    id: 'FH-007',
    pattern: 'credentials.json',
    title: 'Missing credentials.json in .gitignore',
    description: 'Credential files (credentials.json, serviceAccountKey.json) contain secrets. Add them to .gitignore.',
    severity: Severity.Critical,
    cweId: 'CWE-540',
  },
  {
    id: 'FH-008',
    pattern: 'id_rsa',
    title: 'Missing SSH keys in .gitignore',
    description: 'SSH private keys (id_rsa, id_ed25519) should never be committed. Add id_rsa* and id_ed25519* to .gitignore.',
    severity: Severity.Critical,
    cweId: 'CWE-321',
  },
  {
    id: 'FH-009',
    pattern: '.htpasswd',
    title: 'Missing .htpasswd in .gitignore',
    description: '.htpasswd contains hashed passwords for HTTP authentication. Add it to .gitignore.',
    severity: Severity.High,
    cweId: 'CWE-540',
  },
  {
    id: 'FH-010',
    pattern: '*.keystore',
    title: 'Missing keystore files in .gitignore',
    description: 'Java keystore files contain certificates and private keys. Add *.keystore and *.jks to .gitignore.',
    severity: Severity.High,
    cweId: 'CWE-321',
  },
];

/**
 * Patterns that MUST be present in .aiignore to prevent AI tools from reading sensitive files.
 */
export const aiignoreRequiredPatterns: IgnorePatternRule[] = [
  {
    id: 'FH-011',
    pattern: '.env',
    title: 'Missing .env in .aiignore',
    description: 'Environment files (.env) were found in the workspace and are not listed in .aiignore. AI tools may read these files. Consider adding .env and .env.* to .aiignore.',
    severity: Severity.Info,
    cweId: 'CWE-540',
    fileGlobs: ['**/.env', '**/.env.*'],
  },
  {
    id: 'FH-012',
    pattern: '*.pem',
    title: 'Missing *.pem in .aiignore',
    description: 'PEM certificate/key files were found in the workspace and are not listed in .aiignore. AI tools may read these files. Consider adding *.pem to .aiignore.',
    severity: Severity.Info,
    cweId: 'CWE-321',
    fileGlobs: ['**/*.pem'],
  },
  {
    id: 'FH-013',
    pattern: '*.key',
    title: 'Missing *.key in .aiignore',
    description: 'Key files were found in the workspace and are not listed in .aiignore. AI tools may read these files. Consider adding *.key to .aiignore.',
    severity: Severity.Info,
    cweId: 'CWE-321',
    fileGlobs: ['**/*.key'],
  },
  {
    id: 'FH-014',
    pattern: 'credentials.json',
    title: 'Missing credentials.json in .aiignore',
    description: 'Credential files were found in the workspace and are not listed in .aiignore. AI tools may read these files. Consider adding credentials.json to .aiignore.',
    severity: Severity.Info,
    cweId: 'CWE-540',
    fileGlobs: ['**/credentials.json', '**/serviceAccountKey.json'],
  },
  {
    id: 'FH-015',
    pattern: 'id_rsa',
    title: 'Missing SSH keys in .aiignore',
    description: 'SSH private key files were found in the workspace and are not listed in .aiignore. AI tools may read these files. Consider adding id_rsa* to .aiignore.',
    severity: Severity.Info,
    cweId: 'CWE-321',
    fileGlobs: ['**/id_rsa', '**/id_rsa.*', '**/id_ed25519', '**/id_ed25519.*'],
  },
];

/**
 * Sensitive file patterns to detect in the workspace.
 * If these files exist and are NOT covered by .gitignore, flag them.
 */
export const sensitiveFilePatterns: { glob: string; ruleId: string; title: string; description: string; severity: Severity; cweId: string }[] = [
  {
    glob: '**/.env',
    ruleId: 'FH-020',
    title: 'Sensitive .env file not gitignored',
    description: 'An .env file exists in the workspace and is not excluded by .gitignore. This file likely contains secrets and should be gitignored.',
    severity: Severity.Critical,
    cweId: 'CWE-540',
  },
  {
    glob: '**/.env.*',
    ruleId: 'FH-021',
    title: 'Sensitive .env.* file not gitignored',
    description: 'An environment variant file (.env.local, .env.production, etc.) exists and is not excluded by .gitignore.',
    severity: Severity.Critical,
    cweId: 'CWE-540',
  },
  {
    glob: '**/*.pem',
    ruleId: 'FH-022',
    title: 'Certificate/key file not gitignored',
    description: 'A .pem file exists in the workspace and is not excluded by .gitignore. It may contain private keys.',
    severity: Severity.High,
    cweId: 'CWE-321',
  },
  {
    glob: '**/*.key',
    ruleId: 'FH-023',
    title: 'Private key file not gitignored',
    description: 'A .key file exists in the workspace and is not excluded by .gitignore. It likely contains a private key.',
    severity: Severity.High,
    cweId: 'CWE-321',
  },
  {
    glob: '**/id_rsa',
    ruleId: 'FH-024',
    title: 'SSH private key not gitignored',
    description: 'An SSH private key (id_rsa) exists in the workspace and is not excluded by .gitignore.',
    severity: Severity.Critical,
    cweId: 'CWE-321',
  },
  {
    glob: '**/credentials.json',
    ruleId: 'FH-025',
    title: 'Credentials file not gitignored',
    description: 'A credentials.json file exists in the workspace and is not excluded by .gitignore.',
    severity: Severity.Critical,
    cweId: 'CWE-540',
  },
  {
    glob: '**/serviceAccountKey.json',
    ruleId: 'FH-026',
    title: 'Service account key not gitignored',
    description: 'A Google service account key file exists in the workspace and is not excluded by .gitignore.',
    severity: Severity.Critical,
    cweId: 'CWE-540',
  },
  {
    glob: '**/*.sqlite',
    ruleId: 'FH-027',
    title: 'Database file not gitignored',
    description: 'A SQLite database file exists in the workspace and is not excluded by .gitignore. It may contain sensitive data.',
    severity: Severity.Medium,
    cweId: 'CWE-540',
  },
  {
    glob: '**/*.p12',
    ruleId: 'FH-028',
    title: 'PKCS#12 certificate not gitignored',
    description: 'A .p12 certificate file exists in the workspace and is not excluded by .gitignore.',
    severity: Severity.High,
    cweId: 'CWE-321',
  },
  {
    glob: '**/*.pfx',
    ruleId: 'FH-029',
    title: 'PFX certificate not gitignored',
    description: 'A .pfx certificate file exists in the workspace and is not excluded by .gitignore.',
    severity: Severity.High,
    cweId: 'CWE-321',
  },
];
