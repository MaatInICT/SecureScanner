# SecureScanner

**By MaatInICT B.V. — Quality Engineering & Identity Expertise**

SecureScanner is a free Visual Studio Code extension that scans your open workspace for security vulnerabilities, hardcoded credentials, insecure coding patterns, and misconfigurations — all without leaving your editor.

## What It Does

SecureScanner analyzes the code in your current workspace and flags potential security issues before you ship. It runs automatically when you open or save files, and can also scan your entire workspace on demand.

### Scanning Categories

| Category | What It Checks |
|----------|---------------|
| **Credentials & Secrets** | Hardcoded API keys (AWS, GitHub, Slack, Stripe, Google), private keys, passwords, JWT tokens, database connection strings |
| **OWASP Top 10** | SQL injection, XSS (innerHTML, document.write), command injection, eval(), insecure deserialization, weak cryptography (MD5/SHA1), CSRF, path traversal |
| **Vulnerable Dependencies** | Known CVEs in npm (package.json) and pip (requirements.txt) packages, with live updates from the OSV.dev database |
| **Misconfigurations** | Wildcard CORS, disabled TLS verification (`verify=False`), debug mode, insecure random (Math.random), empty catch blocks, hardcoded IPs, missing Helmet.js, binding to 0.0.0.0 |
| **File Hygiene** | Missing or incomplete .gitignore and .aiignore files, sensitive files (.env, *.pem, *.key, credentials.json, SSH keys) not excluded from version control or AI tools |

### Features

- **Real-time scanning** — Automatically scans files on open and save
- **Workspace scan** — Scan up to 5,000 files in one go
- **Security Dashboard** — Visual overview with severity cards, filters, and clickable results
- **Sidebar tree view** — Browse findings by category in the VS Code activity bar
- **Hover tooltips** — See finding details, CWE references, and OWASP IDs by hovering over flagged code
- **Quick fixes** — Suppress findings, move secrets to environment variables, replace innerHTML with textContent
- **Pip update checker** — Check installed packages (`pip list`) and requirements.txt for updates against PyPI or a Nexus 3 Repository Manager (auto-detected from URL), with per-package update buttons
- **Comment detection** — Findings inside comments are automatically downgraded to Info severity to reduce false positives
- **CVE database updates** — Fetch the latest vulnerability data from OSV.dev with one click
- **Test environment mode** — Toggle to suppress findings that are common in test environments (e.g. `verify=False`, debug mode)
- **Export reports** — Export findings as a styled HTML report that can be opened in any browser and shared with colleagues (print-friendly for PDF export)

### Supported Languages

JavaScript, TypeScript, Python, Java, PHP, and framework-specific patterns (React, Express, Django, Flask).

## How to Use

1. Install the extension (VSIX or Marketplace)
2. Open any project folder in VS Code
3. SecureScanner starts scanning automatically
4. Click the shield icon in the status bar to open the Security Dashboard
5. Use the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):
   - `SecureScanner: Scan Current File`
   - `SecureScanner: Scan Workspace`
   - `SecureScanner: Open Security Dashboard`

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `secureScanner.enableOnSave` | `true` | Scan files automatically when saved |
| `secureScanner.enableOnOpen` | `true` | Scan files automatically when opened |
| `secureScanner.severityThreshold` | `Low` | Minimum severity level to report |
| `secureScanner.ignorePaths` | `node_modules, dist, .git, out, build` | Glob patterns for paths to ignore |
| `secureScanner.enabledCategories` | All categories | Which scanner categories to enable |
| `secureScanner.pipIndexUrl` | `https://pypi.org/pypi` | Pip package index URL for update checks (use your Nexus/Artifactory URL for internal repos) |
| `secureScanner.isTestEnvironment` | `false` | Suppress findings common in test environments (e.g. `verify=False`, debug mode) |
| `secureScanner.maxFileSizeKB` | `512` | Maximum file size to scan (KB) |

## Disclaimer

SecureScanner is provided free of charge by MaatInICT B.V. on an "as is" basis, without warranties of any kind. Use of this tool is entirely at your own risk. MaatInICT B.V. shall not be held liable for any damages or consequences arising from its use. This tool does not replace professional security audits or penetration testing.

---

&copy; MaatInICT B.V. — Quality Engineering & Identity Expertise
