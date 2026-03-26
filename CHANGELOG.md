# Changelog

All notable changes to SecureScanner will be documented in this file.

## [1.0.3] - 2026-03-26

### Improved
- **.aiignore findings are now conditional** — Rules for missing .aiignore patterns (*.pem, *.key, credentials.json, etc.) now first check if the sensitive files actually exist in the workspace. No files found = no finding. Files found but not in .aiignore = reported as Info so the developer can decide.
- **Comment/docstring-aware scanning** — Matches found inside comments or docstrings (e.g. `verify=False` in a Python docstring) are now reported as Low severity instead of the original severity, with a note that it is not executable code. Supports comment syntax for Python, JavaScript, TypeScript, SQL, Robot Framework, Lua, HTML, and many more languages.
- **Documentation file awareness** — Findings in documentation files (README.md, CHANGELOG.md, .rst, .txt, etc.) are now reported as Info severity, preventing false positives from code examples in documentation.

## [1.0.0] - 2026-03-26

### Changed
- Official v1.0.0 release
- Updated all branding to MaatInICT B.V.
- Added extension icon (SecureScannerLogo.png) for marketplace and sidebar
- Added MIT license
- Added GitHub repository link

## [0.1.2] - 2026-03-26

### Added
- README with full feature overview, usage instructions, and configuration reference
- This changelog

### Changed
- Version bump to 0.1.2

## [0.1.1] - 2026-03-26

### Added
- **File Hygiene Scanner** — New scanning category that checks .gitignore and .aiignore files
  - 10 checks for missing .gitignore patterns (.env, *.pem, *.key, *.p12, *.pfx, *.sqlite, credentials.json, SSH keys, .htpasswd, *.keystore)
  - 5 checks for missing .aiignore patterns (.env, *.pem, *.key, credentials.json, SSH keys)
  - Workspace-level detection of missing .gitignore and .aiignore files
  - Detection of sensitive files that exist but are not gitignored
- **MaatInICT branding** — Logo and company info in the Security Dashboard
- **Disclaimer** — Legal disclaimer in the dashboard footer
- File Hygiene filter option in the dashboard

### Changed
- Publisher updated to MaatInICT
- Dashboard CSP updated to allow logo images

## [0.1.0] - 2026-03-24

### Added
- Initial release
- **Credential Scanner** — 13 rules detecting hardcoded secrets (AWS keys, GitHub tokens, Slack tokens, Stripe keys, JWT, private keys, API keys, database connection strings)
- **OWASP Scanner** — 15 rules covering OWASP Top 10 2021 (SQL injection, XSS, command injection, eval, insecure deserialization, weak cryptography, CSRF, path traversal)
- **Dependency Scanner** — Scans package.json (npm) and requirements.txt (pip) for known vulnerable versions with semver matching
- **Misconfiguration Scanner** — 10 rules for common misconfigurations (wildcard CORS, disabled TLS, debug mode, Math.random, empty catch blocks, hardcoded IPs, missing Helmet.js)
- **Security Dashboard** — Interactive webview with summary cards, filterable findings table, and export functionality
- **CVE Database Updates** — Fetch latest vulnerability data from OSV.dev API
- **Diagnostics Provider** — Inline VS Code diagnostics with CWE references
- **Tree View** — Sidebar panel with findings grouped by category
- **Hover Provider** — Rich markdown tooltips with severity, CWE/OWASP links
- **Code Action Provider** — Quick fixes for suppression, env var migration, and textContent replacement
- **Auto-scanning** — On file open, save, and editor change (300ms debounce)
- **Workspace scanning** — Bulk scan up to 5,000 files
- **JSON report export**
- Configurable severity threshold, ignore paths, enabled categories, and max file size
