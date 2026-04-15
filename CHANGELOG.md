# Changelog

All notable changes to SecureScanner will be documented in this file.

## [1.1.1] - 2026-04-14

### Changed
- **HTML report export** — Export report is now a styled HTML page instead of raw JSON. The report includes summary cards per severity, category breakdown, and a full findings table with CWE references. Can be opened in any browser and shared directly with colleagues. Print-friendly styling included for PDF export via the browser.

## [1.1.0] - 2026-04-14

### Added
- **Exclude Folders setting** — New setting `secureScanner.excludeFolders` (default: `["results"]`) to skip specific folders during scans. Add folder names like `results` or `management` via VS Code settings (Ctrl+,) and the scanner will automatically exclude them. Prevents false positives from Robot Framework HTML/XML reports and other generated files (e.g. MISC-001 Insecure HTTP URL)

## [1.0.8] - 2026-04-14

### Added
- **Per-package update button** — Each outdated pip package now has an "Update" button that opens a VS Code terminal and runs `pip install --upgrade <package>`
- New "Action" column in the pip package updates table

### Changed
- **Redesigned "Check for Updates" button** — Now uses proper VS Code button styling (matching "Scan Workspace") instead of the previous link-style appearance

## [1.0.7] - 2026-04-14

### Fixed
- **Nexus Repository support for pip update checker** — The pip update checker now correctly queries Nexus 3 Repository Manager search API (`/service/rest/v1/search?format=pypi&name=...`) instead of constructing an invalid PyPI-style URL path
- Automatic detection of Nexus search endpoints vs standard PyPI indexes based on the configured URL
- Pagination support via Nexus `continuationToken` to retrieve all available versions
- Semver-based sorting to reliably determine the latest version from Nexus results

## [1.0.6] - 2026-04-14

### Added
- **Pip package update checker** — Check installed packages (`pip list`) and requirements.txt for available updates against PyPI or a custom Nexus/Artifactory repository
- New `secureScanner.pipIndexUrl` setting (default: `https://pypi.org/pypi`) for configuring internal package indexes
- Dashboard section showing outdated pip packages with current vs latest version
- **Comment detection** — Findings inside code comments are automatically downgraded to Info severity and marked with "(in comment)" to reduce false positives

## [1.0.4] - 2026-04-13

### Added
- **Test Environment toggle** — Dashboard toggle to mark a project as a test environment, suppressing findings that are common in test setups (e.g. `verify=False`, debug mode enabled)
- New `secureScanner.isTestEnvironment` workspace setting
- `testEnvironmentSafe` flag on scanner rules to control which rules are suppressed

### Changed
- Redesigned extension logo — shield with embedded MaatInICT logo (PNG)
- Version bump to 1.0.4

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
- **Report export**
- Configurable severity threshold, ignore paths, enabled categories, and max file size
