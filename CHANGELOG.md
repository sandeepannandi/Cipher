# Changelog

## [Unreleased]

### Added

- **`cipher-ai pr --diff`** — Diff-aware PR reviews: fetches the PR's changed files, only reports findings on lines the PR introduces, and posts **inline comments** on those lines via the GitHub reviews API
- **`cipher-ai watch`** — Continuous monitoring: scans on an interval, persists a findings fingerprint to `.cipher-ai/watch-state.json`, and reports what is **new** since the last scan; `--pr` auto-fixes new findings and opens a GitHub PR; `--once` for cron/CI
- **`.github/workflows/security-watch.yml`** — Nightly scheduled watch that auto-opens a fix PR for new high+ findings
- **`cipher-ai attack --flow`** — Attach real cross-file data-flow evidence to attack chains via the taint engine (proves chains are exploitable, boosts risk when a path is confirmed)
- **`cipher-ai fix --pr`** — Apply fixes, create a branch, push, and open a GitHub PR with a per-fix summary (repo auto-detected from `--repo`, `GITHUB_REPOSITORY`, or git remote)
- **`cipher-ai report --format html`** — Self-contained browser-ready HTML dashboard (security score, severity bars, findings table with CWE/OWASP/usage, print-to-PDF styles)
- **Dependency reachability** — `deps` now finds where each vulnerable package is actually imported in source and boosts exploitability for used packages (lockfile-only packages get discounted)
- **`Finding.usage`** — New serde-backward-compatible field recording where a vulnerable dependency is used in source

### Changed

- **TUI**: New `/attack --flow`, `/fix --pr`, `/report --format html`, `/pr --diff`, and `/watch` commands in help, palette, and input suggestions
- **`pr` workflow** (`.github/workflows/pr-review.yml`): now runs with `--diff` for focused, line-accurate reviews
- **README**: Documented the new `--flow`, `--pr`, `--format html`, `--diff`, and `watch` flags

## [1.0.0] — 2026-07-30

### Added

- **`cipher-ai zeroday`** — 3-layer zero-day vulnerability detection (anomaly detection, taint flow analysis, AI hunter)
- **`cipher-ai sbom`** — CycloneDX/SPDX Software Bill of Materials generation (7 manifest parsers)
- **`cipher-ai report`** — Comprehensive security report (developer/executive/CI modes, terminal/markdown/json)
- **`cipher-ai config`** — Configuration management (API key, default model, settings)
- **`cipher-ai completions`** — Shell completions for bash, zsh, fish, and PowerShell
- **`cipher-ai ci --format json`** — CI pipeline JSON output for easy ingestion
- **`cipher-ai ci --output`** — Write CI results to file
- **`cipher-ai review --format json/sarif`** — SARIF and JSON output for `review`
- **`cipher-ai review --output`** — Write review output to file
- **`cipher-ai zeroday --format json/sarif`** — Zero-day SARIF/JSON output
- **`cipher-ai zeroday --output`** — Write zero-day output to file
- **`cipher-ai zeroday --anomaly-only`** — Only run anomaly detection layer
- **`cipher-ai zeroday --no-flow`** — Skip taint flow analysis
- **`cipher-ai zeroday --ai`** — AI-powered zero-day hunting
- **`src/output.rs`** — Unified styled output system with box-drawn headers, summary boxes, step progress, risk distribution bars
- 4 new manifest parsers: `go.mod`, `Gemfile`, `composer.json`, `pubspec.yaml`
- **60 integration tests** covering scan, zeroday, deps, and sbom modules

### Changed

- **`ci` command**: Now runs **5 scans** (review → secrets → deps → zeroday → attack) + SBOM info
- **`status` command**: Enhanced with language breakdown, API key masking, Dockerfile check, available commands
- **`zeroday --anomaly-only`**: Fixed description (previously said the opposite of what it did)
- **`ci.rs`/`zeroday.rs`**: Now use unified `output::` helpers for systematic, beautiful output
- **TUI**: Updated command lists with new ci/zeroday/sbom flags
- **Cross-platform**: Dockerfile, `.cargo/config.toml` for Windows MSVC/GNU targets

### Refined

- Extracted `collect_zeroday_findings()` for reusable scanning without output side effects
- Added `collect_attack_summary()` and `collect_sbom_summary()` helpers for ci integration
- Removed dead code (`parse_severity_level`) and unused imports across 9 files
- Fixed duplicate `is_supported_ext` function in zeroday.rs
- Comments removed from test files for cleaner code

## [0.1.1] — 2026-07-28

### Fixed

- **Reduced false positives in `review` command** — Tightened regex patterns across all vulnerability categories:
  - SSTI no longer flags every line (removed broken `.*$|\bf` suffix)
  - Removed `JSON.parse` from insecure deserialization (safe in JavaScript)
  - Removed `serde_json::from_str` from insecure deserialization (safe in Rust)
  - Narrowed command injection to real shell exec patterns (removed broad `\beval\b`)
  - Path traversal now requires actual variable interpolation
  - Hardcoded credentials only flag actual string literals, not function calls
  - Sensitive data in logging requires keyword inside the log function's parentheses
  - SSL/TLS verification pattern no longer matches the word "insecure" alone
  - Many other patterns tightened

### Added

- **`cipher-ai review --max-findings N`** — Limit output to top N findings (default: 30, use 0 for no limit)
- **`cipher-ai review --min-severity <level>`** — Filter by minimum severity (critical, high, medium, low)
- **`cipher-ai review --min-confidence <level>`** — Filter by minimum confidence (high, medium, low)
- Output now shows count of filtered-out findings when limits are applied

## [0.1.0] — 2026-07-26

### Added

- **`cipher-ai init`** — Index codebases with git-aware file walking, smart code chunking, and TF‑IDF indexing. Supports 30+ programming languages.
- **`cipher-ai ask`** — Ask security questions answered by Groq AI with relevant code context retrieved from the index.
- **`cipher-ai secrets`** — Scan for 25+ secret patterns (API keys, tokens, credentials) with severity classification and JSON output.
- **`cipher-ai status`** — Display index health, file counts, language distribution, and API key status.
- Groq API integration with configurable model selection.
- Local `.cipher-ai/` storage with persistent config and index.
- `.env` file support and config file fallback for API keys.
- Annotated CLI output with progress spinners and severity badges.
- Binary-file detection to skip non-text files during secret scanning.

### Security

- Secrets scanner skips binary files, lock files, and dependency directories.
- API key stored locally in `.cipher-ai/config.json` with explicit user consent.
- Git-aware walking respects `.gitignore` to avoid indexing generated files.
