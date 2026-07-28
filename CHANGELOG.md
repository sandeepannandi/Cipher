# Changelog

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
