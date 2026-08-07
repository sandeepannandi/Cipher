# Changelog

## [Unreleased]

### Fixed

- **TUI `postinstall.js` release version** — binary download version is now derived from `tui/package.json` (was hardcoded to the stale `v0.1.0`, which had no matching release assets), so `npm install` fetches a real binary and stays in sync with future releases
- **CI cross-compile error `can't find crate for core` / `x86_64-pc-windows-gnu target may not be installed`** — `.cargo/config.toml` no longer forces a global `[build] target = "x86_64-pc-windows-gnu"`; `pr-review` and `security-watch` workflows now build with an explicit `--target x86_64-unknown-linux-gnu`. Local Windows-without-MSVC builds can opt in via `cargo build --target x86_64-pc-windows-gnu` or `CARGO_BUILD_TARGET`
- **`cipher-ai report --format html`** — HTML reports now always export to a file (default `cipher-ai-report.html`, or `--output <path>`) instead of dumping raw HTML to stdout; updated CLI help text and TUI descriptions to match

### Added

- **`cipher-ai pr --diff`** — Diff-aware PR reviews: fetches the PR's changed files, only reports findings on lines the PR introduces, and posts **inline comments** on those lines via the GitHub reviews API
- **`cipher-ai watch`** — Continuous monitoring: scans on an interval, persists a findings fingerprint to `.cipher-ai/watch-state.json`, and reports what is **new** since the last scan; `--pr` auto-fixes new findings and opens a GitHub PR; `--once` for cron/CI
- **`.github/workflows/security-watch.yml`** — Nightly scheduled watch that auto-opens a fix PR for new high+ findings
- **`cipher-ai attack --flow`** — Attach real cross-file data-flow evidence to attack chains via the taint engine (proves chains are exploitable, boosts risk when a path is confirmed)
- **`cipher-ai fix --pr`** — Apply fixes, create a branch, push, and open a GitHub PR with a per-fix summary (repo auto-detected from `--repo`, `GITHUB_REPOSITORY`, or git remote)
- **`cipher-ai report --format html`** — Self-contained browser-ready HTML dashboard (security score, severity bars, findings table with CWE/OWASP/usage, print-to-PDF styles)
- **Dependency reachability** — `deps` now finds where each vulnerable package is actually imported in source and boosts exploitability for used packages (lockfile-only packages get discounted)
- **`Finding.usage`** — New serde-backward-compatible field recording where a vulnerable dependency is used in source
- **Multi-provider AI client** — `cipher-ai config set provider openai|anthropic` + per-provider API keys; `CIPHER_AI_PROVIDER` / `CIPHER_AI_MODEL` / `CIPHER_AI_BASE_URL` overrides; every AI command honors the active provider
- **Agent tool-calling protocol** — provider-agnostic `agent_turn` contract in `src/llm.rs` (`ToolSchema`, `AgentTurn`, `AgentSummary`, structured `AgentTurnError` + `recovery_message` retry loop) that powers the pentester
- **`cipher-ai pentest`** — Phase 1 of the autonomous AI security engineer (`src/pentest/`): a provider-agnostic agent loop that maps the codebase (`list_files`, `get_project_map`, `find_entry_points`), investigates with `search_code`, `read_file`, `semantic_search`, `trace_taint`, and consumes scanner output as hypotheses (`get_scanner_findings`), then reports evidence-backed findings with severity + CWE mapping. `--json` / `--output` / `--max-turns` / `--target-dir` flags. Full plan in `docs/PENTESTER-PLAN.md`
- **Pentest recon (Phase 2)** — framework-aware attack-surface mapping in `src/pentest/recon.rs`: extracts HTTP endpoints with method/path/handler/file:line and per-route auth detection for 10 frameworks (FastAPI, Flask, Express, NestJS, Rails, gin, Spring, Laravel, axum, actix); detects project-wide auth mechanisms (JWT / session cookies / API keys / OAuth), auth middleware names, and likely secret env vars; new `map_attack_surface` agent tool + recon-backed `find_entry_points`
- **Pentest live HTTP tools (Phase 3)** — `cipher-ai pentest --url <target>` arms the agent with a shared session layer (`src/pentest/http.rs`: cookie jar persisted across tools, redirect/no-redirect clients, `CIPHER_AI_PROXY` + `CIPHER_AI_INSECURE=1`, evidence capture with sensitive header + URL-query redaction) and six live tools: `http_request`, `analyze_page` (scraper-based forms/links/tech fingerprint), `login` (form login reusing hidden/CSRF fields, captures session cookie), `generate_totp` (RFC 6238 HMAC-SHA1), `run_command` (`src/pentest/shell.rs` — Docker sandbox: repo mounted read-only, capabilities dropped, memory/pids caps; refuses with clear instructions when Docker is absent; no host execution), and `exploit`. Live-target guidance injected into the agent system prompt
- **Pentest exploit engine (Phase 3 complete — proof-by-exploitation)** — `src/pentest/exploit.rs` + `exploit` tool: deterministic PoC validators for SQL injection (error/boolean/time-based), reflected XSS, SSRF (out-of-band callback listener + `file://` read), command injection (output/time-based), IDOR (object enumeration), session-cookie hardening (HttpOnly/Secure/SameSite), and path traversal (`..` file read). Validators run against the live target through the shared session/cookie jar and return **only proven findings** with reproducible evidence ("no exploit, no report"); the callback accept races the request via `tokio::select!` so slow targets can never deadlock the probe. `Set-Cookie` redaction now preserves security flags so the auth validator can assess them. Unit tests spin up a deliberately vulnerable `tiny_http` target exercising all 7 bug classes, plus a clean-target false-positive suite
- **Pentest live-mode CLI + TUI surfacing** — `pentest --url` help and the command docs now list the `exploit` tool and describe live attack mode; TUI help, palette, and input suggestions add `/pentest --url http://localhost:8080` live-mode examples
- **Pentest multi-agent orchestration (Phase 5)** — `src/pentest/orchestrator.rs`: Shannon-style parallelization of the live pentest. A **deterministic planner** classifies the recon attack-surface map into up to N focused missions (bug class + endpoints); a **guided exploit sweep** discovers live targets (index-page forms, same-origin links, recon routes) and probes them with the deterministic validators — proof-only, no LLM; then up to N **specialist sub-agents** run concurrently over the shared session (same cookie jar), each an `AgentLoop` with a focused objective and mission-labeled progress. Guided proofs + sub-agent findings are merged into the unified `Finding` model, deduplicated, and ranked by `risk_score()`. New `--sub-agents N` flag (default 4, max 8); `pentest --url` now runs the orchestrator; `--json` output gains `sub_agents` / `guided_proofs` fields; the `TurnEngine` gains an `Arc` blanket impl so one engine is shared across sub-agents

### Changed

- **Pentest integration coverage** — `tests/pentest.rs` grows Phase 5 tests: the guided exploit sweep proves SQLi/XSS/session-cookie findings against a live fixture with **no LLM**, and a scripted-engine orchestrator run merges guided proofs with parallel sub-agent findings end-to-end. 9 new `orchestrator` unit tests (planner classification, plan capping, path-param substitution, same-origin, proof→finding mapping, merge/rank)
- **TUI**: `/pentest` suggestions and help now show `--url` and `--sub-agents` live-orchestration examples
- **TUI**: New `/attack --flow`, `/fix --pr`, `/report --format html`, `/pr --diff`, and `/watch` commands in help, palette, and input suggestions
- **TUI**: `/pentest` commands in help, palette, and input suggestions; command arguments are quote-stripped before dispatch; `pentest` gets a 10-minute command budget (up from the 2-minute default)
- **`pr` workflow** (`.github/workflows/pr-review.yml`): now runs with `--diff` for focused, line-accurate reviews
- **README**: Documented the new `--flow`, `--pr`, `--format html`, `--diff`, `watch`, `config provider`, and `pentest` features

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
