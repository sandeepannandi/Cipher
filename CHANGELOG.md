# Changelog

## [Unreleased]

### Fixed

- **TUI `postinstall.js` release version** — binary download version is now derived from `tui/package.json` (was hardcoded to the stale `v0.1.0`, which had no matching release assets), so `npm install` fetches a real binary and stays in sync with future releases
- **CI cross-compile error `can't find crate for core` / `x86_64-pc-windows-gnu target may not be installed`** — `.cargo/config.toml` no longer forces a global `[build] target = "x86_64-pc-windows-gnu"`; `pr-review` and `security-watch` workflows now build with an explicit `--target x86_64-unknown-linux-gnu`. Local Windows-without-MSVC builds can opt in via `cargo build --target x86_64-pc-windows-gnu` or `CARGO_BUILD_TARGET`
- **`cipher-ai report --format html`** — HTML reports now always export to a file (default `cipher-ai-report.html`, or `--output <path>`) instead of dumping raw HTML to stdout; updated CLI help text and TUI descriptions to match

### Added

- **Pentest browser mode (Phase 11 / M8.6 — JS-heavy & SPA targets)** — `cipher-ai pentest --browser --url <target>` drives the locally-installed **headless Chrome/Chromium/Edge** (zero new dependencies — no Playwright/Node; `CIPHER_AI_CHROME` overrides discovery across Windows, WSL interop, macOS and Linux) to render pages that hide their surface behind client-side JS. New **`render_page` agent tool** returns the rendered-DOM analysis (title/forms/links/tech) and the black-box crawler gains `CrawlLimits.browser` so it discovers SPA forms/links the raw HTML never contains, falling back to raw HTML when no browser is installed or a render fails. Safety matches every other live tool: the allowlist is checked in the tool executor **before Chrome is spawned** (the browser bypasses the session's reqwest client), the scope gate applies, and the subprocess is killed on a 20s timeout so a wedged page can never hang a run. `src/pentest/browser.rs` (discovery + `render_dom` with timeout/kill + `render_dom_async` on `spawn_blocking`), `ToolRegistry.with_browser`, orchestrator wiring, CLI + TUI entries updated
- **Pentest email-OTP / magic-link auth (Phase 10 / M8.5 — Shannon auth-matrix parity)** — `login_type: email` in the YAML config completes the auth matrix (form, basic, TOTP, email). A new `src/pentest/email.rs` IMAP reader (implicit TLS on 993 / plain on 143 via `native-tls`, blocking calls on `spawn_blocking`) records a **baseline** message sequence before the credential POST, then polls for the *new* OTP email (subject/from filters, optional custom `code_regex`, default standalone 4–8 digit number preferring 6) and extracts either the numeric code or the **magic sign-in link** (from `<a href>` attributes or bare URLs, host-hinted). The code is POSTed to `otp_url` (default `login_url`) as an extra form field (`otp_field`, default `otp`) reusing hidden/CSRF inputs; a magic link is followed instead; `success_condition` verifies either way. New **`cipher-ai pentest --check-email-auth`** (with `--config`) connects, logs in, selects the mailbox and reports the message count — no AI key, no HTTP requests. The agent gains a **`fetch_otp` tool** for mid-run email retrieval (codes formatted as `otp: <code>` so transcript redaction masks them); IMAP credentials join the transcript scrub list. `native-tls`/`imap` deps added; config, CLI help, README, plan doc and TUI entries updated
- **Pentest Phase 9 / M8.2–M8.4 (black-box, watch, report continuity)** —
  - **`cipher-ai pentest --blackbox --url <target>`** — black-box mode: a new bounded BFS crawler (`src/pentest/crawler.rs` — seed URL, same-origin only, page/depth caps + wall-clock budget, form discovery) maps the live surface and feeds the deterministic exploit sweep — **no source, no AI key**, same "no exploit, no report" policy. The sweep loop was extracted into the shared `orchestrator::sweep_targets`, so source-aware and black-box runs use identical validators and safety bounds
  - **`cipher-ai watch --pentest <url>`** — each scan also runs the deterministic live exploit sweep and merges proven findings into the same fingerprint/alert/fix-PR machinery; the watch fingerprint now includes `usage` so endpoint-only live findings are tracked across scans
  - **`cipher-ai report --pentest <name|all>`** — proven pentest findings from workspace `session.json` files merge into `AggregatedReport.pentest`, deduplicated against review/deps/secrets by `file:line` — one report shows SAST + SCA + live pentest in terminal/markdown/HTML/JSON output
- **Pentest fix-prove loop (Phase 9 / M8.1)** — `cipher-ai fix` now collects **proven pentest findings** from every workspace under `~/.cipher-ai/workspaces/` (deduped across scanners), and sub-agent findings are **code-anchored** to `file:line` from their evidence so they patch cleanly — a proven finding drops straight into the existing AI-fix → build-verify → `--pr` pipeline. New **`cipher-ai pentest --point-retest <finding-id>`**: replays *only* the exact exploit validators that produced the finding's proof against the live target to verify a fix — deterministic, **no AI key required**, session auto-allowlisted to the stored target host. Proof specs are persisted in checkpoints (`ProofRecord.spec`, serde-back-compatible; pre-M8.1 sessions reconstruct a spec from the endpoint + matched param). Verdicts: `STILL VULNERABLE` (fix did not hold) vs `FIXED` (no longer reproduces)
- **Pentest safety hardening (Phase 8)** — `cipher-ai pentest --allow-host <host>` (repeatable) restricts every live request to an allowlist: `HttpSession` refuses out-of-scope hosts **before the request leaves the machine**, and a custom reqwest redirect policy re-checks the allowlist on **every redirect hop** so a redirect to an out-of-scope host is stopped (the 3xx is returned, never followed). `--plan-only` prints the deterministic plan (recon → missions → sweep targets) with **ZERO live requests and no AI key** — it exits before the session/auth bootstrap so even `--config` auth cannot send traffic. Config `rate_limit: { max_per_minute, delay_ms }` throttles the session (token-bucket min-interval) with **429 backoff** honoring `Retry-After` (capped, retried once). Log hygiene: transcript redaction now covers `username`/`totp`/`otp`/`2fa`/`mfa` keys, and exact config credential values (username/password/TOTP secret) are scrubbed from every transcript write. A Shannon-style prompt-injection warning is printed at the start of every run (treat the target codebase as untrusted data)
- **Pentest workspaces + resume (Phase 7)** — `cipher-ai pentest -w <name>` / `--resume <name>` via `src/pentest/workspace.rs`: per-run checkpoints under `~/.cipher-ai/workspaces/<name>/` — `session.json` (stage, objective, config hash, findings, guided proofs), redacted per-agent JSONL transcripts (`agents/*.jsonl`, secrets/API keys scrubbed), `evidence/` captures for every guided proof, and `logs/`. An interrupted run **resumes** from the last stage: completed missions are skipped, stored findings/proofs are reused, and a config change since the last run triggers a warning. A **complete** workspace re-renders its report with **no AI key needed** (report-only early exit)
- **Pentest reports (Phase 7)** — `cipher-ai pentest --format md|sarif|json` via `src/pentest/report.rs`: **Markdown** (`Security-Assessment-Report.md` — executive summary, per-finding severity/risk score, CWE/OWASP tags, reproducible PoC steps with payloads + observed responses, remediation), **SARIF 2.1.0** (rule-per-bug-class `cipher/injection`, `cipher/xss`, `cipher/ssrf`, `cipher/auth`, `cipher/authz`, `cipher/cmdi`, `cipher/idor` with OWASP Top Ten 2025 tags; severity → error/warning/note; anchored to code location when available, else the HTTP entry point) and **JSON** (findings + proofs + PoC evidence). `md`/`sarif` default into the workspace; `json` prints to stdout; report filters from Phase 6 config are honored. For live `--url` runs, `display_orchestration` stats include guided-sweep target/proof counts
- **`cipher-ai ci --pentest <url>`** — optional live-pentest stage in CI: runs the deterministic guided exploit sweep against a URL (no LLM required), merges proven findings into the totals, and honors `--fail-on <severity>` so a proven vulnerability blocks the merge
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
- **Pentest YAML config (Phase 6)** — `cipher-ai pentest --config app.yaml` via `src/pentest/config.rs`: Shannon-parity configuration for real-world targets. **Authentication** (`login_type: form|basic|none`, `login_url`, credentials, `totp_secret`, natural-language `login_flow`, `success_condition` with `url_contains`/`body_contains`/`status`) is bootstrapped once at startup against the shared session — the captured cookie authenticates every later tool call; basic auth + default headers added to `HttpSession`. **Rules of engagement** injected into the agent prompt. **Scope gate**: `rules.avoid`/`rules.focus` (`url_path`, `subdomain`, `domain`, `method`, `header`, `parameter`, `code_path`) are enforced in the tool executor and the guided sweep — out-of-focus requests return a `[SCOPE]` refusal instead of being sent. **`vuln_classes`** narrows the exploit engine (guided sweep, sub-agent missions, and the `exploit` tool itself). **`exploit: false`** forces analysis-only mode (code tools + recon, no live requests). **Report filters**: `min_severity` / `min_confidence` filter findings; `guidance` is appended to the summary. Load errors report the offending YAML line

### Changed

- **Pentest integration coverage (Phase 11 / M8.6)** — `tests/pentest.rs` grows 3 browser-mode tests: `render_page` is inert unless the run armed `--browser` (with a clear error explaining how), with `--browser` + Chrome installed it returns the RENDERED DOM so the JS-injected form/input on a `tiny_http` SPA fixture is visible, and the black-box crawler in browser mode discovers the JS-rendered form target while the raw crawl sees none — all gracefully skipped when no browser exists. `browser.rs` adds 2 unit tests (candidate-path sanity incl. `CIPHER_AI_CHROME` precedence, discovery invariant). The SPA fixture serves `text/html` explicitly (tiny_http's `from_string` defaults to `text/plain`, which would make headless Chrome render the markup as text and never run the JS)
- **Pentest integration coverage (Phase 10 / M8.5)** — `tests/pentest.rs` grows 2 tests: an end-to-end email-OTP bootstrap against a live `tiny_http` fixture + a minimal fake IMAP server (greeting/LOGIN/SELECT/SEARCH/FETCH) that serves the code after the baseline — asserting the session cookie is captured, the code never leaks into output, and later requests are authenticated — plus a `--check-email-auth` mailbox report test. `email.rs` adds 8 unit tests (code extraction from plain/HTML/custom regex, magic-link extraction with/without host hint, entity decoding, message splitting + filters); `config.rs` adds 1 (full email config parse incl. `$otp` flow + scrub values)
- **Pentest integration coverage (Phase 9 / M8.2–M8.4)** — `tests/pentest.rs` grows 4 tests: the black-box crawler maps the live fixture (index links + form targets, same-origin bound), `pentest --blackbox` proves findings with no source and no AI key, `report --pentest` merges a workspace finding into the JSON report, and `watch --once --pentest <url>` completes with the live sweep merged. `crawler.rs` adds 3 unit tests (same-origin guard, query parsing, bounded defaults); `report.rs` adds 2 (pentest-source inclusion in totals/score + cross-scanner dedup against review findings)
- **Pentest integration coverage (Phase 9 / M8.1)** — `tests/pentest.rs` grows 2 tests: a full-loop point re-test (guided sweep proves SQLi → proof + exact spec persisted to a workspace → `--point-retest` replays it and still reproduces against the vulnerable fixture) and a fix-verification test (a proof spec pointed at a patched clean target re-tests as FIXED). `workspace.rs` gains `workspace_root()` + `list_workspaces()` helpers and `ProofSpec` round-trip + endpoint-fallback unit tests; `mod.rs` adds `anchor_from_evidence` unit coverage via the finding-mapping tests
- **Pentest safety tests (Phase 8)** — `tests/pentest.rs` grows 6 tests: `--allow-host` refuses out-of-scope hosts with zero requests sent (and allows subdomain forms), redirects to out-of-scope hosts are stopped (302 returned, never followed), the rate limiter spaces consecutive requests, 429 backoff retries once into a 200, `--plan-only` succeeds with no AI key and no network, and exact credential values are scrubbed from transcripts. 2 new `config` unit tests (`rate_limit` precedence, credential accessor)
- **Pentest integration coverage** — `tests/pentest.rs` grows Phase 6 tests: the scope gate refuses out-of-focus `http_request`s with `[SCOPE]`, `vuln_classes` restrict the exploit engine to allowed classes, the config-driven auth bootstrap logs into a live login-protected fixture and authenticates subsequent requests, and the guided sweep honors focus rules. 7 new `config` unit tests (YAML parse, unknown-rule line errors, scope-rule matching for every rule kind, report filtering)
- **Pentest integration coverage (Phase 5)** — `tests/pentest.rs`: the guided exploit sweep proves SQLi/XSS/session-cookie findings against a live fixture with **no LLM**, and a scripted-engine orchestrator run merges guided proofs with parallel sub-agent findings end-to-end. 9 new `orchestrator` unit tests (planner classification, plan capping, path-param substitution, same-origin, proof→finding mapping, merge/rank)
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
