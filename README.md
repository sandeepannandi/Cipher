<div align="center">

# CipherAI

**AI security analysis for your codebase — from your terminal.**

[![Rust](https://img.shields.io/badge/Rust-1.85+-orange?logo=rust&logoColor=white)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)]()
[![Tests](https://img.shields.io/badge/tests-60%20passing-brightgreen)]()

</div>

CipherAI indexes your codebase, scans for vulnerabilities and secrets, discovers attack paths, detects zero-day anomalies, generates SBOMs, and applies AI-powered fixes. Includes both a CLI and an interactive TUI.

---

## Quick start

### CLI
```sh
git clone https://github.com/sandeepannandi/Cipher.git
cd Cipher
cargo build --release
export GROQ_API_KEY=gsk_your_key_here
./target/release/cipher-ai init
./target/release/cipher-ai ask "Any vulnerabilities?"
```

### TUI
```sh
cd Cipher/tui
npm install && npm run build
node bin/cipher-ai.js
```

Type `/help` inside the TUI for commands, or press `Ctrl+K` for the command palette. Press **Esc** to cancel a running command.

---

## CLI Commands (14 total)

| Command | Description |
|---|---|
| `cipher-ai init` | Index your codebase for AI-powered analysis |
| `cipher-ai ask "..."` | Ask security questions with RAG + AI |
| `cipher-ai review` | Scan for OWASP Top 10 vulnerabilities (20+ patterns) |
| `cipher-ai review --ai` | Review with AI-powered deep analysis |
| `cipher-ai review --format sarif` | SARIF output for CI/CD integration |
| `cipher-ai review --format json` | Machine-readable JSON output |
| `cipher-ai review --min-severity high` | Filter: show only high+ severity |
| `cipher-ai review --max-findings 10` | Limit to top 10 findings |
| `cipher-ai deps` | Check dependency vulnerabilities (embedded DB) |
| `cipher-ai deps --online` | Full CVE coverage via OSV.dev API |
| `cipher-ai deps --fail-on high` | Exit code 1 if high+ severity found |
| `cipher-ai secrets` | Scan for leaked credentials (25+ patterns) |
| `cipher-ai secrets --fail-on high` | Exit code 1 if high+ secrets found |
| `cipher-ai ci` | **Run all 5 scans** with consolidated output |
| `cipher-ai ci --format json` | CI → machine-readable JSON for pipeline ingestion |
| `cipher-ai ci --format json --output ci.json` | Write CI JSON to file |
| `cipher-ai ci --fail-on critical` | CI mode, fail only on critical findings |
| `cipher-ai zeroday` | **3-layer zero-day anomaly detection** |
| `cipher-ai zeroday --ai` | Zero-day + AI-powered novel vulnerability hunting |
| `cipher-ai zeroday --format json` | Zero-day → JSON output |
| `cipher-ai zeroday --format sarif` | Zero-day → SARIF output |
| `cipher-ai zeroday --anomaly-only` | Only run anomaly detection layer |
| `cipher-ai sbom` | Generate **CycloneDX or SPDX** SBOM |
| `cipher-ai sbom --format spdx` | SPDX SBOM format |
| `cipher-ai report` | Generate security report (terminal/markdown/json/html) |
| `cipher-ai report --format html` | Export a browser-ready HTML dashboard (writes `cipher-ai-report.html`) |
| `cipher-ai attack` | Discover attack chains from findings (8 chain types) |
| `cipher-ai attack --flow` | Attack chains with real cross-file data-flow evidence |
| `cipher-ai attack --depth 5` | Deeper attack chain analysis |
| `cipher-ai fix --list` | List all fixable findings |
| `cipher-ai fix --dry-run` | Preview AI-generated fixes without applying |
| `cipher-ai fix --id <UUID>` | Generate and apply AI fix for specific finding |
| `cipher-ai fix --risk critical` | Auto-fix all critical findings |
| `cipher-ai fix --pr` | Apply fixes and open a GitHub PR with them |
| `cipher-ai fix --all -y` | Fix everything without prompting |
| `cipher-ai pr --diff` | Diff-aware PR review — only findings on changed lines + inline comments |
| `cipher-ai watch` | Continuous monitoring — report new findings vs last scan |
| `cipher-ai watch --pr` | Watch + auto-fix new findings and open a GitHub PR (dependabot-style) |
| `cipher-ai watch --once` | Single watch scan (for cron/CI) |
| `cipher-ai pentest "hunt for vulns"` | Autonomous AI security engineer — agent maps the codebase, investigates with tools, reports evidence-backed findings |
| `cipher-ai pentest "hunt and exploit" --url http://localhost:8080 --sub-agents 6` | **Live mode** — orchestrator: parallel specialist sub-agents + guided exploit sweep (SQLi/XSS/SSRF/CMDi/IDOR/auth/path traversal) |
| `cipher-ai pentest "test the login" --url http://localhost:8080 --config app.yaml` | **Config-driven** — YAML authentication (form/basic + TOTP), rules of engagement, focus/avoid scope gate, vuln-class filters, report filters |
| `cipher-ai pentest -w myapp --url http://localhost:8080 --format md` | **Workspace + report** — checkpoints + redacted transcripts under `~/.cipher-ai/workspaces/myapp/`; resumes after interruption; renders Markdown / SARIF / JSON |
| `cipher-ai pentest --resume myapp` | **Resume** — continue an interrupted workspace (completed missions skipped; a complete one re-renders its report with no AI key) |
| `cipher-ai pentest --url http://localhost:8080 --allow-host localhost` | **Safety** — only send live requests to an allowlisted host (repeatable); out-of-scope hosts and redirects are refused before leaving the machine |
| `cipher-ai pentest --plan-only` | **Dry-run** — recon + missions + sweep targets with zero live requests and no AI key |
| `cipher-ai pentest "..." --url http://localhost:8080 --config app.yaml` | **Rate limited** — config `rate_limit: { max_per_minute, delay_ms }` throttles requests with 429 backoff |
| `cipher-ai pentest --point-retest <id>` | **Verify a fix** — replay the exploit validators that proved this finding against the live target (deterministic, no AI key). Workspace auto-detected, or pass `-w <name>`. Prints `STILL VULNERABLE` or `FIXED` |
| `cipher-ai fix --list` | Pentest findings from workspaces now appear — code-anchored ones patch via AI-fix → verify → `--pr` |  | `cipher-ai pentest --blackbox --url http://localhost:8080` | **Black-box mode** — crawl the live target (bounded BFS: same-origin, page/depth caps, form discovery) and sweep every discovery — no source, no AI key |
  | `cipher-ai pentest --config app.yaml` | **email-OTP / magic-link auth** — `login_type: email` reads the one-time code (or sign-in link) from an IMAP mailbox (`authentication.email`) and completes login; `pentest --check-email-auth` verifies the mailbox first |
  | `cipher-ai watch --pentest http://localhost:8080` | Watch + **live exploit sweep** each scan — proven findings merged into the same fingerprint/alert/fix-PR flow |
  | `cipher-ai report --pentest myapp` | One deduped report: SAST + SCA + **proven pentest findings** from workspace (or `all`) |
  | `cipher-ai ci --pentest http://localhost:8080` | CI + **live pentest stage** — deterministic guided exploit sweep (no LLM) merged into totals, `--fail-on` gating |
  | `cipher-ai config` | Show current configuration |
| `cipher-ai config set groq-api-key <key>` | Set Groq API key in config |
| `cipher-ai config set openai-api-key <key>` | Set OpenAI API key in config |
| `cipher-ai config set anthropic-api-key <key>` | Set Anthropic API key in config |
| `cipher-ai config set provider openai` | Switch the active AI provider (groq \| openai \| anthropic) |
| `cipher-ai status` | Show project index, languages, API key status |
| `cipher-ai completions bash` | Generate shell completions (bash/zsh/fish/powershell) |

## TUI Commands

| Command | Description |
|---|---|
| `/help` | Show help screen (scrollable) |
| `/init` | Index your codebase |
| `/review` | Scan for OWASP Top 10 vulnerabilities |
| `/review --ai` | Review with AI deep analysis |
| `/review --format json` | Review → JSON output |
| `/deps` | Check dependency vulnerabilities |
| `/secrets` | Scan for secrets |
| `/ask <question>` | Ask a security question (uses AI) |
| `/report` | Generate security report |
| `/fix --list` | List fixable findings |
| `/fix --dry-run` | Preview fixes |
| `/attack` | Analyze attack paths |
| `/ci` | Run all 5 scans (review + secrets + deps + zeroday + attack) |
| `/ci --format json` | CI → JSON output || `/pentest` | Autonomous AI security engineer (agent hunts + reports findings) |
  | `/pentest --json` | Pentest → machine-readable JSON |
  | `/pentest --url http://localhost:8080` | Live pentest: HTTP tools + exploit validators ("no exploit, no report") |
| `/config` | Show or set configuration |
| `/zeroday` | 3-layer zero-day anomaly detection |
| `/zeroday --ai` | Zero-day + AI analysis |
| `/sbom` | Generate CycloneDX SBOM |
| `/sbom --format spdx` | SPDX SBOM |
| `/model` | Show or switch AI model |
| `/status` | Show index and API key status |
| `/clear` | Clear chat messages |
| `/exit` | Exit the TUI |

## How it works

**`init`** walks your project (respecting `.gitignore`), reads source files, chunks code into overlapping segments, and builds a TF-IDF search index in `.cipher-ai/`. No external database required — everything stays local.

**`ask`** finds relevant code via TF-IDF scoring and sends it to the LLM. Answers reference specific files and line numbers — no more vague security advice.

**`review`** scans files against 20+ OWASP Top 10 vulnerability patterns: SQL injection, command injection, path traversal, SSTI, weak cryptography (MD5, SHA1, DES, ECB), hardcoded credentials, JWT secrets, CORS misconfiguration, insecure deserialization, mass assignment, and more. Optionally runs AI-powered deep analysis. Supports **terminal**, **JSON**, **Markdown**, and **SARIF** output formats.

**`deps`** parses 7 manifest formats: `Cargo.toml`, `package.json`, `requirements.txt`, `go.mod`, `Gemfile`, `composer.json`, `pubspec.yaml`. Checks against an embedded advisory database of 30+ CVEs. The `--online` flag queries the OSV.dev API for full CVE coverage. Supports `--fail-on` for CI/CD pipelines.

**`secrets`** matches 25+ credential patterns including AWS keys, GitHub tokens, GitLab tokens, Stripe keys, JWT secrets, PGP private keys, Slack tokens, Telegram tokens, SSH keys, and generic passwords — with severity classification (critical, high, medium, low).

**`ci`** runs **5 scans in sequence**: review → secrets → deps → zeroday → attack (plus SBOM info). Produces a consolidated summary box and exit code. Supports `--format json` for pipeline ingestion and `--fail-on` for threshold-based failure. Ready for GitHub Actions, GitLab CI, Jenkins, etc.

**`zeroday`** detects novel/unknown vulnerabilities that signature-based scanners miss. Uses 3 layers: (1) **Anomaly Detection** — finds complex functions, dangerous API proximity, missing bounds checks, type confusion, and silent error handling; (2) **Taint Flow Analysis** — tracks untrusted data from sources to dangerous sinks without known signatures; (3) **AI Zero-Day Hunter** — LLM-based novel vulnerability discovery. Supports **terminal**, **JSON**, and **SARIF** output.

**`pentest`** runs the **autonomous AI security engineer**: an agent loop (powered by the provider-agnostic client — Groq/OpenAI/Anthropic) that maps the codebase with `list_files` / `get_project_map` / `find_entry_points` (framework-aware recon), investigates with `search_code` / `read_file` / `semantic_search`, consumes scanner output as hypotheses via `get_scanner_findings`, and confirms cross-file data flows with `trace_taint`. It reports only evidence-backed findings (file:line references) with severity and CWE mapping. Use `--json` for machine-readable output or `--output file.json` to save.

With **`--url <target>`** the agent goes **live** ("no exploit, no report"): it gets a shared session layer (cookie jar persists across calls) and six live tools — `http_request` (raw requests with evidence capture), `analyze_page` (HTML forms/links/tech fingerprint), `login` (form login with hidden/CSRF field reuse), `generate_totp` (RFC 6238 MFA codes), `run_command` (commands execute **inside an ephemeral Docker sandbox** — repo mounted read-only, capabilities dropped; refuses without Docker), and `exploit` (deterministic proof-by-exploitation validators for SQLi, reflected XSS, SSRF with out-of-band callback, command injection, path traversal, IDOR, and session-cookie hardening — returning **only proven findings** with reproducible evidence). Responses are captured as reproducible evidence with sensitive headers/URL params redacted.

A live target runs the **multi-agent orchestrator** (Phase 5): a deterministic planner splits the attack surface into up to N bug-class missions, a **guided exploit sweep** first probes discovered forms, same-origin links, and recon routes with the deterministic validators (proof-only, no LLM), then up to `--sub-agents N` (default 4, max 8) **specialist agents** attack each mission in parallel over the shared session — running `exploit`, discovering params with `analyze_page`, and confirming sinks in source. All guided proofs and sub-agent findings are merged, deduplicated, and ranked by risk.

With **`--config <file.yaml>`** (Phase 6) a real-world target is pentested from a single file: `authentication` (form or basic login with `totp_secret` MFA codes, a natural-language `login_flow`, and a `success_condition` — `url_contains` / `body_contains` / `status`) is bootstrapped once at startup so every tool call is authenticated; `rules_of_engagement` is injected into the agent prompt; `rules.avoid` / `rules.focus` (by `url_path`, `subdomain`, `domain`, `method`, `header`, or `parameter`) form a **scope gate** that refuses out-of-focus requests before they leave the machine; `vuln_classes` narrows the exploit engine; `exploit: false` forces analysis-only mode; and `report.min_severity` / `min_confidence` filter the findings.

Every run prints a **prompt-injection warning** — the target codebase is treated as UNTRUSTED data that may try to manipulate the agent.

With **`--allow-host <host>`** (Phase 8) live requests are restricted to an allowlist (repeatable; subdomains match): `http_request`, `exploit`, `login` and the guided sweep refuse out-of-scope hosts **before the request leaves the machine**, and a custom redirect policy re-checks the allowlist on every redirect hop so a redirect to an out-of-scope host is stopped instead of followed. **`--plan-only`** prints the deterministic plan (recon → missions → sweep targets) with **zero live requests and no AI key** — perfect for CI review or before running an attack. Config **`rate_limit: { max_per_minute, delay_ms }`** throttles the shared session (token bucket) and honors `Retry-After` on 429 responses with a single capped retry. Transcript log-hygiene now also scrubs exact credential values from your config (username/password/TOTP secret).

With **`-w <name>` / `--resume <name>`** (Phase 7) runs are **checkpointed**: `~/.cipher-ai/workspaces/<name>/` holds `session.json` (stage, objective, config hash, findings, guided proofs), redacted per-agent transcripts (`agents/*.jsonl`), and `evidence/` captures for every proof. An interrupted run resumes from the last stage — completed missions are skipped and their proofs reused; a config change since the last run warns. A **complete** workspace re-renders its report with **no AI key required**. `--format md|sarif|json` renders Shannon-grade reports: Markdown (`Security-Assessment-Report.md` — exec summary, PoC steps with payloads + observed responses, remediation), SARIF 2.1.0 (rule per bug class with OWASP Top Ten 2025 tags — imports into GitHub code-scanning), or JSON. `cipher-ai ci --pentest <url>` runs the deterministic guided exploit sweep as a CI stage with `--fail-on` gating.

With **`--point-retest <finding-id>`** (Phase 9 / M8.1) the loop closes: a proven finding is **auto-fixable** — `cipher-ai fix` now collects pentest findings from your workspaces (code-anchored ones patch cleanly, deduped against the other scanners) — and **verifiable** — point re-test replays only the exact validators that produced the proof against the live target, printing `STILL VULNERABLE` (fix did not hold) or `FIXED` (no longer reproduces). Deterministic and AI-key-free; the re-test session is restricted to the stored target's host for safety. Full plan in `docs/PENTESTER-PLAN.md`.

**Phase 9 / M8.2–M8.4** completes the lifecycle. **`--blackbox --url <target>`** (M8.3) runs with *no source at all*: a bounded BFS crawler (`crawler.rs` — seed URL, same-origin only, page/depth caps, wall-clock budget, form discovery) maps the live surface and feeds the same deterministic sweep — no AI key, same "no exploit, no report" gate. **`watch --pentest <url>`** (M8.2) folds the live guided sweep into every scan, so a newly-proven live bug triggers the same NEW-finding alert (and optional fix-PR) as any static finding. **`report --pentest <name|all>`** (M8.4) merges proven workspace findings into one deduped report — the engineer sees SAST + SCA + live pentest in a single terminal/markdown/HTML/JSON view.

**Phase 10 / M8.5** completes Shannon's **auth matrix** (form, basic, TOTP — and now **email-OTP / magic links**). With `login_type: email`, the credential POST triggers an email; a new IMAP reader (`src/pentest/email.rs`) records a baseline message before the POST, then waits for the *new* OTP email (subject/from filters, custom `code_regex`, or the magic link from an `<a href>`) and submits the code to `otp_url` (reusing hidden/CSRF fields) or follows the link. `success_condition` verifies either way and the captured cookie authenticates the whole run. `pentest --check-email-auth --config app.yaml` verifies the mailbox (IMAP login + message count) before a long run — no AI key, no HTTP requests — and the agent can fetch codes mid-run with the new `fetch_otp` tool.

**`sbom`** generates Software Bill of Materials in **CycloneDX** (default) or **SPDX** formats. Parses all dependency manifests and produces a JSON document listing every dependency with its ecosystem and version.

**`report`** aggregates findings from all scanners, computes a 0–100 security score, and outputs terminal, markdown, or JSON reports. `--format html` exports a self-contained browser-ready dashboard to `cipher-ai-report.html` (or the path given with `--output`).

**`attack`** connects isolated findings into **8 attack chain types**: privilege escalation, data exfiltration, remote code execution, authentication bypass, cryptographic breach, information disclosure, supply chain attack, and credential theft. Each chain shows the end-to-end attack path.

**`fix`** sends vulnerable code to the AI, which returns a secure replacement with a colored diff. Supports `--dry-run` for preview, `--list` to see fixable findings, `--risk` for severity filtering, `--id` for targeted fixing, and `--all -y` for unattended batch fixing.

**`config`** manages your API keys, default AI model, active provider, and other settings. No environment variables needed after initial setup.

## AI providers

CipherAI is provider-agnostic. The active provider is resolved from `CIPHER_AI_PROVIDER`, falling back to the persisted `provider` config value, then to `groq` for backward compatibility.

| Provider | Env var for key | Default model |
|---|---|---|
| `groq` (default) | `GROQ_API_KEY` | `llama-3.3-70b-versatile` |
| `openai` | `OPENAI_API_KEY` | `gpt-4o-mini` |
| `anthropic` | `ANTHROPIC_API_KEY` | `claude-3-7-sonnet-20250219` |

Select a provider and persist its key once — no env vars needed afterwards:

```sh
cipher-ai config set provider anthropic
cipher-ai config set anthropic-api-key sk-ant-...
```

Additional overrides:
- `CIPHER_AI_BASE_URL` — route all traffic through a gateway or self-hosted endpoint (LiteLLM, vLLM, Ollama bridge, corporate proxy)
- `CIPHER_AI_MODEL` — override the default model for every call

Every AI-powered command (`ask`, `review --ai`, `verify`, `fix`, `attack`, `trace`, `zeroday`) honors the active provider automatically.

**`completions`** generates shell completions for bash, zsh, fish, and PowerShell.

**TUI** wraps all CLI commands in an interactive chat interface. Features: command palette (`Ctrl+K`) with search, command history (up/down arrows), **Esc to cancel** any running command, scrollable help screen, keyboard-driven navigation, and real-time status.

## Styled output system

All commands produce **systematic, beautiful output** with consistent formatting:
- `┌─` box-drawn headers with colored titles
- Numbered step progress (`[1/5] Running security review...`)
- Colored status indicators: ✓ green (success), ⚠ yellow (warning), ✗ red (error), ● cyan (info)
- Bordered summary boxes with risk distribution bars
- Bulleted recommendation sections

## Supported languages

30+ languages: Rust, JavaScript, TypeScript, Python, Go, Ruby, Java, Kotlin, Swift, C/C++, C#, PHP, Shell (bash/zsh/fish), YAML, JSON, TOML, SQL, Dockerfile, HTML/CSS, Dart, Scala, Lua, R, and more.

## Privacy

Your code stays local. Only retrieved code chunks are sent to the LLM when using `ask`, `review --ai`, `zeroday --ai`, `attack`, `verify`, `trace`, or `fix`. Use a local endpoint (Ollama, vLLM) via `CIPHER_AI_BASE_URL` for zero data egress.

## Project structure

```
Cipher/
├── src/              # Rust CLI source (14 commands)
│   ├── main.rs       # CLI entry point with clap
│   ├── lib.rs        # Library crate root
│   ├── attack.rs     # Attack chain discovery (8 chain types)
│   ├── ci.rs         # CI pipeline (5 scans + SBOM)
│   ├── config.rs     # Configuration management
│   ├── deps.rs       # Dependency scanner (7 manifest parsers)
│   ├── finding.rs    # Finding/FindingReport types
│   ├── fix.rs        # AI-powered auto-fix
│   ├── groq.rs       # Legacy Groq client (thin wrapper)
│   ├── llm.rs        # Multi-provider AI client (Groq/OpenAI/Anthropic)
│   ├── indexer.rs    # TF-IDF code indexer
│   ├── output.rs     # Unified styled output helpers
│   ├── rag.rs        # RAG-based Q&A
│   ├── report.rs     # Security report generator
│   ├── review.rs     # OWASP pattern scanner + AI review
│   ├── sbom.rs       # CycloneDX/SPDX SBOM generator
│   ├── scan.rs       # Shared scan utilities
│   ├── secrets.rs    # Credential scanner (25+ patterns)
│   └── zeroday.rs    # 3-layer zero-day detector
├── tests/
│   └── integration.rs  # 60 integration tests
├── tui/              # Node.js TUI (Ink/React)
│   ├── bin/cipher-ai.js # Entry point
│   ├── src/
│   │   ├── index.jsx       # Main app
│   │   ├── commands/runner.js  # Rust binary bridge
│   │   └── components/     # UI components
│   └── postinstall.js
├── .github/workflows/release.yml
├── Dockerfile
├── Cargo.toml
└── README.md
```

## Tests

```sh
cargo test          # 60 integration tests
cargo test --test integration  # Run integration tests only
```

## License

MIT — see [LICENSE](LICENSE).
