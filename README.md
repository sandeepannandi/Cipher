<div align="center">

# CipherAI

**AI security analysis for your codebase — from your terminal.**

[![Rust](https://img.shields.io/badge/Rust-1.85+-orange?logo=rust&logoColor=white)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)]()

</div>

CipherAI indexes your codebase, scans for vulnerabilities and secrets, discovers attack chains, detects zero-day anomalies, generates SBOMs, applies AI-powered fixes, and runs a **Shannon-class autonomous pentester** against live targets — from a single CLI or the interactive TUI.

---

## Quick start

```sh
git clone https://github.com/sandeepannandi/Cipher.git
cd Cipher
cargo build --release
export GROQ_API_KEY=gsk_your_key_here
./target/release/cipher-ai init
./target/release/cipher-ai ask "Any vulnerabilities?"
```

**TUI:** `cd tui && npm install && npm run build && node bin/cipher-ai.js` — `/help` for commands, `Ctrl+K` for the palette, **Esc** cancels.

---

## CLI Commands

| Command | What it does |
|---|---|
| `cipher-ai init` | Index the codebase (TF-IDF, local, no DB) |
| `cipher-ai ask "…"` | RAG + AI security Q&A over the index |
| `cipher-ai review [--ai] [--format terminal\|json\|sarif\|md] [--min-severity X] [--max-findings N]` | OWASP Top 10 scan (20+ patterns) |
| `cipher-ai deps [--online] [--fail-on X]` | Dependency CVE scan (embedded DB + OSV.dev online) |
| `cipher-ai secrets [--fail-on X]` | Credential leak scan (25+ patterns) |
| `cipher-ai zeroday [--ai] [--anomaly-only] [--format json\|sarif]` | 3-layer zero-day detection (anomaly, taint flow, AI) |
| `cipher-ai attack [--flow] [--depth N]` | Attack chains from findings (8 chain types, data-flow evidence) |
| `cipher-ai sbom [--format cyclonedx\|spdx]` | Software Bill of Materials |
| `cipher-ai report [--format terminal\|md\|json\|html] [--pentest <ws\|all>]` | Aggregated security report (SAST + SCA + pentest) |
| `cipher-ai fix [--list] [--dry-run] [--id <uuid>] [--risk X] [--all -y] [--pr]` | AI-powered fixes (incl. proven pentest findings) + PR |
| `cipher-ai pr --diff` | Diff-aware PR review with inline comments |
| `cipher-ai watch [--once] [--pr] [--pentest <url>]` | Continuous monitoring (live exploit sweep per scan) |
| `cipher-ai ci [--format json] [--output f] [--fail-on X] [--pentest <url>]` | Run all scans + optional live pentest stage |
| `cipher-ai config [set <key> <value>]` | API keys, provider, model (or `status`, `completions`) |

### Pentest — the autonomous AI security engineer

`cipher-ai pentest "<objective>" [flags]` runs the full Shannon-style pipeline: white-box pre-recon (framework-aware endpoints + taint + scanner hypotheses) → parallel bug-class sub-agents → **proof-by-exploitation** ("no exploit, no report" — only findings with reproducible PoCs are reported) → MD/SARIF/JSON report.

| Flag | What it does |
|---|---|
| `--url <target>` | Live mode: shared session (cookie jar), 15 tools, deterministic exploit sweep (12 validator classes) + sub-agents |
| `--config app.yaml` | YAML config: auth (form/basic/TOTP/email-OTP + magic link), ROE, focus/avoid scope gate, rate limit, vuln-class + report filters |
| `--blackbox` | Crawl the live target (bounded BFS, no source, no AI key) and sweep every discovery |
| `--browser` | Headless Chrome: render JS-heavy/SPA pages, drive them (`browser_action`), prove DOM XSS/clickjacking, and run the **browser fuzz pass** (forms submitted in a real engine, XSS proven on marker execution). Install Chrome or set `CIPHER_AI_CHROME` |
| `--openapi spec.yaml\|json` | Schema-aware surface: OpenAPI 3/Swagger 2 + GraphQL introspection → schema-driven targets + mass-assignment field lists (auto-discovers `openapi.json`) |
| `-w <name>` / `--resume <name>` | Checkpointed workspaces (redacted transcripts, evidence) — resume interrupted runs; a complete one re-renders the report with no AI key |
| `--allow-host <host>` / `--plan-only` / `--max-tokens` / `--max-cost` | Safety + cost: allowlist (checked pre-request, per redirect hop), dry-run with zero requests, adaptive token/USD budgets with model routing |
| `--point-retest <id>` | Replay the exact proof against the live target — deterministic, no AI key. Prints `STILL VULNERABLE` / `FIXED` (browser-fuzz proofs re-drive the real engine) |
| `--format md\|sarif\|json` / `--json` / `--output f` | Reports: Shannon-grade Markdown (incl. **Attack Paths** chains), SARIF 2.1.0 (OWASP 2025 tags, code-anchored), JSON |

Multi-step attack chaining (M9.4): proven proofs unlock primitives (user creation, JWT impersonation, SSRF/exec), auth-blocked endpoints are re-probed once with the primed session, and the report shows **attack paths** (e.g. mass assignment → IDOR), not isolated bullets.

**Integration:** `watch --pentest <url>`, `ci --pentest <url>`, `report --pentest <ws>`, `fix` (pentest findings are auto-fixable), `pentest --check-email-auth --config app.yaml` (verify IMAP before a run).

Full design history in [`docs/PENTESTER-PLAN.md`](docs/PENTESTER-PLAN.md).

---

## How it works

- **`init`** builds a local TF-IDF index of the codebase (`.gitignore`-aware, no external DB).
- **`review`** matches 20+ OWASP patterns; **`deps`** parses 7 manifest formats; **`secrets`** matches 25+ credential patterns; **`zeroday`** layers anomaly + taint-flow + AI hunting; **`attack`** links findings into 8 attack-chain types.
- **`pentest`** runs the agent loop with code tools (`search_code`, `trace_taint`, `map_attack_surface`, …) and live tools (`http_request`, `login`, `exploit`, `browser_action`, …). Every run prints a **prompt-injection warning** — the target codebase is treated as untrusted data. Safe by default: Docker-only command execution, allowlist + rate limiting, `--plan-only` makes zero requests.

## AI providers

Provider-agnostic — resolved from `CIPHER_AI_PROVIDER`, then the persisted `provider` config, then `groq`.

| Provider | Env var | Default model |
|---|---|---|
| `groq` | `GROQ_API_KEY` | `llama-3.3-70b-versatile` |
| `openai` | `OPENAI_API_KEY` | `gpt-4o-mini` |
| `anthropic` | `ANTHROPIC_API_KEY` | `claude-3-7-sonnet-20250219` |

`CIPHER_AI_BASE_URL` routes through a gateway (LiteLLM/vLLM/Ollama); `CIPHER_AI_MODEL` overrides the model. Persist keys once: `cipher-ai config set provider anthropic` + `cipher-ai config set anthropic-api-key sk-…`.

## Styled output

All commands use consistent, beautiful terminal output: box-drawn headers, numbered step progress, colored status icons (✓ ⚠ ✗ ●), bordered summary boxes with risk distribution bars.

## Supported languages

30+ (Rust, JS/TS, Python, Go, Ruby, Java, Kotlin, Swift, C/C++, C#, PHP, Shell, YAML, JSON, TOML, SQL, Dockerfile, HTML/CSS, Dart, Scala, Lua, R, …).

## Privacy

Code stays local — only retrieved chunks go to the LLM. Use a local endpoint via `CIPHER_AI_BASE_URL` for zero data egress.

## Project structure

```
Cipher/
├── src/            # Rust CLI + library
│   ├── main.rs     # clap CLI entry
│   ├── llm.rs      # Multi-provider AI client + agent tool-calling
│   ├── review.rs / secrets.rs / deps.rs / zeroday.rs / sbom.rs
│   ├── attack.rs / trace.rs / fix.rs / report.rs / ci.rs / watch.rs
│   └── pentest/    # The autonomous pentester
│       ├── agent.rs      # ReAct agent loop
│       ├── orchestrator.rs # missions, guided sweep, chain engine
│       ├── exploit.rs    # 12 deterministic validators + oracle gate + browser fuzz
│       ├── recon.rs / crawler.rs / schema.rs / http.rs / browser.rs / cdp.rs
│       ├── config.rs / workspace.rs / report.rs / chain.rs / email.rs / adaptive.rs
│       └── tools.rs      # 15 agent tools
├── tests/          # integration.rs, pentest.rs (live-fixture end-to-end)
├── tui/            # Node.js TUI (Ink/React) over the same CLI
└── docs/PENTESTER-PLAN.md
```

## Tests

```sh
cargo test              # 402 tests: unit + pentest fixtures + integration
cargo clippy --all-targets
```

## License

MIT — see [LICENSE](LICENSE).
