<div align="center">

# CipherAI

**AI security analysis for your codebase — from your terminal.**

[![Rust](https://img.shields.io/badge/Rust-1.88+-orange?logo=rust&logoColor=white)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)]()

</div>

CipherAI indexes your codebase, scans for vulnerabilities and secrets, discovers attack chains, detects zero-day anomalies, generates SBOMs, applies AI-powered fixes, and runs a **Shannon-class autonomous pentester** against live targets — from a single CLI or the interactive TUI.

---

## Install

Prebuilt binaries for Linux (x86_64/aarch64), macOS (Intel/Apple silicon), and Windows (x86_64) ship with every [release](https://github.com/sandeepannandi/Cipher/releases). The installer picks the right artifact for your platform, downloads it **with the release's `SHA256SUMS.txt`, and refuses to install unless the checksum verifies**:

```sh
curl -fsSL https://raw.githubusercontent.com/sandeepannandi/Cipher/master/install.sh -o install.sh
sh install.sh                 # latest release, into ~/.local/bin
```

Pin a version or a different prefix explicitly: `sh install.sh --version v1.0.0 --prefix /usr/local/bin`. Then run `cipher-ai setup`.

## Quick start (from source)

```sh
git clone https://github.com/sandeepannandi/Cipher.git
cd Cipher
cargo build --release
./target/release/cipher-ai setup     # guided: pick a provider, key stored owner-only, never echoed
./target/release/cipher-ai init
./target/release/cipher-ai ask "Any vulnerabilities?"
```

Prefer a one-liner? `export GROQ_API_KEY=gsk_your_key_here` works too — `setup` detects it and writes nothing. `cipher-ai doctor` verifies the setup anytime (exit code + `--format json` for scripts).

**TUI:** `cd tui && npm install && npm run build && node bin/cipher-ai.js` — `/help` for commands, `Ctrl+K` for the palette, **Esc** cancels.

---

## CLI Commands

| Command | What it does |
|---|---|
| `cipher-ai init` | Index the codebase (TF-IDF, local, no DB) |
| `cipher-ai ask "…"` | RAG + AI security Q&A over the index |
| `cipher-ai review [--ai] [--format terminal\|json\|sarif\|md] [--min-severity X] [--max-findings N]` | OWASP Top 10 scan (20+ patterns) |
| `cipher-ai review --policy .cipher-ai-policy.yml --fail-on-policy` | Gate only new/expired findings at policy severity + confidence thresholds |
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
| `cipher-ai setup [--provider X] [--key-stdin]` | Guided first-run setup: pick a provider, store the key owner-only (0600, never echoed), verify with doctor |
| `cipher-ai doctor [--format json]` | Check provider/key readiness without printing secrets (exit 1 when setup is needed) |
| `cipher-ai config [set <key> <value>]` | API keys, provider, model (or `status`, `completions`) — stored keys are masked, never printed raw |

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

## Secret handling

API keys live only in `~/.cipher-ai/config.json`, written owner-only (`0600` on Unix; existing loose files are tightened on the next write). `setup` reads keys via a hidden prompt or `--key-stdin`, never echoes them, and `config get` masks stored values. Keys are never committed to the indexed project.

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

## GitHub Actions workflow checks

`cipher-ai review` also checks GitHub Actions workflow files (YAML under `.github/workflows/`, or any YAML with top-level `on:` and `jobs:`). Checks are local to one workflow file:

- **Untrusted checkout in a privileged workflow** (Critical, CWE-829): `pull_request_target` or `workflow_run` plus a checkout `ref`/`repository` pointing at the PR head, or `gh pr checkout` in a run step.
- **Script injection** (High, CWE-94): `${{ }}` with attacker-controlled text (issue/PR/comment/review/discussion title or body, `head_ref`, commit messages and author names, `workflow_run.head_branch`) expanded inside `run:` or `actions/github-script` `script:`. Numeric fields such as `pull_request.number`, and values passed through `env:`, are not flagged.
- **Unpinned third-party action** (Medium, CWE-829): `uses: owner/repo@ref` where `ref` is not a full 40-character commit SHA. Local `./` actions and GitHub-owned `actions/*` and `github/*` are not flagged.
- **Write-all token permissions** (High, CWE-732) and **all secrets exposed** via `toJSON(secrets)` (High, CWE-200).

A missing `permissions:` block is not flagged, because the repository's default token setting decides its effect.

## Repository policy

Copy `.cipher-ai-policy.example.yml` to `.cipher-ai-policy.yml` to make review outcomes deterministic in CI. Policy evaluation uses the stable finding fingerprints already emitted in JSON and SARIF. Display flags such as `--max-findings` and `--min-severity` never weaken the policy gate.

Create or refresh an accepted baseline explicitly:

```sh
cipher-ai review --write-policy-baseline .cipher-ai-policy.yml --path .
```

A baseline accepts only the listed fingerprints. Suppressions are separate, require a non-empty reason, and may include an ISO date expiry. Expired suppressions become gate-eligible again. No policy file means no findings are silently accepted; `--fail-on-policy` refuses to run without an explicit `--policy` or repository `.cipher-ai-policy.yml`. Policy schema errors, unknown keys, duplicate fingerprints, and invalid thresholds fail closed.

Fingerprints are keyed on the rule, file, finding type and the whitespace-normalized flagged line, not the line number, so edits elsewhere in a file do not re-key accepted findings. Changing the flagged line itself produces a new fingerprint. A repeated identical finding in the same file gets its own fingerprint, so a baseline entry never covers a new copy. Findings without a source snippet fall back to the line number.

For CI, run `cipher-ai review --format sarif --output results.sarif --max-findings 0 --fail-on-policy --path .`. SARIF is written before a failing exit so the complete scan remains available for upload and debugging.
