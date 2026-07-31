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
| `cipher-ai report --format html` | Generate a browser-ready HTML dashboard report |
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
| `cipher-ai config` | Show current configuration |
| `cipher-ai config set groq-api-key <key>` | Set API key in config |
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
| `/ci --format json` | CI → JSON output |
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

**`sbom`** generates Software Bill of Materials in **CycloneDX** (default) or **SPDX** formats. Parses all dependency manifests and produces a JSON document listing every dependency with its ecosystem and version.

**`report`** aggregates findings from all scanners, computes a 0–100 security score, and outputs terminal, markdown, or JSON reports.

**`attack`** connects isolated findings into **8 attack chain types**: privilege escalation, data exfiltration, remote code execution, authentication bypass, cryptographic breach, information disclosure, supply chain attack, and credential theft. Each chain shows the end-to-end attack path.

**`fix`** sends vulnerable code to the AI, which returns a secure replacement with a colored diff. Supports `--dry-run` for preview, `--list` to see fixable findings, `--risk` for severity filtering, `--id` for targeted fixing, and `--all -y` for unattended batch fixing.

**`config`** manages your API key, default AI model, and other settings. No environment variables needed after initial setup.

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

Your code stays local. Only retrieved code chunks are sent to the LLM when using `ask`, `review --ai`, `zeroday --ai`, `attack`, or `fix`. Use a local endpoint (Ollama, vLLM) for zero data egress.

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
│   ├── groq.rs       # Groq AI client
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
