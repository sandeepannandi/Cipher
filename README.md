<div align="center">

# CipherAI

**AI security analysis for your codebase — from your terminal.**

[![Rust](https://img.shields.io/badge/Rust-1.85+-orange?logo=rust&logoColor=white)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)]()

</div>

CipherAI indexes your codebase, scans for vulnerabilities and secrets, discovers attack paths, and generates AI-powered fixes. Includes both a CLI and an interactive TUI.

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

## CLI Commands

| Command | Description |
|---|---|
| `cipher-ai init` | Index your codebase |
| `cipher-ai ask "..."` | Ask security questions with AI |
| `cipher-ai review` | Scan for OWASP Top 10 vulnerabilities |
| `cipher-ai review --ai` | Review with AI-powered deep analysis |
| `cipher-ai review --format sarif` | SARIF output for CI integration |
| `cipher-ai deps` | Check dependency vulnerabilities |
| `cipher-ai deps --online` | Full CVE coverage via OSV.dev API |
| `cipher-ai deps --fail-on high` | Exit with code 1 if high+ found |
| `cipher-ai secrets` | Scan for leaked credentials (25+ patterns) |
| `cipher-ai secrets --fail-on high` | Exit with code 1 if high+ found |
| `cipher-ai ci` | Run all scans (CI mode) with consolidated exit code |
| `cipher-ai ci --fail-on critical` | CI mode, fail only on critical |
| `cipher-ai report` | Generate report (terminal/markdown/json) |
| `cipher-ai attack` | Discover attack chains from findings |
| `cipher-ai fix --list` | List fixable findings |
| `cipher-ai fix --dry-run` | Preview fixes without applying |
| `cipher-ai fix --id <UUID>` | Generate and apply AI fix |
| `cipher-ai config` | Show configuration |
| `cipher-ai config set groq-api-key <key>` | Set API key |
| `cipher-ai config set default-model <model>` | Set default AI model |
| `cipher-ai status` | Show index and API key status |
| `cipher-ai completions bash` | Generate shell completions |

## TUI Commands

| Command | Description |
|---|---|
| `/help` | Show help screen |
| `/init` | Index your codebase |
| `/review --ai` | Review with AI deep analysis |
| `/deps` | Check dependency vulnerabilities |
| `/secrets` | Scan for secrets |
| `/ask <question>` | Ask a security question |
| `/report` | Generate security report |
| `/fix --list` | List fixable findings |
| `/fix --dry-run` | Preview fixes |
| `/attack` | Analyze attack paths |
| `/ci` | Run all scans (CI mode) |
| `/config` | Show or set configuration |
| `/status` | Show index and API key status |
| `/clear` | Clear chat messages |
| `/exit` | Exit |

## How it works

**`init`** walks your project (respecting `.gitignore`), reads source files, chunks code, and builds a TF-IDF index in `.cipher-ai/`. No external database required.

**`ask`** finds relevant code via TF-IDF scoring and sends it to the LLM. Answers reference specific files and lines.

**`review`** scans files against 20+ OWASP Top 10 patterns (SQL injection, weak crypto, hardcoded creds, CORS, etc.). Optionally runs AI-powered analysis.

**`deps`** parses `Cargo.toml`, `package.json`, and `requirements.txt`. Checks against an embedded advisory database. The `--online` flag queries OSV.dev API.

**`secrets`** matches 25+ credential patterns (AWS keys, GitHub tokens, Stripe, JWT, private keys) with severity classification.

**`ci`** runs review + secrets + deps in sequence with a consolidated summary and exit code — ready for CI pipelines.

**`config`** manages your API key, default model, and settings without environment variables.

**`report`** aggregates findings from all scanners into terminal, markdown, or JSON output with a 0–100 security score.

**`attack`** connects isolated findings into 8 attack chain types: privilege escalation, data exfiltration, credential theft, RCE, and more.

**`fix`** sends vulnerable code to the AI, which returns a secure replacement. Shows a colored diff before applying.

**TUI** wraps all CLI commands in an interactive chat interface. Features: command palette (`Ctrl+K`), command history (up/down arrows), Esc to cancel, keyboard-driven navigation, and real-time status.

## Supported languages

30+ languages: Rust, JavaScript, TypeScript, Python, Go, Ruby, Java, Kotlin, Swift, C/C++, C#, PHP, Shell, YAML, JSON, TOML, SQL, and more.

## Privacy

Your code stays local. Only retrieved code chunks are sent to the LLM when using `ask`, `review --ai`, `attack`, or `fix`. Use a local endpoint (Ollama, vLLM) for zero data egress.

## Project structure

```
Cipher/
├── src/              # Rust CLI source (review, deps, secrets, fix, attack, config, ci)
├── tui/              # Node.js TUI (Ink/React)
│   ├── bin/cipher-ai.js # Entry point
│   ├── src/          # TUI source
│   │   ├── index.jsx       # Main app with Esc cancel + history
│   │   ├── commands/runner.js  # Rust binary bridge with streaming
│   │   └── components/     # UI components
│   └── postinstall.js  # Binary download on npm install
├── .github/workflows/release.yml
├── Cargo.toml
└── README.md
```

## License

MIT — see [LICENSE](LICENSE).
