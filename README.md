<div align="center">

# Cipher

**AI security analysis for your codebase — from your terminal.**

[![Rust](https://img.shields.io/badge/Rust-1.85+-orange?logo=rust&logoColor=white)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)]()

</div>

Cipher indexes your codebase, scans for vulnerabilities and secrets, discovers attack paths, and generates AI-powered fixes — all from your terminal. Includes both a CLI and an interactive TUI.

---

## Quick start

### CLI mode

```sh
git clone https://github.com/sandeepannandi/Cipher.git
cd Cipher
export GROQ_API_KEY=gsk_your_key_here
cargo build --release
./target/release/cipher init
./target/release/cipher ask "Are there any security vulnerabilities?"
```

**Prerequisites:** Rust 1.85+ and a Groq API key (set via `GROQ_API_KEY` env or `.env` file).

### TUI mode (interactive chat)

```sh
cd Cipher/tui
npm install && npm run build
node bin/cipher.js
```

Or install globally:

```sh
npm install -g @cipher/security
cipher
```

Inside the TUI, type `/help` to see all commands, or just ask a question naturally.

---

## CLI Commands

| Command | Description |
|---|---|
| `cipher init` | Index your codebase |
| `cipher ask "..."` | Ask security questions about your code |
| `cipher review` | Scan for OWASP Top 10 vulnerabilities |
| `cipher review --ai` | Same + AI-powered deep analysis |
| `cipher deps` | Check dependencies for known vulnerabilities |
| `cipher deps --online` | Same + OSV.dev API for full CVE coverage |
| `cipher secrets` | Scan for leaked credentials (25+ patterns) |
| `cipher status` | Show index health and API key status |
| `cipher report` | Generate report (terminal / markdown / json) |
| `cipher attack` | Discover attack chains from findings |
| `cipher fix --list` | List fixable findings |
| `cipher fix --id <UUID>` | Generate and apply an AI-powered fix |

---

## TUI Commands (inside the interactive chat)

| Command | Description |
|---|---|
| `/help` | Show help screen |
| `/init` | Index your codebase |
| `/init --force` | Re-index |
| `/review` | Run security review |
| `/review --ai` | Review with AI deep analysis |
| `/deps` | Check dependency vulnerabilities |
| `/deps --online` | Check with OSV.dev API |
| `/secrets` | Scan for secrets |
| `/ask <question>` | Ask a security question |
| `/report` | Generate security report |
| `/fix --list` | List fixable findings |
| `/attack` | Analyze attack paths |
| `/status` | Show index and API key status |
| `/clear` | Clear chat messages |
| `/exit` | Exit the TUI |
| `? plain text` | Ask naturally (no / needed) |

---

## How it works

**`init`** walks your project (respecting `.gitignore`), reads source files, splits them into chunks, and builds a TF-IDF index stored in `.cipher/`. No external database required.

**`ask`** tokenizes your question, finds relevant code chunks via TF-IDF scoring, and sends them to your LLM with a security prompt. Answers reference specific files and lines.

**`review`** scans every file against 20+ OWASP Top 10 vulnerability patterns (SQL injection, XSS, weak crypto, hardcoded creds, CORS, etc.). Optionally runs AI-powered deep analysis.

**`deps`** parses `Cargo.toml`, `package.json`, and `requirements.txt`, checking against an embedded advisory database. The `--online` flag queries OSV.dev API.

**`secrets`** matches 25+ credential patterns (AWS keys, GitHub tokens, Stripe, JWT, private keys, DB strings) with severity classification.

**`report`** aggregates findings from review, deps, and secrets into a single report with three formats: terminal, markdown, and JSON. Includes a 0–100 security score.

**`attack`** connects isolated findings into realistic attack chains. Eight chain types: privilege escalation, data exfiltration, credential theft, RCE, and more.

**`fix`** sends vulnerable code with surrounding context to the AI, which returns a secure replacement. Shows a colored diff before applying.

**TUI** wraps all CLI commands in an interactive chat interface. Type `/` commands or ask questions in plain English. Built with Ink (React for CLIs).

---

## Supported languages

30+ languages: Rust, JavaScript, TypeScript, Python, Go, Ruby, Java, Kotlin, Swift, C/C++, C#, PHP, Shell, YAML, JSON, TOML, SQL, and more.

---

## Privacy

Your code stays local. Only retrieved code chunks are sent to the LLM when you use `ask`, `review --ai`, `attack`, or `fix`. Set `API_BASE_URL` to a local endpoint (Ollama, vLLM, llama.cpp) for zero data egress.

---

## Project structure

```
Cipher/
├── src/              # Rust CLI source
├── tui/              # Node.js TUI (Ink/React)
│   ├── bin/cipher.js # Entry point
│   ├── src/          # TUI source
│   │   ├── index.jsx       # Main app
│   │   ├── components/     # UI components
│   │   │   ├── ChatArea.jsx
│   │   │   ├── InputBox.jsx
│   │   │   ├── Message.jsx
│   │   │   ├── StatusBar.jsx
│   │   │   ├── CommandHelp.jsx
│   │   ├── commands/runner.js  # Rust binary bridge
│   │   └── utils/binary.js     # Binary path discovery
│   └── postinstall.js  # Binary download on npm install
├── .github/workflows/release.yml  # Builds binaries for all platforms
└── Cargo.toml
```

---

## Roadmap

- **v0.2** — Hybrid scanning, dependency checks, report generation ✅
- **v0.3** — Attack path analysis, auto-fix generation ✅
- **v1.0** — IDE extensions, GitHub PR reviews, team dashboard

---

## License

MIT — see [LICENSE](LICENSE).
