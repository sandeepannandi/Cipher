<div align="center">

# Cipher

**AI security analysis for your codebase — from your terminal.**

[![Rust](https://img.shields.io/badge/Rust-1.85+-orange?logo=rust&logoColor=white)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)]()

</div>

Cipher indexes your codebase, scans for vulnerabilities and secrets, discovers attack paths, and generates AI-powered fixes — all from your terminal.

---

## Quick start

```sh
git clone https://github.com/sandeepannandi/Cipher.git
cd Cipher
export GROQ_API_KEY=gsk_your_key_here
cargo build --release
./target/release/cipher init
./target/release/cipher ask "Are there any security vulnerabilities?"
```

**Prerequisites:** Rust 1.85+ and a Groq API key (set via `GROQ_API_KEY` env or `.env` file).

---

## Commands

| Command | Description |
|---|---|
| `cipher init` | Index your codebase for analysis |
| `cipher ask "..."` | Ask security questions about your code |
| `cipher review` | Scan for OWASP Top 10 vulnerabilities (20+ patterns) |
| `cipher review --ai` | Same + AI-powered deep analysis |
| `cipher deps` | Check dependencies against known vulnerabilities |
| `cipher deps --online` | Same + OSV.dev API for comprehensive CVE coverage |
| `cipher secrets` | Scan for leaked credentials (25+ patterns) |
| `cipher secrets --json` | JSON output for CI/CD |
| `cipher status` | Show index health |
| `cipher report` | Generate security report (terminal / markdown / json) |
| `cipher report --type executive` | Non-technical summary for managers |
| `cipher attack` | Discover attack chains connecting findings into scenarios |
| `cipher attack --no-ai` | Skip AI enrichment for faster results |
| `cipher attack --json` | Machine-readable output |
| `cipher fix --list` | List fixable findings |
| `cipher fix --id <UUID>` | Generate and apply an AI-powered fix |
| `cipher fix --risk critical --yes` | Auto-fix all critical issues |

---

## How it works

**`init`** walks your project (respecting `.gitignore`), reads source files, splits them into chunks, and builds a TF-IDF index stored in `.cipher/`. No external database required.

**`ask`** tokenizes your question, finds the most relevant code chunks via TF-IDF scoring, and sends them to your configured LLM with a security-focused prompt. Answers reference specific files and line numbers.

**`review`** scans every file against 20+ OWASP Top 10 vulnerability patterns (SQL injection, XSS, weak crypto, hardcoded creds, CORS, etc.). Optionally runs AI-powered deep analysis via Groq using the indexed codebase.

**`deps`** parses `Cargo.toml`, `package.json`, and `requirements.txt`, then checks against an embedded advisory database (30+ CVEs). The `--online` flag queries the OSV.dev API for comprehensive coverage.

**`secrets`** matches 25+ credential patterns (AWS keys, GitHub tokens, Stripe, JWT, private keys, DB connection strings, etc.) with severity classification. Supports `--format json` and `--fail-on-secret` for CI/CD.

**`report`** aggregates findings from review, deps, and secrets into a single report with three formats: terminal (color-coded), markdown (shareable), and JSON (CI-friendly). Includes a 0–100 security score.

**`attack`** connects isolated findings into realistic attack chains using pattern-based rules. Eight chain types: privilege escalation, data exfiltration, credential theft, RCE, supply chain, crypto breach, auth bypass, and information disclosure. Optional AI enrichment generates human-readable attack scenarios.

**`fix`** sends vulnerable code with surrounding context to the AI, which returns a secure replacement. Shows a colored diff with `-` (red) and `+` (green) lines, explains the change, and asks for confirmation before writing to disk. A ±4 line-count check prevents file corruption.

---

## Supported languages

30+ languages: Rust, JavaScript, TypeScript, Python, Go, Ruby, Java, Kotlin, Swift, C/C++, C#, PHP, Shell, YAML, JSON, TOML, SQL, and more.

---

## Privacy

Your code stays local. Only retrieved code chunks are sent to the LLM when you use `ask`, `review --ai`, `attack`, or `fix`. Set `API_BASE_URL` to a local endpoint (Ollama, vLLM, llama.cpp) for zero data egress.

---

## Roadmap

- **v0.2** — Hybrid scanning, dependency checks, report generation ✅
- **v0.3** — Attack path analysis, auto-fix generation ✅
- **v1.0** — IDE extensions, GitHub PR reviews, team dashboard

---

## License

MIT — see [LICENSE](LICENSE).
