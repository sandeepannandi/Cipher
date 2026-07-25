<div align="center">

# Cipher

**AI security analysis for your codebase — from your terminal.**

[![Rust](https://img.shields.io/badge/Rust-1.85+-orange?logo=rust&logoColor=white)]()
[![Groq](https://img.shields.io/badge/Groq-API-10B981?logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48Y2lyY2xlIGN4PSIxMiIgY3k9IjEyIiByPSIxMiIgZmlsbD0id2hpdGUiLz48L3N2Zz4=&color=10B981)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)]()

</div>

Cipher indexes your codebase, then lets you ask security questions and scan for secrets — powered by Groq AI.

```sh
cipher init                    # Index your project
cipher ask "Find auth flaws"   # Ask security questions (uses AI)
cipher secrets                  # Scan for leaked credentials
cipher status                   # Show index health
```

## Quick start

```sh
# Prerequisites: Rust 1.85+ and a free Groq API key (console.groq.com)

git clone https://github.com/sandeepannandi/Cipher.git
cd Cipher
export GROQ_API_KEY=gsk_your_key_here
cargo build --release
./target/release/cipher init
./target/release/cipher ask "Are there any security vulnerabilities?"
```

## How it works

1. **`cipher init`** walks your project (respecting `.gitignore`), reads supported source files, splits them into chunks, and builds a TF-IDF index stored in `.cipher/`. No external database required.

2. **`cipher ask "..."`** tokenizes your question, finds the most relevant code chunks via TF-IDF scoring, and sends them to Groq's LLM (`llama-3.3-70b-versatile` by default) with a security-focused prompt. Answers reference specific files and line numbers.

3. **`cipher secrets`** scans for 25+ credential patterns (AWS keys, GitHub tokens, Stripe keys, JWT tokens, DB connection strings, private keys, etc.) with severity classification. Supports `--format json` and `--fail-on-secret` for CI/CD.

4. **`cipher status`** displays index stats and API key status.

**Privacy:** Your code stays local. Only retrieved code chunks are sent to Groq when you ask a question.

## Supported languages

30+ languages: Rust, JavaScript, TypeScript, Python, Go, Ruby, Java, Kotlin, Swift, C/C++, C#, PHP, Shell, YAML, JSON, TOML, SQL, HTML, CSS, Dart, and more.

## Roadmap

- **v0.2** — Hybrid scanning (Semgrep + AI), dependency vulnerability checks, report generation
- **v0.3** — Attack path analysis, auto-fix generation
- **v1.0** — IDE extensions, GitHub PR reviews, team dashboard

## License

MIT — see [LICENSE](LICENSE).
