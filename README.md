<div align="center">

# Cipher

**AI security analysis for your codebase — from your terminal.**

[![Rust](https://img.shields.io/badge/Rust-1.85+-orange?logo=rust&logoColor=white)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)]()

</div>

Cipher indexes your codebase, then lets you ask security questions and scan for secrets — powered by the AI model of your choice.

```sh
cipher init                    # Index your project
cipher ask "Find auth flaws"   # Ask security questions (uses AI)
cipher secrets                  # Scan for leaked credentials
cipher status                   # Show index health
```

## Quick start

```sh
# Prerequisites: Rust 1.85+ and a Groq API key (free at console.groq.com)

git clone https://github.com/sandeepannandi/Cipher.git
cd Cipher
export GROQ_API_KEY=gsk_your_key_here
cargo build --release
./target/release/cipher init
./target/release/cipher ask "Are there any security vulnerabilities?"
```

## Why this project is needed

Traditional security tools fall short in three ways:

- **Static analyzers** (Semgrep, CodeQL, SonarQube) generate thousands of findings. Most are false positives. Teams spend more time triaging than fixing.
- **AI code assistants** (Copilot, ChatGPT) have no persistent understanding of your codebase. They answer in isolation, without the full context of your project.
- **Security engineers** are scarce and expensive. Most teams cannot afford dedicated AppSec engineers, leaving vulnerabilities undiscovered until they reach production.

Cipher exists because teams need a **practical, autonomous security engineer** that:

1. Understands your entire codebase — not just individual files.
2. Answers questions with citations to actual lines of code.
3. Lets you choose the AI model — your data, your provider, your rules.
4. Runs in your terminal — no web dashboards, no CI/CD setup required.
5. Fits into existing workflows — just `cipher init` and start asking.

It is designed for developers who want security feedback *now*, not after a lengthy scan pipeline.

## How it works

1. **`cipher init`** walks your project (respecting `.gitignore`), reads supported source files, splits them into chunks, and builds a TF-IDF index stored in `.cipher/`. No external database required.

2. **`cipher ask "..."`** tokenizes your question, finds the most relevant code chunks via TF-IDF scoring, and sends them to your configured LLM provider with a security-focused prompt. Answers reference specific files and line numbers.

3. **`cipher secrets`** scans for 25+ credential patterns (AWS keys, GitHub tokens, Stripe keys, JWT tokens, DB connection strings, private keys, etc.) with severity classification. Supports `--format json` and `--fail-on-secret` for CI/CD.

4. **`cipher status`** displays index stats and API key status.

**Bring your own key (BYOK) — coming in v0.2.** Cipher will be provider-agnostic, letting you use Groq, OpenAI, Anthropic, or any OpenAI-compatible endpoint (including local models via Ollama, vLLM, or llama.cpp). For now, Cipher requires a Groq API key set via `GROQ_API_KEY`.

**Privacy:** Your code stays local. Only the retrieved code chunks are sent to the LLM provider when you ask a question. With a future local endpoint, your code never leaves your machine.

## Supported languages

30+ languages: Rust, JavaScript, TypeScript, Python, Go, Ruby, Java, Kotlin, Swift, C/C++, C#, PHP, Shell, YAML, JSON, TOML, SQL, HTML, CSS, Dart, and more.

## Roadmap

- **v0.2** — Hybrid scanning (Semgrep + AI), dependency vulnerability checks, report generation
- **v0.3** — Attack path analysis, auto-fix generation
- **v1.0** — IDE extensions, GitHub PR reviews, team dashboard

## License

MIT — see [LICENSE](LICENSE).
