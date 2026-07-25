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
# Prerequisites: Rust 1.85+ and an AI API key (Groq, OpenAI, Anthropic, or local endpoint)

git clone https://github.com/sandeepannandi/Cipher.git
cd Cipher
export API_KEY=your_key_here
export API_BASE_URL=https://api.groq.com/openai/v1  # or your preferred provider
cargo build --release
./target/release/cipher init
./target/release/cipher ask "Are there any security vulnerabilities?"
```

## Why this project is needed

Modern AI coding assistants (Copilot, Cursor, Cody, etc.) are excellent at understanding code context and helping you write and navigate code. However, security analysis is a fundamentally different challenge:

- **Security requires systematic analysis.** AI assistants excel at answering questions about the code you're currently viewing, but they don't run systematic scans across your entire codebase for vulnerability patterns.
- **Security requires specialized knowledge.** Identifying an SQL injection, an auth bypass, or a cryptographic flaw requires deep security domain expertise — not just code reasoning.
- **Security requires persistent indexing.** Every time you ask an AI assistant a question, it rebuilds context from scratch. Cipher maintains a persistent, queryable index of your codebase that enables fast, reproducible security analysis.
- **Traditional SAST tools** (Semgrep, CodeQL, SonarQube) generate thousands of findings. Most are false positives. Teams spend more time triaging than fixing.
- **Security engineers** are scarce and expensive. Most teams cannot afford dedicated AppSec engineers, leaving vulnerabilities undiscovered until they reach production.

Cipher fills this gap — it is a **specialized security agent** designed from the ground up for codebase-wide vulnerability analysis, not general-purpose code assistance.

1. Indexes your entire codebase once, then answers instantly.
2. Answers questions with citations to actual lines of code.
3. Lets you choose the AI model — your data, your provider, your rules (BYOK).
4. Runs in your terminal — no web dashboards, no CI/CD setup required.
5. Built specifically for security: secret scanning, vulnerability analysis, attack path reasoning.

## How it works

1. **`cipher init`** walks your project (respecting `.gitignore`), reads supported source files, splits them into chunks, and builds a TF-IDF index stored in `.cipher/`. No external database required.

2. **`cipher ask "..."`** tokenizes your question, finds the most relevant code chunks via TF-IDF scoring, and sends them to your configured LLM provider with a security-focused prompt. Answers reference specific files and line numbers.

3. **`cipher secrets`** scans for 25+ credential patterns (AWS keys, GitHub tokens, Stripe keys, JWT tokens, DB connection strings, private keys, etc.) with severity classification. Supports `--format json` and `--fail-on-secret` for CI/CD.

4. **`cipher status`** displays index stats and API key status.

**Bring your own key (BYOK).** Cipher supports any OpenAI-compatible API provider — you choose the model that fits your needs: Groq for speed, OpenAI for breadth, Anthropic for depth, or a local endpoint (Ollama, vLLM, llama.cpp) for zero data egress. Set your provider's endpoint and key via environment variables.

**Privacy:** Your code stays local. Only the retrieved code chunks are sent to the LLM provider when you ask a question. With a future local endpoint, your code never leaves your machine.

## Supported languages

30+ languages: Rust, JavaScript, TypeScript, Python, Go, Ruby, Java, Kotlin, Swift, C/C++, C#, PHP, Shell, YAML, JSON, TOML, SQL, HTML, CSS, Dart, and more.

## Roadmap

- **v0.2** — Hybrid scanning (Semgrep + AI), dependency vulnerability checks, report generation
- **v0.3** — Attack path analysis, auto-fix generation
- **v1.0** — IDE extensions, GitHub PR reviews, team dashboard

## License

MIT — see [LICENSE](LICENSE).
