<!-- Improved compatibility of back to top link -->
<a id="readme-top"></a>

<!--
*** Cipher — AI-Powered Security Agent
*** Based on the Best-README-Template by othneildrew
-->

<!-- PROJECT SHIELDS -->
<div align="center">

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![Rust][rust-shield]][rust-url]
[![LinkedIn][linkedin-shield]][linkedin-url]

</div>

<br />

<!-- PROJECT LOGO -->
<div align="center">
  <a href="#">
    <!-- Replace with your project logo -->
    <img src="images/logo.png" alt="Cipher Logo" width="120" height="120" style="border-radius: 20px;">
  </a>

  <h1 align="center" style="font-weight: 700; letter-spacing: -0.5px;">Cipher</h1>

  <p align="center">
    Your AI Security Engineer — an autonomous agent that reviews, attacks, explains, and fixes security vulnerabilities in your codebase.
    <br />
    <br />
    <a href="#-usage"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="#-getting-started">Quick Start</a>
    ·
    <a href="#-roadmap">Roadmap</a>
    ·
    <a href="#-contributing">Contributing</a>
  </p>
</div>

<br />

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#-about-the-project">About The Project</a>
      <ul>
        <li><a href="#how-it-works">How It Works</a></li>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#-getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#-usage">Usage</a></li>
    <li>
      <a href="#-commands">Commands</a>
      <ul>
        <li><a href="#cipher-init"><code>cipher init</code></a></li>
        <li><a href="#cipher-ask"><code>cipher ask</code></a></li>
        <li><a href="#cipher-secrets"><code>cipher secrets</code></a></li>
        <li><a href="#cipher-status"><code>cipher status</code></a></li>
      </ul>
    </li>
    <li><a href="#-roadmap">Roadmap</a></li>
    <li><a href="#-contributing">Contributing</a></li>
    <li><a href="#-license">License</a></li>
    <li><a href="#-contact">Contact</a></li>
    <li><a href="#-acknowledgments">Acknowledgments</a></li>
  </ol>
</details>

---

## 🚀 About The Project

<p align="center">
  <!-- Replace with a CLI demo screenshot/recording -->
  <img src="images/screenshot.png" alt="Cipher CLI Screenshot" width="800" style="border-radius: 8px;">
</p>

**Cipher** is an AI security agent that lives in your terminal. It understands your entire codebase, identifies meaningful security vulnerabilities, explains their impact, and helps you fix them — all without sending your code to the cloud until you ask a question.

Unlike traditional static analysis tools that drown you in false positives, Cipher uses **retrieval-augmented generation (RAG)** with **Groq's ultra-fast AI inference** to deliver precise, context-aware security insights. It doesn't just find bugs — it thinks like a security engineer.

### Why Cipher?

- **Traditional SAST tools** (Semgrep, CodeQL, SonarQube) generate thousands of findings — most are noise.
- **AI code assistants** (GitHub Copilot, ChatGPT) have no persistent understanding of your codebase.
- **Security engineers** are expensive and bottlenecks are everywhere.

Cipher bridges the gap: an **autonomous AI security engineer** that:
1. Indexes your entire codebase with semantic understanding
2. Answers security questions with grounded, line-level citations
3. Scans for hardcoded secrets and exposed credentials
4. Prioritizes findings by severity, exploitability, and business impact

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### How It Works

```
                         ┌──────────────────┐
                         │   Your Codebase  │
                         │   (local, safe)  │
                         └────────┬─────────┘
                                  │
                         ┌────────▼─────────┐
                         │  ▸ cipher init   │
                         │                  │
                         │  Walk files      │
                         │  Chunk code      │
                         │  Build TF-IDF    │
                         │  Store .cipher/  │
                         └────────┬─────────┘
                                  │
                ┌─────────────────┼──────────────────┐
                │                 │                  │
      ┌─────────▼───────┐ ┌──────▼──────┐ ┌────────▼──────┐
      │  ▸ cipher ask   │ │cipher secrets│ │cipher status  │
      │                 │ │             │ │               │
      │  "Find auth    │ │ Scan 25+    │ │ Index health  │
      │   bypasses"    │ │ secret types│ │ & config info │
      └─────────┬───────┘ └─────────────┘ └───────────────┘
                │
      ┌─────────▼──────────────────┐
      │  Groq AI (ultra-fast)      │
      │                             │
      │  ┌─────────────────────┐   │
      │  │ 1. Retrieve chunks  │   │
      │  │ 2. Build context    │   │
      │  │ 3. Analyze with LLM │   │
      │  │ 4. Return answer    │   │
      │  └─────────────────────┘   │
      └────────────────────────────┘
```

**Privacy-first by design.** Your source code stays on your machine. Only the retrieved code chunks — a small fraction of your codebase — are sent to Groq when you ask a question.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

<div align="center">

[![Rust][rust-badge]][rust-url]
[![Groq][groq-badge]][groq-url]
[![Clap][clap-badge]][clap-url]
[![Tokio][tokio-badge]][tokio-url]
[![Serde][serde-badge]][serde-url]

</div>

- **Core Language:** [Rust](https://www.rust-lang.org/) — performance, safety, and a single static binary
- **AI Runtime:** [Groq](https://groq.com) — lightning-fast LLM inference (up to 1,000+ tokens/sec)
- **CLI Framework:** [Clap](https://github.com/clap-rs/clap) — ergonomic command-line argument parsing
- **Async Runtime:** [Tokio](https://tokio.rs) — asynchronous I/O for concurrent scanning
- **Serialization:** [Serde](https://serde.rs) — robust data serialization
- **TF-IDF Indexing:** Custom implementation — zero external dependencies for search
- **File Walking:** [ignore](https://github.com/BurntSushi/ripgrep/tree/master/crates/ignore) — gitignore-aware file traversal (from ripgrep)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## 🚦 Getting Started

Get your own AI security engineer up and running in minutes.

### Prerequisites

- **Rust** 1.85 or later — install via [rustup.rs](https://rustup.rs)
- **Groq API key** — get one free at [console.groq.com](https://console.groq.com)

### Installation

1. **Get a free Groq API key**
   ```sh
   # Sign up at https://console.groq.com
   # Your key looks like: gsk_your_api_key_here
   ```

2. **Clone the repository**
   ```sh
   git clone https://github.com/sandeepannandi/cipher.git
   cd cipher
   ```

3. **Build the binary**
   ```sh
   cargo build --release
   ```

4. **Set your API key**
   ```sh
   export GROQ_API_KEY=gsk_your_api_key_here
   ```

5. **Verify the installation**
   ```sh
   ./target/release/cipher --help
   ```

6. **(Optional) Install globally**
   ```sh
   cargo install --path .
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## ⚡ Usage

Once installed, Cipher works in four simple steps:

### 1. Index Your Codebase

```sh
cipher init
```

This walks your project (respecting `.gitignore`), reads all supported source files, splits them into intelligently-sized code chunks, builds a TF-IDF search index, and saves everything to `.cipher/`.

```sh
cipher init ./path/to/project  # Index a specific project
cipher init --force            # Re-index from scratch
```

### 2. Ask Security Questions

```sh
cipher ask "Are there any authentication bypass vulnerabilities in the API?"
cipher ask "Where are API keys or secrets hardcoded?"
cipher ask "Is the payment flow secure against manipulation?"
cipher ask -n 20 "Analyze authorization logic in detail"  # Retrieve more context
cipher ask -m llama-3.1-8b-instant "Quick security audit"   # Use a faster model
```

Cipher retrieves the most relevant code chunks and sends them to Groq for analysis. Every answer is **grounded in your actual code** with file names and line numbers.

### 3. Scan for Secrets

```sh
cipher secrets
```

Detects 25+ types of hardcoded credentials:

| Severity | Examples |
|----------|---------|
| 🔴 **CRITICAL** | AWS secret keys, GitHub tokens, Stripe live keys, Google service accounts |
| 🟡 **HIGH** | AWS access keys, Google API keys, database connection strings, private keys |
| 🔵 **MEDIUM** | JWT tokens, passwords in code, generic secrets |
| ⚪ **LOW** | Stripe test keys, npm tokens |

```sh
cipher secrets --format json           # Machine-readable output for CI/CD
cipher secrets --fail-on-secret        # Exit with code 1 if secrets found
```

### 4. Check Status

```sh
cipher status
```

Displays index health, file counts, language distribution, and API key configuration.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## 📖 Commands

### `cipher init`

Index your codebase for AI-powered security analysis.

```
Usage: cipher init [OPTIONS] [PATH]

Arguments:
  [PATH]  Path to the project to index

Options:
  -f, --force  Force re-index even if already indexed
  -h, --help   Print help
```

**Supported languages (30+):** Rust, JavaScript, TypeScript, Python, Go, Ruby, Java, Kotlin, Swift, C, C++, C#, PHP, Shell, YAML, JSON, TOML, SQL, GraphQL, Protocol Buffers, Vue, Svelte, HTML, CSS, Dart, Scala, Lua, R, and more.

### `cipher ask`

Ask any security question about your codebase. Cipher retrieves relevant code and generates an expert analysis.

```
Usage: cipher ask [OPTIONS] <QUERY>...

Arguments:
  <QUERY>...  Your security question

Options:
  -n, --top-n <TOP_N>  Number of code chunks to retrieve [default: 10]
  -m, --model <MODEL>  Groq model to use (e.g., llama-3.3-70b-versatile)
  -h, --help            Print help
```

**Example questions:**
- *"Can users escalate privileges?"*
- *"Where is authentication implemented and is it secure?"*
- *"Find SQL injection vulnerabilities in the checkout flow"*
- *"Explain the OAuth flow and identify potential weaknesses"*
- *"What should I fix first, prioritized by risk?"*

### `cipher secrets`

Scan for exposed credentials and sensitive configuration.

```
Usage: cipher secrets [OPTIONS] [PATH]

Arguments:
  [PATH]  Path to scan

Options:
  -f, --format <FORMAT>  Output format [default: pretty] [possible values: pretty, json, compact]
      --fail-on-secret   Exit with error code if secrets found (CI/CD)
  -h, --help             Print help
```

### `cipher status`

Display index status and configuration.

```
Usage: cipher status [OPTIONS]

Options:
  -p, --path <PATH>  Path to the project directory
  -h, --help         Print help
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## 🗺️ Roadmap

### v0.1 — Current
- ✅ CLI with `init`, `ask`, `secrets`, `status` commands
- ✅ Git-aware file indexing with TF-IDF search
- ✅ Groq-powered AI security analysis (RAG)
- ✅ Secret detection (25+ patterns)
- ✅ Privacy-first local architecture

### v0.2 — Coming Soon
- [ ] `cipher scan` — Hybrid vulnerability detection (Semgrep rules + AI reasoning)
- [ ] Dependency vulnerability scanning (OSV, CVE lookup)
- [ ] JSON/PDF report generation
- [ ] GitHub Actions CI/CD integration

### v0.3
- [ ] Attack path analysis — graph-based vulnerability chaining
- [ ] Auto-fix generation with secure patch previews
- [ ] Multi-repo scanning

### v1.0
- [ ] VS Code extension
- [ ] GitHub App for automated PR reviews
- [ ] Team dashboard with aggregated metrics
- [ ] Custom rule creation via natural language

See the [open issues](https://github.com/sandeepannandi/cipher/issues) for a full list of proposed features and known issues.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make Cipher better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".

Don't forget to give the project a star ⭐ — it helps others discover Cipher!

1. **Fork** the Project
2. **Create** your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your Changes (`git commit -m 'Add some AmazingFeature'`)
4. **Push** to the Branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

For more details, see [CONTRIBUTING.md](CONTRIBUTING.md).

### Top Contributors

<a href="https://github.com/your-org/cipher/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=your-org/cipher" alt="contributors" />
</a>

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## 📬 Contact

Maintainer: [@your_handle](https://twitter.com/your_handle) — email@example.com

Project Link: [https://github.com/sandeepannandi/cipher](https://github.com/sandeepannandi/cipher)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## 🙏 Acknowledgments

- [Best-README-Template](https://github.com/othneildrew/Best-README-Template) — README structure inspiration
- [Groq](https://groq.com) — Ultra-fast AI inference API
- [Clap](https://github.com/clap-rs/clap) — Rust CLI framework
- [Ripgrep](https://github.com/BurntSushi/ripgrep) — Git-aware file walking (ignore crate)
- [Semgrep](https://semgrep.dev) — Open-source static analysis (future integration)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

<!-- MARKDOWN LINKS & IMAGES -->
<!-- Replace sandeepannandi with your GitHub organization/username -->
[contributors-shield]: https://img.shields.io/github/contributors/sandeepannandi/cipher.svg?style=for-the-badge&logo=github&color=2ea44f
[contributors-url]: https://github.com/sandeepannandi/cipher/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/sandeepannandi/cipher.svg?style=for-the-badge&logo=github
[forks-url]: https://github.com/sandeepannandi/cipher/network/members
[stars-shield]: https://img.shields.io/github/stars/sandeepannandi/cipher.svg?style=for-the-badge&logo=github&color=gold
[stars-url]: https://github.com/sandeepannandi/cipher/stargazers
[issues-shield]: https://img.shields.io/github/issues/sandeepannandi/cipher.svg?style=for-the-badge&logo=github&color=red
[issues-url]: https://github.com/sandeepannandi/cipher/issues
[license-shield]: https://img.shields.io/github/license/sandeepannandi/cipher.svg?style=for-the-badge&logo=github&color=blue
[license-url]: https://github.com/sandeepannandi/cipher/blob/main/LICENSE
[rust-shield]: https://img.shields.io/badge/Rust-1.85+-orange?style=for-the-badge&logo=rust&logoColor=white
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/company/sandeepannandi
[rust-url]: https://www.rust-lang.org/

<!-- Technology Badges -->
[rust-badge]: https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white
[rust-url]: https://www.rust-lang.org/
[groq-badge]: https://img.shields.io/badge/Groq-10B981?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48Y2lyY2xlIGN4PSIxMiIgY3k9IjEyIiByPSIxMiIgZmlsbD0id2hpdGUiLz48L3N2Zz4=&color=10B981
[groq-url]: https://groq.com/
[clap-badge]: https://img.shields.io/badge/Clap-4.x-8B5CF6?style=for-the-badge&logo=rust&logoColor=white
[clap-url]: https://github.com/clap-rs/clap
[tokio-badge]: https://img.shields.io/badge/Tokio-1.x-FF6B6B?style=for-the-badge&logo=rust&logoColor=white
[tokio-url]: https://tokio.rs
[serde-badge]: https://img.shields.io/badge/Serde-1.x-3B82F6?style=for-the-badge&logo=rust&logoColor=white
[serde-url]: https://serde.rs
