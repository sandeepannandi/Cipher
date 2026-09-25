# Contributing to CipherAI

Thank you for your interest in contributing to CipherAI! We welcome all contributions — bug reports, feature requests, documentation improvements, and code changes.

## Getting Started

1. Fork the repository and clone your fork.
2. Ensure you have Rust 1.88+ installed (`rustup update`).
3. Set `GROQ_API_KEY` in your environment.
4. Run `cargo build` to verify your setup.

## Development Workflow

```bash
# Build
cargo build

# Run
cargo run -- init
cargo run -- ask "test query"

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt --check
```

## Policy gate precheck

Pull requests and the nightly scan enforce a policy gate (`review --fail-on-policy`): findings that are not in the accepted `.cipher-ai-policy.yml` baseline (or whose suppression expired) fail CI. Run the same check locally before pushing:

```bash
bash scripts/policy-precheck.sh
```

The script builds the release binary if needed, scans a copy of the working tree (excluding `.git/`, `target/`, and the intentionally vulnerable `benchmarks/accuracy/` corpus, matching the CI boundary), and exits non-zero with the offending fingerprints when the gate would fail.

## Pull Request Guidelines

- Keep changes focused and atomic. One feature/fix per PR.
- Add tests for new functionality when possible.
- Update CHANGELOG.md with your changes under the `[Unreleased]` section.
- Run `cargo clippy` and ensure no new warnings.
- Describe your changes clearly in the PR description.

## Code Style

- Follow standard Rust formatting (`cargo fmt`).
- Use meaningful variable names and document public APIs.
- Prefer `anyhow::Result` for fallible functions.
- Use `tracing` for debug logging, `colored` for user-facing output.

## Reporting Issues

- Use the GitHub issue tracker.
- Include the output of `cipher-ai status` and your Rust version.
- Provide steps to reproduce the issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
