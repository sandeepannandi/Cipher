# Contributing to CipherAI

Thank you for your interest in contributing to CipherAI! We welcome all contributions — bug reports, feature requests, documentation improvements, and code changes.

## Getting Started

1. Fork the repository and clone your fork.
2. Ensure you have Rust 1.85+ installed (`rustup update`).
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
