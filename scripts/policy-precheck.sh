#!/usr/bin/env bash
# Local precheck for the CI policy gate.
#
# pr-review.yml and security-watch.yml run `cipher-ai review --fail-on-policy`
# over the repository (minus the intentionally vulnerable benchmarks/accuracy
# corpus) and fail when new or expired findings meet the gate thresholds. This
# script runs the same check locally against the current working tree, including
# uncommitted changes, so a policy failure is caught before push.
#
# Usage: scripts/policy-precheck.sh
# Env:   CIPHER_AI_BIN - path to a prebuilt cipher-ai binary
#        (default: target/release/cipher-ai, built on demand)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${CIPHER_AI_BIN:-$repo_root/target/release/cipher-ai}"

if [ ! -x "$binary" ]; then
  echo "building release binary (cargo build --release --locked)..."
  cargo build --release --locked --manifest-path "$repo_root/Cargo.toml"
fi

# Scan a copy of the working tree so the run matches the CI boundary:
# benchmarks/accuracy is excluded there, and .git/target add no source signal.
scan_dir="$(mktemp -d)"
trap 'rm -rf "$scan_dir"' EXIT
if command -v rsync >/dev/null 2>&1; then
  rsync -a --exclude=.git --exclude=target --exclude=benchmarks/accuracy \
    "$repo_root/" "$scan_dir/"
else
  (cd "$repo_root" && tar --exclude=.git --exclude=target \
    --exclude=benchmarks/accuracy -cf - .) | (cd "$scan_dir" && tar xf -)
fi

echo "scanning working tree with --fail-on-policy..."
if "$binary" review --max-findings 0 --fail-on-policy --path "$scan_dir"; then
  echo "policy precheck passed: no new or expired gate-eligible findings"
else
  status=$?
  echo "policy precheck FAILED: new or expired findings meet the gate thresholds" >&2
  echo "fix the findings, or accept them with review --write-policy-baseline after inspection" >&2
  exit "$status"
fi
