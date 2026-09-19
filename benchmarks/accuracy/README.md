# Accuracy benchmark

A small deterministic baseline for Cipher's pattern scanner. It uses isolated Python, JavaScript, and Rust fixtures so each expected finding is attributable to one case. Positive cases cover known CWE classes; negative controls measure obvious false positives.

## Run

```bash
python3 benchmarks/accuracy/run.py --cipher ./target/release/cipher-ai
```

The command writes `benchmarks/accuracy/results/latest.json` and exits non-zero if any expected vulnerability is missed or any negative control is flagged.

This baseline is intentionally small. It measures the deterministic `review` path, not AI verification, interprocedural data flow, dependency scanning, or real-world precision. Expand it with pinned public benchmark subsets after stable rule IDs and line-level expected-result matching are in place.
