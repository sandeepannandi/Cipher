# Accuracy benchmark

A deterministic baseline for Cipher's review pipeline. It keeps the corpus stripped to isolated source files so each expected result is attributable to a single case. The benchmark intentionally stays in the benchmark layer only and does not alter scanner behavior.

## Schema

The manifest uses schema version 2 and records metadata for each case:

- `family`: `handpicked`, `extracted`, `mutation`, or `control`
- `vulnerability_class`: the canonical class used for grouping and regression checks
- `provenance`: required for non-handpicked cases; for extracted cases it includes the verified public suite page, pinned archive URL, upstream suite/version, and original ID
- `expected_title`: required for positive cases so title matching is explicit and deterministic

The extracted Java cases are small normalized/extracted CWE-pattern fixtures derived from the public Juliet Java suite, not byte-for-byte copies of upstream source files unless source-path verification was explicitly performed. This benchmark is intentionally a realism check for deterministic rule coverage, not a perfect reproduction of every upstream source artifact.

### Selected-language depth case

The JavaScript/TypeScript path-traversal cases exercise a narrow local data-flow
model: request path input, aliases or path construction, and a filesystem sink.
The clean control uses `path.basename` before construction. This was chosen over
adding more language breadth because path traversal was already a supported,
high-severity class, but its previous rule only recognized a same-line string
concatenation at `readFile`/`writeFile`.

## Run

```bash
python3 benchmarks/accuracy/run.py --cipher ./target/release/cipher-ai
```

The script validates the manifest, runs each fixture through the review path, and writes `benchmarks/accuracy/results/latest.json`. It exits non-zero if the manifest is invalid, any execution error occurs, or a configured threshold for precision/recall/F1 or execution errors is missed.

This benchmark is intentionally small. It measures the deterministic `review` path, not AI verification, interprocedural data flow, dependency scanning, or real-world precision. Expand it with pinned public benchmark subsets after stable rule IDs and line-level expected-result matching are in place.
