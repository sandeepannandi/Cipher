# Pinned repository gate

Cipher's precision and recall claims rest on scans of third-party repositories pinned by commit. This directory makes those scans repeatable in CI instead of a local procedure.

- `manifest.json`: the ten benchmark repositories (url + commit SHA).
- `ledger.json`: 86 labeled (file, line) pairs, the findings each benchmark's ground truth says must exist. A pair missing from a scan fails the gate, and `--update` refuses to write expected data that drops one.
- `expected/<repo>.tsv`: every finding Cipher currently reports for that repository as `path<TAB>line<TAB>title`. The scan must equal this file exactly. Any added, removed or retitled finding fails the gate until the change is committed here, so it shows up as a data diff in the pull request that caused it.
- `production.json` and `production-expected/`: the same comparison for the 12 pinned production repositories, run weekly and on demand by `.github/workflows/production-baseline.yml`. Guava is included now that throughput issue #149 is fixed (about 5.5 minutes). A repo can be skipped by adding a `skip` reason to its entry.

Run locally:

    python3 benchmarks/pinned/check.py --cipher ./target/release/cipher-ai --suite benchmark

Regenerate after an intended change (review the diff before committing):

    python3 benchmarks/pinned/check.py --cipher ./target/release/cipher-ai --suite benchmark --update

Do not edit `ledger.json` to make a failing gate pass. Changing a label needs the ground-truth evidence (the app's own tutorial, README or source comment) in the pull request description.
- `production-triage.json`: a verdict (TP, FP, JUDGMENT) and a reason for each key in `production-expected/`, from reading the pinned source. `test_triage.py` keeps it in step with the expected files. It records precision; it does not change what the gate compares.
