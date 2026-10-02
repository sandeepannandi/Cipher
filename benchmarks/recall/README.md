# Advisory recall (pinned pre-fix commits)

Answers one question: how many real, published vulnerabilities does Cipher flag in the code as it was before the fix?

- `manifest.json`: GitHub advisories with a public fix commit. `pre_fix` is the fix commit's first parent; that exact tree is scanned.
- `labels.json`: one entry per vulnerable sink line, chosen by hand from the fix diff (old-file line numbers). Not every vulnerable line is labeled.
- `results.json`: recorded outcome per label with the current binary. HIT = a finding on that file:line, NEAR = within 3 lines, MISS = none.
- `unlabeled.json`: advisories harvested but not scored, because the diff has no single clear sink line (guards added, refactors, validation changes) or the project is too large to label reliably. They are listed, not hidden.
- `recall.py`: recomputes everything from fresh pinned clones. `--check` fails only if a recorded HIT is lost. Misses never fail it and are not tuned away.

Source: https://api.github.com/advisories (reviewed, high/critical, fix commit referenced). Repos are cloned at the pinned SHA and statically scanned; nothing from them is executed.

Run: `python3 benchmarks/recall/recall.py --cipher target/release/cipher-ai --check`
