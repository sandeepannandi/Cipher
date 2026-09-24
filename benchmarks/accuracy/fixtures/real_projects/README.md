# Pinned real-project snapshots

These fixtures are small, verbatim source snapshots from public projects that explicitly describe themselves as intentionally vulnerable. They are benchmark inputs only and are never compiled or shipped in Cipher binaries.

| Project | Commit | Files | License | Upstream |
|---|---|---|---|---|
| `kcyap/python-vuln-demo` | `30801ba7f10c55087c0ffde26a189433603270db` | `main.py` | MIT, included beside the source | https://github.com/kcyap/python-vuln-demo/tree/30801ba7f10c55087c0ffde26a189433603270db |
| `alexm-acsa/vulnerable-node-api` | `1f8fed353712940752a7bd9d7ddff06a65fb4791` | `src/service/index.js`, `src/controller/index.js` | MIT, included beside the source | https://github.com/alexm-acsa/vulnerable-node-api/tree/1f8fed353712940752a7bd9d7ddff06a65fb4791 |

The Java corpus is intentionally deferred. The authoritative OWASP Benchmark Java source is GPL-2.0, which would introduce a different redistribution obligation into this MIT repository. No Java source is copied here.

## Label notes

- `python-vuln-demo/main.py:20` (`os.popen(c)`, with `c = request.args.get("cmd", ...)` on the line above) is labeled Command Injection / CWE-78. Upstream marks it `# command injection (intentional)` on line 18. It was missing from the original labels and was added when the same-file command-injection data flow started reporting it. It is a real, upstream-declared vulnerability, not a relabel to improve a score.
- `vulnerable-node-api/src/service/index.js:47`, `:71`, and `:80` are labeled SQL Injection / CWE-89. Upstream's README lists "SQL injection via string concatenation in query | src/service/index.js | ~44, ~68, ~79" (`findUserByName`, `loginUser`, `searchProducts`). The labels sit on the query-execution lines. They were missing from the original labels and were added when cross-file data flow started following `controller -> service` calls. Line 47 (`findUserByName`) has no caller in the snapshot, so request flow cannot reach it. It is expected to stay a false negative until Cipher reports unreached query builders.
