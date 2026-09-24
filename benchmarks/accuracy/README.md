# Accuracy benchmark

A deterministic baseline for Cipher's review pipeline. It keeps the corpus stripped to isolated source files so each expected result is attributable to a single case. The benchmark intentionally stays in the benchmark layer only and does not alter scanner behavior.

## Schema

The manifest uses schema version 2 and records metadata for each case:

- `family`: `handpicked`, `extracted`, `mutation`, or `control`
- `vulnerability_class`: the canonical class used for grouping and regression checks
- `provenance`: required for non-handpicked cases; for extracted cases it includes the verified public suite page, pinned archive URL, upstream suite/version, and original ID
- `project`: optional project identifier; defaults to `focused-corpus`
- `expected_title`: legacy single-finding expectation, retained for the focused corpus
- `expected_findings`: exact project-case expectations, matched one-for-one by title and optionally CWE, relative file, and line

A case may point to one source file or a project directory. Directory cases are copied into an isolated scan root and run once, so interactions and unrelated findings are measured rather than hidden by per-file execution. Unexpected findings count as false positives; unmatched expectations count as false negatives. Results include micro totals plus macro averages and breakdowns by language, vulnerability class, family, and project.

The extracted Java cases are small normalized/extracted CWE-pattern fixtures derived from the public Juliet Java suite, not byte-for-byte copies of upstream source files unless source-path verification was explicitly performed. This benchmark is intentionally a realism check for deterministic rule coverage, not a perfect reproduction of every upstream source artifact.

### Selected-language depth case

The JavaScript/TypeScript, Python, Java, and Go path-traversal cases exercise
narrow local models: request path input, aliases or path construction, and a
filesystem sink. The clean controls use basename-style sanitizers
(`getFileName()` in Java, `filepath.Base` in Go) before construction. The Java
and Go cases are self-written fixtures, not upstream corpus files. This was
chosen over
adding more language breadth because path traversal was already a supported,
high-severity class, but its previous rule only recognized a same-line string
concatenation at `readFile`/`writeFile`.

### SQL injection data-flow cases

The `DF-*-SQLI-001` cases carry request input through a local query-string
binding (f-string, template literal, concatenation, `fmt.Sprintf`) into a SQL
sink in each of Python, JavaScript, Java, and Go. Each `CTRL-*-SQLI-001` control
uses the same request value as a bind parameter of a parameterized query
(`?`, `$1`, `PreparedStatement.setString`) and must stay clean. These are
self-written fixtures, not upstream corpus files.

### Command injection data-flow cases

The `DF-*-CMDI-001` cases carry request input through a local command-string
binding into a shell sink (`subprocess.run(..., shell=True)`, `exec`,
`ProcessBuilder("sh", "-c", ...)`, `exec.Command("sh", "-c", ...)`) in each of
Python, JavaScript, Java, and Go. Each `CTRL-*-CMDI-001` control passes the same
request value as one element of an argument vector with no shell and must stay
clean. These are self-written fixtures, not upstream corpus files.

### SSRF data-flow cases

The `DF-*-SSRF-001` cases carry a request-supplied URL through a local binding
into the URL argument of an HTTP client (`requests.get`, `fetch`, `new URL`,
`http.Get`) in each of Python, JavaScript, Java, and Go. Each `CTRL-*-SSRF-001`
control sends the request value only as a query parameter or body of a fixed
URL and must stay clean. These are self-written fixtures, not upstream corpus
files.

### Interprocedural data-flow cases

The `IP-*-SQLI-001` cases pass request input from a handler into a helper
function defined in the same file, and the helper builds the SQL text and
runs it (JavaScript goes through a two-function chain, controller-style
handler -> `lookup` -> `findUserByName`). `IP-PY-CMDI-001` does the same through
a `self.` method call into a `shell=True` helper. The expected finding is the
sink line inside the callee. Each `CTRL-IP-*` control keeps the same call shape
but the helper uses a bind parameter, the caller converts the value to an
integer, or the caller quotes it with `shlex.quote`, and must stay clean. These
are self-written fixtures, not upstream corpus files. Cross-file calls are covered
by the cases below.

### Cross-file data-flow cases

`XF-JS-SQLI-001` and `XF-PY-SQLI-001` are small project cases. A route or view
file reads request input and calls a function exported by another file it
imports (`require('../services/users')`, `from .repository import
find_orders`). That function builds and runs the SQL. The expected finding is
the sink line in the imported file. `CTRL-XF-JS-SQLI-001` keeps the same call
but the service uses a bind parameter. `CTRL-XF-PY-SQLI-001` converts the value
to an integer before the call. Both must stay clean. These are self-written
fixtures, not upstream corpus files.

`XF-JAVA-SQLI-001` and `XF-GO-SQLI-001`/`002` are the Java and Go project
cases. A servlet calls a static method of a sibling class in the same package;
a Go handler calls a function defined in a sibling file of the same package,
or in another package of the same module resolved through `go.mod`. That
function builds and runs the SQL. The expected finding is the sink line in
the other file. The controls keep the same call shape but the callee uses a
bind parameter or the caller converts the value with `strconv.Atoi`, and must
stay clean. These are self-written fixtures, not upstream corpus files.

## Run

```bash
python3 benchmarks/accuracy/run.py --cipher ./target/release/cipher-ai
```

The script validates the manifest, runs each fixture through the review path, and writes `benchmarks/accuracy/results/latest.json`. It exits non-zero if the manifest is invalid, any execution error occurs, or a configured threshold for precision/recall/F1 or execution errors is missed.

The focused corpus remains intentionally small and measures the deterministic `review` path, not AI verification or dependency scanning. The runner now supports pinned public project subsets with exact finding labels; those realism cases belong in a separate manifest and CI job so their measured baseline cannot weaken the focused regression gate.

## CI gates and report

CI keeps the three suites as separate required signals:

- focused corpus (`manifest.json`)
- pinned MIT real projects (`real_projects_manifest.json`)
- deterministic mutations and controls (`mutations_manifest.json`)

Each gate writes and uploads its own JSON result, so a strong suite cannot hide a regression in another suite. The final reporting job renders `report.py` output into the GitHub Actions step summary and uploads the same Markdown as `cipher-accuracy-report`.

To render the combined report locally after running all suites:

```bash
python3 benchmarks/accuracy/report.py \
  /tmp/focused.json /tmp/real-projects.json /tmp/mutations.json \
  --output /tmp/accuracy-report.md
```
