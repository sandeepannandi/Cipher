# Deterministic real-project mutations

These fixtures are small transformations of the pinned MIT real-project corpus. Each mutation has a paired safe control and a written recipe in `mutations_manifest.json`.

- Python MD5: replace the direct `hashlib.md5(payload)` call with a local callable alias. The safe control changes only the algorithm to SHA-256.
- JavaScript path traversal: rename locals and replace `path.join` with `path.resolve` while preserving the request-to-`readFile` flow. The safe control adds `path.basename` before path construction.

The files are committed inputs, not generated during CI. This makes the suite reproducible and reviewable. A false negative is retained as measured evidence; labels are not changed to fit scanner output.
