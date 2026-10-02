#!/usr/bin/env python3
"""Pinned-repo key gate.

Scans repositories pinned by commit SHA and compares every finding, as
(path, line, title), against the committed expected files. A scan that differs
from the expected data fails, so any change to a finding set has to appear as
a reviewed data diff in the same pull request. Labeled ledger pairs (benchmark
suite) must stay present in the scan; --update refuses to write an expected
file that drops one unless --allow-ledger-change is given.

Usage:
  check.py --cipher BIN --suite benchmark [--cache DIR] [--only NAME] [--update]
  check.py --cipher BIN --suite production [--cache DIR] [--only NAME] [--update]
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SUITES = {
    "benchmark": ("manifest.json", "expected", True),
    "production": ("production.json", "production-expected", False),
}


def parse_scan_output(text):
    """The review command can print log lines before the JSON document."""
    start = text.find("\n{\n")
    if text.startswith("{\n"):
        start = 0
    elif start >= 0:
        start += 1
    else:
        raise ValueError("no JSON document in scan output")
    return json.loads(text[start:])


def relativize(path, root):
    root = os.path.abspath(root).rstrip("/") + "/"
    if path.startswith(root):
        return path[len(root):]
    return path


def finding_keys(doc, root):
    keys = set()
    for f in doc.get("findings", []):
        path = relativize(f.get("file_path") or "", root)
        keys.add((path, int(f.get("line_number") or 0), f.get("title") or ""))
    return sorted(keys)


def format_keys(keys):
    return "".join(f"{p}\t{l}\t{t}\n" for p, l, t in keys)


def read_keys(path):
    if not os.path.exists(path):
        return None
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh.read().splitlines():
            p, l, t = line.split("\t", 2)
            out.append((p, int(l), t))
    return sorted(out)


def diff_keys(expected, actual):
    e, a = set(expected), set(actual)
    return sorted(e - a), sorted(a - e)


def ledger_missing(ledger_pairs, keys):
    present = {(p, l) for p, l, _ in keys}
    return [(p, l) for p, l in ledger_pairs if (p, l) not in present]


def ensure_clone(url, sha, dest):
    if os.path.isdir(os.path.join(dest, ".git")):
        head = subprocess.run(["git", "-C", dest, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        if head == sha:
            return
        subprocess.run(["rm", "-rf", dest], check=True)
    os.makedirs(dest, exist_ok=True)
    for cmd in (["init", "-q"], ["remote", "add", "origin", url], ["fetch", "-q", "--depth", "1", "origin", sha], ["checkout", "-q", "FETCH_HEAD"]):
        subprocess.run(["git", "-C", dest] + cmd, check=True)


def scan(cipher, root):
    proc = subprocess.run([cipher, "review", "--format", "json", "--max-findings", "0", "-p", root],
                          capture_output=True, text=True)
    return parse_scan_output(proc.stdout)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cipher", required=True)
    ap.add_argument("--suite", choices=sorted(SUITES), required=True)
    ap.add_argument("--cache", default=os.path.join(os.environ.get("TMPDIR", "/tmp"), "cipher-pinned-cache"))
    ap.add_argument("--only")
    ap.add_argument("--update", action="store_true")
    ap.add_argument("--allow-ledger-change", action="store_true")
    args = ap.parse_args(argv)

    manifest_name, expected_dir, has_ledger = SUITES[args.suite]
    with open(os.path.join(HERE, manifest_name), encoding="utf-8") as fh:
        manifest = json.load(fh)
    ledger = {}
    if has_ledger:
        with open(os.path.join(HERE, "ledger.json"), encoding="utf-8") as fh:
            ledger = json.load(fh)

    failed = False
    for repo in manifest["repos"]:
        name = repo["name"]
        if args.only and args.only != name:
            continue
        if repo.get("skip"):
            print(f"SKIP {name}: {repo['skip']}")
            continue
        root = os.path.join(args.cache, name)
        ensure_clone(repo["url"], repo["sha"], root)
        keys = finding_keys(scan(args.cipher, root), root)
        pairs = [(e["file"], e["line"]) for e in ledger.get(name, [])]
        lost = ledger_missing(pairs, keys)
        path = os.path.join(HERE, expected_dir, name + ".tsv")
        if lost:
            failed = True
            print(f"FAIL {name}: labeled ledger pairs missing from the scan: {lost}")
        if args.update:
            if lost and not args.allow_ledger_change:
                print(f"REFUSED update for {name}: would drop labeled pairs (use --allow-ledger-change and edit ledger.json in the same change)")
                continue
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(format_keys(keys))
            print(f"WROTE {name}: {len(keys)} keys")
            continue
        expected = read_keys(path)
        if expected is None:
            failed = True
            print(f"FAIL {name}: no expected file at {path}; run with --update")
            continue
        removed, added = diff_keys(expected, keys)
        if removed or added:
            failed = True
            print(f"FAIL {name}: finding set changed (expected {len(expected)}, got {len(keys)})")
            for k in removed:
                print(f"  - {k[0]}:{k[1]}  {k[2]}")
            for k in added:
                print(f"  + {k[0]}:{k[1]}  {k[2]}")
            print("  Review the delta; if intended, regenerate with --update and commit the data diff.")
        elif not lost:
            print(f"OK   {name}: {len(keys)} keys match" + (f", {len(pairs)} ledger pairs present" if pairs else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
