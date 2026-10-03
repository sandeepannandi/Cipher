#!/usr/bin/env python3
"""Recall against real, pinned, pre-fix commits of open-source projects.

Each entry in manifest.json is a published GitHub security advisory with a fix
commit. The scanned tree is the fix commit's first parent (the code as it was
before the fix). A label is a source line, taken by hand from the fix diff, that
holds the vulnerable sink. A label is a HIT when the scan reports any finding on
that exact file:line, NEAR when within 3 lines, MISS otherwise. Misses are kept
and reported; nothing here is tuned to make them disappear.

  recall.py --cipher BIN [--cache DIR] [--only OWNER/REPO] [--check] [--write]

--check exits 1 if a label recorded as HIT in results.json is no longer a HIT
(recall regression), or if any recorded status differs from the computed one
(stale record, e.g. a newly gained HIT that was not written down). Misses that
stay misses never fail the check.
"""
import argparse, json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "pinned"))
import check  # parse_scan_output, relativize


def load(name):
    with open(os.path.join(HERE, name)) as f:
        return json.load(f)


def clone(repo, sha, cache):
    dest = os.path.join(cache, repo.replace("/", "__"))
    have = subprocess.run(["git", "-C", dest, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    if have == sha:
        return dest
    subprocess.run(["rm", "-rf", dest], check=True)
    os.makedirs(dest)
    for cmd in (["init", "-q"], ["remote", "add", "origin", f"https://github.com/{repo}"],
                ["fetch", "-q", "--depth", "1", "origin", sha], ["checkout", "-q", "FETCH_HEAD"]):
        subprocess.run(["git", "-C", dest] + cmd, check=True)
    return dest


def status(findings, line):
    if any(l == line for l, _ in findings):
        return "HIT"
    if any(l and abs(l - line) <= 3 for l, _ in findings):
        return "NEAR"
    return "MISS"


def compare(recorded, computed):
    """Split computed statuses against results.json.

    Returns (lost, stale): `lost` are recorded HITs that are no longer HITs;
    `stale` are every other label whose recorded status is missing or differs
    from the computed one, in either direction.
    """
    lost, stale = [], []
    for key, st in computed.items():
        was = recorded.get(key)
        if was == st:
            continue
        label = "{} {}:{}".format(*key)
        if was == "HIT":
            lost.append(f"{label} (HIT -> {st})")
        else:
            stale.append(f"{label} (recorded {was}, now {st})")
    return lost, stale


def updated_results(results, computed_by_label):
    """results.json rows with statuses replaced by the computed ones.

    `computed_by_label` maps (ghsa, file, line) to a status. Rows keep their
    order and keys; a label that was not scanned keeps its recorded status.
    """
    return [dict(r, status=computed_by_label.get((r["ghsa"], r["file"], r["line"]), r["status"])) for r in results]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cipher", required=True)
    ap.add_argument("--cache", default="/tmp/cipher-recall-clones")
    ap.add_argument("--only")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--write", action="store_true", help="record the computed statuses in results.json")
    a = ap.parse_args()
    manifest = {m["ghsa"]: m for m in load("manifest.json")}
    labels = load("labels.json")
    recorded = {(r["ghsa"], r["file"], r["line"]): r["status"] for r in load("results.json")}
    by_adv = {}
    for l in labels:
        by_adv.setdefault(l["ghsa"], []).append(l)
    counts = {"HIT": 0, "NEAR": 0, "MISS": 0}
    computed = {}
    names = {}
    out = []
    for ghsa, ls in by_adv.items():
        m = manifest[ghsa]
        if a.only and a.only != m["repo"]:
            continue
        root = clone(m["repo"], m["pre_fix"], a.cache)
        proc = subprocess.run([a.cipher, "review", "--format", "json", "--max-findings", "0", "-p", root],
                              capture_output=True, text=True)
        doc = check.parse_scan_output(proc.stdout)
        per_file = {}
        for f in doc.get("findings", []):
            per_file.setdefault(check.relativize(f.get("file_path") or "", root), []).append((f.get("line_number"), f.get("title")))
        for l in ls:
            st = status(per_file.get(l["file"], []), l["line"])
            counts[st] += 1
            out.append({"ghsa": ghsa, "repo": m["repo"], "cwe": l["cwe"], "file": l["file"], "line": l["line"], "status": st})
            print(f"{st:4} {m['repo']} {l['file']}:{l['line']} ({l['cwe']})")
            computed[(m["repo"], l["file"], l["line"])] = st
            names[(m["repo"], l["file"], l["line"])] = (ghsa, l["file"], l["line"])
    total = sum(counts.values())
    print(f"recall: {counts['HIT']}/{total} exact, {counts['NEAR']} near, {counts['MISS']} miss")
    if a.write:
        by_label = {names[k]: st for k, st in computed.items()}
        text = json.dumps(updated_results(load("results.json"), by_label), indent=1) + "\n"
        with open(os.path.join(HERE, "results.json"), "w") as f:
            f.write(text)
        print("results.json updated")
    if a.check:
        lost, stale = compare({k: recorded.get(v) for k, v in names.items()}, computed)
        if lost:
            print("REGRESSION: recorded hits lost:", *lost, sep="\n  ")
        if stale:
            print("STALE results.json: update it from this run (python3 benchmarks/recall/recall.py "
                  "--cipher BIN --write), and the recall numbers in CHANGELOG.md:", *stale, sep="\n  ")
        if lost or stale:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
