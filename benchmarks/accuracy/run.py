#!/usr/bin/env python3
import argparse, json, os, pathlib, subprocess, tempfile, time

ROOT = pathlib.Path(__file__).resolve().parent

def main():
    p = argparse.ArgumentParser(description="Run Cipher's deterministic accuracy baseline")
    p.add_argument("--cipher", default=os.environ.get("CIPHER_BIN", "cipher-ai"))
    p.add_argument("--output", default=str(ROOT / "results" / "latest.json"))
    args = p.parse_args()
    manifest = json.loads((ROOT / "manifest.json").read_text())
    rows = []
    for case in manifest["cases"]:
        src = ROOT / "fixtures" / case["file"]
        with tempfile.TemporaryDirectory(prefix="cipher-bench-") as td:
            dst = pathlib.Path(td) / src.name
            dst.write_bytes(src.read_bytes())
            raw = pathlib.Path(td) / "result.json"
            started = time.perf_counter()
            cp = subprocess.run([args.cipher, "review", "--path", td, "--format", "json", "--max-findings", "0", "--output", str(raw)], text=True, capture_output=True)
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
            error = None
            if cp.returncode != 0:
                error = f"cipher exited with {cp.returncode}: {cp.stderr.strip()}"
            elif not raw.exists():
                error = "cipher did not write the JSON report"
            try:
                report = json.loads(raw.read_text()) if raw.exists() else {"findings": []}
            except (json.JSONDecodeError, OSError) as exc:
                report = {"findings": []}
                error = f"invalid JSON report: {exc}"
        findings = [f for f in report.get("findings", []) if pathlib.Path(f.get("file_path", "")).name == src.name]
        titles = [f.get("title") for f in findings]
        expected = case["expected"]
        matched = next((f for f in findings if f.get("title") == case.get("expected_title")), None)
        detected = bool(matched) if expected else bool(findings)
        outcome = "TP" if expected and matched else "FN" if expected else "FP" if findings else "TN"
        evidence = bool(matched and matched.get("file_path") and matched.get("line_number") and matched.get("code_snippet"))
        remediation = (matched or {}).get("remediation", "")
        fix_terms = case.get("fix_terms", [])
        fix_quality = "actionable" if matched and remediation and all(t.lower() in remediation.lower() for t in fix_terms) else "missing_or_generic" if matched else "not_applicable"
        rows.append({**case, "outcome": outcome, "reported_titles": titles, "runtime_ms": elapsed_ms, "evidence_complete": evidence, "fix_quality": fix_quality, "exit_code": cp.returncode, "error": error})
    counts = {k: sum(r["outcome"] == k for r in rows) for k in ("TP","FP","FN","TN")}
    precision = counts["TP"] / (counts["TP"] + counts["FP"]) if counts["TP"] + counts["FP"] else 0
    recall = counts["TP"] / (counts["TP"] + counts["FN"]) if counts["TP"] + counts["FN"] else 0
    summary = {
        **counts,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0,
        "evidence_complete_rate": round(sum(r["evidence_complete"] for r in rows if r["expected"]) / max(1, sum(r["expected"] for r in rows)), 4),
        "actionable_fix_rate": round(sum(r["fix_quality"] == "actionable" for r in rows if r["expected"]) / max(1, sum(r["expected"] for r in rows)), 4),
        "runtime_ms_total": round(sum(r["runtime_ms"] for r in rows), 2),
        "runtime_ms_median": sorted(r["runtime_ms"] for r in rows)[len(rows)//2]
    }
    result = {"schema_version": 1, "suite": manifest["suite"], "cipher": args.cipher, "summary": summary, "cases": rows}
    out = pathlib.Path(args.output); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    execution_errors = sum(bool(r["error"]) for r in rows)
    raise SystemExit(1 if counts["FN"] or counts["FP"] or execution_errors else 0)

if __name__ == "__main__": main()
