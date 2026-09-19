#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent
VALID_FAMILIES = {"handpicked", "extracted", "mutation", "control"}
REQUIRED_PROVENANCE_FIELDS = (
    "source_url",
    "archive_url",
    "upstream_suite",
    "upstream_version",
    "original_id",
    "origin",
)


def normalize_title(value):
    return " ".join(str(value).strip().lower().split())


def validate_thresholds(thresholds):
    if thresholds is None:
        return
    if not isinstance(thresholds, dict):
        raise ValueError("manifest thresholds must be an object when present")
    for name, value in thresholds.items():
        if not isinstance(name, str):
            raise ValueError("threshold names must be strings")
        if not isinstance(value, (int, float)):
            raise ValueError(f"threshold {name!r} must be numeric")
        if name not in {"min_precision", "min_recall", "min_f1", "max_false_positive_rate", "max_execution_errors"}:
            raise ValueError(f"unsupported threshold {name!r}")


def validate_manifest(manifest):
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    if manifest.get("schema_version") != 2:
        raise ValueError("benchmark manifest must use schema_version 2")

    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("manifest must contain a non-empty cases list")

    seen_ids = set()
    seen_files = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError(f"case at index {index} is not an object")

        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError(f"case at index {index} is missing a valid id")
        if case_id in seen_ids:
            raise ValueError(f"duplicate case id: {case_id}")
        seen_ids.add(case_id)

        rel_path = case.get("file")
        if not isinstance(rel_path, str) or not rel_path.strip():
            raise ValueError(f"case {case_id} is missing a valid file")
        if rel_path in seen_files:
            raise ValueError(f"duplicate case file: {rel_path}")
        seen_files.add(rel_path)

        fixture_path = ROOT / "fixtures" / rel_path
        if not fixture_path.exists():
            raise ValueError(f"case {case_id} points to a missing fixture: {rel_path}")

        family = case.get("family")
        if family not in VALID_FAMILIES:
            raise ValueError(f"case {case_id} has invalid family: {family!r}")

        language = case.get("language")
        if not isinstance(language, str) or not language.strip():
            raise ValueError(f"case {case_id} is missing a language")

        vulnerability_class = case.get("vulnerability_class")
        if not isinstance(vulnerability_class, str) or not vulnerability_class.strip():
            raise ValueError(f"case {case_id} is missing a vulnerability_class")

        expected = case.get("expected")
        if not isinstance(expected, bool):
            raise ValueError(f"case {case_id} expected must be boolean")
        if expected:
            expected_title = case.get("expected_title")
            if not isinstance(expected_title, str) or not expected_title.strip():
                raise ValueError(f"positive case {case_id} must include expected_title")
            fix_terms = case.get("fix_terms", [])
            if not isinstance(fix_terms, list) or not fix_terms:
                raise ValueError(f"positive case {case_id} must include a non-empty fix_terms list")

        if family != "handpicked":
            provenance = case.get("provenance")
            if not isinstance(provenance, dict):
                raise ValueError(f"case {case_id} must include provenance because it is not handpicked")
            missing = [field for field in REQUIRED_PROVENANCE_FIELDS if not provenance.get(field)]
            if missing:
                raise ValueError(f"case {case_id} provenance missing required fields: {missing}")

        if family == "extracted":
            provenance = case.get("provenance", {})
            if provenance.get("source_url", "").startswith("http") is False:
                raise ValueError(f"extracted case {case_id} must include a public source_url")
            if not provenance.get("upstream_suite") or not provenance.get("upstream_version"):
                raise ValueError(f"extracted case {case_id} provenance requires upstream_suite and upstream_version")

    thresholds = manifest.get("thresholds")
    validate_thresholds(thresholds)


def compute_metrics(tp, fp, fn, tn):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    return {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(false_positive_rate, 4),
    }


def summarize_group(rows, key_name):
    buckets = {}
    for row in rows:
        group = row.get(key_name)
        if group is None:
            continue
        bucket = buckets.setdefault(group, {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "execution_errors": 0, "cases": 0})
        bucket["TP"] += row.get("TP", 0)
        bucket["FP"] += row.get("FP", 0)
        bucket["FN"] += row.get("FN", 0)
        bucket["TN"] += row.get("TN", 0)
        bucket["execution_errors"] += int(bool(row.get("error")))
        bucket["cases"] += 1

    result = {}
    for group, counts in sorted(buckets.items()):
        result[group] = compute_metrics(counts["TP"], counts["FP"], counts["FN"], counts["TN"])
        result[group]["execution_errors"] = counts["execution_errors"]
        result[group]["cases"] = counts["cases"]
    return result


def score_case(case, findings, elapsed_ms, returncode, error):
    titles = [finding.get("title") for finding in findings]
    expected = bool(case.get("expected"))
    expected_title = case.get("expected_title")

    if expected:
        matched = [
            finding
            for finding in findings
            if normalize_title(finding.get("title")) == normalize_title(expected_title)
        ]
        wrong = [
            finding
            for finding in findings
            if normalize_title(finding.get("title")) != normalize_title(expected_title)
        ]
        tp = 1 if matched else 0
        fp = len(wrong)
        fn = 0 if matched else 1
        tn = 0
        evidence = bool(matched and matched[0].get("file_path") and matched[0].get("line_number") and matched[0].get("code_snippet"))
        remediation = (matched or [{}])[0].get("remediation", "")
        fix_terms = case.get("fix_terms", [])
        if matched:
            fix_quality = "actionable" if remediation and all(term.lower() in remediation.lower() for term in fix_terms) else "missing_or_generic"
        else:
            fix_quality = "not_applicable"
    else:
        tp = 0
        fp = len(findings)
        fn = 0
        tn = 1 if not findings else 0
        evidence = False
        remediation = ""
        fix_quality = "not_applicable"

    return {
        **case,
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "outcome": "TP" if tp else "FN" if fn else "FP" if fp else "TN",
        "reported_titles": titles,
        "runtime_ms": elapsed_ms,
        "evidence_complete": evidence,
        "fix_quality": fix_quality,
        "exit_code": returncode,
        "error": error,
    }


def evaluate_thresholds(summary, thresholds):
    if not thresholds:
        return [], []

    checks = []
    overall = summary.get("overall", {})
    execution_errors = summary.get("execution_errors", {}).get("total", 0)
    for metric_name, limit in thresholds.items():
        if metric_name == "max_execution_errors":
            actual = execution_errors
        elif metric_name.startswith("min_"):
            actual = overall.get(metric_name[4:])
            if actual is None:
                actual = overall.get(metric_name)
            if actual is None:
                raise ValueError(f"threshold {metric_name!r} has no matching metric in the summary")
        elif metric_name.startswith("max_"):
            actual = overall.get(metric_name[4:])
            if actual is None:
                actual = overall.get(metric_name)
            if actual is None:
                raise ValueError(f"threshold {metric_name!r} has no matching metric in the summary")
        else:
            actual = overall.get(metric_name)
        if metric_name == "max_execution_errors":
            passed = actual <= limit
        elif metric_name.startswith("min_"):
            passed = actual >= limit
        elif metric_name.startswith("max_"):
            passed = actual <= limit
        else:
            passed = actual is not None and actual >= limit
        checks.append({"metric": metric_name, "threshold": limit, "actual": actual, "passed": passed})

    failures = [check for check in checks if not check["passed"]]
    return checks, failures


def main():
    p = argparse.ArgumentParser(description="Run Cipher's deterministic accuracy baseline")
    p.add_argument("--cipher", default=os.environ.get("CIPHER_BIN", "cipher-ai"))
    p.add_argument("--output", default=str(ROOT / "results" / "latest.json"))
    args = p.parse_args()

    manifest = json.loads((ROOT / "manifest.json").read_text())
    validate_manifest(manifest)

    rows = []
    execution_errors = []
    for case in manifest["cases"]:
        src = ROOT / "fixtures" / case["file"]
        with tempfile.TemporaryDirectory(prefix="cipher-bench-") as td:
            dst = pathlib.Path(td) / src.name
            dst.write_bytes(src.read_bytes())
            raw = pathlib.Path(td) / "result.json"
            started = time.perf_counter()
            command = [
                args.cipher,
                "review",
                "--path",
                td,
                "--format",
                "json",
                "--max-findings",
                "0",
                "--output",
                str(raw),
            ]
            cp = subprocess.run(command, text=True, capture_output=True)
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

        findings = [
            finding
            for finding in report.get("findings", [])
            if pathlib.Path(str(finding.get("file_path", ""))).name == src.name
        ]
        case_result = score_case(case, findings, elapsed_ms, cp.returncode, error)
        rows.append(case_result)
        if error:
            execution_errors.append(case["id"])

    counts = {k: sum(row.get(k, 0) for row in rows) for k in ("TP", "FP", "FN", "TN")}
    overall = compute_metrics(counts["TP"], counts["FP"], counts["FN"], counts["TN"])
    overall["execution_errors"] = len(execution_errors)
    overall["runtime_ms_total"] = round(sum(row["runtime_ms"] for row in rows), 2)
    overall["runtime_ms_median"] = sorted(row["runtime_ms"] for row in rows)[len(rows) // 2] if rows else 0

    grouped_languages = summarize_group(rows, "language")
    grouped_classes = summarize_group(rows, "vulnerability_class")
    family_counts = {}
    for case in manifest["cases"]:
        family_counts[case["family"]] = family_counts.get(case["family"], 0) + 1

    summary = {
        "schema_version": manifest["schema_version"],
        "suite": manifest.get("suite"),
        "cipher": args.cipher,
        "thresholds": manifest.get("thresholds", {}),
        "overall": overall,
        "groups": {"language": grouped_languages, "vulnerability_class": grouped_classes},
        "family_counts": family_counts,
        "execution_errors": {"total": len(execution_errors), "cases": execution_errors},
        "cases": rows,
    }

    checks, failed_checks = evaluate_thresholds(summary, manifest.get("thresholds", {}))
    result = {"summary": summary, "threshold_checks": checks, "threshold_failures": failed_checks}

    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")

    print(json.dumps({"overall": summary["overall"], "family_counts": family_counts, "execution_errors": summary["execution_errors"]}, indent=2))

    if failed_checks:
        raise SystemExit(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
