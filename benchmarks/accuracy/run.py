#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import shutil
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

        project = case.get("project", "focused-corpus")
        if not isinstance(project, str) or not project.strip():
            raise ValueError(f"case {case_id} project must be a non-empty string")

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
        expected_findings = case.get("expected_findings")
        if expected_findings is not None:
            if not isinstance(expected_findings, list) or not expected_findings:
                raise ValueError(f"case {case_id} expected_findings must be a non-empty list")
            if not expected:
                raise ValueError(f"negative case {case_id} cannot include expected_findings")
            for finding_index, finding in enumerate(expected_findings):
                if not isinstance(finding, dict):
                    raise ValueError(
                        f"case {case_id} expected finding at index {finding_index} is not an object"
                    )
                title = finding.get("title")
                if not isinstance(title, str) or not title.strip():
                    raise ValueError(
                        f"case {case_id} expected finding at index {finding_index} is missing a title"
                    )
                for field in ("cwe", "file"):
                    value = finding.get(field)
                    if value is not None and (not isinstance(value, str) or not value.strip()):
                        raise ValueError(
                            f"case {case_id} expected finding field {field!r} must be a non-empty string"
                        )
                line = finding.get("line")
                if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
                    raise ValueError(
                        f"case {case_id} expected finding line must be a positive integer"
                    )

        if expected:
            expected_title = case.get("expected_title")
            if expected_findings is None and (
                not isinstance(expected_title, str) or not expected_title.strip()
            ):
                raise ValueError(
                    f"positive case {case_id} must include expected_title or expected_findings"
                )
            fix_terms = case.get("fix_terms", [])
            if not isinstance(fix_terms, list):
                raise ValueError(f"positive case {case_id} fix_terms must be a list")
            if expected_findings is None and not fix_terms:
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


def canonical_finding_cwe(finding):
    return str(finding.get("cwe_id") or finding.get("cwe") or "").strip().upper()


def expected_specs(case):
    configured = case.get("expected_findings")
    if configured is not None:
        return configured
    if not case.get("expected"):
        return []
    # Preserve schema-v2 focused-corpus behavior: legacy expectations match by
    # title only. Broader project cases opt into stricter CWE/file/line matching
    # through expected_findings.
    return [{"title": case["expected_title"]}]


def finding_matches(spec, finding):
    if normalize_title(finding.get("title")) != normalize_title(spec.get("title")):
        return False
    if spec.get("cwe") and canonical_finding_cwe(finding) != str(spec["cwe"]).strip().upper():
        return False
    if spec.get("file"):
        actual_path = pathlib.PurePosixPath(str(finding.get("file_path", "")).replace("\\", "/"))
        expected_path = pathlib.PurePosixPath(spec["file"].replace("\\", "/"))
        if actual_path != expected_path and not str(actual_path).endswith("/" + str(expected_path)):
            return False
    if spec.get("line") is not None and finding.get("line_number") != spec["line"]:
        return False
    return True


def match_findings(specs, findings):
    unmatched = set(range(len(findings)))
    matched = []
    for spec in specs:
        match_index = next(
            (index for index in sorted(unmatched) if finding_matches(spec, findings[index])),
            None,
        )
        if match_index is not None:
            unmatched.remove(match_index)
            matched.append(findings[match_index])
    return matched, [findings[index] for index in sorted(unmatched)]


def score_case(case, findings, elapsed_ms, returncode, error):
    specs = expected_specs(case)
    matched, unexpected = match_findings(specs, findings)
    tp = len(matched)
    fn = len(specs) - tp
    fp = len(unexpected)
    tn = 1 if not specs and not findings else 0

    evidence = all(
        finding.get("file_path")
        and finding.get("line_number")
        and finding.get("code_snippet")
        for finding in matched
    ) if matched else False
    fix_terms = case.get("fix_terms", [])
    remediation = matched[0].get("remediation", "") if matched else ""
    if matched and fix_terms:
        fix_quality = (
            "actionable"
            if remediation and all(term.lower() in remediation.lower() for term in fix_terms)
            else "missing_or_generic"
        )
    elif matched:
        fix_quality = "not_assessed"
    else:
        fix_quality = "not_applicable"

    if error:
        outcome = "ERROR"
    elif fn:
        outcome = "FN" if not fp else "FN+FP"
    elif fp:
        outcome = "FP"
    elif tp:
        outcome = "TP"
    else:
        outcome = "TN"

    return {
        **case,
        "project": case.get("project", "focused-corpus"),
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "outcome": outcome,
        "reported_titles": [finding.get("title") for finding in findings],
        "matched_findings": len(matched),
        "unexpected_findings": len(unexpected),
        "runtime_ms": elapsed_ms,
        "evidence_complete": evidence,
        "fix_quality": fix_quality,
        "exit_code": returncode,
        "error": error,
    }


def compute_macro_metrics(groups):
    if not groups:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0, "false_positive_rate": 0.0, "groups": 0}
    metric_names = ("precision", "recall", "f1", "false_positive_rate")
    result = {
        name: round(sum(group[name] for group in groups.values()) / len(groups), 4)
        for name in metric_names
    }
    result["groups"] = len(groups)
    return result


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
            scan_root = pathlib.Path(td) / "source"
            if src.is_dir():
                shutil.copytree(src, scan_root)
            else:
                scan_root.mkdir()
                shutil.copy2(src, scan_root / src.name)
            raw = pathlib.Path(td) / "result.json"
            started = time.perf_counter()
            command = [
                args.cipher,
                "review",
                "--path",
                str(scan_root),
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

        findings = report.get("findings", [])
        if src.is_file():
            findings = [
                finding
                for finding in findings
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
    grouped_families = summarize_group(rows, "family")
    grouped_projects = summarize_group(rows, "project")
    family_counts = {}
    for case in manifest["cases"]:
        family_counts[case["family"]] = family_counts.get(case["family"], 0) + 1

    summary = {
        "schema_version": manifest["schema_version"],
        "suite": manifest.get("suite"),
        "cipher": args.cipher,
        "thresholds": manifest.get("thresholds", {}),
        "overall": overall,
        "aggregates": {
            "micro": overall,
            "macro_language": compute_macro_metrics(grouped_languages),
            "macro_project": compute_macro_metrics(grouped_projects),
        },
        "groups": {
            "language": grouped_languages,
            "vulnerability_class": grouped_classes,
            "family": grouped_families,
            "project": grouped_projects,
        },
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
