#!/usr/bin/env python3
"""Render benchmark JSON results as a compact Markdown report."""

import argparse
import json
import pathlib


def status_for(result):
    return "PASS" if not result.get("threshold_failures") else "FAIL"


def render_report(results):
    lines = [
        "# Cipher accuracy benchmark report",
        "",
        "| Suite | Gate | TP | FP | FN | TN | Precision | Recall | F1 | Errors |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for result in results:
        summary = result["summary"]
        overall = summary["overall"]
        lines.append(
            "| {suite} | {gate} | {TP} | {FP} | {FN} | {TN} | {precision:.4f} | "
            "{recall:.4f} | {f1:.4f} | {errors} |".format(
                suite=summary.get("suite", "unknown"),
                gate=status_for(result),
                errors=summary.get("execution_errors", {}).get("total", 0),
                **overall,
            )
        )

    failures = []
    for result in results:
        suite = result["summary"].get("suite", "unknown")
        for failure in result.get("threshold_failures", []):
            failures.append(
                f"- `{suite}`: `{failure['metric']}` was {failure['actual']} "
                f"(required {failure['threshold']})"
            )
    lines.extend(["", "## Gate failures", ""])
    lines.extend(failures or ["None."])
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Render Cipher accuracy benchmark results")
    parser.add_argument("results", nargs="+", help="benchmark result JSON files")
    parser.add_argument("--output", required=True, help="Markdown output path")
    args = parser.parse_args()

    results = [json.loads(pathlib.Path(path).read_text()) for path in args.results]
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_report(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
