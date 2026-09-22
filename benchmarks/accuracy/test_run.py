import pathlib
import unittest

import run as benchmark_run


class BenchmarkRunTests(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(__file__).resolve().parent

    def test_duplicate_and_missing_validation(self):
        manifest = {
            "schema_version": 2,
            "suite": "dup-check",
            "cases": [
                {"id": "A", "file": "python/weak_md5.py", "language": "python", "expected": True, "expected_title": "Weak Hash Algorithm — MD5", "family": "handpicked", "vulnerability_class": "weak_hash", "fix_terms": ["SHA-256"]},
                {"id": "A", "file": "python/unsafe_pickle.py", "language": "python", "expected": True, "expected_title": "Insecure Deserialization", "family": "handpicked", "vulnerability_class": "insecure_deserialization", "fix_terms": ["safe deserialization"]},
                {"id": "B", "file": "missing.py", "language": "python", "expected": False, "family": "control", "vulnerability_class": "weak_hash"},
            ],
        }
        with self.assertRaises(ValueError):
            benchmark_run.validate_manifest(manifest)

    def test_non_handpicked_case_requires_provenance(self):
        manifest = {
            "schema_version": 2,
            "suite": "prov-check",
            "cases": [
                {"id": "M1", "file": "python/mutation_md5_helper.py", "language": "python", "expected": True, "expected_title": "Weak Hash Algorithm — MD5", "family": "mutation", "vulnerability_class": "weak_hash", "fix_terms": ["SHA-256"]},
            ],
        }
        with self.assertRaises(ValueError):
            benchmark_run.validate_manifest(manifest)

    def test_positive_case_with_wrong_title_counts_as_fn_and_fp(self):
        case = {"id": "X", "file": "python/weak_md5.py", "language": "python", "expected": True, "expected_title": "Weak Hash Algorithm — MD5", "family": "handpicked", "vulnerability_class": "weak_hash", "fix_terms": ["SHA-256"]}
        findings = [
            {"file_path": str(self.root / "fixtures" / "python" / "weak_md5.py"), "title": "Hardcoded Credentials", "line_number": 1, "code_snippet": "x"},
        ]
        result = benchmark_run.score_case(case, findings, 10.0, 0, None)
        self.assertEqual(result["FN"], 1)
        self.assertEqual(result["FP"], 1)
        self.assertEqual(result["TP"], 0)

    def test_grouped_metrics_and_thresholds(self):
        rows = [
            {"language": "python", "vulnerability_class": "weak_hash", "TP": 1, "FP": 0, "FN": 0, "TN": 1, "error": None},
            {"language": "python", "vulnerability_class": "weak_hash", "TP": 0, "FP": 1, "FN": 1, "TN": 0, "error": None},
            {"language": "javascript", "vulnerability_class": "hardcoded_secret", "TP": 1, "FP": 0, "FN": 0, "TN": 0, "error": None},
        ]
        grouped_lang = benchmark_run.summarize_group(rows, "language")
        grouped_class = benchmark_run.summarize_group(rows, "vulnerability_class")
        self.assertEqual(grouped_lang["python"]["TP"], 1)
        self.assertEqual(grouped_lang["javascript"]["TP"], 1)
        self.assertEqual(grouped_class["weak_hash"]["FN"], 1)
        self.assertEqual(grouped_class["hardcoded_secret"]["FP"], 0)

        summary = {"overall": benchmark_run.compute_metrics(2, 1, 1, 1), "execution_errors": {"total": 0}}
        checks, failures = benchmark_run.evaluate_thresholds(summary, {"min_precision": 0.66, "min_recall": 0.66, "min_f1": 0.66, "max_execution_errors": 0})
        self.assertEqual(len(failures), 0)

        failing_summary = {"overall": benchmark_run.compute_metrics(0, 1, 1, 0), "execution_errors": {"total": 0}}
        _, failing = benchmark_run.evaluate_thresholds(failing_summary, {"min_precision": 0.66, "min_recall": 0.66, "min_f1": 0.66, "max_execution_errors": 0})
        self.assertTrue(failing)

    def test_execution_error_threshold_fails(self):
        summary = {"overall": {"precision": 1.0, "recall": 1.0, "f1": 1.0}, "execution_errors": {"total": 1}}
        checks, failures = benchmark_run.evaluate_thresholds(summary, {"max_execution_errors": 0})
        self.assertFalse(checks[0]["passed"])
        self.assertEqual(len(failures), 1)

    def test_custom_manifest_argument_is_available(self):
        parser_source = (self.root / "run.py").read_text()
        self.assertIn('p.add_argument("--manifest"', parser_source)
        self.assertIn('manifest_path = pathlib.Path(args.manifest)', parser_source)


if __name__ == "__main__":
    unittest.main()


class BroaderBenchmarkContractTests(unittest.TestCase):
    def test_expected_findings_match_title_cwe_file_and_line(self):
        case = {
            "id": "REAL-PY-001",
            "file": "python/weak_md5.py",
            "language": "python",
            "project": "example-project",
            "expected": True,
            "expected_findings": [
                {
                    "title": "Weak Hash Algorithm — MD5",
                    "cwe": "CWE-328",
                    "file": "src/hash.py",
                    "line": 7,
                }
            ],
            "family": "extracted",
            "vulnerability_class": "weak_hash",
            "provenance": {
                "source_url": "https://example.invalid/source",
                "archive_url": "https://example.invalid/archive",
                "upstream_suite": "example",
                "upstream_version": "abc123",
                "original_id": "REAL-PY-001",
                "origin": "example fixture",
            },
        }
        findings = [
            {
                "title": "Weak Hash Algorithm — MD5",
                "cwe_id": "CWE-328",
                "file_path": "/tmp/source/src/hash.py",
                "line_number": 7,
                "code_snippet": "hashlib.md5(data)",
                "remediation": "Use SHA-256",
            },
            {
                "title": "Hardcoded Credentials",
                "cwe_id": "CWE-798",
                "file_path": "/tmp/source/src/config.py",
                "line_number": 3,
                "code_snippet": "password = 'test'",
            },
        ]
        result = benchmark_run.score_case(case, findings, 10.0, 0, None)
        self.assertEqual((result["TP"], result["FP"], result["FN"]), (1, 1, 0))
        self.assertEqual(result["project"], "example-project")

    def test_multiple_expected_findings_are_matched_once_each(self):
        case = {
            "id": "MULTI",
            "file": "python/weak_md5.py",
            "language": "python",
            "expected": True,
            "expected_findings": [
                {"title": "Weak Hash Algorithm — MD5", "file": "a.py"},
                {"title": "Weak Hash Algorithm — MD5", "file": "b.py"},
            ],
            "family": "handpicked",
            "vulnerability_class": "weak_hash",
        }
        findings = [
            {"title": "Weak Hash Algorithm — MD5", "file_path": "/tmp/a.py"},
            {"title": "Weak Hash Algorithm — MD5", "file_path": "/tmp/b.py"},
        ]
        result = benchmark_run.score_case(case, findings, 1.0, 0, None)
        self.assertEqual((result["TP"], result["FP"], result["FN"]), (2, 0, 0))

    def test_macro_metrics_average_group_rates(self):
        groups = {
            "python": benchmark_run.compute_metrics(3, 1, 1, 5),
            "java": benchmark_run.compute_metrics(1, 0, 3, 4),
        }
        macro = benchmark_run.compute_macro_metrics(groups)
        self.assertEqual(macro["groups"], 2)
        self.assertEqual(macro["precision"], 0.875)
        self.assertEqual(macro["recall"], 0.5)

    def test_negative_case_cannot_declare_expected_findings(self):
        manifest = {
            "schema_version": 2,
            "suite": "invalid-negative",
            "cases": [
                {
                    "id": "NEG",
                    "file": "python/safe_hash.py",
                    "language": "python",
                    "expected": False,
                    "expected_findings": [{"title": "Weak Hash Algorithm — MD5"}],
                    "family": "handpicked",
                    "vulnerability_class": "weak_hash",
                }
            ],
        }
        with self.assertRaises(ValueError):
            benchmark_run.validate_manifest(manifest)
