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


if __name__ == "__main__":
    unittest.main()
