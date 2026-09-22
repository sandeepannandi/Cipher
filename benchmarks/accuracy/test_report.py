import unittest

import report


class BenchmarkReportTests(unittest.TestCase):
    def test_report_keeps_suite_gates_separate_and_lists_failures(self):
        passing = {
            "summary": {
                "suite": "focused",
                "overall": {"TP": 2, "FP": 0, "FN": 0, "TN": 1, "precision": 1.0, "recall": 1.0, "f1": 1.0},
                "execution_errors": {"total": 0},
            },
            "threshold_failures": [],
        }
        failing = {
            "summary": {
                "suite": "mutations",
                "overall": {"TP": 1, "FP": 0, "FN": 1, "TN": 2, "precision": 1.0, "recall": 0.5, "f1": 0.6667},
                "execution_errors": {"total": 0},
            },
            "threshold_failures": [{"metric": "min_recall", "actual": 0.5, "threshold": 0.75, "passed": False}],
        }
        markdown = report.render_report([passing, failing])
        self.assertIn("| focused | PASS |", markdown)
        self.assertIn("| mutations | FAIL |", markdown)
        self.assertIn("`min_recall` was 0.5 (required 0.75)", markdown)


if __name__ == "__main__":
    unittest.main()
