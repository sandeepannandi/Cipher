import json, os, unittest

import recall


class StatusTests(unittest.TestCase):
    def test_exact_line_is_hit(self):
        self.assertEqual(recall.status([(10, "Command Injection")], 10), "HIT")

    def test_within_three_lines_is_near(self):
        self.assertEqual(recall.status([(13, "x")], 10), "NEAR")
        self.assertEqual(recall.status([(7, "x")], 10), "NEAR")

    def test_four_lines_away_is_miss(self):
        self.assertEqual(recall.status([(14, "x")], 10), "MISS")

    def test_no_findings_is_miss(self):
        self.assertEqual(recall.status([], 10), "MISS")

    def test_missing_line_number_is_not_near(self):
        self.assertEqual(recall.status([(None, "x")], 10), "MISS")


class RecordedDataTests(unittest.TestCase):
    def test_every_label_has_a_recorded_result(self):
        labels = recall.load("labels.json")
        results = {(r["ghsa"], r["file"], r["line"]) for r in recall.load("results.json")}
        for l in labels:
            self.assertIn((l["ghsa"], l["file"], l["line"]), results)
        self.assertEqual(len(labels), len(results))

    def test_results_use_known_statuses(self):
        for r in recall.load("results.json"):
            self.assertIn(r["status"], {"HIT", "NEAR", "MISS"})

    def test_every_label_advisory_is_in_the_manifest(self):
        manifest = {m["ghsa"] for m in recall.load("manifest.json")}
        for l in recall.load("labels.json"):
            self.assertIn(l["ghsa"], manifest)


if __name__ == "__main__":
    unittest.main()
