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


class CompareTests(unittest.TestCase):
    K = ("o/r", "a.py", 3)

    def test_matching_record_is_clean(self):
        self.assertEqual(recall.compare({self.K: "MISS"}, {self.K: "MISS"}), ([], []))
        self.assertEqual(recall.compare({self.K: "HIT"}, {self.K: "HIT"}), ([], []))

    def test_lost_hit(self):
        lost, stale = recall.compare({self.K: "HIT"}, {self.K: "MISS"})
        self.assertEqual((len(lost), stale), (1, []))

    def test_gained_hit_not_recorded_is_stale(self):
        lost, stale = recall.compare({self.K: "MISS"}, {self.K: "HIT"})
        self.assertEqual((lost, len(stale)), ([], 1))

    def test_missing_record_is_stale(self):
        lost, stale = recall.compare({self.K: None}, {self.K: "MISS"})
        self.assertEqual((lost, len(stale)), ([], 1))

    def test_near_change_is_stale(self):
        lost, stale = recall.compare({self.K: "NEAR"}, {self.K: "MISS"})
        self.assertEqual((lost, len(stale)), ([], 1))


class WriteTests(unittest.TestCase):
    def test_statuses_replaced_in_order_and_unscanned_kept(self):
        rows = [
            {"ghsa": "A", "file": "f", "line": 1, "status": "MISS"},
            {"ghsa": "B", "file": "g", "line": 2, "status": "HIT"},
        ]
        out = recall.updated_results(rows, {("A", "f", 1): "HIT"})
        self.assertEqual([r["status"] for r in out], ["HIT", "HIT"])
        self.assertEqual([r["ghsa"] for r in out], ["A", "B"])
        self.assertEqual(rows[0]["status"], "MISS")

    def test_recorded_file_round_trips_byte_for_byte(self):
        path = os.path.join(recall.HERE, "results.json")
        raw = open(path).read()
        self.assertEqual(json.dumps(json.loads(raw), indent=1) + "\n", raw)
        self.assertEqual(recall.updated_results(json.loads(raw), {}), json.loads(raw))


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
