import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check


class CheckTests(unittest.TestCase):
    def test_parse_scan_output_skips_log_lines(self):
        text = 'scanning...\nwarn: x\n{\n"findings": []\n}\n'
        self.assertEqual(check.parse_scan_output(text), {"findings": []})

    def test_parse_scan_output_plain_json(self):
        self.assertEqual(check.parse_scan_output('{\n"findings": []\n}'), {"findings": []})

    def test_parse_scan_output_rejects_missing_json(self):
        with self.assertRaises(ValueError):
            check.parse_scan_output("no json here")

    def test_keys_are_relative_and_clone_location_independent(self):
        doc = {"findings": [{"file_path": "/a/b/repo/x/y.py", "line_number": 3, "title": "T"}]}
        self.assertEqual(check.finding_keys(doc, "/a/b/repo"), [("x/y.py", 3, "T")])
        doc2 = {"findings": [{"file_path": "/other/repo/x/y.py", "line_number": 3, "title": "T"}]}
        self.assertEqual(check.finding_keys(doc2, "/other/repo"), [("x/y.py", 3, "T")])

    def test_round_trip_format(self):
        keys = [("a.py", 1, "A"), ("b/c.rb", 20, "Title with spaces")]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "k.tsv")
            with open(p, "w") as fh:
                fh.write(check.format_keys(keys))
            self.assertEqual(check.read_keys(p), keys)
        self.assertIsNone(check.read_keys("/nonexistent/file.tsv"))

    def test_diff_reports_added_and_removed(self):
        removed, added = check.diff_keys([("a", 1, "X"), ("b", 2, "Y")], [("b", 2, "Y"), ("c", 3, "Z")])
        self.assertEqual(removed, [("a", 1, "X")])
        self.assertEqual(added, [("c", 3, "Z")])

    def test_title_change_is_a_delta(self):
        removed, added = check.diff_keys([("a", 1, "SQL Injection")], [("a", 1, "NoSQL Injection")])
        self.assertTrue(removed and added)

    def test_ledger_loss_detected_and_control_passes(self):
        keys = [("a.py", 1, "X"), ("b.py", 2, "Y")]
        self.assertEqual(check.ledger_missing([("a.py", 1), ("b.py", 2)], keys), [])
        self.assertEqual(check.ledger_missing([("a.py", 1), ("c.py", 9)], keys), [("c.py", 9)])

    def test_committed_data_is_consistent(self):
        here = os.path.dirname(os.path.abspath(__file__))
        manifest = json.load(open(os.path.join(here, "manifest.json")))
        ledger = json.load(open(os.path.join(here, "ledger.json")))
        names = {r["name"] for r in manifest["repos"]}
        for r in manifest["repos"]:
            self.assertEqual(len(r["sha"]), 40)
            self.assertTrue(os.path.exists(os.path.join(here, "expected", r["name"] + ".tsv")), r["name"])
        for name, pairs in ledger.items():
            self.assertIn(name, names)
            keys = check.read_keys(os.path.join(here, "expected", name + ".tsv"))
            self.assertEqual(check.ledger_missing([(e["file"], e["line"]) for e in pairs], keys), [], name)
        self.assertEqual(sum(len(v) for v in ledger.values()), 86)


if __name__ == "__main__":
    unittest.main()
