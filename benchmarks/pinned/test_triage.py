import glob
import json
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
VERDICTS = {"TP", "FP", "JUDGMENT"}


def expected_keys():
    keys = set()
    for path in glob.glob(os.path.join(HERE, "production-expected", "*.tsv")):
        repo = os.path.basename(path)[:-4]
        for line in open(path, encoding="utf-8"):
            line = line.rstrip("\n")
            if line:
                f, n, t = line.split("\t")
                keys.add((repo, f, int(n), t))
    return keys


class TriageTests(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(HERE, "production-triage.json"), encoding="utf-8") as fh:
            self.rows = json.load(fh)

    def test_every_expected_key_has_one_verdict_and_none_is_stale(self):
        got = [(r["repo"], r["file"], r["line"], r["title"]) for r in self.rows]
        self.assertEqual(len(got), len(set(got)))
        self.assertEqual(set(got), expected_keys())

    def test_verdicts_are_valid_and_have_reasons(self):
        for r in self.rows:
            self.assertIn(r["verdict"], VERDICTS)
            self.assertGreater(len(r["reason"]), 20)


if __name__ == "__main__":
    unittest.main()
