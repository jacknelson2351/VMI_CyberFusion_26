import importlib.util
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("eval_harness", BASE / "scripts" / "eval.py")
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)


CHALS = [
    {"id": "a", "name": "Alpha", "category": "rev"},
    {"id": "b", "name": "Bravo", "category": "web"},
    {"id": "c", "name": "Charlie", "category": "rev"},
]


class SelectTests(unittest.TestCase):
    def test_by_ids_preserves_order(self):
        got = ev.select_challenges(CHALS, ids=["c", "a"])
        self.assertEqual([c["id"] for c in got], ["c", "a"])

    def test_by_ids_skips_unknown(self):
        got = ev.select_challenges(CHALS, ids=["a", "zzz"])
        self.assertEqual([c["id"] for c in got], ["a"])

    def test_by_category(self):
        got = ev.select_challenges(CHALS, category="rev")
        self.assertEqual([c["id"] for c in got], ["a", "c"])

    def test_by_count(self):
        got = ev.select_challenges(CHALS, count=2)
        self.assertEqual(len(got), 2)


class BudgetTests(unittest.TestCase):
    def test_gate(self):
        self.assertFalse(ev.budget_exhausted(1.0, 5.0))
        self.assertTrue(ev.budget_exhausted(5.0, 5.0))
        self.assertTrue(ev.budget_exhausted(6.0, 5.0))
        self.assertFalse(ev.budget_exhausted(100.0, None))


class SummaryTests(unittest.TestCase):
    def test_summarize(self):
        results = [
            {"status": "solved", "cost_usd": 0.10},
            {"status": "unsolved", "cost_usd": 0.20},
            {"status": "pending_approval", "cost_usd": 0.05},
            {"status": "solved", "cost_usd": 0.15},
        ]
        s = ev.summarize(results)
        self.assertEqual(s["total"], 4)
        self.assertEqual(s["solved"], 2)
        self.assertEqual(s["pending_approval"], 1)
        self.assertEqual(s["found"], 3)          # solved + pending_approval
        self.assertEqual(s["found_rate"], 0.75)
        self.assertAlmostEqual(s["total_cost_usd"], 0.50, places=4)

    def test_markdown_contains_totals_and_rows(self):
        results = [{"id": "a", "name": "Alpha", "category": "rev", "status": "solved",
                    "flag": "F{x}", "cost_usd": 0.1, "steps": 5, "secs": 12}]
        totals = ev.summarize(results)
        meta = {"generated_at": "now", "set": "s", "model": "m", "arch": "single_loop",
                "budget": 5.0, "max_steps": 20, "stopped_for_budget": False}
        md = ev.format_markdown(meta, results, totals)
        self.assertIn("Alpha", md)
        self.assertIn("flag found 1/1", md)


if __name__ == "__main__":
    unittest.main()
