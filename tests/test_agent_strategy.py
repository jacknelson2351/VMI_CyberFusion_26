import unittest

from agent.strategy import (
    cadence_due,
    checkpoint_due,
    choose_phase,
    rank_tool_names,
    reorder_tool_definitions,
)


class AgentStrategyTests(unittest.TestCase):
    def test_choose_phase_progression_and_stall_pivot(self):
        self.assertEqual(choose_phase(step=1, current_phase="idle"), "recon")
        self.assertEqual(choose_phase(step=3, current_phase="recon"), "analyze")
        self.assertEqual(choose_phase(step=8, current_phase="analyze"), "exploit")
        self.assertEqual(
            choose_phase(step=8, current_phase="exploit", no_progress_streak=3),
            "analyze",
        )
        self.assertEqual(
            choose_phase(step=8, current_phase="exploit", has_flag_candidate=True),
            "verify",
        )

    def test_cadence_helpers(self):
        self.assertTrue(checkpoint_due(step=5, last_step=0, interval=5))
        self.assertFalse(checkpoint_due(step=4, last_step=0, interval=5))
        self.assertTrue(cadence_due(step=10, interval=5))
        self.assertFalse(cadence_due(step=11, interval=5))

    def test_rank_tool_names_prefers_phase_and_successful_tools(self):
        names = ["run_command", "http_request", "run_gdb", "search_flag"]
        stats = {
            "http_request": {"calls": 4, "progress": 3, "errors": 0},
            "run_command": {"calls": 5, "progress": 0, "errors": 2},
        }
        ranked = rank_tool_names("web", "exploit", stats, names)
        self.assertEqual(ranked[0], "http_request")
        self.assertLess(ranked.index("run_command"), len(ranked))

    def test_reorder_tool_definitions_preserves_schema(self):
        tools = [
            {"type": "function", "function": {"name": "run_command"}},
            {"type": "function", "function": {"name": "http_request"}},
        ]
        ordered = reorder_tool_definitions(
            "web",
            "exploit",
            {"http_request": {"calls": 2, "progress": 2, "errors": 0}},
            tools,
        )
        self.assertEqual(ordered[0]["function"]["name"], "http_request")
        self.assertEqual(tools[0]["function"]["name"], "run_command")


if __name__ == "__main__":
    unittest.main()
