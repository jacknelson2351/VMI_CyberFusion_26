import json
import unittest

import agent.graph_pe as pe
from agent import CTFAgent


class _Mem:
    def __init__(self):
        self.confirmed = []
        self.ruled_out = []
    def save(self):
        pass


def _agent():
    a = CTFAgent.__new__(CTFAgent)
    a.memory = _Mem()
    a.running = True
    a.step = 0
    a.messages = []
    a._candidates = []
    a.cfg = {"executor_task_budget": 6}
    a._current_phase = "analyze"
    # no-op emitters / phase / trace
    a.emit = lambda *x, **k: None
    a._set_phase = lambda *x, **k: None
    a._trace_loop = lambda *x, **k: None
    return a


class PlannerExecutorTests(unittest.TestCase):
    def test_planner_declares_solved(self):
        a = _agent()
        a._complete_text = lambda *x, **k: json.dumps({"analysis": "done", "solved": True})
        res = pe.run_planner_executor(a, [{"role": "user", "content": "brief"}], max_steps=20)
        self.assertEqual(res["stop_reason"], "solved")

    def test_planner_give_up(self):
        a = _agent()
        a._complete_text = lambda *x, **k: json.dumps({"analysis": "stuck", "give_up": True})
        res = pe.run_planner_executor(a, [{"role": "user", "content": "b"}], max_steps=20)
        self.assertEqual(res["stop_reason"], "planner_gave_up")

    def test_delegates_task_then_executor_halts_on_flag(self):
        a = _agent()
        a._complete_text = lambda *x, **k: json.dumps(
            {"analysis": "go", "next_task": {"goal": "find the flag", "approach": "grep",
                                             "success_looks_like": "flag printed"}})
        calls = {"n": 0}

        def fake_exec(agent, messages, max_steps, start_round=0):
            calls["n"] += 1
            agent.step = max_steps
            agent.running = False  # simulate a verified-flag halt (Spec B)
            return {"stop_reason": "submitted"}

        orig = pe.run_solver_graph
        pe.run_solver_graph = fake_exec
        try:
            res = pe.run_planner_executor(a, [{"role": "user", "content": "b"}], max_steps=20)
        finally:
            pe.run_solver_graph = orig
        self.assertEqual(res["stop_reason"], "submitted")
        self.assertEqual(calls["n"], 1)

    def test_respects_global_step_budget(self):
        a = _agent()
        a._complete_text = lambda *x, **k: json.dumps(
            {"analysis": "go", "next_task": {"goal": "keep trying", "approach": "",
                                             "success_looks_like": "x"}})

        def fake_exec(agent, messages, max_steps, start_round=0):
            agent.step = max_steps  # each executor consumes its whole sub-budget, no flag
            return {"stop_reason": "max_steps"}

        orig = pe.run_solver_graph
        pe.run_solver_graph = fake_exec
        try:
            res = pe.run_planner_executor(a, [{"role": "user", "content": "b"}], max_steps=12)
        finally:
            pe.run_solver_graph = orig
        self.assertEqual(res["stop_reason"], "max_steps")
        self.assertGreaterEqual(a.step, 12)


if __name__ == "__main__":
    unittest.main()
