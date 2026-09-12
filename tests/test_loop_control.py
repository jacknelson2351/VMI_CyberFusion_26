import unittest

from agent import CTFAgent


def _agent(policy="verified_only", flag_format=""):
    """Build an agent shell without the heavy __init__ (no DB/docker/socket)."""
    a = CTFAgent.__new__(CTFAgent)
    a.flag_stop_policy = policy
    a.flag_format = flag_format
    a.allow_nonstandard_submit = False
    a.strict_auto_submit = True
    a._candidates = []
    a._flag_evidence = {}
    a.step = 1
    return a


class ShouldHaltTests(unittest.TestCase):
    def test_decoy_never_halts(self):
        a = _agent()
        self.assertFalse(a._should_halt_for("UMDCTF{test_flag}", "run_command: strings bin", "", "proposed"))
        self.assertFalse(a._should_halt_for("flag{fake_flag}", "http_request: GET /", "", "proposed"))

    def test_scraped_token_does_not_halt_without_format(self):
        a = _agent()
        # A real-looking token scraped from untrusted output must NOT stop the run.
        self.assertFalse(a._should_halt_for("UMDCTF{abc123}", "run_command: strings bin", "", "proposed"))

    def test_model_submission_halts(self):
        a = _agent()
        self.assertTrue(a._should_halt_for("UMDCTF{abc123}", "submit_flag", "exploit output", "verified"))

    def test_format_plus_deterministic_halts(self):
        a = _agent(flag_format="UMDCTF{")
        self.assertTrue(a._should_halt_for("UMDCTF{abc}", "run_command: python solve.py", "", "proposed"))

    def test_format_but_noisy_source_does_not_halt(self):
        a = _agent(flag_format="UMDCTF{")
        self.assertFalse(a._should_halt_for("UMDCTF{abc}", "run_command: curl http://target/", "", "proposed"))

    def test_first_candidate_policy_halts_on_anything(self):
        a = _agent(policy="first_candidate")
        self.assertTrue(a._should_halt_for("anything{x}", "run_command: strings bin", "", "proposed"))

    def test_never_policy_never_halts(self):
        a = _agent(policy="never")
        self.assertFalse(a._should_halt_for("UMDCTF{abc}", "submit_flag", "", "verified"))


class LedgerTests(unittest.TestCase):
    def test_record_and_dedup(self):
        a = _agent()
        a._record_candidate("UMDCTF{a}", "run_command", "", "proposed")
        a._record_candidate("UMDCTF{a}", "run_command", "", "submitted")  # same flag updates
        a._record_candidate("UMDCTF{b}", "submit_flag", "", "submitted")
        self.assertEqual(len(a._candidates), 2)
        first = next(c for c in a._candidates if c["flag"] == "UMDCTF{a}")
        self.assertEqual(first["status"], "submitted")


if __name__ == "__main__":
    unittest.main()
