import unittest

from agent.aci import condense, salient_lines, actionable_error
from agent import CTFAgent


class ACITests(unittest.TestCase):
    def test_small_output_passthrough(self):
        self.assertEqual(condense("hello world", limit=100), "hello world")

    def test_flag_in_middle_survives_condensation(self):
        noise = "\n".join(f"line {i} boring output" for i in range(2000))
        text = noise + "\nUMDCTF{the_real_flag_deep_in_output}\n" + noise
        out = condense(text, limit=2000)
        self.assertLessEqual(len(out), 2200)  # limit + small salient overhead
        self.assertIn("UMDCTF{the_real_flag_deep_in_output}", out)

    def test_respects_limit_when_no_salient(self):
        text = "x" * 50000
        out = condense(text, limit=1000)
        self.assertLess(len(out), 1400)

    def test_salient_lines_picks_errors_and_addresses(self):
        text = "ok\nSegmentation fault\nnothing\n0xdeadbeef1234\nboring"
        sal = salient_lines(text)
        self.assertTrue(any("Segmentation fault" in s for s in sal))
        self.assertTrue(any("0xdeadbeef1234" in s for s in sal))

    def test_actionable_error(self):
        self.assertIn("Path not found", actionable_error("cat: /ctf/x: No such file or directory"))
        self.assertIn("not installed", actionable_error("bash: ropper: command not found"))
        self.assertIn("module", actionable_error("ModuleNotFoundError: No module named 'pwn'"))
        self.assertIsNone(actionable_error("all good, flag printed"))


class SessionExtractTests(unittest.TestCase):
    def _agent(self):
        return CTFAgent.__new__(CTFAgent)

    def test_extract_output_between_script_and_marker(self):
        a = self._agent()
        pane = (
            "user@ctf:/ctf$ . /ctf/.sessions/sh_main_1.sh; echo __CTF_DONE_1__ rc=$?\n"
            "hello from the session\n"
            "second line\n"
            "__CTF_DONE_1__ rc=0\n"
            "user@ctf:/ctf$ "
        )
        out = a._im_extract(pane, "/ctf/.sessions/sh_main_1.sh", "__CTF_DONE_1__")
        self.assertIn("hello from the session", out)
        self.assertIn("second line", out)
        self.assertNotIn("__CTF_DONE_1__", out)

    def test_extract_reports_nonzero_exit(self):
        a = self._agent()
        pane = (". /ctf/.sessions/sh_main_2.sh; echo __CTF_DONE_2__ rc=$?\n"
                "boom\n__CTF_DONE_2__ rc=1\n")
        out = a._im_extract(pane, "/ctf/.sessions/sh_main_2.sh", "__CTF_DONE_2__")
        self.assertIn("boom", out)
        self.assertIn("[exit 1]", out)

    def test_extract_no_marker_yet(self):
        a = self._agent()
        out = a._im_extract("still running...\n", "/ctf/x.sh", "__CTF_DONE_9__")
        self.assertIn("no completion marker", out)


if __name__ == "__main__":
    unittest.main()
