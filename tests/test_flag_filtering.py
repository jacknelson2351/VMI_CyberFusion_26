import unittest

from agent.flags import FlagsMixin
from utils import _is_plausible_flag_token


class DummyFlags(FlagsMixin):
    flag_format = ""


class FlagFilteringTests(unittest.TestCase):
    def test_css_blocks_are_not_plausible_flags(self):
        self.assertFalse(_is_plausible_flag_token("hover{ transform: translateY(-2px); filter:brightness(1.02); }"))
        self.assertFalse(_is_plausible_flag_token("active{ transform: translateY(0px); }"))

    def test_real_ctf_shapes_still_pass(self):
        self.assertTrue(_is_plausible_flag_token("picoCTF{real_signal_123}"))
        self.assertTrue(_is_plausible_flag_token("flag{real_signal_123}"))

    def test_extractor_skips_css_noise(self):
        flags = DummyFlags()
        text = ".btn:hover{ transform: translateY(-2px); filter:brightness(1.02); } picoCTF{ok_real}"
        self.assertEqual(flags._extract_flag_candidates(text), ["picoCTF{ok_real}"])


if __name__ == "__main__":
    unittest.main()
