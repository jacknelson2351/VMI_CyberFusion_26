import unittest

from prompts import (
    CATEGORY_TOOL_CHECKS,
    SYSTEM_TOOL_INSTALLERS,
    TOOL_APT_PACKAGES,
    TOOL_INSTALL_COMMANDS,
)


class ToolDependencyTests(unittest.TestCase):
    def test_jwt_tool_preflight_name_is_installed(self):
        self.assertIn("jwt-tool", CATEGORY_TOOL_CHECKS["web"])

        for installers in (TOOL_INSTALL_COMMANDS, SYSTEM_TOOL_INSTALLERS):
            command = installers["jwt-tool"]
            self.assertIn("/opt/jwt_tool/requirements.txt", command)
            self.assertIn("/usr/local/bin/jwt-tool", command)
            self.assertIn("/usr/local/bin/jwt_tool", command)

    def test_special_preflight_tools_have_custom_installers(self):
        for tool in ("one_gadget", "RsaCtfTool", "pdf-parser.py"):
            self.assertIn(tool, TOOL_INSTALL_COMMANDS)
            self.assertIn(tool, SYSTEM_TOOL_INSTALLERS)
        self.assertIn("exec python3 /opt/DidierStevensSuite/pdf-parser.py", TOOL_INSTALL_COMMANDS["pdf-parser.py"])
        self.assertIn("exec python3 /opt/DidierStevensSuite/pdf-parser.py", SYSTEM_TOOL_INSTALLERS["pdf-parser.py"])

    def test_network_preflight_tools_map_to_apt_packages(self):
        self.assertEqual(TOOL_APT_PACKAGES["tshark"], "tshark")
        self.assertEqual(TOOL_APT_PACKAGES["tcpdump"], "tcpdump")
        self.assertEqual(TOOL_APT_PACKAGES["capinfos"], "wireshark-common")


if __name__ == "__main__":
    unittest.main()
