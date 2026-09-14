import json
import unittest

from agent.web import (
    parse_ffuf_json, format_ffuf_hits, summarize_headers,
    parse_sqlmap, format_sqlmap_verdict,
)


class FfufTests(unittest.TestCase):
    SAMPLE = json.dumps({"results": [
        {"input": {"FUZZ": "admin"}, "url": "http://t/admin", "status": 200, "length": 512, "words": 40},
        {"input": {"FUZZ": "css"}, "url": "http://t/css", "status": 301, "length": 0, "words": 1},
        {"input": {"FUZZ": "secret"}, "url": "http://t/secret", "status": 403, "length": 12, "words": 2},
    ]})

    def test_parse_and_rank(self):
        hits = parse_ffuf_json(self.SAMPLE)
        self.assertEqual(len(hits), 3)
        self.assertEqual(hits[0]["status"], 200)  # 200 ranked first
        self.assertEqual(hits[0]["url"], "http://t/admin")

    def test_bad_json(self):
        self.assertEqual(parse_ffuf_json("not json"), [])

    def test_format(self):
        out = format_ffuf_hits(parse_ffuf_json(self.SAMPLE))
        self.assertIn("admin", out)
        self.assertIn("200", out)


class HeaderTests(unittest.TestCase):
    def test_notable_only(self):
        raw = ("HTTP/1.1 200 OK\r\nDate: now\r\nServer: nginx\r\n"
               "X-Powered-By: PHP/8.1\r\nSet-Cookie: sess=abc\r\nContent-Length: 5\r\n")
        out = summarize_headers(raw)
        self.assertIn("Server: nginx", out)
        self.assertIn("X-Powered-By: PHP/8.1", out)
        self.assertIn("Set-Cookie", out)
        self.assertNotIn("Date:", out)


class SqlmapTests(unittest.TestCase):
    VULN = (
        "sqlmap identified the following injection point(s)\n"
        "Parameter: id (GET)\n"
        "    Type: boolean-based blind\n"
        "    Type: UNION query\n"
        "available databases [2]:\n[*] information_schema\n[*] webapp\n"
    )
    SAFE = "all tested parameters do not appear to be injectable."

    def test_vulnerable(self):
        v = parse_sqlmap(self.VULN)
        self.assertTrue(v["injectable"])
        self.assertEqual(v["parameter"], "id")
        self.assertIn("webapp", v["databases"])
        self.assertTrue(any("blind" in t for t in v["techniques"]))
        self.assertIn("INJECTABLE", format_sqlmap_verdict(v))

    def test_safe(self):
        v = parse_sqlmap(self.SAFE)
        self.assertFalse(v["injectable"])
        self.assertIn("no injection", format_sqlmap_verdict(v))


if __name__ == "__main__":
    unittest.main()
