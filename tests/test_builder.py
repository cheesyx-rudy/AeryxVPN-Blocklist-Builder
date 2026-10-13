import unittest

from blocklist_builder.builder import canonicalize, parse_candidates


class ParseCandidatesTests(unittest.TestCase):
    def test_valid_ipv4_and_ipv6(self):
        raw = b"1.1.1.1\n8.8.8.0/24\n2606:4700::/32\n"
        networks, stats = parse_candidates(raw, "text")
        self.assertIn("1.1.1.1/32", networks)
        self.assertIn("8.8.8.0/24", networks)
        self.assertIn("2606:4700::/32", networks)
        self.assertGreaterEqual(stats["accepted"], 3)

    def test_private_and_documentation_ranges_excluded(self):
        raw = b"10.0.0.1\n192.0.2.0/24\n127.0.0.1\n8.8.4.4\n"
        networks, _ = parse_candidates(raw, "text")
        self.assertEqual(networks, {"8.8.4.4/32"})

    def test_invalid_tokens_ignored(self):
        networks, stats = parse_candidates(b"999.999.999.999\n8.8.8.8\n", "text")
        self.assertEqual(networks, {"8.8.8.8/32"})
        self.assertGreaterEqual(stats["invalid"], 1)

    def test_json_payload(self):
        raw = b'{"ips": ["8.8.8.8", "2606:4700::/32"], "note": "registry snapshot"}'
        networks, _ = parse_candidates(raw, "auto")
        self.assertIn("8.8.8.8/32", networks)
        self.assertIn("2606:4700::/32", networks)

    def test_collapse_overlapping_networks(self):
        got = canonicalize({"8.8.8.0/25", "8.8.8.128/25", "1.1.1.1"})
        self.assertEqual(got, ["1.1.1.1/32", "8.8.8.0/24"])


if __name__ == "__main__":
    unittest.main()
