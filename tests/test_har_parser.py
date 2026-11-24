import os
import unittest
from shadowapi.core.har_parser import HARParser


class TestHARParser(unittest.TestCase):
    def setUp(self):
        self.example_har = "/home/emprogue/Projects/shadowapi/examples/traffic.har"

    def test_parse_har_file(self):
        self.assertTrue(os.path.isfile(self.example_har))
        txs = HARParser.parse_file(self.example_har)
        self.assertEqual(len(txs), 4)

        paths = [t.path for t in txs]
        self.assertIn("/api/v1/users", paths)
        self.assertIn("/api/v1/users/42", paths)
        self.assertIn("/api/v1/legacy-login", paths)
        self.assertIn("/api/v1/internal/admin/dump-db", paths)

    def test_parse_raw_entries(self):
        entries = [
            {
                "request": {"method": "GET", "url": "https://example.com/items?limit=10"},
                "response": {"status": 200, "content": {"text": "{\"items\": []}"}},
            }
        ]
        txs = HARParser.parse_data(entries)
        self.assertEqual(len(txs), 1)
        self.assertEqual(txs[0].method, "GET")
        self.assertEqual(txs[0].path, "/items")
        self.assertEqual(txs[0].query_params.get("limit"), ["10"])
        self.assertEqual(txs[0].response_body, {"items": []})


if __name__ == "__main__":
    unittest.main()
