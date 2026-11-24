import os
import tempfile
import unittest
from shadowapi.cli import handle_diff, handle_synthesize
import argparse


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.spec_file = "/home/emprogue/Projects/shadowapi/examples/declared_spec.json"
        self.har_file = "/home/emprogue/Projects/shadowapi/examples/traffic.har"

    def test_cli_synthesize(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
            out_path = f.name

        try:
            args = argparse.Namespace(
                traffic=self.har_file,
                output=out_path,
                title="Synthesized Test API",
                version="1.0.0",
            )
            code = handle_synthesize(args)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isfile(out_path))
            with open(out_path, "r") as f:
                content = f.read()
            self.assertIn('"openapi": "3.1.0"', content)
        finally:
            if os.path.exists(out_path):
                os.remove(out_path)

    def test_cli_diff(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f_json:
            out_json = f_json.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as f_html:
            out_html = f_html.name

        try:
            args = argparse.Namespace(
                traffic=self.har_file,
                spec=self.spec_file,
                output_json=out_json,
                output_html=out_html,
                fail_on_risk=0,
            )
            code = handle_diff(args)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isfile(out_json))
            self.assertTrue(os.path.isfile(out_html))
        finally:
            for p in (out_json, out_html):
                if os.path.exists(p):
                    os.remove(p)


if __name__ == "__main__":
    unittest.main()
