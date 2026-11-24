import unittest
from shadowapi.core.models import HTTPTransaction
from shadowapi.core.spec_builder import SpecBuilder


class TestSpecBuilder(unittest.TestCase):
    def test_build_spec_and_export(self):
        txs = [
            HTTPTransaction(
                method="GET",
                url="https://api.test/api/v1/users/1",
                path="/api/v1/users/1",
                headers={"authorization": "Bearer token123"},
                status_code=200,
                response_body={"id": 1, "username": "alice"},
            ),
            HTTPTransaction(
                method="POST",
                url="https://api.test/api/v1/users",
                path="/api/v1/users",
                headers={"authorization": "Bearer token123"},
                request_body={"username": "bob", "role": "admin"},
                status_code=201,
                response_body={"id": 2, "username": "bob"},
            ),
        ]

        builder = SpecBuilder(title="Test API", version="1.0.0")
        sigs = builder.build_signatures(txs)
        self.assertEqual(len(sigs), 2)

        spec = builder.synthesize_openapi(sigs)
        self.assertEqual(spec["openapi"], "3.1.0")
        self.assertEqual(spec["info"]["title"], "Test API")
        self.assertIn("/api/v1/users/{user_id}", spec["paths"])
        self.assertIn("/api/v1/users", spec["paths"])

        # Check export
        json_out = builder.export_json(spec)
        self.assertIn('"openapi": "3.1.0"', json_out)


if __name__ == "__main__":
    unittest.main()
