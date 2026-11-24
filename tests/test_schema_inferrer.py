import unittest
from shadowapi.core.schema_inferrer import SchemaInferrer


class TestSchemaInferrer(unittest.TestCase):
    def test_normalize_path(self):
        # Numeric ID
        path1, params1 = SchemaInferrer.normalize_path("/api/v1/users/42/orders/99")
        self.assertEqual(path1, "/api/v1/users/{user_id}/orders/{order_id}")
        self.assertEqual(params1, ["user_id", "order_id"])

        # UUID
        path2, params2 = SchemaInferrer.normalize_path("/api/v1/tenants/550e8400-e29b-41d4-a716-446655440000")
        self.assertEqual(path2, "/api/v1/tenants/{tenant_uuid}")
        self.assertEqual(params2, ["tenant_uuid"])

        # Hex Hash
        path3, params3 = SchemaInferrer.normalize_path("/api/v1/commits/0123456789abcdef0123456789abcdef")
        self.assertEqual(path3, "/api/v1/commits/{commit_hash}")

    def test_infer_schema(self):
        sample = {
            "name": "Jane",
            "age": 30,
            "is_admin": False,
            "roles": ["editor", "viewer"],
            "metadata": {"department": "Security"},
        }
        schema = SchemaInferrer.infer_schema(sample)
        self.assertEqual(schema["type"], "object")
        props = schema["properties"]
        self.assertEqual(props["name"]["type"], "string")
        self.assertEqual(props["age"]["type"], "integer")
        self.assertEqual(props["is_admin"]["type"], "boolean")
        self.assertEqual(props["roles"]["type"], "array")
        self.assertEqual(props["roles"]["items"]["type"], "string")
        self.assertEqual(props["metadata"]["type"], "object")

    def test_detect_sensitive_data(self):
        payload = {
            "user_id": 101,
            "client_secret": "super_secret_token_123",
            "aws_creds": {"key": "AKIAIOSFODNN7EXAMPLE"},
        }
        exposures = SchemaInferrer.detect_sensitive_data(payload)
        reasons = [e["reason"] for e in exposures]
        self.assertTrue(any("Sensitive key detected" in r for r in reasons))
        self.assertTrue(any("AWS Access Key" in r for r in reasons))


if __name__ == "__main__":
    unittest.main()
