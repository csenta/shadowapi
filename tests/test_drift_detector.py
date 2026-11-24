import unittest
from shadowapi.core.har_parser import HARParser
from shadowapi.core.models import DriftType
from shadowapi.core.spec_builder import SpecBuilder
from shadowapi.engine.drift_detector import DriftDetector


class TestDriftDetector(unittest.TestCase):
    def setUp(self):
        self.spec_file = "/home/emprogue/Projects/shadowapi/examples/declared_spec.json"
        self.har_file = "/home/emprogue/Projects/shadowapi/examples/traffic.har"

    def test_drift_detection_suite(self):
        detector = DriftDetector.from_file(self.spec_file)
        txs = HARParser.parse_file(self.har_file)

        builder = SpecBuilder()
        signatures = builder.build_signatures(txs)
        report = detector.analyze(signatures, txs)

        drift_types = [f.drift_type for f in report.findings]

        # 1. Shadow Endpoint detected (/api/v1/internal/admin/dump-db)
        self.assertIn(DriftType.SHADOW_ENDPOINT, drift_types)

        # 2. Zombie Endpoint detected (/api/v1/legacy-login)
        self.assertIn(DriftType.ZOMBIE_ENDPOINT, drift_types)

        # 3. Auth Gap detected (/api/v1/users/42 called without Authorization header)
        self.assertIn(DriftType.AUTH_DISCREPANCY, drift_types)

        # 4. Sensitive Data Exposure detected (AWS key in response)
        self.assertIn(DriftType.SENSITIVE_DATA_EXPOSURE, drift_types)

        # 5. Risk score calculated properly
        self.assertGreater(report.risk_score, 50)


if __name__ == "__main__":
    unittest.main()
