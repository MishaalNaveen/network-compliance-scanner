import unittest
from compliance_scanner.risk_engine import POLICY_PRIORITY_LABELS, classify_risk


class RiskEngineTests(unittest.TestCase):
    def test_violation_escalates_to_high_with_reason(self):
        risk, reason = classify_risk("violation", "Low")
        self.assertEqual(risk, "High")
        self.assertIn("Policy baseline violation", reason)
        self.assertIn("not a CVSS score", reason)

    def test_review_retains_explainable_baseline(self):
        priority, reason = classify_risk("review", "Medium")
        self.assertEqual(priority, "Medium")
        self.assertIn("not a CVSS or NIST risk score", reason)

    def test_priority_labels_are_policy_ordering_not_standardized_scores(self):
        self.assertEqual(set(POLICY_PRIORITY_LABELS), {"Low", "Medium", "High"})
        self.assertIn("configured service rule", POLICY_PRIORITY_LABELS["High"])

    def test_invalid_review_priority_is_rejected(self):
        with self.assertRaises(ValueError):
            classify_risk("review", "Critical")

    def test_unknown_status_is_rejected(self):
        with self.assertRaises(ValueError):
            classify_risk("unknown", "High")


if __name__ == "__main__":
    unittest.main()
