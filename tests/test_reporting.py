import importlib.util
import unittest

from compliance_scanner.reporting import ReportGenerator


@unittest.skipUnless(importlib.util.find_spec("reportlab"), "ReportLab is not installed")
class ReportingTests(unittest.TestCase):
    def test_generates_pdf_from_assessment_and_existing_mapping(self):
        pdf = ReportGenerator().generate({
            "id": 4, "target": "127.0.0.1", "profile": "standard", "status": "completed",
            "created_at": "2026-10-12T10:30:00Z", "findings": [{
                "port": 23, "protocol": "tcp", "service": "telnet", "observed_state": "open",
                "status": "review", "risk": "High", "observation": "Open TCP service observed.",
                "why_matters": "Cleartext management can expose credentials.",
                "recommendation": "Disable Telnet and use SSH.", "verification": "Confirm approved management path.",
                "framework_mappings": [{"identifier": "PR.DS-02", "title": "Protect data-in-transit",
                                        "rationale": "Telnet does not encrypt management traffic."}],
            }],
        })
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertIn(b"%%EOF", pdf)

    def test_missing_optional_values_and_empty_findings_are_handled(self):
        pdf = ReportGenerator().generate({"findings": [{"port": 80, "service": "http",
                                                            "framework_mappings": None}]})
        self.assertTrue(pdf.startswith(b"%PDF-"))
        empty_pdf = ReportGenerator().generate({"findings": []})
        self.assertTrue(empty_pdf.startswith(b"%PDF-"))


if __name__ == "__main__":
    unittest.main()
