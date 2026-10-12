import tempfile
import unittest
import importlib.util
from unittest.mock import Mock
try:
    from flask import Flask
    from compliance_scanner.routes import create_app
    from compliance_scanner.scanner import ScannerUnavailable
    from compliance_scanner.database import create_assessment
    from compliance_scanner.policy_engine import evaluate_services
except ImportError:
    Flask = None


@unittest.skipIf(Flask is None, "Flask is not installed; install requirements to run route tests")
class RouteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.scanner = Mock()
        self.scanner.scan.side_effect = ScannerUnavailable("Nmap was not found; no assessment was saved.")
        self.app = create_app({"TESTING": True, "DATABASE": self.temp.name + "/routes.sqlite3",
                               "SECRET_KEY": "test", "SCANNER": self.scanner})
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp.cleanup()

    def test_dashboard_has_empty_state_and_no_fake_data(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No network scan has been run", response.data)
        self.assertIn(b"DEMO DATA", response.data)

    def test_scan_form_is_reachable_and_post_reports_missing_scanner(self):
        self.assertEqual(self.client.get("/scan").status_code, 200)
        response = self.client.post("/scan", data={"target": "192.0.2.1", "profile": "standard", "authorized": "yes"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Nmap was not found", response.data)
        self.assertEqual(self.scanner.scan.call_count, 1)

    def test_successful_scan_is_evaluated_persisted_and_shown(self):
        self.scanner.scan.side_effect = None
        self.scanner.scan.return_value = {"target": "127.0.0.1", "profile": "standard", "observations": [
            {"port": 23, "protocol": "tcp", "service": "telnet", "state": "open"}]}
        response = self.client.post("/scan", data={"target": "127.0.0.1", "profile": "standard", "authorized": "yes"})
        self.assertEqual(response.status_code, 302)
        detail = self.client.get(response.location)
        self.assertEqual(detail.status_code, 200)
        self.assertIn(b"127.0.0.1", detail.data)
        self.assertIn(b"High", detail.data)
        self.assertIn(b"Disable Telnet", detail.data)
        self.assertIn(b"NIST Cybersecurity Framework 2.0", detail.data)
        self.assertIn(b"Evidence limit:", detail.data)
        self.assertIn(b"Official framework source", detail.data)
        self.assertIn(b"Not assessed; no verified CVE", detail.data)
        dashboard = self.client.get("/")
        self.assertIn(b"open ports observed", dashboard.data)
        self.assertIn(b"direct framework references", dashboard.data)

    def test_cvss_is_rendered_only_for_complete_verified_record(self):
        findings = evaluate_services([{"port": 443, "service": "https"}])
        findings[0]["vulnerability"] = {"verified": True, "cve": "CVE-2024-12345", "cvss_version": "4.0",
            "cvss_score": 8.1, "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"}
        assessment_id = create_assessment(self.app.config["DATABASE"], "127.0.0.1", "standard", findings=findings)
        detail = self.client.get(f"/assessments/{assessment_id}")
        self.assertIn(b"CVE-2024-12345", detail.data)
        self.assertIn(b"CVSS 4.0", detail.data)

    def test_assessment_page_shows_historical_observed_port_comparison(self):
        first = evaluate_services([{"port": 22, "service": "ssh"}, {"port": 445, "service": "smb"}])
        second = evaluate_services([{"port": 22, "service": "ssh"}, {"port": 80, "service": "http"}])
        create_assessment(self.app.config["DATABASE"], "target.example", "standard", findings=first)
        current_id = create_assessment(self.app.config["DATABASE"], "target.example", "standard", findings=second)
        detail = self.client.get(f"/assessments/{current_id}")
        self.assertIn(b"Observed change from previous scan", detail.data)
        self.assertIn(b"Appeared (1)", detail.data)
        self.assertIn(b"80", detail.data)
        self.assertIn(b"Disappeared (1)", detail.data)
        self.assertIn(b"These are changes in observed open ports", detail.data)

    def test_unmapped_service_is_labeled_without_direct_framework_mapping(self):
        finding = evaluate_services([{"port": 445, "service": "microsoft-ds"}])
        assessment_id = create_assessment(self.app.config["DATABASE"], "fileserver.example", "standard", findings=finding)
        detail = self.client.get(f"/assessments/{assessment_id}")
        self.assertIn(b"No direct mapping assigned", detail.data)

    def test_history_and_unknown_assessment(self):
        self.assertIn(b"No assessment history", self.client.get("/history").data)
        self.assertEqual(self.client.get("/assessments/99").status_code, 404)
        self.assertEqual(self.client.get("/assessments/99/report.pdf").status_code, 404)

    @unittest.skipUnless(importlib.util.find_spec("reportlab"), "ReportLab is not installed")
    def test_assessment_page_links_to_downloadable_pdf_report(self):
        assessment_id = create_assessment(self.app.config["DATABASE"], "127.0.0.1", "standard",
                                          findings=evaluate_services([{"port": 23, "service": "telnet"}]))
        detail = self.client.get(f"/assessments/{assessment_id}")
        self.assertIn(b"Download PDF Report", detail.data)
        report = self.client.get(f"/assessments/{assessment_id}/report.pdf")
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.mimetype, "application/pdf")
        self.assertTrue(report.data.startswith(b"%PDF-"))
        self.assertIn('attachment; filename="assessment-', report.headers["Content-Disposition"])

    def test_scan_requires_authorization_confirmation(self):
        response = self.client.post("/scan", data={"target": "127.0.0.1", "profile": "standard"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"explicit authorization", response.data)
        self.scanner.scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
