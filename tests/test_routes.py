import tempfile
import unittest
import importlib.util
import re
from unittest.mock import Mock, patch
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
            {"port": 23, "protocol": "tcp", "service": "telnet", "state": "open", "service_method": "probed"},
            {"port": 8080, "protocol": "tcp", "service": "http-proxy", "state": "open", "service_method": "table"}]}
        response = self.client.post("/scan", data={"target": "127.0.0.1", "profile": "standard", "authorized": "yes"})
        self.assertEqual(response.status_code, 302)
        detail = self.client.get(response.location)
        self.assertEqual(detail.status_code, 200)
        self.assertIn(b"127.0.0.1", detail.data)
        self.assertIn(b"High", detail.data)
        self.assertNotIn(b"POLICY STATUS", detail.data)
        self.assertNotIn(b"Review required", detail.data)
        self.assertIn(b"POLICY PRIORITY", detail.data)
        self.assertIn(b"OBSERVED EXPOSURE", detail.data)
        self.assertIn(b"Why and next checks", detail.data)
        self.assertIn(b"Disable Telnet", detail.data)
        self.assertIn(b"Not assessed; no verified CVE", detail.data)
        self.assertIn(b"POTENTIAL FRAMEWORK ALIGNMENT", detail.data)
        self.assertIn(b"service identity is unverified", detail.data)
        alignment = re.findall(rb'<td class="framework-alignment">(.*?)</td>', detail.data, re.S)
        self.assertEqual([cell.count(b'class="framework-entry"') for cell in alignment], [2, 1])
        self.assertIn("NIST CSF 2.0 · PR.DS-02".encode(), alignment[0])
        self.assertIn("CIS Controls 8.1 · 4.8".encode(), alignment[0])
        self.assertIn(b"Protect data in transit", alignment[0])
        self.assertIn(b"A probe identified a cleartext-capable service.", alignment[0])
        self.assertIn(b"Disable or remove unnecessary services", alignment[0])
        self.assertIn(b'<abbr title="Evidence-supported relevance">E</abbr>', alignment[0])
        self.assertIn(b'<abbr title="Potential control relevance">P</abbr>', alignment[0])
        finding_details = re.findall(rb'<td class="recommendation finding-details">(.*?)</td>', detail.data, re.S)
        self.assertEqual(len(finding_details), 2)
        for cell in finding_details:
            self.assertEqual(re.findall(rb'<p><b>(.*?)</b>', cell),
                             [b"Why it matters:", b"Verify:", b"Suggested action:", b"Priority rationale:"])
        for hidden in (b"Evidence limit:", b"Observed evidence:", b"no TLS tunnel reported",
                       b"check approved business need and dependencies"):
            self.assertNotIn(hidden, detail.data)
        dashboard = self.client.get("/")
        self.assertIn(b"open ports observed", dashboard.data)
        self.assertIn(b"<b>2</b><span>with framework references", dashboard.data)

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
        finding = [{"port": 445, "service": "SMB", "observation": "Original SMB observation."}]
        assessment_id = create_assessment(self.app.config["DATABASE"], "fileserver.example", "standard", findings=finding)
        detail = self.client.get(f"/assessments/{assessment_id}")
        self.assertIn(b"No direct mapping assigned.", detail.data)
        self.assertIn(b"Original SMB observation.", detail.data)

    def test_historical_mapping_renders_with_original_rationale_and_no_added_category(self):
        mapping = {"framework": "NIST Cybersecurity Framework", "version": "2.0", "identifier": "PR.DS-02",
                   "title": "Saved transport reference", "rationale": "Saved mapping rationale."}
        assessment_id = create_assessment(self.app.config["DATABASE"], "old.example", "standard", findings=[
            {"port": 23, "service": "Telnet", "framework_mappings": [mapping]},
        ])
        detail = self.client.get(f"/assessments/{assessment_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertIn(b"Saved mapping rationale.", detail.data)
        self.assertNotIn(b"<abbr", detail.data)
        self.assertNotIn(b"CIS Controls", detail.data)

    def test_history_and_unknown_assessment(self):
        self.assertIn(b"No assessment history", self.client.get("/history").data)
        self.assertEqual(self.client.get("/assessments/99").status_code, 404)
        self.assertEqual(self.client.get("/assessments/99/report.pdf").status_code, 404)

    @unittest.skipUnless(importlib.util.find_spec("reportlab"), "ReportLab is not installed")
    def test_assessment_page_links_to_downloadable_pdf_report(self):
        assessment_id = create_assessment(self.app.config["DATABASE"], "127.0.0.1", "standard",
                                          findings=evaluate_services([
                                              {"port": 8080, "service": "http", "service_method": "probed"},
                                              {"port": 8000, "service": "http-alt", "service_method": "table"},
                                              {"port": 22, "service": "ssh", "service_method": "probed"}]))
        detail = self.client.get(f"/assessments/{assessment_id}")
        self.assertIn(b"Download PDF Report", detail.data)
        with patch("reportlab.rl_config.pageCompression", 0):
            report = self.client.get(f"/assessments/{assessment_id}/report.pdf")
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.mimetype, "application/pdf")
        self.assertTrue(report.data.startswith(b"%PDF-"))
        self.assertIn(b"Identifier: PR.DS-02", report.data)
        self.assertIn(b"Identifier: PR.PS-01", report.data)
        self.assertIn(b"CIS Controls 8.1", report.data)
        self.assertIn(b"Identifier: 6.5", report.data)
        self.assertIn(b"Evidence-supported relevance", report.data)
        self.assertIn(b"Potential control relevance", report.data)
        self.assertIn(b"Require MFA for Administrative Access", report.data)
        self.assertIn(b"authentication path may be in scope for administrative MFA.", report.data)
        self.assertIn(b"Observed evidence:", report.data)
        self.assertIn(b"Confirm administrative use and MFA support", report.data)
        self.assertIn(b"Evidence limit:", report.data)
        self.assertIn(b"service identity is unverified", report.data)
        self.assertIn(b"Policy status: Review required", report.data)
        self.assertIn('attachment; filename="assessment-', report.headers["Content-Disposition"])

    def test_scan_requires_authorization_confirmation(self):
        response = self.client.post("/scan", data={"target": "127.0.0.1", "profile": "standard"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"explicit authorization", response.data)
        self.scanner.scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
