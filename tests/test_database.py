import tempfile
import sqlite3
import unittest
from pathlib import Path
from compliance_scanner.database import compare_assessment, create_assessment, dashboard_summary, initialize, list_assessments
from compliance_scanner.policy_engine import evaluate_services


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "nested" / "test.sqlite3")
        initialize(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def test_assessment_and_findings_round_trip_with_demo_marker(self):
        finding = evaluate_services([{"port": 23, "service": "telnet"}])
        assessment_id = create_assessment(self.path, "demo.invalid", "standard", is_demo=True, findings=finding)
        items = list_assessments(self.path)
        self.assertEqual(items[0]["id"], assessment_id)
        self.assertEqual(items[0]["is_demo"], 1)
        self.assertEqual(items[0]["findings"][0]["risk"], "High")
        self.assertEqual(items[0]["findings"][0]["nist_csf"], "PR.DS-02")
        self.assertEqual(items[0]["findings"][0]["framework_mappings"][0]["version"], "2.0")
        self.assertEqual(items[0]["findings"][0]["vulnerability_status"], "not_assessed")

    def test_empty_database_returns_empty_history(self):
        self.assertEqual(list_assessments(self.path), [])

    def test_dashboard_summary_aggregates_persisted_findings(self):
        create_assessment(self.path, "example.internal", "standard", findings=evaluate_services([
            {"port": 23, "service": "telnet"}, {"port": 22, "service": "ssh"}]))
        summary = dashboard_summary(self.path)
        self.assertEqual(summary, {"assessments": 1, "findings": 2, "review": 2,
                                   "risks": {"High": 1, "Medium": 1, "Low": 0}})

    def test_comparison_groups_ports_for_same_target_without_erasing_history(self):
        first = evaluate_services([{"port": 22, "service": "ssh"}, {"port": 445, "service": "smb"}])
        second = evaluate_services([{"port": 22, "service": "ssh"}, {"port": 80, "service": "http"}])
        first_id = create_assessment(self.path, "HOST.example", "standard", findings=first)
        second_id = create_assessment(self.path, "host.example", "standard", findings=second)
        diff = compare_assessment(self.path, second_id)
        self.assertEqual(diff["previous"]["id"], first_id)
        self.assertEqual([f["port"] for f in diff["appeared"]], [80])
        self.assertEqual([f["port"] for f in diff["disappeared"]], [445])
        self.assertEqual([entry["current"]["port"] for entry in diff["remained"]], [22])
        self.assertEqual(len(list_assessments(self.path)), 2)

    def test_cvss_fields_are_stored_only_for_complete_verified_record(self):
        findings = evaluate_services([{"port": 443, "service": "https"}, {"port": 22, "service": "ssh"}])
        findings[0]["vulnerability"] = {"verified": True, "cve": "CVE-2024-12345", "cvss_version": "4.0",
            "cvss_score": 8.1, "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "source": "https://www.first.org/cvss/"}
        findings[1]["vulnerability"] = {"verified": False, "cve": "CVE-2024-12345", "cvss_version": "4.0",
            "cvss_score": 8.1, "cvss_vector": "CVSS:4.0/vector", "source": "https://example.test"}
        create_assessment(self.path, "host.example", "standard", findings=findings)
        saved = list_assessments(self.path)[0]["findings"]
        by_port = {finding["port"]: finding for finding in saved}
        self.assertEqual(by_port[443]["vulnerability_status"], "verified")
        self.assertEqual(by_port[443]["cvss_score"], 8.1)
        self.assertEqual(by_port[22]["vulnerability_status"], "not_assessed")
        self.assertIsNone(by_port[22]["cve"])

    def test_additive_migration_preserves_legacy_records(self):
        legacy_path = str(Path(self.temp.name) / "legacy.sqlite3")
        db = sqlite3.connect(legacy_path)
        try:
            db.executescript("""
                CREATE TABLE assessments(id INTEGER PRIMARY KEY,target TEXT,profile TEXT,status TEXT,is_demo INTEGER,created_at TEXT,error TEXT);
                CREATE TABLE findings(id INTEGER PRIMARY KEY,assessment_id INTEGER,port INTEGER,service TEXT,status TEXT,risk TEXT,
                    explanation TEXT,risk_reason TEXT,recommendation TEXT,nist_csf TEXT);
                INSERT INTO assessments VALUES(1,'old.example','standard','completed',0,'2025-01-01T00:00:00Z',NULL);
                INSERT INTO findings VALUES(1,1,23,'Telnet','violation','High','old evidence','old rationale','old action','PR.AA-05,PR.DS-02');
            """)
        finally:
            db.close()
        initialize(legacy_path)
        old = list_assessments(legacy_path)[0]
        self.assertEqual(old["target"], "old.example")
        self.assertEqual(old["findings"][0]["nist_csf"], "PR.AA-05,PR.DS-02")
        self.assertEqual(old["findings"][0]["framework_mappings"], [])
        self.assertEqual(old["findings"][0]["vulnerability_status"], "not_assessed")
        self.assertEqual(old["findings"][0]["status"], "review")
        self.assertEqual(old["findings"][0]["legacy_status"], "violation")


if __name__ == "__main__":
    unittest.main()
