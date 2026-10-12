import unittest
from dataclasses import replace

from compliance_scanner.policy_definitions import FRAMEWORKS, POLICIES
from compliance_scanner.policy_engine import evaluate_services


class PolicyEngineTests(unittest.TestCase):
    def test_telnet_is_review_not_automatic_violation_or_vulnerability(self):
        finding, = evaluate_services([{"port": 23, "protocol": "tcp", "service": "telnet", "state": "open"}])
        self.assertEqual((finding["status"], finding["risk"]), ("review", "High"))
        self.assertEqual(finding["vulnerability_status"], "not_assessed")
        self.assertIn("TCP port 23 open", finding["observation"])
        self.assertIn("PR.DS-02", finding["nist_csf"])
        self.assertEqual(finding["framework_mappings"][0]["version"], "2.0")

    def test_violation_requires_explicit_baseline_rule(self):
        incomplete = replace(POLICIES["telnet"], status="violation")
        pending, = evaluate_services([{"port": 23, "service": "telnet"}], policies={"telnet": incomplete})
        self.assertEqual(pending["status"], "review")

        restricted = replace(POLICIES["telnet"], status="violation",
                             baseline_requirement="Only SSH is permitted for remote administration.")
        finding, = evaluate_services([{"port": 23, "service": "telnet"}], policies={"telnet": restricted})
        self.assertEqual(finding["status"], "violation")
        self.assertEqual(finding["violation_requirement"], restricted.baseline_requirement)
        self.assertEqual(finding["vulnerability_status"], "not_assessed")

    def test_services_have_specific_observation_verification_and_guidance(self):
        observations = [
            {"port": 135, "service": "msrpc"}, {"port": 445, "service": "microsoft-ds"},
            {"port": 80, "service": "http"}, {"port": 443, "service": "https"},
            {"port": 21, "service": "ftp"}, {"port": 22, "service": "ssh"},
            {"port": 3389, "service": "ms-wbt-server"}, {"port": 8001, "service": "oddsvc"},
        ]
        findings = evaluate_services(observations)
        self.assertEqual([f["service"] for f in findings], ["MSRPC", "SMB", "HTTP", "HTTPS", "FTP", "SSH", "RDP", "Oddsvc"])
        for finding in findings:
            self.assertIn("Nmap reported", finding["observation"])
            self.assertTrue(finding["verification"])
            self.assertTrue(finding["recommendation"])
            self.assertEqual(finding["status"], "review")
            self.assertEqual(finding["vulnerability_status"], "not_assessed")
        self.assertIn("share permissions", findings[1]["verification"])
        self.assertIn("does not establish TLS", findings[3]["why_matters"])
        self.assertIn("business purpose", findings[-1]["why_matters"])
        self.assertEqual(findings[0]["framework_mappings"], [])

    def test_only_open_observations_are_evaluated(self):
        findings = evaluate_services([{"port": 22, "service": "ssh", "state": "closed"}])
        self.assertEqual(findings, [])

    def test_nist_framework_mappings_are_versioned_and_have_exact_title_and_rationale(self):
        mappings = [mapping for policy in POLICIES.values() for mapping in policy.framework_rationales]
        self.assertTrue(mappings)
        for framework_id, rationale, evidence_limit in mappings:
            self.assertIn(framework_id, FRAMEWORKS)
            record = FRAMEWORKS[framework_id]
            self.assertEqual(record["framework"], "NIST Cybersecurity Framework")
            self.assertEqual(record["version"], "2.0")
            self.assertTrue(record["title"])
            self.assertTrue(record["source"].startswith("https://www.nist.gov/"))
            self.assertTrue(rationale)
            self.assertTrue(evidence_limit)
        self.assertEqual(FRAMEWORKS["PR.DS-02"]["title"],
            "The confidentiality, integrity, and availability of data-in-transit are protected")


if __name__ == "__main__":
    unittest.main()
