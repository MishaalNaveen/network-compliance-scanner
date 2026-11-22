import unittest
from dataclasses import replace

from compliance_scanner.policy_definitions import FRAMEWORKS, POLICIES
from compliance_scanner.policy_engine import evaluate_services


class PolicyEngineTests(unittest.TestCase):
    def test_telnet_is_review_not_automatic_violation_or_vulnerability(self):
        finding, = evaluate_services([{"port": 23, "protocol": "tcp", "service": "telnet",
                                       "state": "open", "service_method": "probed"}])
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

    def test_mapping_assignment_for_all_service_rules(self):
        for port, name, expected in (
            (23, "telnet", ["PR.DS-02", "4.8"]), (21, "ftp", ["PR.DS-02", "4.8"]),
            (80, "http", ["PR.DS-02", "PR.PS-01"]), (8000, "http-alt", ["PR.DS-02", "PR.PS-01"]),
            (8080, "http-proxy", ["PR.DS-02", "PR.PS-01"]), (22, "ssh", ["PR.AA-03", "6.5"]),
            (443, "https", ["PR.DS-02"]), (139, "netbios-ssn", ["PR.IR-01", "4.8"]),
            (445, "microsoft-ds", ["PR.IR-01", "4.8"]), (135, "msrpc", ["PR.IR-01"]),
            (593, "ncacn_http", ["PR.IR-01"]), (3389, "ms-wbt-server", ["PR.AA-03", "6.5"]),
            (8001, "oddsvc", ["ID.AM-02"]),
        ):
            with self.subTest(port=port, name=name):
                finding, = evaluate_services([{"port": port, "service": name, "service_method": "probed"}])
                self.assertEqual(finding["nist_csf"], [identifier for identifier in expected if "-" in identifier])
                mappings = finding["framework_mappings"]
                self.assertEqual([m["identifier"] for m in mappings], expected)
                evidence_supported = name in {"telnet", "ftp", "http", "http-alt", "http-proxy"}
                for index, mapping in enumerate(mappings):
                    category = "Evidence-supported relevance" if evidence_supported and index == 0 else "Potential control relevance"
                    self.assertEqual(mapping["category"], category)
                    self.assertIn(f"port {port} open", mapping["evidence"])
                    self.assertTrue(mapping["rationale"])
                    self.assertTrue(mapping["verification"])
                    self.assertIn("does not establish compliance or noncompliance", mapping["evidence_limit"])

    def test_uncertain_conflicting_and_tls_service_evidence_uses_potential_references(self):
        for port, service, method, tunnel, expected in (
            (23, "telnet", "table", None, "4.8"), (21, "ftp", None, None, "4.8"),
            (80, "unknown", None, None, "PR.PS-01"), (80, "other", "probed", None, "ID.AM-02"),
            (8000, "http-alt", "table", None, "PR.PS-01"), (8080, "http-proxy", "table", None, "PR.PS-01"),
            (8000, "unknown", None, None, "ID.AM-02"), (8080, "unknown", None, None, "ID.AM-02"),
            (8080, "http", "probed", "ssl", "PR.DS-02"), (80, "https", "probed", None, "PR.DS-02"),
        ):
            with self.subTest(port=port, service=service, method=method, tunnel=tunnel):
                finding, = evaluate_services([{"port": port, "service": service,
                                               "service_method": method, "service_tunnel": tunnel}])
                mapping, = finding["framework_mappings"]
                self.assertEqual(mapping["identifier"], expected)
                self.assertEqual(mapping["category"], "Potential control relevance")
                if method != "probed":
                    self.assertIn("service identity is unverified", mapping["evidence"])
                if method == "table":
                    self.assertIn("inferred the label from its port table", mapping["evidence"])
                self.assertEqual(finding["policy_status"], "review")

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
        self.assertEqual({key: entry["title"] for key, entry in FRAMEWORKS.items() if entry["version"] == "2.0"}, {
            "PR.DS-02": "The confidentiality, integrity, and availability of data-in-transit are protected",
            "ID.AM-02": "Inventories of software, services, and systems managed by the organization are maintained",
            "PR.PS-01": "Configuration management practices are established and applied",
            "PR.IR-01": "Networks and environments are protected from unauthorized logical access and usage",
            "PR.AA-03": "Users, services, and hardware are authenticated",
        })

    def test_cis_v81_exact_safeguard_titles_and_descriptions(self):
        self.assertEqual({key: (entry["title"], entry["description"]) for key, entry in FRAMEWORKS.items()
                          if entry["framework"] == "CIS Controls" and entry["version"] == "8.1"}, {
            "4.8": ("Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
                    "Uninstall or disable unnecessary services on enterprise assets and software, such as an unused file sharing service, web application module, or service function."),
            "6.5": ("Require MFA for Administrative Access",
                    "Require MFA for all administrative access accounts, where supported, on all enterprise assets, whether managed on-site or through a service provider."),
        })


if __name__ == "__main__":
    unittest.main()
