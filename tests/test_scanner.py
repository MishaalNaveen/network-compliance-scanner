import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from compliance_scanner.scanner import (
    PROFILES, InvalidTarget, ScanTimeout, Scanner, ScannerError, ScannerUnavailable,
    build_arguments, parse_nmap_xml, validate_target,
)

XML = '''<?xml version="1.0"?>
<nmaprun><host><ports>
  <port protocol="tcp" portid="23"><state state="open"/><service name="telnet" method="probed" tunnel="ssl"/></port>
  <port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
  <port protocol="udp" portid="161"><state state="open|filtered"/><service name="snmp"/></port>
  <port protocol="udp" portid="53"><state state="open"/><service name="domain" method="table"/></port>
</ports></host></nmaprun>'''


class TargetValidationTests(unittest.TestCase):
    def test_accepts_ipv4_ipv6_and_hostname(self):
        self.assertEqual(validate_target("127.0.0.1"), "127.0.0.1")
        self.assertEqual(validate_target("2001:db8::1"), "2001:db8::1")
        self.assertEqual(validate_target("host.example.org"), "host.example.org")

    def test_rejects_options_ranges_whitespace_and_malformed_names(self):
        for target in ("-oX", "192.0.2.1/24", "999.999.999.999", "host name", "bad..host", "host;whoami", ""):
            with self.subTest(target=target), self.assertRaises(InvalidTarget):
                validate_target(target)


class NmapAdapterTests(unittest.TestCase):
    def test_profiles_build_fixed_bounded_arguments(self):
        for key, expected in (("safe", "25"), ("standard", "100"), ("comprehensive", "1-1024")):
            argv = build_arguments(r"C:\Nmap\nmap.exe", "127.0.0.1", key, "out.xml")
            self.assertEqual(argv[0], r"C:\Nmap\nmap.exe")
            self.assertIn("--", argv)
            self.assertEqual(argv[-1], "127.0.0.1")
            self.assertEqual(argv[argv.index("--top-ports") + 1] if "--top-ports" in argv else argv[argv.index("-p") + 1], expected)
            self.assertFalse(any(arg.startswith("-o") and arg != "-oX" for arg in argv))
        with self.assertRaises(ValueError):
            build_arguments("nmap", "127.0.0.1", "custom", "out.xml")

    def test_xml_parser_returns_normalized_only_open_observations(self):
        self.assertEqual(parse_nmap_xml(XML), [
            {"port": 23, "protocol": "tcp", "service": "telnet", "state": "open",
             "service_method": "probed", "service_tunnel": "ssl"},
            {"port": 53, "protocol": "udp", "service": "domain", "state": "open",
             "service_method": "table", "service_tunnel": None},
        ])
        with self.assertRaises(ScannerError):
            parse_nmap_xml("not xml")

    @patch("compliance_scanner.scanner.subprocess.run")
    def test_scan_uses_argv_xml_file_and_removes_temp_file(self, run):
        def write_output(argv, **kwargs):
            output_file = Path(argv[argv.index("-oX") + 1])
            output_file.write_text(XML, encoding="utf-8")
            return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        run.side_effect = write_output
        with patch.dict(os.environ, {"NMAP_PATH": r"C:\Custom\nmap.exe"}):
            scanner = Scanner()
        result = scanner.scan("127.0.0.1", "safe")
        self.assertEqual(scanner.executable, r"C:\Custom\nmap.exe")
        self.assertEqual(len(result["observations"]), 2)
        argv = run.call_args.args[0]
        self.assertIsInstance(argv, list)
        self.assertEqual(run.call_args.kwargs["timeout"], PROFILES["safe"]["timeout"])
        self.assertIs(run.call_args.kwargs["shell"], False)
        self.assertFalse(Path(argv[argv.index("-oX") + 1]).exists())

    @patch("compliance_scanner.scanner.subprocess.run", side_effect=__import__("subprocess").TimeoutExpired("nmap", 1))
    def test_timeout_has_safe_message_and_cleans_xml_file(self, run):
        with self.assertRaises(ScanTimeout) as caught:
            Scanner(executable="nmap", timeout=1).scan("localhost", "safe")
        self.assertIn("no assessment was saved", str(caught.exception))
        argv = run.call_args.args[0]
        self.assertFalse(Path(argv[argv.index("-oX") + 1]).exists())

    @patch("compliance_scanner.scanner.subprocess.run", side_effect=FileNotFoundError("private system path"))
    def test_missing_executable_does_not_expose_system_error(self, run):
        with self.assertRaises(ScannerUnavailable) as caught:
            Scanner(executable="missing-nmap").scan("localhost", "safe")
        self.assertIn("NMAP_PATH", str(caught.exception))
        self.assertNotIn("private system path", str(caught.exception))

    @patch("compliance_scanner.scanner.subprocess.run")
    def test_nonzero_nmap_exit_does_not_save_success(self, run):
        run.return_value = type("Result", (), {"returncode": 2, "stdout": "", "stderr": "secret detail"})()
        with self.assertRaises(ScannerError) as caught:
            Scanner(executable="nmap").scan("localhost", "safe")
        self.assertIn("no assessment was saved", str(caught.exception))
        self.assertNotIn("secret detail", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
