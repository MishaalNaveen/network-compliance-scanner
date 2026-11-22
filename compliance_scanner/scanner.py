"""Bounded Nmap adapter. Scans are started only by an explicit form submission."""
import ipaddress
import os
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path


class ScannerError(RuntimeError):
    """Safe, user-displayable scan error."""


class ScannerUnavailable(ScannerError):
    """Nmap could not be started or is not installed/configured."""


class ScanTimeout(ScannerError):
    """Nmap exceeded the configured time limit."""


class InvalidTarget(ValueError):
    pass


DEFAULT_NMAP_EXECUTABLE = r"C:\Program Files (x86)\Nmap\nmap.exe"
NMAP_ENVIRONMENT_VARIABLE = "NMAP_PATH"

# Every option is application-owned. Do not append form or environment input here.
PROFILES = {
    "safe": {
        "label": "Safe discovery",
        "arguments": ("-sT", "-Pn", "-T2", "--top-ports", "25"),
        "timeout": 60,
    },
    "standard": {
        "label": "Standard service review",
        "arguments": ("-sT", "-sV", "--version-light", "-Pn", "-T3", "--top-ports", "100"),
        "timeout": 150,
    },
    "comprehensive": {
        "label": "Comprehensive inventory",
        "arguments": ("-sT", "-sV", "--version-light", "-Pn", "-T3", "-p", "1-1024"),
        "timeout": 240,
    },
}

_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def validate_target(target):
    """Accept one IP address or a DNS hostname; reject options, ranges and malformed input."""
    if not isinstance(target, str):
        raise InvalidTarget("Enter one valid hostname or IP address.")
    target = target.strip()
    if not target or len(target) > 253 or target.startswith("-"):
        raise InvalidTarget("Enter one valid hostname or IP address; scan ranges are not accepted.")
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass
    if re.fullmatch(r"[0-9.]+", target):
        raise InvalidTarget("Enter a valid IP address or hostname.")
    hostname = target[:-1] if target.endswith(".") else target
    if not hostname or len(hostname) > 253 or any(not _HOST_LABEL.fullmatch(label) for label in hostname.split(".")):
        raise InvalidTarget("Enter one valid hostname or IP address; scan ranges and Nmap options are not accepted.")
    return hostname


def build_arguments(executable, target, profile, xml_path):
    """Build a fixed, shell-free argv list for a supported profile."""
    normalized_target = validate_target(target)
    if profile not in PROFILES:
        raise ValueError("Choose a valid scan profile.")
    return [str(executable), *PROFILES[profile]["arguments"], "-oX", str(xml_path), "--", normalized_target]


def parse_nmap_xml(xml_content):
    """Return normalized open TCP/UDP port observations from Nmap XML."""
    try:
        root = ET.fromstring(xml_content)
    except (ET.ParseError, TypeError, ValueError) as exc:
        raise ScannerError("Nmap returned unreadable scan results. No assessment was saved.") from exc
    observations = []
    for port in root.findall(".//host/ports/port"):
        state_element = port.find("state")
        state = state_element.get("state", "unknown") if state_element is not None else "unknown"
        if state != "open":
            continue
        service_element = port.find("service")
        service = service_element.get("name", "unknown") if service_element is not None else "unknown"
        observations.append({
            "port": int(port.get("portid")),
            "protocol": port.get("protocol", "unknown"),
            "service": service or "unknown",
            "service_method": service_element.get("method") if service_element is not None else None,
            "service_tunnel": service_element.get("tunnel") if service_element is not None else None,
            "state": state,
        })
    return observations


class Scanner:
    def __init__(self, executable=None, timeout=None):
        self.executable = executable or os.environ.get(NMAP_ENVIRONMENT_VARIABLE) or DEFAULT_NMAP_EXECUTABLE
        self.timeout = timeout

    def scan(self, target, profile):
        normalized_target = validate_target(target)
        if profile not in PROFILES:
            raise ValueError("Choose a valid scan profile.")
        timeout = self.timeout or PROFILES[profile]["timeout"]
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile(prefix="compliance-nmap-", suffix=".xml", delete=False) as xml_file:
                temp_name = xml_file.name
            args = build_arguments(self.executable, normalized_target, profile, temp_name)
            result = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                                    check=False, shell=False)
            if result.returncode != 0:
                raise ScannerError("Nmap could not complete this scan. Check the target, profile, and Nmap installation; no assessment was saved.")
            try:
                xml_data = Path(temp_name).read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise ScannerError("Nmap did not produce readable results. No assessment was saved.") from exc
            observations = parse_nmap_xml(xml_data)
            return {"target": normalized_target, "profile": profile, "observations": observations}
        except subprocess.TimeoutExpired as exc:
            raise ScanTimeout("The scan exceeded its time limit. Narrow the target or choose a lighter profile; no assessment was saved.") from exc
        except FileNotFoundError as exc:
            raise ScannerUnavailable("Nmap was not found. Install Nmap or set the NMAP_PATH environment variable to nmap.exe; no assessment was saved.") from exc
        except PermissionError as exc:
            raise ScannerUnavailable("Nmap could not be started with the current permissions. Check the Nmap installation; no assessment was saved.") from exc
        except OSError as exc:
            raise ScannerUnavailable("Nmap could not be started. Check the Nmap installation and NMAP_PATH setting; no assessment was saved.") from exc
        finally:
            if temp_name:
                try:
                    Path(temp_name).unlink(missing_ok=True)
                except OSError:
                    pass
